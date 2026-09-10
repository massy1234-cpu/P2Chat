package connection

import (
	clientdb "P2Chat/cmd/client/database"
	blind "P2Chat/cmd/client/internals/network/blind_signature"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	"P2Chat/cmd/client/internals/protocol/pqxdh"
	"P2Chat/cmd/client/internals/storage"
	serverdb "P2Chat/cmd/server/database"
	idserver "P2Chat/cmd/server/internals/ID_server"
	serverblind "P2Chat/cmd/server/internals/network/blind_signature"
	serverclient "P2Chat/cmd/server/internals/network/client"
	serverconn "P2Chat/cmd/server/internals/network/connection"
	serverbundle "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"github.com/awnumar/memguard"
	"github.com/hashicorp/yamux"
	bbolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestLoginOverTLSAndYamux(t *testing.T) {
	oldPath := storage.BasePath
	storage.BasePath = t.TempDir()
	if err := serverdb.Init(); err != nil {
		t.Fatal(err)
	}
	db, err := bbolt.Open(filepath.Join(storage.BasePath, "client.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDB := clientdb.DB
	clientdb.DB = db
	t.Cleanup(func() { db.Close(); clientdb.DB = oldDB; serverdb.CloseDB(); storage.BasePath = oldPath })
	password := memguard.NewBufferRandom(32).Seal()
	if err := idserver.Init(1, password, false); err != nil {
		t.Fatal(err)
	}
	public, _, err := pqxdh.CreateBundles(password, 1, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	stored := &serverbundle.PublicBundle{}
	if err := proto.Unmarshal(encoded, stored); err != nil {
		t.Fatal(err)
	}
	h1, h2 := sha256.Sum256(stored.IkX25519), sha256.Sum256(stored.IkMldsa)
	bundleID := sha256.Sum256(append(h1[:], h2[:]...))
	if err := serverdb.SaveBundle(&serverbundle.BundleUploadPayload{PublicBundle: stored}, bundleID, []byte("wire-login")); err != nil {
		t.Fatal(err)
	}
	identity := idserver.GetCurrentID()
	serverID := sha256.Sum256(append(identity.PubMLDSA.Bytes(), identity.PubX25519.Bytes()...))
	// The handler tests exercise issuance; seed its resulting token for reconnect tests.
	keys, err := serverblind.GetLoginKeys()
	if err != nil {
		t.Fatal(err)
	}
	st, point, err := blind.CreateAndBlind()
	if err != nil {
		t.Fatal(err)
	}
	blindSig, _ := keys.Keys.Sk.SignBlind(point)
	sig := st.Unblind(blindSig)
	sigBytes := sig.Bytes()
	tokenBytes, err := proto.Marshal(&loginproto.LoginToken{Message: st.Msg, Signature: sigBytes[:], KeyHash: keys.Hash[:], ExpiresAt: keys.ExpiresAt, ServerId: serverID[:]})
	if err != nil {
		t.Fatal(err)
	}
	token := memguard.NewEnclave(tokenBytes)
	memguard.WipeBytes(tokenBytes)
	memguard.WipeBytes(st.Msg)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	var connections []*Connection
	var servers []*serverconn.Connection
	t.Cleanup(func() {
		for _, c := range connections {
			c.Close()
		}
		for _, s := range servers {
			s.Close()
		}
	})
	for i := 0; i < 3; i++ {
		left, right := net.Pipe()
		clientTLS := tls.Client(left, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		serverTLS := tls.Server(right, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		deadline := time.Now().Add(20 * time.Second)
		left.SetDeadline(deadline)
		right.SetDeadline(deadline)
		handshake := make(chan error, 1)
		go func() { handshake <- serverTLS.Handshake() }()
		if err := clientTLS.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-handshake; err != nil {
			t.Fatal(err)
		}
		cs, ss := clientTLS.ConnectionState(), serverTLS.ConnectionState()
		binding, err := cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		serverBinding, err := ss.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		remote := serverclient.NewClient(serverTLS, make(chan uint64, 1))
		if remote == nil {
			t.Fatal("server client creation failed")
		}
		cy, err := yamux.Client(clientTLS, nil)
		if err != nil {
			t.Fatal(err)
		}
		s := remote.Conn
		if string(s.Binding) != string(serverBinding) || remote.Authed.Load() {
			t.Fatal("invalid initial client state")
		}
		c := NewConnection(cy)
		c.Endpoint = "192.0.2.1:9000"
		connections = append(connections, c)
		servers = append(servers, s)
		next, err := c.Login(binding, &clientdb.LoginBundle{LocalID: 0, BundleID: bundleID[:]}, password, token)
		if err != nil {
			t.Fatalf("login %d: %v", i+1, err)
		}
		if !remote.Authed.Load() || s.Auth.Load() == nil || serverconn.ActiveConnections(bundleID) != i+1 {
			t.Fatal("missing authenticated presence")
		}
		if i == 2 && next != nil {
			t.Fatal("exhausted token retained")
		}
	}
	connections[0].Close()
	deadline := time.Now().Add(3 * time.Second)
	for serverconn.ActiveConnections(bundleID) != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if serverconn.ActiveConnections(bundleID) != 2 {
		t.Fatal("closing one connection removed wrong presence")
	}
	if servers[0].Authed.Load() {
		t.Fatal("closed client still authenticated")
	}
}
