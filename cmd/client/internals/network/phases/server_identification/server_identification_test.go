package server_identification

import (
	"P2Chat/cmd/client/database"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/network/phases"
	serverproto "P2Chat/cmd/client/internals/proto_generated/server_identification/proto_struct_server"
	"P2Chat/cmd/client/internals/storage"
	idserver "P2Chat/cmd/server/internals/ID_server"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	messagepack "github.com/vmihailenco/msgpack/v5"
	bbolt "go.etcd.io/bbolt"
	proto "google.golang.org/protobuf/proto"
)

func TestIdentificationVerification(t *testing.T) {
	serverConns := make(chan *tls.Conn, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			serverConns <- conn.(*tls.Conn)
		}
	}
	server.StartTLS()
	defer server.Close()
	mlPrivate, mlPublic, err := mldsa_keys.CreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	xPrivate, xPublic, err := x25519.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write(mlPublic.Bytes())
	hash.Write(xPublic.Bytes())
	id := hash.Sum(nil)
	for _, name := range []string{"valid", "wrong nonce", "wrong binding", "wrong ID", "bad MLDSA", "bad X25519", "wrong MLDSA key size", "wrong X25519 key size", "wrong MLDSA signature size", "wrong X25519 signature size", "oversized version", "oversized payload", "truncated"} {
		t.Run(name, func(t *testing.T) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			serverConn := <-serverConns
			if err := serverConn.Handshake(); err != nil {
				t.Fatal(err)
			}
			previousRoot := storage.ProjectRoot
			storage.ProjectRoot = t.TempDir()
			if err := database.Init(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = database.CloseDB()
				storage.ProjectRoot = previousRoot
			}()
			clientTLSState := conn.ConnectionState()
			clientBinding, err := clientTLSState.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
			if err != nil {
				t.Fatal(err)
			}
			var phaseState any = &IdentificationClient{Binding: clientBinding}
			start := Handler(phases.ServerIdentityRequest, nil, &phaseState)
			if start.Err != nil || len(start.IntoWire) != 1 || start.NextDeadline != 30*time.Second {
				t.Fatalf("invalid start: %+v", start)
			}
			request := &serverproto.IdentificationRequest{}
			if err := proto.Unmarshal(start.IntoWire[0][1:], request); err != nil {
				t.Fatal(err)
			}
			if len(request.Nonce) != 32 {
				t.Fatal("invalid nonce length")
			}
			tlsState := serverConn.ConnectionState()
			binding, err := tlsState.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
			if err != nil {
				t.Fatal(err)
			}
			if name == "wrong nonce" {
				request.Nonce[0] ^= 1
			}
			if name == "wrong binding" {
				binding[0] ^= 1
			}
			message := append([]byte{1}, request.Nonce...)
			message = append(message, binding...)
			mlSignature, err := mlPrivate.Sign(message, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			xSignature, err := xPrivate.Sign(message)
			if err != nil {
				t.Fatal(err)
			}
			response := &serverproto.ServerID{VersionP2: 1, Id: append([]byte(nil), id...), PubMldsa: mlPublic.Bytes(), PubX25519: xPublic.Bytes(), MldsaSign: mlSignature, X25519Sign: xSignature}
			switch name {
			case "wrong ID":
				response.Id[0] ^= 1
			case "bad MLDSA":
				response.MldsaSign[0] ^= 1
			case "bad X25519":
				response.X25519Sign[0] ^= 1
			case "wrong MLDSA key size":
				response.PubMldsa = response.PubMldsa[:len(response.PubMldsa)-1]
			case "wrong X25519 key size":
				response.PubX25519 = response.PubX25519[:len(response.PubX25519)-1]
			case "wrong MLDSA signature size":
				response.MldsaSign = response.MldsaSign[:len(response.MldsaSign)-1]
			case "wrong X25519 signature size":
				response.X25519Sign = response.X25519Sign[:len(response.X25519Sign)-1]
			case "oversized version":
				response.VersionP2 = 256
			}
			payload, err := proto.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if name == "truncated" {
				payload = payload[:len(payload)-1]
			}
			if name == "oversized payload" {
				payload = make([]byte, 8193)
			}
			result := Handler(phases.ServerIdentityResponse, payload, &phaseState)
			if name != "valid" {
				if result.Err == nil || !result.CloseStream {
					t.Fatal("invalid response accepted")
				}
				if name != "oversized payload" && phaseState.(*IdentificationClient).state != stateFailed {
					t.Fatal("failed identification was not marked as failed")
				}
				if err := database.DB.View(func(tx *bbolt.Tx) error {
					servers := tx.Bucket([]byte("servers"))
					if servers != nil {
						serverID, _ := servers.Cursor().First()
						if serverID != nil {
							t.Fatal("invalid identity reached database")
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return
			}
			if result.Err != nil || !result.Completed {
				t.Fatalf("valid response rejected: %+v", result)
			}
			var stored idserver.IDServer
			if err := database.DB.View(func(tx *bbolt.Tx) error {
				return messagepack.Unmarshal(tx.Bucket([]byte("servers")).Bucket(id).Get([]byte("identity")), &stored)
			}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored.PubMLDSA, response.PubMldsa) {
				t.Fatal("wrong saved identity")
			}
			if exists, err := database.SaveServerID(&stored); err != nil || !exists {
				t.Fatalf("existing identity not detected: %v", err)
			}
			if replay := Handler(phases.ServerIdentityResponse, payload, &phaseState); replay.Err == nil {
				t.Fatal("completed phase accepted replay")
			}
		})
	}
}
