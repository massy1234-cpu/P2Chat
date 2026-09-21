package login

import (
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	x25519 "P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/network/phases"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/cmd/server/database"
	idserver "P2Chat/cmd/server/internals/ID_server"
	pow "P2Chat/cmd/server/internals/network/PoW"
	serverlogin "P2Chat/cmd/server/internals/network/phases/login"
	bundleproto "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/awnumar/memguard"
	"google.golang.org/protobuf/proto"
)

func TestAnonymousPassTokenProtocol(t *testing.T) {
	previous := storage.BasePath
	storage.BasePath = t.TempDir()
	t.Cleanup(func() {
		_ = database.CloseSignature()
		database.CloseDB()
		storage.BasePath = previous
	})
	if err := database.Init(); err != nil {
		t.Fatal(err)
	}
	if err := database.InitSignature(); err != nil {
		t.Fatal(err)
	}
	if err := idserver.Init(1, memguard.NewBufferRandom(32).Seal(), false); err != nil {
		t.Fatal(err)
	}
	mlSK, mlPK, err := mldsa.CreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	xSK, xPK, err := x25519.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	h1, h2 := sha256.Sum256(xPK.Bytes()), sha256.Sum256(mlPK.Bytes())
	bundleID := sha256.Sum256(append(h1[:], h2[:]...))
	bundle := &bundleproto.UserBundle{Nickname: "login-test", PublicBundle: &bundleproto.PublicBundle{IkMldsa: mlPK.Bytes(), IkX25519: xPK.Bytes()}}
	if err := database.SaveBundle(bundle, nil, nil, bundleID); err != nil {
		t.Fatal(err)
	}
	identity := idserver.GetCurrentID()
	serverID := sha256.Sum256(append(identity.PubMLDSA.Bytes(), identity.PubX25519.Bytes()...))
	binding := bytes.Repeat([]byte{7}, 32)
	keys := &Credentials{BundleID: bundleID[:], MLDSA: mlSK, X25519: xSK}

	fullAuthenticated := false
	server := &serverlogin.LoginServer{
		Binding: binding,
		Level:   pow.Level1,
		Authenticate: func(id []byte, full bool) error {
			fullAuthenticated = full && bytes.Equal(id, bundleID[:])
			return nil
		},
		AuthenticateAnonymous: func() error {
			t.Fatal("full login authenticated anonymously")
			return nil
		},
	}
	event := runProtocol(t, server, binding, serverID[:], keys, nil)
	if !fullAuthenticated || len(event) < 2 || event[0] != NotifyCompleted {
		t.Fatal("full PoW and bundle proof did not complete")
	}
	batch := &loginproto.LoginTokenBatch{}
	if err := proto.Unmarshal(event[1:], batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Tokens) != 3 {
		t.Fatalf("issued %d pass tokens", len(batch.Tokens))
	}

	var firstToken []byte
	for i, pass := range batch.Tokens {
		serialized, err := proto.Marshal(pass)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstToken = append([]byte(nil), serialized...)
		}
		anonymousAuthenticated := false
		server := &serverlogin.LoginServer{
			Binding: binding,
			Level:   pow.Level1,
			Authenticate: func([]byte, bool) error {
				t.Fatal("pass token requested a bundle proof")
				return nil
			},
			AuthenticateAnonymous: func() error {
				anonymousAuthenticated = true
				return nil
			},
		}
		result := runProtocol(t, server, binding, serverID[:], keys, serialized)
		if !anonymousAuthenticated || len(result) != 1 || result[0] != NotifyCompleted {
			t.Fatalf("fresh pass token %d was not accepted anonymously", i+1)
		}
	}
	anonymousAuthenticated := false
	server = &serverlogin.LoginServer{
		Binding: binding,
		Level:   pow.Level1,
		Authenticate: func([]byte, bool) error {
			t.Fatal("spent pass token requested a bundle proof")
			return nil
		},
		AuthenticateAnonymous: func() error {
			anonymousAuthenticated = true
			return nil
		},
	}
	result := runProtocol(t, server, binding, serverID[:], keys, firstToken)
	if anonymousAuthenticated || len(result) != 1 || result[0] != NotifyTokenRejected {
		t.Fatal("spent pass token was accepted")
	}
}

func runProtocol(t *testing.T, server *serverlogin.LoginServer, binding, serverID []byte, keys *Credentials, token []byte) []byte {
	t.Helper()
	var clientState any
	var serverState any = server
	result := Handler(StartLogin, nil, &clientState)
	for step := 0; step < 16; step++ {
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if result.Completed {
			if len(result.Events) != 1 {
				t.Fatal("missing completion event")
			}
			return result.Events[0]
		}
		if len(result.Events) == 1 {
			event := result.Events[0]
			var tag byte
			var payload []byte
			var err error
			switch event[0] {
			case NotifyReady:
				tag = Parameters
				payload, err = EncodeParameters(binding, serverID, keys.BundleID, token != nil)
			case NotifyPassToken:
				tag, payload = PassToken, append([]byte(nil), token...)
			case NotifySolvePoW:
				tag = PoWSolution
				payload, err = SolveChallenge(context.Background(), event[1:])
			case NotifySignProof:
				tag = SignedProof
				payload, err = SignProof(keys, event[1:])
			default:
				t.Fatalf("unexpected event %x", event[0])
			}
			if err != nil {
				t.Fatal(err)
			}
			result = Handler(tag, payload, &clientState)
			continue
		}
		if len(result.IntoWire) != 1 {
			t.Fatalf("missing wire request at step %d", step)
		}
		wire := result.IntoWire[0]
		serverResult := serverlogin.Handler(wire[0], wire[1:], &serverState)
		if serverResult.Err != nil {
			t.Fatal(serverResult.Err)
		}
		if len(serverResult.IntoWire) != 1 {
			t.Fatal("missing server response")
		}
		wire = serverResult.IntoWire[0]
		result = Handler(wire[0], wire[1:], &clientState)
	}
	t.Fatal("login protocol did not complete")
	return nil
}

func TestLoginCreatesOwnState(t *testing.T) {
	var state any
	result := Handler(StartLogin, nil, &state)
	if result.Err != nil || len(result.Events) != 1 || result.Events[0][0] != NotifyReady {
		t.Fatal("login must request parameters through Events")
	}
	if _, ok := state.(*LoginClient); !ok {
		t.Fatal("handler did not initialize its own state")
	}
	result = Handler(phases.LoginChallengeNonce, make([]byte, 34), &state)
	if result.Err == nil || state.(*LoginClient).state != stateFailed {
		t.Fatal("accepted nonce before local parameters")
	}
}
