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
	serverphases "P2Chat/cmd/server/internals/network/phases"
	serverlogin "P2Chat/cmd/server/internals/network/phases/login"
	bundleproto "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/awnumar/memguard"
	"google.golang.org/protobuf/proto"
	"testing"
	"time"
)

func TestLoginProtocol(t *testing.T) {
	previous := storage.BasePath
	storage.BasePath = t.TempDir()
	t.Cleanup(func() { database.CloseDB(); storage.BasePath = previous })
	if err := database.Init(); err != nil {
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
	if err := database.SaveBundle(&bundleproto.UserBundle{PublicBundle: &bundleproto.PublicBundle{IkMldsa: mlPK.Bytes(), IkX25519: xPK.Bytes()}}, bundleID, []byte("login-test")); err != nil {
		t.Fatal(err)
	}
	identity := idserver.GetCurrentID()
	serverID := sha256.Sum256(append(identity.PubMLDSA.Bytes(), identity.PubX25519.Bytes()...))
	binding := bytes.Repeat([]byte{7}, 32)
	var issued *memguard.Enclave
	run := func(t *testing.T, token *memguard.Enclave, mutate func(*loginproto.LoginProof), wrongBinding bool, wantSuccess bool) {
		t.Helper()
		authed := false
		keys := &Credentials{BundleID: bundleID[:], MLDSA: mlSK, X25519: xSK}
		serverBinding := append([]byte(nil), binding...)
		if wrongBinding {
			serverBinding[0] ^= 1
		}
		server := &serverlogin.LoginServer{Binding: serverBinding, Level: pow.Level1, Authenticate: func(id []byte, full bool) error {
			if !bytes.Equal(id, bundleID[:]) {
				t.Fatal("wrong authenticated identity")
			}
			if full != (token == nil) {
				t.Fatal("wrong PoW authentication state")
			}
			authed = true
			return nil
		}}
		var cstate any
		var sstate any = server
		result := Handler(StartLogin, nil, &cstate)
		var lastProof []byte
		for step := 0; step < 15; step++ {
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			if result.Completed {
				break
			}
			if len(result.Events) == 1 {
				event := result.Events[0]
				var tag byte
				var payload []byte
				var err error
				switch event[0] {
				case NotifyReady:
					tag = Parameters
					payload, err = EncodeParameters(binding, serverID[:], bundleID[:], token != nil)
				case NotifyPassToken:
					tag = PassToken
					opened, openErr := token.Open()
					if openErr != nil {
						t.Fatal(openErr)
					}
					payload = append([]byte(nil), opened.Bytes()...)
					opened.Destroy()
				case NotifySolvePoW:
					tag = PoWSolution
					payload, err = SolveChallenge(context.Background(), event[1:])
				case NotifySignProof:
					tag = SignedProof
					payload, err = SignProof(keys, event[1:])
				default:
					t.Fatalf("unexpected phase event: %v", event[0])
				}
				if err != nil {
					t.Fatal(err)
				}
				result = Handler(tag, payload, &cstate)
				continue
			}
			if len(result.IntoWire) != 1 {
				t.Fatalf("missing request at step %d", step)
			}
			wire := append([]byte(nil), result.IntoWire[0]...)
			if wire[0] == phases.LoginIdentityProof {
				proof := &loginproto.LoginProof{}
				if err := proto.Unmarshal(wire[1:], proof); err != nil {
					t.Fatal(err)
				}
				if mutate != nil {
					mutate(proof)
				}
				payload, err := proto.Marshal(proof)
				if err != nil {
					t.Fatal(err)
				}
				wire = append([]byte{phases.LoginIdentityProof}, payload...)
				lastProof = append([]byte(nil), payload...)
			}
			sresult := serverlogin.Handler(wire[0], wire[1:], &sstate)
			if sresult.Err != nil {
				if wantSuccess {
					t.Fatalf("server rejected: %v", sresult.Err)
				}
				if authed {
					t.Fatal("invalid proof authenticated connection")
				}
				return
			}
			if len(sresult.IntoWire) != 1 {
				t.Fatal("missing server reply")
			}
			wire = sresult.IntoWire[0]
			result = Handler(wire[0], wire[1:], &cstate)
		}
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if wantSuccess {
			if !authed || !result.Completed || len(result.Events) != 1 || result.Events[0][0] != NotifyCompleted {
				t.Fatal("login did not complete")
			}
			if token == nil {
				if len(result.Events[0]) <= 2 {
					t.Fatal("missing issued token")
				}
				issued = memguard.NewEnclave(result.Events[0][2:])
			}
			if replay := serverlogin.Handler(serverphases.LoginIdentityProof, lastProof, &sstate); replay.Err == nil {
				t.Fatal("accepted replay after completion")
			}
		} else if authed || len(result.Events) != 1 || result.Events[0][0] != NotifyTokenRejected {
			t.Fatal("invalid login accepted")
		}
	}
	t.Run("full login issues verified blind token", func(t *testing.T) {
		run(t, nil, nil, false, true)
		if issued == nil {
			t.Fatal("missing token")
		}
	})
	for _, tc := range []struct {
		name    string
		mutate  func(*loginproto.LoginProof)
		binding bool
	}{
		{"bad MLDSA", func(p *loginproto.LoginProof) { p.MldsaSignature[0] ^= 1 }, false},
		{"bad X25519", func(p *loginproto.LoginProof) { p.X25519Signature[0] ^= 1 }, false},
		{"unknown bundle", func(p *loginproto.LoginProof) { p.BundleId[0] ^= 1 }, false},
		{"wrong timestamp", func(p *loginproto.LoginProof) { p.Timestamp-- }, false},
		{"different TLS binding", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) { run(t, issued, tc.mutate, tc.binding, false) })
	}
	for _, name := range []string{"first use", "second use", "third use"} {
		t.Run(name, func(t *testing.T) { run(t, issued, nil, false, true) })
	}
	t.Run("fourth use refused", func(t *testing.T) { run(t, issued, nil, false, false) })
	t.Run("PoW timeout preserved", func(t *testing.T) {
		var st any = &serverlogin.LoginServer{Binding: binding, Authenticate: func([]byte, bool) error { return nil }}
		res := serverlogin.Handler(phases.LoginStart, nil, &st)
		if res.Err != nil || res.NextDeadline != 10*time.Minute {
			t.Fatalf("bad PoW deadline: %+v", res)
		}
	})
}

func TestLoginCreatesOwnState(t *testing.T) {
	var st any
	result := Handler(StartLogin, nil, &st)
	if result.Err != nil || len(result.IntoWire) != 0 || len(result.Events) != 1 || result.Events[0][0] != NotifyReady {
		t.Fatal("login must request parameters through Events")
	}
	if _, ok := st.(*LoginClient); !ok {
		t.Fatal("handler did not initialize its own state")
	}
	result = Handler(phases.LoginChallengeNonce, make([]byte, 34), &st)
	if result.Err == nil {
		t.Fatal("accepted network nonce before local parameters")
	}
	if st.(*LoginClient).state != stateFailed {
		t.Fatal("failed login was not marked as failed")
	}
}

func TestLoginPoWCancellation(t *testing.T) {
	var st any = &serverlogin.LoginServer{Binding: bytes.Repeat([]byte{1}, 32), Level: pow.Level1, Authenticate: func([]byte, bool) error { return nil }}
	result := serverlogin.Handler(phases.LoginStart, nil, &st)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SolveChallenge(ctx, result.IntoWire[0][1:]); err == nil {
		t.Fatal("cancelled PoW continued")
	}
}
