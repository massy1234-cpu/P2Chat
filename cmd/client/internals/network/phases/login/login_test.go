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
	if err := database.SaveBundle(&bundleproto.BundleUploadPayload{PublicBundle: &bundleproto.PublicBundle{IkMldsa: mlPK.Bytes(), IkX25519: xPK.Bytes()}}, bundleID, []byte("login-test")); err != nil {
		t.Fatal(err)
	}
	identity := idserver.GetCurrentID()
	serverID := sha256.Sum256(append(identity.PubMLDSA.Bytes(), identity.PubX25519.Bytes()...))
	binding := bytes.Repeat([]byte{7}, 32)
	var issued *memguard.Enclave
	run := func(t *testing.T, token *memguard.Enclave, mutate func(*loginproto.LoginProof), wrongBinding bool, wantSuccess bool) {
		t.Helper()
		authed := false
		var next *memguard.Enclave
		client := &LoginClient{Binding: binding, ServerID: serverID[:], BundleID: bundleID[:], MLDSA: mlSK, X25519: xSK, Token: token, SaveToken: func(value *memguard.Enclave) { next = value }}
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
		var cstate any = client
		var sstate any = server
		result := Handler(phases.LoginAccessRequest, nil, &cstate)
		var lastProof []byte
		for step := 0; step < 5; step++ {
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			if result.Completed {
				break
			}
			if len(result.Replies) != 1 {
				t.Fatalf("missing request at step %d", step)
			}
			wire := append([]byte(nil), result.Replies[0]...)
			if wire[0] == phases.LoginProof {
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
				wire = append([]byte{phases.LoginProof}, payload...)
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
			if len(sresult.Replies) != 1 {
				t.Fatal("missing server reply")
			}
			wire = sresult.Replies[0]
			result = Handler(wire[0], wire[1:], &cstate)
		}
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if wantSuccess {
			if !authed || !result.Completed || len(result.Events) != 1 || result.Events[0][0] != 1 {
				t.Fatal("login did not complete")
			}
			if token == nil {
				issued = next
			}
			if replay := serverlogin.Handler(serverphases.LoginProof, lastProof, &sstate); replay.Err == nil {
				t.Fatal("accepted replay after completion")
			}
		} else if authed || len(result.Events) != 1 || result.Events[0][0] != 0 {
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
		res := serverlogin.Handler(phases.LoginAccessRequest, nil, &st)
		if res.Err != nil || res.NextDeadline != 10*time.Minute {
			t.Fatalf("bad PoW deadline: %+v", res)
		}
	})
}
