package login

import (
	clientblind "P2Chat/cmd/client/internals/network/blind_signature"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	pow "P2Chat/cmd/server/internals/network/PoW"
	blind "P2Chat/cmd/server/internals/network/blind_signature"
	"P2Chat/cmd/server/internals/network/phases"
	"bytes"
	"encoding/binary"
	"github.com/awnumar/memguard"
	"testing"
	"time"
)

func TestTokenScopeAndExpiry(t *testing.T) {
	keys, err := blind.GetLoginKeys()
	if err != nil {
		t.Fatal(err)
	}
	state, point, err := clientblind.CreateAndBlind()
	if err != nil {
		t.Fatal(err)
	}
	defer memguard.WipeBytes(state.Msg)
	signed, _ := keys.Keys.Sk.SignBlind(point)
	signature := state.Unblind(signed)
	encoded := signature.Bytes()
	token := &loginproto.LoginToken{Message: state.Msg, Signature: encoded[:], KeyHash: keys.Hash[:], ExpiresAt: keys.ExpiresAt}
	if err := verifyToken(token); err != nil {
		t.Fatal(err)
	}
	token.ExpiresAt--
	if err := verifyToken(token); err == nil {
		t.Fatal("client-chosen expiry accepted")
	}
	token.ExpiresAt = keys.ExpiresAt
	other, _, err := blind.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signed, _ = other.SignBlind(point)
	signature = state.Unblind(signed)
	encoded = signature.Bytes()
	token.Signature = encoded[:]
	if err := verifyToken(token); err == nil {
		t.Fatal("token signed with another scope key accepted")
	}
}

func TestPoWFailureAndDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		secret := memguard.NewBufferRandom(32)
		challenge, err := pow.Issue(secret.Bytes(), pow.Level1)
		if err != nil {
			t.Fatal(err)
		}
		var nonce uint64
		for pow.Verify(secret.Bytes(), challenge, nonce) {
			nonce++
		}
		deadline := time.Now().Add(time.Minute)
		if expired {
			deadline = time.Now().Add(-time.Second)
		}
		var state any = &LoginServer{Binding: bytes.Repeat([]byte{1}, 32), Authenticate: func([]byte, bool) error { t.Fatal("invalid PoW authenticated"); return nil }, state: stateAwaitPoW, secret: secret.Seal(), challenge: challenge, deadline: deadline}
		result := Handler(phases.LoginPowResponse, binary.BigEndian.AppendUint64(nil, nonce), &state)
		if result.Err == nil || !result.CloseStream || len(result.Replies) != 0 {
			t.Fatal("invalid or expired proof accepted")
		}
	}
}
