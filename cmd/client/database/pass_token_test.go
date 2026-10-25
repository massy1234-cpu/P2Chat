package database

import (
	idserver "P2Chat/cmd/server/internals/ID_server"
	"bytes"
	"testing"
)

func TestPassTokensStoredUnderServer(t *testing.T) {
	useTestStore(t)
	serverID := bytes.Repeat([]byte{1}, 32)
	if _, err := SaveKnownServer(&idserver.IDServer{ID: serverID, PubMLDSA: []byte{2}, PubX25519: []byte{3}}, "192.0.2.1:9000"); err != nil {
		t.Fatal(err)
	}
	if err := SavePassTokens(serverID, [][]byte{{1}, {2}, {3}}); err != nil {
		t.Fatal(err)
	}
	for slot := byte(1); slot <= 3; slot++ {
		token, err := LoadPassToken(serverID)
		if err != nil {
			t.Fatal(err)
		}
		if token == nil || token.Slot != slot || !bytes.Equal(token.Serialized, []byte{slot}) {
			t.Fatalf("unexpected token in slot %d: %+v", slot, token)
		}
		if err := DeletePassToken(serverID, token.Slot); err != nil {
			t.Fatal(err)
		}
	}
	token, err := LoadPassToken(serverID)
	if err != nil || token != nil {
		t.Fatalf("pass token bucket not empty: %+v %v", token, err)
	}
}
