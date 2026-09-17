package database

import (
	"bytes"
	"testing"

	"github.com/dgraph-io/badger/v4"
)

func withBlindSignatureTestDB(t *testing.T) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions(t.TempDir()).WithLogger(nil))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	previousDB := tokenDB
	tokenDB = db
	t.Cleanup(func() {
		_ = db.Close()
		tokenDB = previousDB
	})
}

func TestSaveAndLoadBlindKey(t *testing.T) {
	withBlindSignatureTestDB(t)

	sk := []byte("serialized-private-key")
	if err := SaveBlindKey(sk); err != nil {
		t.Fatalf("SaveBlindKey: %v", err)
	}

	loaded, err := LoadBlindKey()
	if err != nil {
		t.Fatalf("LoadBlindKey: %v", err)
	}
	if !bytes.Equal(loaded, sk) {
		t.Fatal("loaded blind key does not match saved key")
	}
}

func TestTokenDeduplication(t *testing.T) {
	withBlindSignatureTestDB(t)

	var tokenHash [32]byte
	tokenHash[0] = 1

	notUsed, err := TokenDeduplication(tokenHash)
	if err != nil || !notUsed {
		t.Fatalf("first token use: notUsed=%v err=%v", notUsed, err)
	}
	notUsed, err = TokenDeduplication(tokenHash)
	if err != nil || notUsed {
		t.Fatalf("second token use: notUsed=%v err=%v", notUsed, err)
	}
}
