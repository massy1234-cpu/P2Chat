package database

import (
	idserver "P2Chat/cmd/server/internals/ID_server"
	"bytes"
	messagepack "github.com/vmihailenco/msgpack/v5"
	bbolt "go.etcd.io/bbolt"
	"path/filepath"
	"testing"
)

func TestServerPinning(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "client.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := DB
	DB = db
	t.Cleanup(func() { db.Close(); DB = previous })
	id := &idserver.IDServer{ID: bytes.Repeat([]byte{1}, 32), PubMLDSA: []byte{2}, PubX25519: []byte{3}, MldsaSign: []byte{4}}
	if known, changed, err := SaveKnownServer(id, "192.0.2.1:9000"); err != nil || known || changed {
		t.Fatalf("new identity: %v", err)
	}
	if known, changed, err := SaveKnownServer(id, "192.0.2.1:9000"); err != nil || !known || changed {
		t.Fatalf("known identity: %v", err)
	}
	if known, changed, err := SaveKnownServer(id, "192.0.2.2:9000"); err != nil || !known || !changed {
		t.Fatalf("changed IP: %v", err)
	}
	other := &idserver.IDServer{ID: bytes.Repeat([]byte{9}, 32)}
	if _, _, err := SaveKnownServer(other, "192.0.2.2:9000"); err == nil {
		t.Fatal("overwrote pinned server")
	}
	if _, _, err := SaveKnownServer(other, "192.0.2.3:9000"); err == nil {
		t.Fatal("blacklisted identity accepted")
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		if !bytes.Equal(tx.Bucket([]byte("server:endpoints")).Get([]byte("192.0.2.2:9000")), id.ID) {
			t.Fatal("pin overwritten")
		}
		var stored idserver.IDServer
		if err := messagepack.Unmarshal(tx.Bucket([]byte("server:identities")).Get(id.ID), &stored); err != nil {
			return err
		}
		if len(stored.MldsaSign) != 0 {
			t.Fatal("stored ephemeral signature")
		}
		var address ServerAddress
		if err := messagepack.Unmarshal(tx.Bucket([]byte("server:observed-ip")).Get(id.ID), &address); err != nil {
			return err
		}
		if address.IP != "192.0.2.2" {
			t.Fatal("IP mapping missing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
