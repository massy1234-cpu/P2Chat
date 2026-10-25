package database

import (
	identityproto "P2Chat/cmd/server/internals/proto_generated/identity/proto_server_identity"
	"bytes"
	"github.com/dgraph-io/badger/v4"
	proto "google.golang.org/protobuf/proto"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadIDUsesProtobuf(t *testing.T) {
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(t.TempDir(), "db")).WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	useTestStore(t, db)

	want := &identityproto.StoredServerIdentity{
		PubMldsa:  []byte("mldsa-public"),
		PubX25519: []byte("x25519-public"),
	}
	if err := SaveID(want); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	if err := defaultStore.view(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(keyServerIdentity))
		if err != nil {
			return err
		}
		raw, err = item.ValueCopy(nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	direct := &identityproto.StoredServerIdentity{}
	if err := proto.Unmarshal(raw, direct); err != nil {
		t.Fatalf("database value is not a protobuf server identity: %v", err)
	}

	found, got, err := LoadID()
	if err != nil {
		t.Fatal(err)
	}
	if !found || !bytes.Equal(got.PubMldsa, want.PubMldsa) || !bytes.Equal(got.PubX25519, want.PubX25519) {
		t.Fatal("loaded server identity differs from the saved protobuf")
	}
}
