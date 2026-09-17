package database

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"

	"github.com/dgraph-io/badger/v4"
	"google.golang.org/protobuf/proto"
)

func TestSaveBundleStoresPublicDataAndSets(t *testing.T) {
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(t.TempDir(), "db")).WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	previous := db_manager
	db_manager = db
	t.Cleanup(func() {
		_ = db_manager.Close()
		db_manager = previous
	})

	id := [32]byte{1, 2, 3}
	bundle := &proto_struct_bundle.UserBundle{
		Nickname:     []byte("alice"),
		PublicBundle: &proto_struct_bundle.PublicBundle{IkMldsa: []byte("public-key")},
	}
	curveSets := [][]byte{[]byte("curve-0"), []byte("curve-1")}
	kemSets := [][]byte{[]byte("kem-0")}
	if err := SaveBundle(bundle, curveSets, kemSets, id); err != nil {
		t.Fatal(err)
	}

	storedBundle, err := GetValue(id[:])
	if err != nil {
		t.Fatal(err)
	}
	decoded := &proto_struct_bundle.UserBundle{}
	if err := proto.Unmarshal(storedBundle, decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.GetNickname(), bundle.GetNickname()) {
		t.Fatal("stored bundle has the wrong nickname")
	}

	storedID, err := GetValue([]byte("nickname:alice"))
	if err != nil || !bytes.Equal(storedID, id[:]) {
		t.Fatal("nickname association was not stored")
	}
	for i, want := range curveSets {
		got, err := GetValue(publicSetKey(id, "curve", uint32(i)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("curve set %d was not stored", i)
		}
	}
	for i, want := range kemSets {
		got, err := GetValue(publicSetKey(id, "kem", uint32(i)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("KEM set %d was not stored", i)
		}
	}

	if err := DeleteAllAssociation(id, bundle.GetNickname(), len(curveSets), len(kemSets)); err != nil {
		t.Fatal(err)
	}
	if _, err := GetValue(id[:]); !errors.Is(err, badger.ErrKeyNotFound) {
		t.Fatal("bundle association was not deleted")
	}
}
