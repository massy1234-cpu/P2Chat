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
		Nickname:     "alice",
		PublicBundle: &proto_struct_bundle.PublicBundle{IkMldsa: []byte("public-key")},
	}
	curveSets := []*proto_struct_bundle.CurveSet{
		{Identifier: 0, X25519Key: []byte("curve-0")},
		{Identifier: 1, X25519Key: []byte("curve-1")},
	}
	kemSets := []*proto_struct_bundle.PqkemSet{{Identifier: 0, PqkemKey: []byte("kem-0")}}
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
	if decoded.GetNickname() != bundle.GetNickname() {
		t.Fatal("stored bundle has the wrong nickname")
	}

	storedID, err := GetValue([]byte("nickname:alice"))
	if err != nil || !bytes.Equal(storedID, id[:]) {
		t.Fatal("nickname association was not stored")
	}
	for i, want := range curveSets {
		wantBytes, err := proto.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := GetValue(publicSetKey(id, "curve", uint32(i)))
		if err != nil || !bytes.Equal(got, wantBytes) {
			t.Fatalf("curve set %d was not stored", i)
		}
	}
	for i, want := range kemSets {
		wantBytes, err := proto.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := GetValue(publicSetKey(id, "kem", uint32(i)))
		if err != nil || !bytes.Equal(got, wantBytes) {
			t.Fatalf("KEM set %d was not stored", i)
		}
	}

	if err := DeleteAllAssociation(id, []byte(bundle.GetNickname()), len(curveSets), len(kemSets)); err != nil {
		t.Fatal(err)
	}
	if _, err := GetValue(id[:]); !errors.Is(err, badger.ErrKeyNotFound) {
		t.Fatal("bundle association was not deleted")
	}
}
