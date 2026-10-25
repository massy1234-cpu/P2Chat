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
	useTestStore(t, db)

	id := [32]byte{1, 2, 3}
	bundle := &proto_struct_bundle.UserBundle{
		Nickname:     "alice",
		PublicBundle: &proto_struct_bundle.PublicBundle{IkMldsa: []byte("public-key"), SpkId: 31, LastResortId: 47},
	}
	curveSets := []*proto_struct_bundle.CurveSet{
		{Identifier: 7, X25519Key: []byte("curve-7")},
		{Identifier: 11, X25519Key: []byte("curve-11")},
	}
	kemSets := []*proto_struct_bundle.PqkemSet{{Identifier: 42, PqkemKey: []byte("kem-42")}}
	bundle.CurvePublicSets = curveSets
	bundle.KemPublicSets = kemSets
	if taken, err := CheckAndReserve(bundle.GetNickname()); err != nil || taken {
		t.Fatalf("reserve nickname: taken=%v err=%v", taken, err)
	}
	for _, mutate := range []func(*proto_struct_bundle.PublicBundle){
		func(b *proto_struct_bundle.PublicBundle) { b.SpkId = -1 },
		func(b *proto_struct_bundle.PublicBundle) { b.LastResortId = -1 },
	} {
		invalid := proto.Clone(bundle).(*proto_struct_bundle.UserBundle)
		mutate(invalid.PublicBundle)
		if err := SaveBundle(invalid, id); err == nil {
			t.Fatal("negative prekey identifier accepted")
		}
	}
	if err := SaveBundle(bundle, id); err != nil {
		t.Fatal(err)
	}

	storedBundle, err := defaultStore.getValue(id[:])
	if err != nil {
		t.Fatal(err)
	}
	decoded := &proto_struct_bundle.PublicBundle{}
	if err := proto.Unmarshal(storedBundle, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetSpkId() != 31 || decoded.GetLastResortId() != 47 {
		t.Fatal("stored prekey identifiers differ")
	}
	if !bytes.Equal(decoded.GetIkMldsa(), bundle.GetPublicBundle().GetIkMldsa()) {
		t.Fatal("stored public bundle differs from uploaded public bundle")
	}

	storedID, err := GetBundleIDByNickname([]byte("alice"))
	if err != nil || !bytes.Equal(storedID, id[:]) {
		t.Fatal("nickname association was not stored")
	}
	for _, want := range curveSets {
		wantBytes, err := proto.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := defaultStore.getValue(curvePrekeyKey(id, uint32(want.GetIdentifier())))
		if err != nil || !bytes.Equal(got, wantBytes) {
			t.Fatalf("curve set %d was not stored", want.GetIdentifier())
		}
	}
	for _, want := range kemSets {
		wantBytes, err := proto.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := defaultStore.getValue(kemPrekeyKey(id, uint32(want.GetIdentifier())))
		if err != nil || !bytes.Equal(got, wantBytes) {
			t.Fatalf("KEM set %d was not stored", want.GetIdentifier())
		}
	}

	if _, err := defaultStore.getValue(reservationKey(bundle.GetNickname())); !errors.Is(err, badger.ErrKeyNotFound) {
		t.Fatal("nickname reservation was not consumed")
	}

	wrongID := [32]byte{9, 9, 9}
	if err := DeleteUserData(wrongID, []byte(bundle.GetNickname())); err == nil {
		t.Fatal("user data was deleted with a mismatched BundleID")
	}
	if _, err := defaultStore.getValue(id[:]); err != nil {
		t.Fatal("bundle was modified after a mismatched deletion request")
	}

	if err := DeleteUserData(id, []byte(bundle.GetNickname())); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultStore.getValue(id[:]); !errors.Is(err, badger.ErrKeyNotFound) {
		t.Fatal("bundle association was not deleted")
	}
	if _, err := defaultStore.getValue(curvePrekeyKey(id, 7)); !errors.Is(err, badger.ErrKeyNotFound) {
		t.Fatal("curve prekeys were not deleted by BundleID prefix")
	}
}

func TestPreparePrekeyRecordsRejectsInvalidSets(t *testing.T) {
	id := [32]byte{1}
	tests := []struct {
		name  string
		curve []*proto_struct_bundle.CurveSet
		kem   []*proto_struct_bundle.PqkemSet
	}{
		{
			name:  "duplicate curve identifier",
			curve: []*proto_struct_bundle.CurveSet{{Identifier: 1}, {Identifier: 1}},
		},
		{
			name: "duplicate KEM identifier",
			kem:  []*proto_struct_bundle.PqkemSet{{Identifier: 1}, {Identifier: 1}},
		},
		{
			name:  "negative identifier",
			curve: []*proto_struct_bundle.CurveSet{{Identifier: -1}},
		},
		{
			name:  "oversized curve set",
			curve: []*proto_struct_bundle.CurveSet{{Identifier: 1, X25519Key: make([]byte, maxCurveSetSize+1)}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := preparePrekeyRecords(id, test.curve, test.kem); err == nil {
				t.Fatal("invalid prekey sets were accepted")
			}
		})
	}

	tooMany := make([]*proto_struct_bundle.CurveSet, maxOneTimeSetsPerType+1)
	if _, err := preparePrekeyRecords(id, tooMany, nil); err == nil {
		t.Fatal("too many prekey sets were accepted")
	}
}
