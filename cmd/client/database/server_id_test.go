package database

import (
	commitmentproto "P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	idserver "P2Chat/cmd/server/internals/ID_server"
	serverbundle "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"bytes"
	"encoding/binary"
	messagepack "github.com/vmihailenco/msgpack/v5"
	bbolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
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
	if err := CreateBuckets(); err != nil {
		t.Fatal(err)
	}
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
	collision := *id
	collision.PubMLDSA = []byte{8}
	if _, _, err := SaveKnownServer(&collision, "192.0.2.2:9000"); err == nil {
		t.Fatal("replaced stored identity with different public keys")
	}
	other := &idserver.IDServer{ID: bytes.Repeat([]byte{9}, 32)}
	if _, _, err := SaveKnownServer(other, "192.0.2.2:9000"); err == nil {
		t.Fatal("overwrote pinned server")
	}
	if _, _, err := SaveKnownServer(other, "192.0.2.3:9000"); err == nil {
		t.Fatal("blacklisted identity accepted")
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		servers := tx.Bucket(bucketServers)
		server := servers.Bucket(id.ID)
		if server == nil {
			t.Fatal("server bucket missing")
		}
		if !bytes.Equal(server.Get(keyServerEndpoint), []byte("192.0.2.2:9000")) {
			t.Fatal("endpoint missing")
		}
		var stored idserver.IDServer
		if err := messagepack.Unmarshal(server.Get(keyServerIdentity), &stored); err != nil {
			return err
		}
		if len(stored.MldsaSign) != 0 {
			t.Fatal("stored ephemeral signature")
		}
		if !bytes.Equal(stored.PubMLDSA, id.PubMLDSA) {
			t.Fatal("stored identity overwritten")
		}
		if !bytes.Equal(server.Get(keyServerIP), []byte("192.0.2.2")) {
			t.Fatal("IP mapping missing")
		}
		if tx.Bucket(bucketServerBlacklist).Get(other.ID) == nil {
			t.Fatal("conflicting server was not blacklisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateBundleHierarchyAndServerAssociation(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "client.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := DB
	DB = db
	t.Cleanup(func() { db.Close(); DB = previous })
	if err := CreateBuckets(); err != nil {
		t.Fatal(err)
	}

	serverID := bytes.Repeat([]byte{1}, 32)
	bundleID := bytes.Repeat([]byte{2}, 32)
	identity := &idserver.IDServer{ID: serverID, PubMLDSA: []byte{3}, PubX25519: []byte{4}}
	if _, _, err := SaveKnownServer(identity, "192.0.2.1:9000"); err != nil {
		t.Fatal(err)
	}
	if err := SaveSets([][]byte{{5}, {6}}, bundleID, "curve"); err != nil {
		t.Fatal(err)
	}
	if err := SaveSets([][]byte{{7}}, bundleID, "kem"); err != nil {
		t.Fatal(err)
	}
	if err := SavePrivateBundle(&structures.PrivateBundle{ID: 4, SPK: []byte{8}}, bundleID); err != nil {
		t.Fatal(err)
	}
	privateCommitment := &commitmentproto.CommitmentSchemePrivate{PskEncrypted: []byte{9}, EncryptionParams: []byte{10}}
	if err := SaveCommitment(privateCommitment, bundleID); err != nil {
		t.Fatal(err)
	}
	loadedCommitment, err := LoadCommitment(bundleID)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(loadedCommitment, privateCommitment) {
		t.Fatal("wrong private commitment")
	}
	if err := SaveLoginBundle(serverID, &LoginBundle{LocalID: 4, BundleID: bundleID}); err != nil {
		t.Fatal(err)
	}
	userBundle := &serverbundle.UserBundle{Nickname: "alice"}
	if err := SaveUserBundle(userBundle, serverID, true); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadLoginBundle(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.LocalID != 4 || !bytes.Equal(loaded.BundleID, bundleID) {
		t.Fatal("wrong login bundle association")
	}
	loadedUser, err := LoadBundle([]byte("alice"), serverID)
	if err != nil {
		t.Fatal(err)
	}
	if loadedUser.Nickname != userBundle.Nickname {
		t.Fatal("wrong user bundle")
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		server := tx.Bucket(bucketServers).Bucket(serverID)
		if !bytes.Equal(server.Get(keyLoginBundle), bundleID) {
			t.Fatal("server does not point directly to the bundle ID")
		}
		if server.Bucket(bucketServerUsers).Get([]byte("alice")) == nil {
			t.Fatal("user bundle is not nested under its server")
		}
		private := tx.Bucket(bucketPrivateBundles).Bucket(bundleID)
		if private == nil || private.Get(keyPrivateBundle) == nil || private.Get(keyCommitment) == nil {
			t.Fatal("private bundle hierarchy missing")
		}
		index := make([]byte, 4)
		binary.BigEndian.PutUint32(index, 1)
		if !bytes.Equal(private.Bucket(bucketCurveSets).Get(index), []byte{6}) {
			t.Fatal("curve set index missing")
		}
		binary.BigEndian.PutUint32(index, 0)
		if !bytes.Equal(private.Bucket(bucketKEMSets).Get(index), []byte{7}) {
			t.Fatal("KEM set index missing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
