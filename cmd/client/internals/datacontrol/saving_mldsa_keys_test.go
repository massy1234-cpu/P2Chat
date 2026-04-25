package datacontrol

import (
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"encoding/json"
	"reflect"
	"testing"
	"google.golang.org/protobuf/proto"
)

// Test if the serialized keys written by the test match the keys loaded from disk.
func TestStoreKeys(t *testing.T) {
	tempDir := t.TempDir()

	//test with some pre-created key for import cycle error
	//the test want only to verificate that the write and read of the keys is correcly set
	privateKey := &pb.PrivateKeyMLDSA{
		Algorithm:     "ML-DSA-87",
		P2ChatVersion: []byte("P2"),
		Ciphertext:    []byte("ciphertext"),
		Nonce:         []byte("nonce"),
		Timestamp:     123456789,
	}

	publicKey := &PublicKeyMLDSA{
		Algorithm:            "ML-DSA-87",
		P2ChatVersion:        "P2",
		Timestamp:            "2026-04-23T12:00:00Z",
		PublicKeyMLDSABase64: "cHVibGljLWtleQ==",
	}

	privateKeyBytes, err := proto.Marshal(privateKey)
	if err != nil {
		t.Fatal("error during private key marshaling", err)
	}

	err = SaveBytesOnFile(privateKeyBytes, tempDir, "SK.bin")
	if err != nil {
		t.Fatal("error during private key save", err)
	}

	publicKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		t.Fatal("error during public key marshaling", err)
	}

	err = SaveBytesOnFile(publicKeyBytes, tempDir, "PK.json")
	if err != nil {
		t.Fatal("error during public key save", err)
	}

	privateKeyStruct, err := LoadPrivateKeyMLDSAFromFile(tempDir, "SK.bin")
	if err != nil {
		t.Fatal("error during loading private key", err)
	}

	publicKeyStruct, err := LoadPublicKeyMLDSAFromFile(tempDir, "PK.json")
	if err != nil {
		t.Fatal("error during loading public key", err)
	}

	if !proto.Equal(privateKey, privateKeyStruct) {
		t.Fatal("private key doesnt match with file SK.bin")
	}

	if !reflect.DeepEqual(publicKey, publicKeyStruct) {
		t.Fatal("public key doesnt match with file PK.json")
	}
}
