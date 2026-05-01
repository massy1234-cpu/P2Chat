package datacontrol

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/cmd/client/internals/encryption"
	encryptmldsa "P2Chat/cmd/client/internals/encryption/mldsa"
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/cmd/client/internals/p2version"
	"encoding/base64"
	"encoding/json"
	"github.com/awnumar/memguard"
	"google.golang.org/protobuf/proto"
	"os"
	"reflect"
	"testing"
	"time"
)

// Test if the serialized keys written by the test match the keys loaded from disk.
func TestStoreKeys(t *testing.T) {
	tempDir := t.TempDir()

	//test with some pre-created key for import cycle error
	//the test want only to verificate that the write and read of the keys is correcly set
	privateKey := &pb.PrivateKeyMLDSA{
		Algorithm:     "ML-DSA-87",
		P2ChatVersion: []byte("P2CH1"),
		Key:           []byte("encrypted-key"),
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

func TestLoadKeysFromFileErrors(t *testing.T) {
	tempDir := t.TempDir()

	_, err := LoadPrivateKeyMLDSAFromFile(tempDir, "missing.bin")
	if err == nil {
		t.Fatal("missing private key file should return error")
	}

	_, err = LoadPublicKeyMLDSAFromFile(tempDir, "missing.json")
	if err == nil {
		t.Fatal("missing public key file should return error")
	}
}

func TestLoadPrivateKeyMLDSAFromCorruptedFile(t *testing.T) {
	tempDir := t.TempDir()

	privateKey, _, err := createRealKeyPairForTest()
	if err != nil {
		t.Fatal("error during real private key creation", err)
	}

	privateKeyBytes, err := proto.Marshal(privateKey)
	if err != nil {
		t.Fatal("error during private key marshaling", err)
	}

	err = SaveBytesOnFile(privateKeyBytes, tempDir, "SK.bin")
	if err != nil {
		t.Fatal("error during private key save", err)
	}

	streamByte, err := os.ReadFile(tempDir + "/SK.bin")
	if err != nil {
		t.Fatal("error during reading private key file", err)
	}

	streamByte[0] = 0xFF
	streamByte[1] = 0xFF

	err = os.WriteFile(tempDir+"/SK.bin", streamByte, 0o600)
	if err != nil {
		t.Fatal("error during corrupted private key save", err)
	}

	_, err = LoadPrivateKeyMLDSAFromFile(tempDir, "SK.bin")
	if err == nil {
		t.Fatal("corrupted private key file should return error")
	}
}


func TestLoadPublicKeyMLDSAFromCorruptedFile(t *testing.T) {
	tempDir := t.TempDir()

	_, publicKey, err := createRealKeyPairForTest()
	if err != nil {
		t.Fatal("error during real public key creation", err)
	}

	publicKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		t.Fatal("error during public key marshaling", err)
	}

	err = SaveBytesOnFile(publicKeyBytes, tempDir, "PK.json")
	if err != nil {
		t.Fatal("error during public key save", err)
	}

	streamByte, err := os.ReadFile(tempDir + "/PK.json")
	if err != nil {
		t.Fatal("error during reading public key file", err)
	}

	streamByte[0] = 'x'
	streamByte[1] = 'x'

	err = os.WriteFile(tempDir+"/PK.json", streamByte, 0o600)
	if err != nil {
		t.Fatal("error during corrupted public key save", err)
	}

	_, err = LoadPublicKeyMLDSAFromFile(tempDir, "PK.json")
	if err == nil {
		t.Fatal("corrupted public key file should return error")
	}
}

func createRealKeyPairForTest() (*pb.PrivateKeyMLDSA, *PublicKeyMLDSA, error) {
	password := encryption.Encaps("password1")
	defer password.Destroy()

	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyExposed.Destroy()

	privateKey := memguard.NewBuffer(privateKeyExposed.Scheme().PrivateKeySize())
	copy(privateKey.Bytes(), privateKeyExposed.Bytes())
	defer privateKey.Destroy()

	ciphertext, nonce, salt, err := encryptmldsa.EncryptPrivateKey(password, privateKey, 3)
	if err != nil {
		return nil, nil, err
	}

	argonParams := argon.CreateArgonParams(3)
	argonParams.Salt = salt

	privateKeyStruct := &pb.PrivateKeyMLDSA{
		Algorithm:     "ML-DSA-87",
		P2ChatVersion: p2version.MagicByte(),
		Timestamp:     time.Now().Unix(),
		Nonce:         nonce,
		Key:           ciphertext,
		ArgonParams:   argonParams,
	}

	publicKeyStruct := &PublicKeyMLDSA{
		Algorithm:            "ML-DSA-87",
		P2ChatVersion:        string(p2version.MagicByte()),
		Timestamp:            time.Now().String(),
		PublicKeyMLDSABase64: base64.StdEncoding.EncodeToString(publicKey.Bytes()),
	}

	return privateKeyStruct, publicKeyStruct, nil
}
