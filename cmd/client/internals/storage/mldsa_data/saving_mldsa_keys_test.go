package mldsa_data

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	keyencryption "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/cmd/client/internals/p2version"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	data "P2Chat/cmd/client/internals/storage"
	"os"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"google.golang.org/protobuf/proto"
)

func TestLoadKeysFromFileErrors(t *testing.T) {
	tempDir := t.TempDir()

	_, err := LoadPrivateKeyFromFile(tempDir, "missing.bin")
	if err == nil {
		t.Fatal("missing private key file should return error")
	}

	_, err = LoadPublicKeyFromFile(tempDir, "missing.bin")
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

	err = data.SaveBytesOnFile(privateKeyBytes, tempDir, "SK.bin")
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

	_, err = LoadPrivateKeyFromFile(tempDir, "SK.bin")
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

	publicKeyBytes, err := proto.Marshal(publicKey)
	if err != nil {
		t.Fatal("error during public key marshaling", err)
	}

	err = data.SaveBytesOnFile(publicKeyBytes, tempDir, "PK.bin")
	if err != nil {
		t.Fatal("error during public key save", err)
	}

	streamByte, err := os.ReadFile(tempDir + "/PK.bin")
	if err != nil {
		t.Fatal("error during reading public key file", err)
	}

	streamByte[0] = 0xFF
	streamByte[1] = 0xFF

	err = os.WriteFile(tempDir+"/PK.bin", streamByte, 0o600)
	if err != nil {
		t.Fatal("error during corrupted public key save", err)
	}

	_, err = LoadPublicKeyFromFile(tempDir, "PK.bin")
	if err == nil {
		t.Fatal("corrupted public key file should return error")
	}
}

func createRealKeyPairForTest() (*struct_mldsa.PrivateKeyMLDSA, *struct_mldsa.PublicKeyMLDSA, error) {
	password := memguard.NewEnclave([]byte("password1"))

	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyExposed.Destroy()

	privateKeyBuf, err := privateKeyExposed.LockedBuffer()
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyBuf.Destroy()

	privateKeyEnc := memguard.NewEnclave(privateKeyBuf.Bytes())

	ciphertext, nonce, salt, _, err := keyencryption.Encrypt(password, privateKeyEnc, 3, false)
	if err != nil {
		return nil, nil, err
	}

	argonParams := argon.CreateArgonParams(3)
	argonParams.Salt = salt

	privateKeyStruct := &struct_mldsa.PrivateKeyMLDSA{
		Algorithm:     "ML-DSA-87",
		P2ChatVersion: p2version.MagicByte(),
		Timestamp:     time.Now().Unix(),
		Nonce:         nonce,
		Key:           ciphertext,
		ArgonParams:   argonParams,
	}

	if err := privateKeyStruct.SetChecksum(); err != nil {
		return nil, nil, err
	}

	var packedPublic [mldsa87.PublicKeySize]byte
	publicKey.Pack(&packedPublic)

	publicKeyStruct := &struct_mldsa.PublicKeyMLDSA{
		Algorithm:     "ML-DSA-87",
		P2ChatVersion: string(p2version.MagicByte()),
		Timestamp:     uint32(time.Now().Unix()),
		Key:           packedPublic[:],
	}

	if err := publicKeyStruct.SetChecksum(); err != nil {
		return nil, nil, err
	}

	return privateKeyStruct, publicKeyStruct, nil
}
