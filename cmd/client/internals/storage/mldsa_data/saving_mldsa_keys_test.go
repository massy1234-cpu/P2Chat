package mldsa_data_test

import (
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	data "P2Chat/cmd/client/internals/storage"
	mldsadata "P2Chat/cmd/client/internals/storage/mldsa_data"
	"os"
	"testing"

	"github.com/awnumar/memguard"

	"google.golang.org/protobuf/proto"
)

func TestLoadKeysFromFileErrors(t *testing.T) {
	tempDir := t.TempDir()

	_, err := mldsadata.LoadPrivateKeyFromFile(tempDir, "missing.bin")
	if err == nil {
		t.Fatal("missing private key file should return error")
	}

	_, err = mldsadata.LoadPublicKeyFromFile(tempDir, "missing.bin")
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

	_, err = mldsadata.LoadPrivateKeyFromFile(tempDir, "SK.bin")
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

	_, err = mldsadata.LoadPublicKeyFromFile(tempDir, "PK.bin")
	if err == nil {
		t.Fatal("corrupted public key file should return error")
	}
}

func createRealKeyPairForTest() (*struct_mldsa.PrivateKeyMLDSA, *struct_mldsa.PublicKeyMLDSA, error) {
	password := memguard.NewEnclave([]byte("password1"))
	private, public, err := mldsa.CreateKeys()
	if err != nil {
		return nil, nil, err
	}
	encrypted, err := private.Encrypt(password, 3, false)
	if err != nil {
		return nil, nil, err
	}
	serializedPublic, err := public.Serialize()
	if err != nil {
		return nil, nil, err
	}
	if err := encrypted.SetChecksum(); err != nil {
		return nil, nil, err
	}
	if err := serializedPublic.SetChecksum(); err != nil {
		return nil, nil, err
	}
	return encrypted, serializedPublic, nil
}
