package mldsa_keys

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	data "P2Chat/cmd/client/internals/storage"
	mldsa_data "P2Chat/cmd/client/internals/storage/mldsa_data"
	"P2Chat/cmd/client/internals/encryption"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/cmd/client/internals/p2version"
	"github.com/awnumar/memguard"
	"google.golang.org/protobuf/proto"
	"reflect"
	"testing"
)

func lockToEnc(t *testing.T, buf *memguard.LockedBuffer) *memguard.Enclave {
	t.Helper()
	enc := memguard.NewEnclave(buf.Bytes())
	buf.Destroy()
	return enc
}

// Test if keys are stored correcly - the func try to generate and then read the keys
func TestStoreKeys(t *testing.T) {
	tempDir := t.TempDir()

	//test with some pre-created key for import cycle error
	//the test want only to verificate that the write and read of the keys is correcly set

	rawPriv, rawPub, err := CreateKeys()
	if err != nil {
		t.Fatal("error during key creation", err)
	}

	privateKey, err := EncryptPrivateKey(lockToEnc(t, encryption.Encaps("password")), rawPriv, 3, false)
	if err != nil {
		t.Fatal("error during key encryption", err)
	}

	publicKey, err := NewPublicKey(rawPub)
	if err != nil {
		t.Fatal("error during public key creation", err)
	}

	if err := privateKey.SetChecksum(); err != nil {
		t.Fatal("error setting private key checksum", err)
	}

	if err := publicKey.SetChecksum(); err != nil {
		t.Fatal("error setting public key checksum", err)
	}

	privateKeyBytes, err := proto.Marshal(privateKey)
	if err != nil {
		t.Fatal("error during private key marshaling", err)
	}

	err = data.SaveBytesOnFile(privateKeyBytes, tempDir, "SK.bin")
	if err != nil {
		t.Fatal("error during private key save", err)
	}

	publicKeyBytes, err := proto.Marshal(publicKey)
	if err != nil {
		t.Fatal("error during public key marshaling", err)
	}

	err = data.SaveBytesOnFile(publicKeyBytes, tempDir, "PK.bin")
	if err != nil {
		t.Fatal("error during public key save", err)
	}

	privateKeyStruct, err := mldsa_data.LoadPrivateKeyFromFile(tempDir, "SK.bin")
	if err != nil {
		t.Fatal("error during loading private key", err)
	}

	publicKeyStruct, err := mldsa_data.LoadPublicKeyFromFile(tempDir, "PK.bin")
	if err != nil {
		t.Fatal("error during loading public key", err)
	}

	if !proto.Equal(privateKey, privateKeyStruct) {
		t.Fatal("private key doesnt match with file SK.bin")
	}

	if !proto.Equal(publicKey, publicKeyStruct) {
		t.Fatal("public key doesnt match with file PK.bin")
	}
}

// Test if the signature of a pair of ml-dsa87 key works.
func TestSignature(t *testing.T) {

	rawPriv, rawPub, err := CreateKeys()
	if err != nil {
		t.Fatal("error during key creation", err)
	}

	// signature will contain the sign of the key and ctx is an another control that during the Verify() must coincide
	msg := []byte("message to verify")
	signature := make([]byte, mldsa87.SignatureSize)
	ctx := []byte("test")

	var rawKey mldsa87.PrivateKey

	buffer, err := rawPriv.Open()
	if err != nil {
		t.Fatal("error during open Enclave")
	}
	defer buffer.Destroy()

	err = rawKey.UnmarshalBinaryFromLockedBuffer(buffer)
	if err != nil {
		t.Fatal("error during private key unmarshal from protected buffer", err)
	}
	err = mldsa87.SignTo(&rawKey, msg, ctx, true, signature) //randomized add entropy to the sign

	if err != nil {
		t.Fatal("error during Signature of the message", err)
	}

	verify := mldsa87.Verify(rawPub, msg, ctx, signature)
	if verify == false {
		t.Fatal("error verify of the message", err)
	}
}

// Test if CreateKeys fills all expected fields.
func TestCreateKeysFields(t *testing.T) {
	const level = 3

	rawPriv, rawPub, err := CreateKeys()
	if err != nil {
		t.Fatal("error during key creation", err)
	}

	privateKeyStruct, err := EncryptPrivateKey(lockToEnc(t, encryption.Encaps("password1")), rawPriv, level, false)
	if err != nil {
		t.Fatal("error during key encryption", err)
	}

	publicKeyStruct, err := NewPublicKey(rawPub)
	if err != nil {
		t.Fatal("error during public key creation", err)
	}

	if privateKeyStruct == nil {
		t.Fatal("private key struct is nil")
	}

	if publicKeyStruct == nil {
		t.Fatal("public key struct is nil")
	}

	if privateKeyStruct.Algorithm == "" {
		t.Fatal("private key algorithm is empty")
	}

	if privateKeyStruct.Algorithm != "ML-DSA-87" {
		t.Fatal("unexpected private key algorithm")
	}

	if len(privateKeyStruct.Key) == 0 {
		t.Fatal("private key key field is empty")
	}

	if len(privateKeyStruct.Nonce) == 0 {
		t.Fatal("private key nonce is empty")
	}

	if privateKeyStruct.Timestamp <= 0 {
		t.Fatal("private key timestamp is not valid")
	}

	if privateKeyStruct.ArgonParams == nil {
		t.Fatal("argon params are nil")
	}

	expectedArgon := argon.CreateArgonParams(level)

	expectedArgon.Salt = privateKeyStruct.ArgonParams.Salt

	//proto.equal is better than reflect when compared
	if !proto.Equal(privateKeyStruct.ArgonParams, expectedArgon) {
		t.Fatal("argon params do not match expected values")
	}

	if len(privateKeyStruct.ArgonParams.Salt) == 0 {
		t.Fatal("argon salt is empty")
	}

	if len(privateKeyStruct.P2ChatVersion) == 0 {
		t.Fatal("private key P2Chat version is empty")
	}

	if !reflect.DeepEqual(privateKeyStruct.P2ChatVersion, p2version.MagicByte()) {
		t.Fatal("private key P2Chat version is not correct")
	}

	if publicKeyStruct.Algorithm == "" {
		t.Fatal("public key algorithm is empty")
	}

	if publicKeyStruct.Algorithm != "ML-DSA-87" {
		t.Fatal("unexpected public key algorithm")
	}

	if publicKeyStruct.P2ChatVersion == "" {
		t.Fatal("public key P2Chat version is empty")
	}

	if publicKeyStruct.P2ChatVersion != string(p2version.MagicByte()) {
		t.Fatal("public key P2Chat version is not correct")
	}

	if publicKeyStruct.Timestamp == 0 {
		t.Fatal("public key timestamp is empty")
	}

	if len(publicKeyStruct.Key) == 0 {
		t.Fatal("public key bytes are empty")
	}

	if len(publicKeyStruct.Key) != mldsa87.PublicKeySize {
		t.Fatal("public key raw bytes size is not correct")
	}

}

func TestDecodePublicKeyMLDSAErrors(t *testing.T) {
	publicKey := &struct_mldsa.PublicKeyMLDSA{
		Key: []byte("short"),
	}

	_, err := DecodePublicKey(publicKey)
	if err == nil {
		t.Fatal("invalid raw public key bytes should return error")
	}
}

func TestDecodePrivateKeyMLDSAWrongPassword(t *testing.T) {
	rawPriv, _, err := CreateKeys()
	if err != nil {
		t.Fatal("error during key creation", err)
	}

	privateKeyStruct, err := EncryptPrivateKey(lockToEnc(t, encryption.Encaps("password1")), rawPriv, 3, false)
	if err != nil {
		t.Fatal("error during key encryption", err)
	}

	_, err = DecodePrivateKey(lockToEnc(t, encryption.Encaps("wrong-password")), privateKeyStruct)
	if err == nil {
		t.Fatal("wrong password should not decrypt private key")
	}
}

func TestDecodePrivateKeyMLDSAInvalidKeyField(t *testing.T) {
	rawPriv, _, err := CreateKeys()
	if err != nil {
		t.Fatal("error during key creation", err)
	}

	privateKeyStruct, err := EncryptPrivateKey(lockToEnc(t, encryption.Encaps("password1")), rawPriv, 3, false)
	if err != nil {
		t.Fatal("error during key encryption", err)
	}

	corruptedPrivateKey := &struct_mldsa.PrivateKeyMLDSA{
		Algorithm:     privateKeyStruct.Algorithm,
		P2ChatVersion: privateKeyStruct.P2ChatVersion,
		Key:           []byte("broken"),
		Nonce:         privateKeyStruct.Nonce,
		Timestamp:     privateKeyStruct.Timestamp,
		ArgonParams:   privateKeyStruct.ArgonParams,
	}

	_, err = DecodePrivateKey(lockToEnc(t, encryption.Encaps("password1")), corruptedPrivateKey)
	if err == nil {
		t.Fatal("invalid private key field should return error")
	}
}
