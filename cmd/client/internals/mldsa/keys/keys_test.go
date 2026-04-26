package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/cmd/client/internals/mldsa/argon"
	"P2Chat/cmd/client/internals/p2version"
	"encoding/base64"
	"google.golang.org/protobuf/proto"
	"reflect"
	"testing"
)

// Test if the signature of a pair of ml-dsa87 key works.
// The test call the method CreateKey()
func TestSignature(t *testing.T) {

	privateKeyStruct, publicKeyStruct, err := CreateMLDSAKeys(3, encryption.Encaps("password1"), false)

	//signature will contain the sign of the key and ctx is an another control that during the Verify() must coincide
	msg := []byte("message to verify")
	signature := make([]byte, mldsa87.SignatureSize)
	ctx := []byte("test")

	//i decided to manage the hash with argon not internal at DecodePrivateKeyMLDSA for better control of the aesKey and for efficency
	aesKey, err := argon.HashWithArgon(3, encryption.Encaps("password1"), privateKeyStruct.ArgonParams.Salt)
	if err != nil {
		t.Fatal("Hashing password with params", err)
	}

	rawPublicKey, rawPrivateKey, err := DecodePairKeysMLDSA(publicKeyStruct, privateKeyStruct, aesKey, 3, privateKeyStruct.ArgonParams.Salt)
	if err != nil {
		t.Fatal("error during decoding keys from struct", err)
	}

	var rawKey mldsa87.PrivateKey

	buffer, err := rawPrivateKey.Open()
	if err != nil {
		t.Fatal("error during open Enclave")
	}

	err = rawKey.UnmarshalBinary(buffer.Bytes())
	err = mldsa87.SignTo(&rawKey, msg, ctx, true, signature) //randomized add entropy to the sign
	if err != nil {
		t.Fatal("error during Signature of the message", err)
	}

	//if signature succeeded, then i try to do the opposite operation

	verify := mldsa87.Verify(rawPublicKey, msg, ctx, signature)
	if verify == false {
		t.Fatal("error verify of the message", err)
	}
}

// Test if CreateKeys fills all expected fields.
func TestCreateKeysFields(t *testing.T) {
	const level = 3

	privateKeyStruct, publicKeyStruct, err := CreateMLDSAKeys(level, encryption.Encaps("password1"), false)
	if err != nil {
		t.Fatal("error during key creation", err)
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

	if len(privateKeyStruct.Ciphertext) == 0 {
		t.Fatal("private key ciphertext is empty")
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

	if publicKeyStruct.Timestamp == "" {
		t.Fatal("public key timestamp is empty")
	}

	if publicKeyStruct.PublicKeyMLDSABase64 == "" {
		t.Fatal("public key base64 is empty")
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyStruct.PublicKeyMLDSABase64)
	if err != nil {
		t.Fatal("public key base64 is not valid", err)
	}

	if len(publicKeyBytes) != mldsa87.PublicKeySize {
		t.Fatal("public key raw bytes size is not correct")
	}
}
