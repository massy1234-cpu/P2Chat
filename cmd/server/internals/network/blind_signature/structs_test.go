package blindsignature

import (
	"bytes"
	"testing"

	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

func TestPrivateKeySerializationRoundTrip(t *testing.T) {
	passwordBytes := bytes.Repeat([]byte{1}, 32)
	passwordBuffer := memguard.NewBufferFromBytes(passwordBytes)
	memguard.WipeBytes(passwordBytes)
	password := passwordBuffer.Seal()

	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	serialized, err := privateKey.SerializeAndEncryptKey(password, 1, false)
	if err != nil {
		t.Fatalf("SerializeAndEncryptKey: %v", err)
	}

	var encrypted PrivateKeyEncrypted
	if err := messagepack.Unmarshal(serialized, &encrypted); err != nil {
		t.Fatalf("unmarshal encrypted private key: %v", err)
	}
	decrypted, err := encrypted.DecryptKey(password)
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}
	derivedPublicKey, err := decrypted.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	want := publicKey.Bytes()
	got := derivedPublicKey.Bytes()
	if !bytes.Equal(want[:], got[:]) {
		t.Fatal("derived public key changed after private key round trip")
	}
	decoded, err := NewPublicKey(want[:])
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bytes() != want {
		t.Fatal("public key encoding changed")
	}
	if _, err := NewPublicKey(make([]byte, 96)); err == nil {
		t.Fatal("invalid public key accepted")
	}
}
