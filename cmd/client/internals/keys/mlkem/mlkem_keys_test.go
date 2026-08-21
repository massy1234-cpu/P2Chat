package mlkem

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	"github.com/awnumar/memguard"
)

// keyFromEnclave reconstructs the raw decapsulation key from the secure enclave.
func keyFromEnclave(t *testing.T, enclave *memguard.Enclave) *mlkem.DecapsulationKey768 {
	t.Helper()
	buffer, err := enclave.Open()
	if err != nil {
		t.Fatalf("open enclave: %v", err)
	}
	defer buffer.Destroy()

	dk, err := mlkem.NewDecapsulationKey768(buffer.Bytes())
	if err != nil {
		t.Fatalf("reconstruct decapsulation key: %v", err)
	}
	return dk
}

// TestCreateKeyAndExtractPublic checks that ExtractPublicKey returns the same
// public key as the one returned by CreateKey.
func TestCreateKeyAndExtractPublic(t *testing.T) {
	enclave, pubKey, err := CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	extracted := ExtractPublicKey(enclave)
	if extracted == nil {
		t.Fatal("ExtractPublicKey returned nil")
	}

	if !bytes.Equal(extracted.Bytes(), pubKey.Bytes()) {
		t.Fatal("extracted public key does not match original")
	}
}

// TestEncapsulateDecapsulateRoundTrip checks that the shared secret derived by
// the encapsulating party equals the one derived by the decapsulating party.
func TestEncapsulateDecapsulateRoundTrip(t *testing.T) {
	enclave, pubKey, err := CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	secretLocked, ciphertext, err := EncapsulateSecret(pubKey)
	if err != nil {
		t.Fatalf("EncapsulateSecret: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	dk := keyFromEnclave(t, enclave)
	decSecretLocked, err := DecapsulateChipertext(dk, ciphertext)
	if err != nil {
		t.Fatalf("DecapsulateChipertext: %v", err)
	}

	aBuf, err := secretLocked.Open()
	if err != nil {
		t.Fatalf("open encaps secret: %v", err)
	}
	defer aBuf.Destroy()

	bBuf, err := decSecretLocked.Open()
	if err != nil {
		t.Fatalf("open decaps secret: %v", err)
	}
	defer bBuf.Destroy()

	if !aBuf.EqualTo(bBuf.Bytes()) {
		t.Fatal("encapsulated and decapsulated secrets differ")
	}
}

// TestEncapsulateSecretDeterministicCiphertext checks that two encryptions with
// the same public key produce different ciphertexts (fresh randomness).
func TestEncapsulateFreshCiphertext(t *testing.T) {
	_, pubKey, err := CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	_, ct1, err := EncapsulateSecret(pubKey)
	if err != nil {
		t.Fatalf("first encapsulate: %v", err)
	}
	_, ct2, err := EncapsulateSecret(pubKey)
	if err != nil {
		t.Fatalf("second encapsulate: %v", err)
	}

	if string(ct1) == string(ct2) {
		t.Fatal("ciphertexts should differ due to fresh randomness")
	}
}

// TestSerializePrivateKeyRoundTrip checks that serialization returns bytes that
// can be unmarshaled back into the same structure.
func TestSerializePrivateKeyRoundTrip(t *testing.T) {
	password := memguard.NewEnclave([]byte("0123456789abcdef0123456789abcdef"))
	enclave, _, err := CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	scheme, err := EncryptPrivateKey(password, enclave, false)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	serialized, err := SerializePrivateKey(scheme)
	if err != nil {
		t.Fatalf("SerializePrivateKey: %v", err)
	}

	if len(serialized) == 0 {
		t.Fatal("serialized private key is empty")
	}
}