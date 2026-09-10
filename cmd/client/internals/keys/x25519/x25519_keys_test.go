package x25519

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"github.com/awnumar/memguard"
)

func rawPrivateKey(t *testing.T, enclave *memguard.Enclave) *ecdh.PrivateKey {
	t.Helper()
	buffer, err := enclave.Open()
	if err != nil {
		t.Fatalf("open enclave: %v", err)
	}
	defer buffer.Destroy()

	key, err := ecdh.X25519().NewPrivateKey(buffer.Bytes())
	if err != nil {
		t.Fatalf("reconstruct private key: %v", err)
	}
	return key
}

// TestCreateKeyAndExtractPublic checks that ExtractPublicKey reproduces the
// public key returned by CreateKey.
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

// TestDeriveSecretShared checks that both parties derive the same shared secret.
func TestDeriveSecretShared(t *testing.T) {
	aliceEnclave, alicePub, err := CreateKey()
	if err != nil {
		t.Fatalf("alice CreateKey: %v", err)
	}
	bobEnclave, bobPub, err := CreateKey()
	if err != nil {
		t.Fatalf("bob CreateKey: %v", err)
	}

	aliceSecret, err := DerivateSecret(rawPrivateKey(t, aliceEnclave), bobPub)
	if err != nil {
		t.Fatalf("alice derive: %v", err)
	}
	bobSecret, err := DerivateSecret(rawPrivateKey(t, bobEnclave), alicePub)
	if err != nil {
		t.Fatalf("bob derive: %v", err)
	}

	aBuf, err := aliceSecret.Open()
	if err != nil {
		t.Fatalf("open alice secret: %v", err)
	}
	defer aBuf.Destroy()

	bBuf, err := bobSecret.Open()
	if err != nil {
		t.Fatalf("open bob secret: %v", err)
	}
	defer bBuf.Destroy()

	if !aBuf.EqualTo(bBuf.Bytes()) {
		t.Fatal("shared secrets differ")
	}
}

// TestSerializeDecryptRoundTrip checks that an encrypted key can be decrypted
// back into the original raw key.
func TestSerializeDecryptRoundTrip(t *testing.T) {
	password := memguard.NewEnclave([]byte("0123456789abcdef0123456789abcdef"))
	enclave, _, err := CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	scheme, err := EncryptPrivateKey(password, enclave, 1, false)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	serialized, err := SerializePrivateKey(scheme)
	if err != nil {
		t.Fatalf("SerializePrivateKey: %v", err)
	}

	decrypted, err := DecryptPrivateKey(password, serialized)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	orig := rawPrivateKey(t, enclave)
	dec := rawPrivateKey(t, decrypted)

	if !bytes.Equal(orig.Bytes(), dec.Bytes()) {
		t.Fatal("decrypted key does not match original")
	}
}

// TestDecryptWrongPassword checks that decrypting with a wrong password fails.
func TestDecryptWrongPassword(t *testing.T) {
	password := memguard.NewEnclave([]byte("0123456789abcdef0123456789abcdef"))
	enclave, _, err := CreateKey()
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	scheme, err := EncryptPrivateKey(password, enclave, 1, false)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	serialized, err := SerializePrivateKey(scheme)
	if err != nil {
		t.Fatalf("SerializePrivateKey: %v", err)
	}

	wrong := memguard.NewEnclave([]byte("fedcba9876543210fedcba9876543210"))
	if _, err := DecryptPrivateKey(wrong, serialized); err == nil {
		t.Fatal("expected decrypt failure with wrong password")
	}
}