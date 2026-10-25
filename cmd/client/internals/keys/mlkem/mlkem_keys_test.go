package mlkem

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	"github.com/awnumar/memguard"
)

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

	pubKey, err = NewPublicKey(pubKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	secretLocked, ciphertext, err := pubKey.Encapsulate()
	if err != nil {
		t.Fatalf("EncapsulateSecret: %v", err)
	}
	defer secretLocked.Destroy()

	if secretLocked.Size() != mlkem.SharedKeySize {
		t.Fatalf("shared secret size = %d, want %d", secretLocked.Size(), mlkem.SharedKeySize)
	}
	if len(ciphertext) != mlkem.CiphertextSize768 {
		t.Fatalf("ciphertext size = %d, want %d", len(ciphertext), mlkem.CiphertextSize768)
	}

	decSecretLocked, err := enclave.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("DecapsulateChipertext: %v", err)
	}

	defer decSecretLocked.Destroy()
	if decSecretLocked.Size() != mlkem.SharedKeySize {
		t.Fatalf("recovered secret size = %d, want %d", decSecretLocked.Size(), mlkem.SharedKeySize)
	}

	if !secretLocked.EqualTo(decSecretLocked.Bytes()) {
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

	secret1, ct1, err := EncapsulateSecret(pubKey)
	if err != nil {
		t.Fatalf("first encapsulate: %v", err)
	}
	secret2, ct2, err := EncapsulateSecret(pubKey)
	if err != nil {
		t.Fatalf("second encapsulate: %v", err)
	}

	defer secret1.Destroy()
	defer secret2.Destroy()

	if string(ct1) == string(ct2) {
		t.Fatal("ciphertexts should differ due to fresh randomness")
	}
}

// TestSerializePrivateKeyRoundTrip checks that serialization returns bytes that
// can be unmarshaled back into the same structure.
func TestSerializePrivateKeyRoundTrip(t *testing.T) {
	password := memguard.NewEnclave([]byte("0123456789abcdef0123456789abcdef"))
	enclave, public, err := CreateKey()
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

	if len(serialized) == 0 {
		t.Fatal("serialized private key is empty")
	}
	restored, err := DecryptPrivateKey(password, serialized)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.PublicKey().Bytes(), public.Bytes()) {
		t.Fatal("stored ML-KEM identity changed")
	}
	secret, ciphertext, err := public.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restored.Decapsulate(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	defer recovered.Destroy()

	if !secret.EqualTo(recovered.Bytes()) {
		t.Fatal("restored key cannot decapsulate")
	}
	if result, err := restored.Decapsulate([]byte("invalid")); err == nil || result != nil {
		t.Fatal("invalid ciphertext accepted")
	}
}

func BenchmarkMLKEM768(b *testing.B) {
	private, public, err := CreateKey()
	if err != nil {
		b.Fatal(err)
	}
	ss, ciphertext, err := public.Encapsulate()
	if err != nil {
		b.Fatal(err)
	}
	defer ss.Destroy()
	recovered, err := private.Decapsulate(ciphertext)
	if err != nil {
		b.Fatal(err)
	}
	if !ss.EqualTo(recovered.Bytes()) {
		recovered.Destroy()
		b.Fatal("encapsulated and decapsulated secrets differ")
	}
	recovered.Destroy()

	b.Run("Encapsulate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {									// For a more accurate benchmark
			secret, _, err := public.Encapsulate()
			if err != nil {
				b.Fatal(err)
			}
			secret.Destroy()
		}
	})
	b.Run("Decapsulate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			secret, err := private.Decapsulate(ciphertext)
			if err != nil {
				b.Fatal(err)
			}
			secret.Destroy()
		}
	})
}
