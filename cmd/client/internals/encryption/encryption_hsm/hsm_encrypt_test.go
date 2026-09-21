package HSM

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/awnumar/memguard"
)

func TestEncryptDecryptSoftwareRoundTrip(t *testing.T) {
	password := memguard.NewEnclave([]byte("test-password"))
	secret := []byte("private-key-material")
	plaintext := memguard.NewEnclave(append([]byte(nil), secret...))

	ciphertext, params, err := Encrypt(password, plaintext, 1, false)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if params.HSMMethod != 0 || len(params.Nonce) == 0 || len(params.Salt) != 32 {
		t.Fatalf("unexpected metadata: method=%d nonce=%d salt=%d", params.HSMMethod, len(params.Nonce), len(params.Salt))
	}

	decrypted, err := Decrypt(password, ciphertext, params)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	decryptedBuffer, err := decrypted.Open()
	if err != nil {
		t.Fatalf("open decrypted enclave: %v", err)
	}
	defer decryptedBuffer.Destroy()

	if !bytes.Equal(decryptedBuffer.Bytes(), secret) {
		t.Fatal("decrypted plaintext does not match")
	}
}

func TestWhichOS(t *testing.T) {
	method := WhichOS()
	if method != 1 && method != 2 && method != -1 {
		t.Fatalf("unexpected method: %d", method)
	}
	t.Logf("WhichOS() = %d", method)
}

func TestEncryptHSMNilPlaintext(t *testing.T) {
	password := memguard.NewEnclave([]byte("password"))
	_, _, err := EncryptHSM(password, nil)
	if err == nil {
		t.Fatal("expected error for nil plaintext")
	}
	t.Logf("nil plaintext correctly rejected: %s", err)
}

func TestEncryptHSMNilPassword(t *testing.T) {
	plaintext := memguard.NewBufferFromBytes([]byte("test data"))
	defer plaintext.Destroy()

	ciphertext, nonce, err := EncryptHSM(nil, plaintext)
	if err != nil {
		t.Logf("nil password: %s (expected on linux/windows, SE on darwin ignores password)", err)
		return
	}
	t.Logf("ciphertext (base64): %s", base64.StdEncoding.EncodeToString(ciphertext))
	if nonce != nil {
		t.Logf("nonce (base64): %s", base64.StdEncoding.EncodeToString(nonce))
	}
}

func TestEncryptHSMEmptyPlaintext(t *testing.T) {
	password := memguard.NewEnclave([]byte("password"))
	plaintext := memguard.NewBufferFromBytes([]byte{})
	defer plaintext.Destroy()

	ciphertext, nonce, err := EncryptHSM(password, plaintext)
	if err != nil {
		t.Logf("empty plaintext: %s", err)
		return
	}
	t.Logf("ciphertext (base64): %s", base64.StdEncoding.EncodeToString(ciphertext))
	if nonce != nil {
		t.Logf("nonce (base64): %s", base64.StdEncoding.EncodeToString(nonce))
	}
}

func TestEncryptHSMSmallPlaintext(t *testing.T) {
	password := memguard.NewEnclave([]byte("password"))
	plaintext := memguard.NewBufferFromBytes([]byte{0x42})
	defer plaintext.Destroy()

	ciphertext, nonce, err := EncryptHSM(password, plaintext)
	if err != nil {
		t.Logf("small plaintext: %s", err)
		return
	}
	t.Logf("ciphertext (base64): %s", base64.StdEncoding.EncodeToString(ciphertext))
	if nonce != nil {
		t.Logf("nonce (base64): %s", base64.StdEncoding.EncodeToString(nonce))
	}
}
