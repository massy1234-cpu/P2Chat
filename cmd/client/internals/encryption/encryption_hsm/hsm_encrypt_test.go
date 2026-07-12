package HSM

import (
	"encoding/base64"
	"testing"

	"github.com/awnumar/memguard"
)

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
