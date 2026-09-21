package encryption

import (
	"P2Chat/cmd/client/internals/argon"
	"bytes"
	"testing"

	"github.com/awnumar/memguard"
)

type tests struct {
	name               string
	password           *memguard.Enclave
	secret             *memguard.LockedBuffer
	aesKey             *memguard.LockedBuffer
	decryptKey         *memguard.LockedBuffer
	level              int
	forceNonce         []byte
	forceCiphertext    []byte
	corruptNonce       bool
	corruptCiphertext  bool
	truncateCiphertext bool
	wantError          bool
}

// Simple test that encrypt and decrypt text
func TestEncryptionAndDecryption(t *testing.T) {
	t.Parallel()

	longPassword := "thisIsAnExtremelyLongPasswordDesignedToStressTheEncryptionPath123456789!@#$%^&*()"
	binarySecret := []byte{0, 1, 2, 3, 0, 4, 5, 0, 6, 255}

	tests := []tests{
		{name: "nil password", password: nil, secret: Encaps("secret"), level: 3, wantError: true},
		{name: "empty password", password: memguard.NewEnclave([]byte{}), secret: Encaps("secret"), level: 3, wantError: true},
		{name: "level zero", password: passwordEnclave("password"), secret: Encaps("secret"), level: 0, wantError: true},
		{name: "level four", password: passwordEnclave("password"), secret: Encaps("secret"), level: 4, wantError: true},
		{name: "negative level", password: passwordEnclave("password"), secret: Encaps("secret"), level: -1, wantError: true},
		{name: "nil secret", password: passwordEnclave("password"), secret: nil, level: 3, wantError: true},
		{name: "nil aes key", aesKey: nil, secret: Encaps("secret"), wantError: true},
		{name: "short aes key", aesKey: memguard.NewBufferFromBytes([]byte("short")), secret: Encaps("secret"), wantError: true},
		{name: "long aes key", aesKey: memguard.NewBufferFromBytes(bytes.Repeat([]byte{1}, 64)), secret: Encaps("secret"), wantError: true},
		{name: "minimal valid inputs", password: passwordEnclave("p"), secret: Encaps("x"), level: 1, wantError: false},
		{name: "empty plaintext", password: passwordEnclave("password"), secret: memguard.NewBufferFromBytes([]byte{}), level: 3, wantError: false},
		{name: "whitespace password", password: passwordEnclave(" "), secret: Encaps("secret"), level: 2, wantError: false},
		{name: "long password", password: passwordEnclave(longPassword), secret: Encaps("secret"), level: 3, wantError: false},
		{name: "binary plaintext", password: passwordEnclave("password"), secret: memguard.NewBufferFromBytes(binarySecret), level: 3, wantError: false},
		{name: "wrong decrypt key", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, decryptKey: memguard.NewBufferFromBytes(bytes.Repeat([]byte{9}, 32)), wantError: true},
		{name: "decrypt key from different salt", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, decryptKey: mustArgonKey(t, passwordEnclave("password"), 3), wantError: true},
		{name: "nil nonce during decrypt", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, forceNonce: nil, wantError: true},
		{name: "empty nonce during decrypt", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, forceNonce: []byte{}, wantError: true},
		{name: "corrupted nonce", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, corruptNonce: true, wantError: true},
		{name: "nil ciphertext during decrypt", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, forceCiphertext: nil, wantError: true},
		{name: "empty ciphertext during decrypt", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, forceCiphertext: []byte{}, wantError: true},
		{name: "truncated ciphertext", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, truncateCiphertext: true, wantError: true},
		{name: "corrupted ciphertext", password: passwordEnclave("password"), secret: Encaps("secret"), level: 3, corruptCiphertext: true, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.secret != nil {
				defer tt.secret.Destroy()
			}
			if tt.aesKey != nil {
				defer tt.aesKey.Destroy()
			}
			if tt.decryptKey != nil {
				defer tt.decryptKey.Destroy()
			}

			var (
				encryptKey *memguard.LockedBuffer
				err        error
			)

			if tt.aesKey != nil || tt.name == "nil aes key" {
				encryptKey = tt.aesKey
			} else {
				encryptKey, _, err = argon.HashWithArgon(tt.level, tt.password)
				if err != nil {
					if !tt.wantError {
						t.Fatalf("unexpected argon error: %v", err)
					}
					return
				}
				defer encryptKey.Destroy()
			}

			var secretBytes []byte
			if tt.secret != nil {
				secretBytes = tt.secret.Bytes()
				if secretBytes == nil {
					secretBytes = []byte{}
				}
			}

			ciphertext, nonce, err := EncryptAes256(encryptKey, secretBytes)
			if err != nil {
				if !tt.wantError {
					t.Fatalf("unexpected encryption error: %v", err)
				}
				return
			}

			decryptKey := encryptKey
			if tt.decryptKey != nil {
				decryptKey = tt.decryptKey
			}

			if tt.forceNonce != nil || (tt.wantError && tt.name == "nil nonce during decrypt") {
				nonce = tt.forceNonce
			}

			if tt.forceCiphertext != nil || (tt.wantError && tt.name == "nil ciphertext during decrypt") {
				ciphertext = tt.forceCiphertext
			}

			if tt.corruptNonce {
				nonce = append([]byte(nil), nonce...)
				nonce[0] ^= 0xFF
			}

			if tt.truncateCiphertext {
				ciphertext = append([]byte(nil), ciphertext[:len(ciphertext)-1]...)
			}

			if tt.corruptCiphertext {
				ciphertext = append([]byte(nil), ciphertext...)
				ciphertext[len(ciphertext)-1] ^= 0xFF
			}

			plaintext, err := DecryptAes256(decryptKey, nonce, ciphertext)
			if plaintext != nil {
				defer plaintext.Destroy()
			}

			if tt.wantError {
				if err == nil {
					t.Fatal("expected decrypt flow to fail")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected decrypt error: %v", err)
			}

			if !bytes.Equal(plaintext.Bytes(), tt.secret.Bytes()) {
				t.Fatal("plaintext does not match original secret")
			}
		})
	}

}

// Test the case we want to decrypt something with a wrong password
func TestEncryptFailed(t *testing.T) {
	t.Parallel()

	password := passwordEnclave("password_correct")

	secret := Encaps("really important secret!!!")
	defer secret.Destroy()

	aesKey, _, err := argon.HashWithArgon(3, password)
	if err != nil {
		t.Fatalf("error during create aeskey")
	}
	defer aesKey.Destroy()

	ciphertext, nonce, err := EncryptAes256(aesKey, secret.Bytes())
	if err != nil {
		t.Fatalf("error during encrypting")
	}

	//tries to decrypt with wrong password
	wrongPassword := passwordEnclave("wrong_password")

	wrongAesKey, _, err := argon.HashWithArgon(3, wrongPassword)
	if err != nil {
		t.Fatalf("error during create wrong aeskey: %v", err)
	}
	defer wrongAesKey.Destroy()

	_, err = DecryptAes256(wrongAesKey, nonce, ciphertext)
	if err == nil {
		t.Fatal("expected decrypt failure with wrong password")
	}
}

func mustArgonKey(t *testing.T, password *memguard.Enclave, level int) *memguard.LockedBuffer {
	t.Helper()

	key, _, err := argon.HashWithArgon(level, password)
	if err != nil {
		t.Fatalf("failed to derive argon key for test setup: %v", err)
	}

	return key
}

func passwordEnclave(password string) *memguard.Enclave {
	return memguard.NewEnclave([]byte(password))
}
