package HSM

import (
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"runtime"
)

// Encrypt protects a secret using the platform HSM when requested, otherwise
// it derives an AES-256 key from the password with Argon2id.
func Encrypt(password *memguard.Enclave, plaintext *memguard.Enclave, level int, useHSM bool) (ciphertext, nonce, salt []byte, method uint32, err error) {
	if plaintext == nil {
		return nil, nil, nil, 0, apperr.New("plaintext is nil")
	}
	if level < 1 || level > 3 {
		return nil, nil, nil, 0, apperr.New("argon level must be between 1 and 3")
	}

	plaintextBuffer, err := plaintext.Open()
	if err != nil {
		return nil, nil, nil, 0, apperr.Wrap("open plaintext enclave", err)
	}
	defer plaintextBuffer.Destroy()

	if useHSM {
		ciphertext, nonce, err = EncryptHSM(password, plaintextBuffer)
		if err != nil {
			return nil, nil, nil, 0, apperr.Wrap("encrypt with HSM", err)
		}
		return ciphertext, nonce, nil, uint32(WhichOS()), nil
	}

	if password == nil {
		return nil, nil, nil, 0, apperr.New("password is nil")
	}
	passwordBuffer, err := password.Open()
	if err != nil {
		return nil, nil, nil, 0, apperr.Wrap("open password enclave", err)
	}
	defer passwordBuffer.Destroy()

	salt, err = encryption.GenerateSalt(32)
	if err != nil {
		return nil, nil, nil, 0, apperr.Wrap("generate salt", err)
	}

	aesKey, err := argon.HashWithArgon(level, passwordBuffer, salt)
	if err != nil {
		return nil, nil, nil, 0, apperr.Wrap("derive encryption key with argon2id", err)
	}
	defer aesKey.Destroy()

	ciphertext, nonce, err = encryption.EncryptAes256(aesKey, plaintextBuffer.Bytes())
	if err != nil {
		return nil, nil, nil, 0, apperr.Wrap("encrypt with AES-256-GCM", err)
	}
	return ciphertext, nonce, salt, 0, nil
}

// Decrypt reverses Encrypt using the stored HSM method. Method 0 selects
// Argon2id + AES-256-GCM, 1 selects Secure Enclave and 2 selects TPM.
func Decrypt(password *memguard.Enclave, ciphertext, nonce, salt []byte, level int, method uint32) (*memguard.Enclave, error) {
	if len(ciphertext) == 0 {
		return nil, apperr.New("ciphertext is empty")
	}

	var plaintext *memguard.LockedBuffer
	var err error

	switch method {
	case 0:
		if password == nil {
			return nil, apperr.New("password is nil")
		}
		if level < 1 || level > 3 {
			return nil, apperr.New("argon level must be between 1 and 3")
		}

		passwordBuffer, openErr := password.Open()
		if openErr != nil {
			return nil, apperr.Wrap("open password enclave", openErr)
		}
		defer passwordBuffer.Destroy()

		aesKey, deriveErr := argon.HashWithArgon(level, passwordBuffer, salt)
		if deriveErr != nil {
			return nil, apperr.Wrap("derive decryption key with argon2id", deriveErr)
		}
		defer aesKey.Destroy()

		plaintext, err = encryption.DecryptAes256(aesKey, nonce, ciphertext)
	case 1, 2:
		plaintext, err = DecryptHSM(password, ciphertext, nonce, int(method))
	default:
		return nil, apperr.New("unknown encryption method")
	}
	if err != nil {
		return nil, apperr.Wrap("decrypt private key", err)
	}
	defer plaintext.Destroy()

	return memguard.NewEnclave(plaintext.Bytes()), nil
}

// EncryptPrivateKey encrypts plaintext using hardware-backed security.
// encryptMethod: 1=SE (darwin), 2=TPM (linux|windows).
// For method 0 (password-only) use encryption.EncryptAes256 directly.
// Password is required for TPM, ignored for SE.
func EncryptHSM(password *memguard.Enclave, plaintext *memguard.LockedBuffer) (ciphertext []byte, nonce []byte, err error) {

	// understand which function to use
	method := WhichOS()

	if method == -1 {
		return nil, nil, apperr.New("use EncryptAes256 directly for non-HSM encryption")
	}
	if plaintext == nil {
		return nil, nil, apperr.New("plaintext is nil")
	}
	return platformEncrypt(password, plaintext, method)
}

// DecryptHSM decrypts ciphertext using hardware-backed security.
// method: 1=SE (darwin), 2=TPM (linux|windows).
// For SE the nonce is ignored; for TPM the nonce is required.
func DecryptHSM(password *memguard.Enclave, ciphertext []byte, nonce []byte, method int) (*memguard.LockedBuffer, error) {

	if ciphertext == nil {
		return nil, apperr.New("ciphertext is nil")
	}
	return platformDecrypt(password, ciphertext, nonce, method)
}

// 1 = SE | 2 = TPM | 0 = no HSM used
func WhichOS() int {

	systemOS := runtime.GOOS
	switch systemOS {
	case "darwin":
		return 1
	case "linux", "windows":
		return 2
	default:
		return -1
	}

}
