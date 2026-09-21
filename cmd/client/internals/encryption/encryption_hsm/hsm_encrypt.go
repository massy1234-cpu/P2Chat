package HSM

import (
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"runtime"
)

type EncryptParams struct {
	Nonce      []byte
	Salt       []byte
	ArgonLevel int
	HSMMethod  uint32
}

// Encrypt protects a secret using the platform HSM when requested, otherwise
// it derives an AES-256 key from the password with Argon2id.
func Encrypt(password *memguard.Enclave, plaintext *memguard.Enclave, level int, useHSM bool) ([]byte, *EncryptParams, error) {
	if plaintext == nil {
		return nil, nil, apperr.New("plaintext is nil")
	}
	if level < 1 || level > 3 {
		return nil, nil, apperr.New("argon level must be between 1 and 3")
	}

	plaintextBuffer, err := plaintext.Open()
	if err != nil {
		return nil, nil, apperr.Wrap("open plaintext enclave", err)
	}
	defer plaintextBuffer.Destroy()

	if useHSM {
		ciphertext, nonce, err := EncryptHSM(password, plaintextBuffer)
		if err != nil {
			return nil, nil, apperr.Wrap("encrypt with HSM", err)
		}
		return ciphertext, &EncryptParams{
			Nonce:      nonce,
			ArgonLevel: level,
			HSMMethod:  uint32(WhichOS()),
		}, nil
	}

	if password == nil {
		return nil, nil, apperr.New("password is nil")
	}
	aesKey, argonParams, err := argon.HashWithArgon(level, password)
	if err != nil {
		return nil, nil, apperr.Wrap("derive encryption key with argon2id", err)
	}
	defer aesKey.Destroy()

	ciphertext, nonce, err := encryption.EncryptAes256(aesKey, plaintextBuffer.Bytes())
	if err != nil {
		return nil, nil, apperr.Wrap("encrypt with AES-256-GCM", err)
	}
	return ciphertext, &EncryptParams{
		Nonce:      nonce,
		Salt:       argonParams.GetSalt(),
		ArgonLevel: level,
		HSMMethod:  0,
	}, nil
}

// Decrypt reverses Encrypt using the stored HSM method. Method 0 selects
// Argon2id + AES-256-GCM, 1 selects Secure Enclave and 2 selects TPM.
func Decrypt(password *memguard.Enclave, ciphertext []byte, params *EncryptParams) (*memguard.Enclave, error) {
	if len(ciphertext) == 0 {
		return nil, apperr.New("ciphertext is empty")
	}
	if params == nil {
		return nil, apperr.New("encryption parameters are nil")
	}

	var plaintext *memguard.LockedBuffer
	var err error

	switch params.HSMMethod {
	case 0:
		if password == nil {
			return nil, apperr.New("password is nil")
		}
		if params.ArgonLevel < 1 || params.ArgonLevel > 3 {
			return nil, apperr.New("argon level must be between 1 and 3")
		}

		aesKey, deriveErr := argon.DeriveWithArgon(params.ArgonLevel, password, params.Salt)
		if deriveErr != nil {
			return nil, apperr.Wrap("derive decryption key with argon2id", deriveErr)
		}
		defer aesKey.Destroy()

		plaintext, err = encryption.DecryptAes256(aesKey, params.Nonce, ciphertext)
	case 1, 2:
		plaintext, err = DecryptHSM(password, ciphertext, params.Nonce, int(params.HSMMethod))
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
