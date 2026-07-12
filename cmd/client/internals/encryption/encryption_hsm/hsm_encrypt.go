package HSM

import (
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"runtime"
)

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
	return platformEncrypt(password,plaintext,method)
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
	case "linux","windows":
		return 2
	default:
		return -1
	}

}
