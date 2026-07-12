//go:build darwin

package HSM

import (
	SE "P2Chat/cmd/client/internals/HSM/SE"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
)

// Encrypt using SE, all inside the SE, no password needed
func platformEncrypt(_ *memguard.Enclave, plaintext *memguard.LockedBuffer, method int) ([]byte, []byte, error) {
	if method != 1 {
		return nil, nil, apperr.New("only SE (method 1) is supported on darwin")
	}
	if !SE.Available() {
		return nil, nil, apperr.New("SE not available on this device")
	}
	ciphertext, err := SE.Encrypt(plaintext.Bytes())
	if err != nil {
		return nil, nil, apperr.Wrap("encrypt with SE", err)
	}
	return ciphertext, nil, nil
}

// Decrypt using SE, no password or nonce needed (ECIES manages internally)
func platformDecrypt(_ *memguard.Enclave, ciphertext []byte, _ []byte, method int) (*memguard.LockedBuffer, error) {
	if method != 1 {
		return nil, apperr.New("only SE (method 1) is supported on darwin")
	}
	if !SE.Available() {
		return nil, apperr.New("SE not available on this device")
	}
	return SE.Decrypt(ciphertext)
}
