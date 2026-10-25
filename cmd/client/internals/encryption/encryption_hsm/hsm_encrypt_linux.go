//go:build linux || windows

package HSM

import (
	"P2Chat/cmd/client/internals/encryption"
	tpmcore "P2Chat/cmd/client/internals/HSM/TPM"
	tpmhsm "P2Chat/cmd/client/internals/encryption/encryption_hsm/TPM"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
)

// Encrypt using TPM, use AES with combining the password with the secret inside the TPM
func platformEncrypt(password *memguard.Enclave, plaintext *memguard.LockedBuffer, method int) ([]byte, []byte, error) {
	if method != 2 {
		return nil, nil, apperr.New("only TPM (method 2) is supported on this platform")
	}
	
	if password == nil {
		return nil, nil, apperr.New("password is nil, required for TPM encryption")
	}

	privateBlob, publicBlob, err := tpmcore.LoadBlobs()
	if err != nil {
		return nil, nil, apperr.Wrap("TPM blobs not found, run Inizialize() first", err)
	}

	secret, err := tpmhsm.UnwrapSecret(privateBlob, publicBlob)
	if err != nil {
		return nil, nil, apperr.Wrap("unseal TPM secret", err)
	}

	combined, err := tpmhsm.Combine(password, secret)
	if err != nil {
		return nil, nil, apperr.Wrap("combine TPM secret with password", err)
	}

	combinedBuf, err := combined.Open()
	if err != nil {
		return nil, nil, apperr.Wrap("open combined key", err)
	}
	defer combinedBuf.Destroy()

	encrypted, err := encryption.EncryptAes256(combinedBuf, plaintext.Bytes())
	if err != nil {
		return nil, nil, apperr.Wrap("encrypt with TPM-derived key", err)
	}

	return encrypted.Ciphertext, encrypted.Nonce, nil
}

// Decrypt using TPM: unseal secret, combine with password, AES-256-GCM decrypt
func platformDecrypt(password *memguard.Enclave, ciphertext []byte, nonce []byte, method int) (*memguard.LockedBuffer, error) {
	if method != 2 {
		return nil, apperr.New("only TPM (method 2) is supported on this platform")
	}
	if password == nil {
		return nil, apperr.New("password is nil, required for TPM decryption")
	}

	privateBlob, publicBlob, err := tpmcore.LoadBlobs()
	if err != nil {
		return nil, apperr.Wrap("TPM blobs not found, run Inizialize() first", err)
	}

	secret, err := tpmhsm.UnwrapSecret(privateBlob, publicBlob)
	if err != nil {
		return nil, apperr.Wrap("unseal TPM secret", err)
	}

	combined, err := tpmhsm.Combine(password, secret)
	if err != nil {
		return nil, apperr.Wrap("combine TPM secret with password", err)
	}

	combinedBuf, err := combined.Open()
	if err != nil {
		return nil, apperr.Wrap("open combined key", err)
	}
	defer combinedBuf.Destroy()

	plaintext, err := encryption.DecryptAes256(combinedBuf, &encryption.EncryptedPayload{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	})
	if err != nil {
		return nil, apperr.Wrap("decrypt with TPM-derived key", err)
	}

	return plaintext, nil
}
