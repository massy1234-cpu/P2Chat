package x25519

import (
	"P2Chat/pkg/apperr"
	"crypto"
	"crypto/rand"
	"go.step.sm/crypto/x25519"
)

// Sign signs a message with an X25519 private key stored in a memguard Enclave.
// The key in the memguard Enclave must be NOT encrypt
func (privateKey *PrivateX25519) Sign(message []byte) (signed_message []byte, err error) {
	if privateKey == nil || privateKey.Enclave == nil {
		return nil, apperr.New("private X25519 key is nil")
	}

	buffer, err := privateKey.Enclave.Open()
	if err != nil {
		return nil, apperr.Wrap("open private key enclave", err)
	}
	defer buffer.Destroy()

	rawKey := x25519.PrivateKey(buffer.Bytes())

	signature, err := rawKey.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, apperr.Wrap("error during the signature", err)
	}

	return signature, nil

}

// verify if the signature is valid or not
func (publicKey *PublicX25519) Verify(message []byte, signature []byte) bool {
	if publicKey == nil || publicKey.Key == nil {
		return false
	}
	return x25519.Verify(x25519.PublicKey(publicKey.Key.Bytes()), message, signature)
}
