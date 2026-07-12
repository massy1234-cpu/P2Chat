package x25519

import (
	"P2Chat/pkg/apperr"
	"crypto"
	"crypto/rand"
	"go.step.sm/crypto/x25519"
	"github.com/awnumar/memguard"
)

// Sign signs a message with an X25519 private key stored in a memguard Enclave. 
// The key in the memguard Enclave must be NOT encrypt
func Sign(privateKey *memguard.Enclave, message []byte) (signed_message []byte, err error) {

	buffer, err := privateKey.Open()
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
func verifySignature(publicKey x25519.PublicKey, message []byte, signature []byte) bool {

    verify := x25519.Verify(publicKey, message, signature)
    return verify

}