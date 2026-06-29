package x25519

import (
	"P2Chat/pkg/apperr"
	"crypto"
	"crypto/rand"
	"go.step.sm/crypto/x25519"
)

// use a X25519 key for the signature
func Signto(privateKey x25519.PrivateKey, message []byte) (signed_message []byte, err error) {

	// the sign function doesnt need the hash, already do internally 
	signature,err := privateKey.Sign(rand.Reader,message,crypto.Hash(0))
	if err != nil {
		return nil, apperr.Wrap("error during the signature",err)
	}

	return signature,nil

}


// verify if the signature is valid or not
func verifySignature(publicKey x25519.PublicKey, message []byte, signature []byte) bool {

    verify := x25519.Verify(publicKey, message, signature)
    return verify

}