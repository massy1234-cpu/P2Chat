package mldsa_keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/pkg/apperr"
)

// signature function for mldsa keys, the parameter randomized add entropy with a nonce
func Sign(privateKey *mldsa87.PrivateKey,message []byte,context []byte, randomized bool) (signature []byte,err error) {

	signatureBuffer := make([]byte, mldsa87.SignatureSize)


	// context is a optional string for add a layer of security
	err = mldsa87.SignTo(privateKey, message, context, true, signatureBuffer)

	// if signature succeeded, then i try to do the opposite operation
	if err != nil {
		return nil, apperr.Wrap("error during Signature of the message", err)
	}

	return signatureBuffer,nil
}


// verify the message's signature, the context must be the same used in the Sign 
func verifySignature(publicKey *mldsa87.PublicKey,signedMessage []byte,context []byte) bool {

	signatureBuffer := make([]byte, mldsa87.SignatureSize)

	verify := mldsa87.Verify(publicKey, signedMessage, context, signatureBuffer)
	
	return verify
	
}