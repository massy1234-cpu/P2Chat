package mldsa_keys

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/pkg/apperr"

	"github.com/awnumar/memguard"
)

// Sign signs a message using an ML-DSA private key stored in a memguard Enclave.
// The function opens the enclave, unmarshals the key from protected memory, signs,
// and destroys the temporary buffer.
// the context is optional but must coincide during the verification of the sign, add more entropy
func Sign(privateKey *memguard.Enclave, message []byte, context []byte, randomized bool) (signature []byte, err error) {

	buffer, err := privateKey.Open()
	if err != nil {
		return nil, apperr.Wrap("open private key enclave", err)
	}
	defer buffer.Destroy()

	var rawKey mldsa87.PrivateKey
	if err := rawKey.UnmarshalBinaryFromLockedBuffer(buffer); err != nil {
		return nil, apperr.Wrap("unmarshal private key from locked buffer", err)
	}
	defer encryption.Wipe(&rawKey)	// clean rawKey from the memory

	signatureBuffer := make([]byte, mldsa87.SignatureSize)

	err = mldsa87.SignTo(&rawKey, message, context, randomized, signatureBuffer)
	if err != nil {
		return nil, apperr.Wrap("error during Signature of the message", err)
	}

	return signatureBuffer, nil
}


// verify the message's signature, the context must be the same used in the Sign 
func VerifySignature(publicKey *mldsa87.PublicKey, message []byte, context []byte, signature []byte) bool {

	return mldsa87.Verify(publicKey, message, context, signature)

}