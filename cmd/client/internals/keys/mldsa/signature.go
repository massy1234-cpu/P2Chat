package mldsa_keys

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/pkg/apperr"
)

// Sign signs a message using an ML-DSA private key stored in a memguard Enclave.
// The function opens the enclave, unmarshals the key from protected memory, signs,
// and destroys the temporary buffer.
// the context is optional but must coincide during the verification of the sign, add more entropy
func (privateKey *PrivateMLDSA) Sign(message []byte, context []byte, randomized bool) (signature []byte, err error) {
	if privateKey == nil || privateKey.enclave == nil {
		return nil, apperr.New("private ML-DSA key is nil")
	}

	rawKey, err := privateKey.native()
	if err != nil {
		return nil, err
	}
	defer wipeNativeMLDSA(rawKey)

	signatureBuffer := make([]byte, mldsa87.SignatureSize)

	err = mldsa87.SignTo(rawKey, message, context, randomized, signatureBuffer)
	if err != nil {
		return nil, apperr.Wrap("error during Signature of the message", err)
	}

	return signatureBuffer, nil
}
