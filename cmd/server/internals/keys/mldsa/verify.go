package mldsa_keys

import (
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
)

// DecodePublicKey converts the packed ML-DSA public key bytes (as stored in the
// PublicBundle ik_mldsa field) into an operational ML-DSA object.
func DecodePublicKey(publicKey []byte) (*mldsa.PublicMLDSA, error) {
	return mldsa.NewPublicKey(publicKey)
}

// VerifySignature verifies an ML-DSA signature over msg with the given context.
// The context must be the same one used during signing.
func VerifySignature(publicKey []byte, msg, ctx, sig []byte) (bool, error) {
	rawKey, err := DecodePublicKey(publicKey)
	if err != nil {
		return false, err
	}
	return rawKey.Verify(msg, ctx, sig), nil
}
