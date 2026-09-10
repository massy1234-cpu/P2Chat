package mldsa_keys

import (
	mldsa87 "P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/pkg/apperr"
)

// DecodePublicKey converts the packed ML-DSA public key bytes (as stored in the
// PublicBundle ik_mldsa field) into a raw ML-DSA public key.
func DecodePublicKey(publicKey []byte) (*mldsa87.PublicKey, error) {
	var rawKey mldsa87.PublicKey
	if err := rawKey.UnmarshalBinary(publicKey); err != nil {
		return nil, apperr.Wrap("convert bytes in public key", err)
	}
	return &rawKey, nil
}

// VerifySignature verifies an ML-DSA signature over msg with the given context.
// The context must be the same one used during signing.
func VerifySignature(publicKey []byte, msg, ctx, sig []byte) (bool, error) {
	rawKey, err := DecodePublicKey(publicKey)
	if err != nil {
		return false, err
	}
	return mldsa87.Verify(rawKey, msg, ctx, sig), nil
}
