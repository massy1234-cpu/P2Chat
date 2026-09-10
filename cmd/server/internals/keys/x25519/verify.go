package x25519_keys

import (
	stepx25519 "go.step.sm/crypto/x25519"
)

// VerifySignature verifies an XEdDSA (X25519-derived Ed25519) signature over
// message, using the X25519 public key bytes (as stored in the PublicBundle
// ik_x25519 field).
func VerifySignature(publicKey []byte, message, signature []byte) bool {
	return stepx25519.Verify(stepx25519.PublicKey(publicKey), message, signature)
}
