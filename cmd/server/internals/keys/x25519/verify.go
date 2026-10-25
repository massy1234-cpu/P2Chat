package x25519_keys

import (
	x25519 "P2Chat/cmd/client/internals/keys/x25519"
)

// VerifySignature verifies an XEdDSA (X25519-derived Ed25519) signature over
// message, using the X25519 public key bytes (as stored in the PublicBundle
// ik_x25519 field).
func VerifySignature(publicKey []byte, message, signature []byte) bool {
	key, err := x25519.NewPublicKey(publicKey)
	return err == nil && key.Verify(message, signature)
}
