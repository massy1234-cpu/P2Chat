package PQXDH

import (
	upload "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"crypto/sha256"
)

// HashPublicIK computes the user ID as the hash of the two public identity keys,
// mirroring the client-side computation:
// ID = sha256( sha256(ik_x25519) || sha256(ik_mldsa) )
func HashPublicIK(bundle *upload.PublicBundle) [32]byte {
	h1 := sha256.Sum256(bundle.GetIkX25519())
	h2 := sha256.Sum256(bundle.GetIkMldsa())

	var r []byte
	r = append(r, h1[:]...)
	r = append(r, h2[:]...)

	return sha256.Sum256(r)
}
