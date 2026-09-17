package blindsignature

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/database"
	"P2Chat/pkg/apperr"
	"crypto/sha256"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381" // contains the point on the curve
)

// required: RFC 9380
var dst = []byte("P2CHAT-BLINDBLS_BLS12381G1_XMD:SHA-256_SSWU_RO_")

// pkHash returns the SHA-256 fingerprint of a public key.
func pkHash(pk *PublicKey) [32]byte {
	b := pk.Y.Bytes()
	return sha256.Sum256(b[:])
}

// Do a blind signature on a point bond with some noise, return the signature and public key hash
func (sk *PrivateKey) SignBlind(blindedPoint *bls.G1Affine) (*bls.G1Affine, [32]byte) {
	if sk == nil || blindedPoint == nil {
		return nil, [32]byte{}
	}
	xBig := new(big.Int)
	defer xBig.SetInt64(0)
	x := sk.GetX()
	if x == nil {
		p2log.Error("error during blind signature, x is nil")
		return nil, [32]byte{}
	}
	defer func() { x.SetZero() }()
	x.BigInt(xBig)

	var p, res bls.G1Jac
	p.FromAffine(blindedPoint)
	res.ScalarMultiplication(&p, xBig) // blind signature -> scalar multiplication

	var out bls.G1Affine
	out.FromJacobian(&res)

	pk, err := sk.GetPublicKey()
	if err != nil {
		p2log.Error("error during blind signature")
		return nil, [32]byte{}
	}
	hash := pkHash(pk)

	return &out, hash
}

// Verify check the blind signature via pairing check: e(sig,G2) == e(M,Y),
// true only if sig was generated with the same private key as Y
func Verify(pk *PublicKey, msg []byte, sig *bls.G1Affine) (bool, error) {
	if pk == nil || sig == nil {
		return false, apperr.New("blind signature public key or signature is nil")
	}
	M, err := bls.HashToG1(msg, dst)
	if err != nil {
		return false, err
	}

	_, _, _, g2Gen := bls.Generators()

	var negY bls.G2Affine
	negY.Neg(&pk.Y)

	ok, err := bls.PairingCheck(
		[]bls.G1Affine{*sig, M},
		[]bls.G2Affine{g2Gen, negY},
	)

	if err != nil {
		return false, err
	}

	return ok, nil
}

// SerializeAndSave hashes the signature and stores it in the database to avoid
// reuse of the token. It returns true if the token was not used yet (and is now
// saved), false if it was already present.
func SerializeAndSave(token *bls.G1Affine) (bool, error) {
	if token == nil {
		return false, apperr.New("blind signature token is nil")
	}
	serialization := token.Bytes()
	b := sha256.Sum256(serialization[:])
	notUsed, err := database.TokenDeduplication(b)
	return notUsed, err
}
