package blindsignature

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"math/big"

	"github.com/awnumar/memguard"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381" // contains the point on the curve
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"  // contains the scalar
)

// required: RFC 9380
var dst = []byte("P2CHAT-BLINDBLS_BLS12381G1_XMD:SHA-256_SSWU_RO_")

type KeysBlindSignature struct {
	Sk *PrivateKey
	Pk *PublicKey
}

type PrivateKey struct {
	//x fr.Element
	x *memguard.Enclave
}

type PublicKey struct {
	Y bls.G2Affine
} 

func IsInitialized() bool {
	return currentKeys.Load() != nil
}

// Create the Public and Private key for the blind signature
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	var x fr.Element

	// private key is a secret scalar
	_, err := x.SetRandom()
	if err != nil {
		return nil, nil, apperr.Wrap("error in the key creation for blind signature", err)
	}
	bytes := x.Bytes()
	enclave := memguard.NewEnclave(bytes[:])
	memguard.WipeBytes(bytes[:])
	defer func() { x.SetZero() }()

	// return some point that are const in this protocol
	_, _, _, g2Gen := bls.Generators()

	// this is the same point but with X,Y,Z
	var g2GenJac bls.G2Jac
	g2GenJac.FromAffine(&g2Gen)

	// scalar multiplication with x and the points (bond the secret key with the public key)
	var Yj bls.G2Jac
	xBig := new(big.Int)
	x.BigInt(xBig)
	Yj.ScalarMultiplication(&g2GenJac, xBig)

	// convert the result in the corret format
	var Y bls.G2Affine
	Y.FromJacobian(&Yj)

	return &PrivateKey{x: enclave}, &PublicKey{Y: Y}, nil
}

// publicKeyFromPrivateBytes derives the public key Y = x·G2 from the private
// key, managing the memguard enclave so no secret trace is left in memory.
func publicKeyFromPrivateBytes(sk *PrivateKey) (*PublicKey, error) {
	x := sk.GetX()
	if x == nil {
		return nil, apperr.New("cannot access the private key")
	}
	defer func() { x.SetZero() }()

	_, _, _, g2Gen := bls.Generators()
	var g2GenJac bls.G2Jac
	g2GenJac.FromAffine(&g2Gen)

	var Yj bls.G2Jac
	xBig := new(big.Int)
	x.BigInt(xBig)
	Yj.ScalarMultiplication(&g2GenJac, xBig)
	defer func() { xBig.SetInt64(0) }()

	var Y bls.G2Affine
	Y.FromJacobian(&Yj)

	return &PublicKey{Y: Y}, nil
}

func (sk *PrivateKey) GetX() *fr.Element {
	var x fr.Element

	buffer, err := sk.x.Open()
	if err != nil {
		return nil
	}
	x.SetBytes(buffer.Bytes())
	defer buffer.Destroy()

	return &x
}

// Do a blind signature on a point bond with some noise, return the signature and public key hash 
func (sk *PrivateKey) SignBlind(blindedPoint *bls.G1Affine) (*bls.G1Affine,[32]byte) {
	xBig := new(big.Int)
	x := sk.GetX()
	if x == nil {
		p2log.Error("error during blind signature, x is nil")
		return nil,[32]byte{}
	}
	defer func() { x.SetZero() }()
	x.BigInt(xBig)

	var p, res bls.G1Jac
	p.FromAffine(blindedPoint)
	res.ScalarMultiplication(&p, xBig) // blind signature -> scalar multiplication

	var out bls.G1Affine
	out.FromJacobian(&res)

	pk,err := publicKeyFromPrivateBytes(sk)
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
