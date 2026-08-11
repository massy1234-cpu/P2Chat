package blindsignature

import (
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"math/big"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)


var dst = []byte("P2CHAT-BLINDBLS_BLS12381G1_XMD:SHA-256_SSWU_RO_")

// save the actual point
type BlindState struct {
	rInv fr.Element
	msg []byte
}
 
// CreateAndBlind map the message on the curve and bond the coordinates with a noise r
// and save the r^-1 into the struct BlindState for the Unblind process
func CreateAndBlind() (*BlindState, *bls.G1Affine, error) {

	msg := make([]byte,64)
	_,err := rand.Read(msg)
	if err != nil {
		return nil,nil,apperr.Wrap("error during secret creation: ",err)
	}

	// hash the message and use that hash for derivate some coordinates on the curve
	M, err := bls.HashToG1(msg, dst)
	if err != nil {
		return nil, nil, err
	}
 
	// create the noise
	var r fr.Element
	if _, err := r.SetRandom(); err != nil {
		return nil, nil, err
	}
	var rInv fr.Element
	rInv.Inverse(&r)
 
	rBig := new(big.Int)
	r.BigInt(rBig)
 
	// bond the noise with the real coordinates
	var Mj, blindedJ bls.G1Jac
	Mj.FromAffine(&M)
	blindedJ.ScalarMultiplication(&Mj, rBig)
 
	var blinded bls.G1Affine
	blinded.FromJacobian(&blindedJ)
 
	return &BlindState{rInv: rInv,msg: msg}, &blinded, nil
}

// remove the noise from the signature, now the server cannot associate
// the user request with the signature
func (st *BlindState) Unblind(blindedSig *bls.G1Affine) bls.G1Affine {

	// get the r^-1 and use it for delete the noise from the signature
	rInvBig := new(big.Int)
	st.rInv.BigInt(rInvBig)
 
	var bj, sj bls.G1Jac
	bj.FromAffine(blindedSig)
	sj.ScalarMultiplication(&bj, rInvBig)
 
	var sig bls.G1Affine
	sig.FromJacobian(&sj)
	return sig
}