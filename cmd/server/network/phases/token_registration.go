package phases

import (
	"P2Chat/cmd/client/internals/p2log"
	challengeStruct "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	pow "P2Chat/cmd/server/network/PoW"
	blindsignature "P2Chat/cmd/server/network/blind_signature"
	"P2Chat/cmd/server/network/session"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"encoding/binary"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381" // contains the point on the curve
	"google.golang.org/protobuf/proto"
)

// handle all the process with the client for exchange a
func RequestTokenRegistration(session *session.SingleSession,level pow.Level,privateKey *blindsignature.PrivateKey) bool {
	secret := make([]byte,64)
	if _, err := rand.Read(secret); err != nil {
		p2log.Error("error generating registration secret")
		return false
	}

	challenge, err := issueChallenge(session, secret, level)
	if err != nil {
		return false
	}

	nonce, ok := receiveNonce(session, level)
	if !ok {
		return false
	}

	verified := pow.Verify(secret,challenge,nonce)

	if !verified {
		p2log.Error("challenge not solved")
		return false
	}

	// blind signature
	blindSignature,err := ReceiveAndSign(session,privateKey)
	if err != nil {
		p2log.Error("error in blind signature", err)
		return false
	}
	sendBlindSignature(session,blindSignature)


	return true
}

// create the challenge with the level requested, serialize it and send it to the client
func issueChallenge(session *session.SingleSession, secret []byte, level pow.Level) (*challengeStruct.Challenge, error) {
	// create and serialize the challenge
	challenge,err := pow.Issue(secret,level)
	if err != nil {
		p2log.Error("error in challenge creation")
		return nil, err
	}

	challengeSerialized, err := proto.Marshal(challenge)
	if err != nil {
		p2log.Error("error in challenge serialization")
		return nil, err
	}

	// insert the bytecode before the message 
	data := append([]byte{PowToken},challengeSerialized...)

	// send the message
	session.PutOutgoing(data)

	return challenge, nil
}


// wait the response of the client and parse the nonce, the timeout depends on the PoW level
func receiveNonce(session *session.SingleSession, level pow.Level) (uint64, bool) {
	var response []byte

	select {
	case response = <- session.Incoming:
		p2log.Info("nonce challenge received")
	case <-time.After(powResponseTimeout(level)):
		p2log.Error("nonce challenge client response timeout")
		return 0, false
	}

	payload, ok := StripTag(response, ChallengeResponse)
	if !ok {
		return 0, false
	}

	if !CheckSize(ChallengeResponse, len(payload)) {
		p2log.Error("nonce challenge response with invalid size")
		return 0, false
	}

	return binary.BigEndian.Uint64(payload), true
}

// estimate the time that the client need for solve the challenge in base of the level
func powResponseTimeout(level pow.Level) time.Duration {
	switch level {
	case pow.Level1:
		return 30 * time.Second
	case pow.Level2:
		return 1 * time.Minute
	case pow.Level3:
		return 2 * time.Minute
	case pow.Level4:
		return 5 * time.Minute
	case pow.Level5:
		return 10 * time.Minute
	default:
		return 1 * time.Minute
	}
}


// ReceiveAndSign wait for the M obfuscated from the client and sign it using the private key
func ReceiveAndSign(session *session.SingleSession,privateKey *blindsignature.PrivateKey) (*bls.G1Affine,error) {
	// the challenge is solved, now i wait for an M' and sign it
	var response []byte
	var M_obfuscated bls.G1Affine
	
	select {
	case response = <- session.Incoming:
		p2log.Info("M' blind signature received")
	case <-time.After(1 * time.Minute):
		p2log.Error("M' blind signature response timeout")
		return nil,apperr.New("M' blind signature response timeout")
	}

	response,ok := StripTag(response,SignatureRequest)
	if !ok {
		p2log.Error("SignatureRequest bytecode doesn not match with the actual response")
		return nil,apperr.New("SignatureRequest bytecode doesn not match with the actual response")
	}

	if !CheckSize(SignatureRequest, len(response)) {
		p2log.Error("M' blind signature request with invalid size")
		return nil,apperr.New("M' blind signature request with invalid size")
	}

	_,err := M_obfuscated.SetBytes(response)
	if err != nil {
		p2log.Error("error with the byte conversion to raw to G1Affine", err)
		return nil,apperr.Wrap("error with the byte conversion to raw to G1Affine",err)
	}

	signedPoint := privateKey.SignBlind(&M_obfuscated)
	
	return signedPoint,nil
}


func sendBlindSignature(session *session.SingleSession,blindSignature *bls.G1Affine) {
	signatureSerialized := blindSignature.Bytes()

	slice := []byte{TokenEmission}
	slice = append(slice, signatureSerialized[:]...)

	session.PutOutgoing(slice)
}