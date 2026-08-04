package phases

import (
	pow "P2Chat/cmd/client/internals/network/PoW"
	blindsignature "P2Chat/cmd/client/internals/network/blind_signature"
	"P2Chat/cmd/client/internals/network/session"
	"P2Chat/cmd/client/internals/p2log"
	challengeStruct "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	"P2Chat/pkg/apperr"
	"encoding/binary"
	"time"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	proto "google.golang.org/protobuf/proto"
)

// request a registration token to the server, send a token request, solve the PoW challenge and send back the nonce
func RequestTokenRegistration(sess *session.SingleSession) error {
	// request registration token
	challenge, err := requestChallenge(sess)
	if err != nil {
		return err
	}

	// solve the PoW and send back the nonce (solution)
	nonce, err := solveChallenge(challenge)
	if err != nil {
		return err
	}
	sendNonce(sess, nonce)

	// send factor for blind siganture
	blindstate,M_obfuscated,err := blindsignature.CreateAndBlind()
	if err != nil {
		return apperr.Wrap("error during the blind signature ",err)
	}
	SendFactor(sess,M_obfuscated)

	// wait for the obfuscated token signed 
	blindedSignature,err := GetTokenObfuscated(sess)
	if err != nil {
		return err
	}

	// token received 
	_ = blindstate.Unblind(blindedSignature)

	return nil
}

// send the request for the token and wait the PoW challenge from the server
func requestChallenge(sess *session.SingleSession) (*challengeStruct.Challenge, error) {
	request := []byte{RegisterTokenReq}
	sess.PutOutgoing(request)

	var response []byte

	select {
	case <- time.After(1 * time.Minute):
		p2log.Error("timeout for token request, server probably offline")
		return nil, apperr.New("timeout for token request, server probably offline")
	case response = <- sess.Incoming:
	}

	p2log.Info("challenge received from server")

	payload, ok := StripTag(response, PowToken)
	if !ok {
		p2log.Error("challenge received not valid")
		return nil, apperr.New("challenge received not valid, error")
	}

	if !CheckSize(PowToken, len(payload)) {
		p2log.Error("challenge received with invalid size")
		return nil, apperr.New("challenge received with invalid size, error")
	}

	challenge := &challengeStruct.Challenge{}

	err := proto.Unmarshal(payload,challenge)
	if err != nil {
		p2log.Error("error Unmarshal response into the challenge")
		return nil, apperr.New("error Unmarshal response into the challenge")
	}

	return challenge, nil
}

// solve the challenge received from the server
func solveChallenge(challenge *challengeStruct.Challenge) (uint64, error) {
	nonce, err := pow.Solve(challenge)
	if err != nil {
		p2log.Error("error solving the challenge, maybe too hard, server is overloaded")
		return 0, apperr.New("error solving the challenge, maybe too hard, server is overloaded")
	}

	return nonce, nil
}

// send back the nonce to the server
func sendNonce(sess *session.SingleSession, nonce uint64) {
	buf := make([]byte,8)
	binary.BigEndian.PutUint64(buf, nonce)
	
	response := []byte{ChallengeResponse}
	response = append(response,buf...)

	sess.PutOutgoing(response)
}


// create the M_Obfuscated, return the r^-1 and send to the server
func SendFactor(sess *session.SingleSession,M_obfuscated *bls.G1Affine) error {
	if M_obfuscated == nil {
		return apperr.New("M_obfuscated not valid")
	}

var slice []byte

	M_serialized := M_obfuscated.Bytes()
	slice = append(slice, SignatureRequest)
	slice = append(slice,M_serialized[:]...)
	
	sess.PutOutgoing(slice)
	return nil
}


func GetTokenObfuscated(sess *session.SingleSession) (*bls.G1Affine,error) {
	var point bls.G1Affine
	var response []byte

	select {
	case <- time.After(30 * time.Second):
		return nil,apperr.New("timeout blind signature token request")
	case response = <- sess.Incoming:
	}

	response,ok := StripTag(response,TokenEmission)
	if !ok {
		return nil,apperr.New("response received does not match with the token emission bytecode")
	}

	if !CheckSize(TokenEmission, len(response)) {
		return nil,apperr.New("blinded signature received with invalid size")
	}

	_,err := point.SetBytes(response)
	if err != nil {
		return nil,apperr.Wrap("error during token conversion",err)
	}

	return &point,nil
}