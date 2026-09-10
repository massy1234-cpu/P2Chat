package token_registration

import (
	pow "P2Chat/cmd/client/internals/network/PoW"
	blindsignature "P2Chat/cmd/client/internals/network/blind_signature"
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	challengeStruct "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	"P2Chat/pkg/apperr"
	"encoding/binary"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	proto "google.golang.org/protobuf/proto"
)

// define the registration phase states
type state uint8

const (
	stateAwaitChallenge state = iota // initial state, client request the PoW to the server
	stateAwaitToken                  // the client had resolved the PoW and now wait the Token
	stateCompleted                   // process is completed
	stateFailed                      // process is not completed, some error occured
)

// this struct contains the only informations that must be saved for the token registration request phase
type RegistrationClient struct {
	state       state
	blindState  *blindsignature.BlindState
	challenge   *challengeStruct.Challenge
	token       *bls.G1Affine
	signature   *proto_struct_pow.Signature
	nonce       uint64
	obfuscated  *bls.G1Affine
}

func Handler(byteCode byte, msg []byte, state *any) *phases.Result {
	result := &phases.Result{}

	currentState, errResult := phases.GetPhase[RegistrationClient](byteCode, msg, state, CheckSize)
	if errResult != nil {
		return errResult
	}

	// not initialized yet -> create the right struct for this phase
	if currentState == nil {
		currentState = &RegistrationClient{
			state: stateAwaitChallenge,
		}
		*state = currentState
	}

	switch currentState.state {
	case stateAwaitChallenge:
		return handleChallenge(result, currentState, byteCode, msg)

	case stateAwaitToken:
		return handleToken(result, currentState, byteCode, msg)

	case stateCompleted:
		p2log.Warning("registration received a message after completion")
		return phases.FillResult(result, nil, 0, true, false, nil, nil)

	case stateFailed:
		p2log.Warning("registration received a message after failure")
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration phase failed"))
	}

	return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration reached an invalid state"))
}

// handleChallenge decodes the PoW challenge, solves it, creates the blind
// request and sends nonce + M' to the server in one shot.
func handleChallenge(result *phases.Result, currentState *RegistrationClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode == phases.RegistrationError {
		p2log.Error("registration failed on the server side")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration failed on the server side"))
	}

	if byteCode != phases.PowToken {
		p2log.Error("registration received an invalid challenge")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration received an invalid challenge"))
	}

	// decode the payload
	challenge, err := decodeChallenge(msg)
	if err != nil {
		p2log.Error("registration received an invalid challenge", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	p2log.Info("registration received PoW challenge, level: ", challenge.GetLevel())
	
	currentState.challenge = challenge

	nonce, err := solveChallenge(challenge)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	p2log.Info("registration PoW solved, nonce: ", nonce)

	blindState, obfuscated, err := blindsignature.CreateAndBlind()
	if err != nil {
		p2log.Error("error creating blind signature request", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("error creating blind signature request", err))
	}
	p2log.Debug("registration blind signature request created")

	nonceReply := make([]byte, 9)
	nonceReply[0] = phases.ChallengeResponse
	binary.BigEndian.PutUint64(nonceReply[1:], nonce)

	serialized := obfuscated.Bytes()
	signatureReply := make([]byte, 49)
	signatureReply[0] = phases.SignatureRequest
	copy(signatureReply[1:], serialized[:])

	currentState.blindState = blindState
	currentState.nonce = nonce
	currentState.obfuscated = obfuscated
	currentState.state = stateAwaitToken

	// send to the server the challenge solved (nonce) and the M'
	bytes := [][]byte{nonceReply, signatureReply}
	timeWait := 1 * time.Minute

	return phases.FillResult(result, bytes, timeWait, false, false, nil, nil)
}

// handleToken unblinds the received signature and emits the resulting token
// on the session Events chan for the next phase.
func handleToken(result *phases.Result, currentState *RegistrationClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode == phases.PoWVerified {
		p2log.Debug("registration PoW verified by the server")
		return phases.FillResult(result, nil, 0, false, false, nil, nil)
	}

	if byteCode == phases.RegistrationError {
		p2log.Error("registration failed on the server side")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration failed on the server side"))
	}

	if byteCode != phases.TokenEmission {
		p2log.Error("registration received an invalid token emission")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration received an invalid token emission"))
	}

	if currentState.blindState == nil {
		p2log.Error("registration blind state is nil")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration blind state is nil"))
	}

	p2log.Debug("token obfuscated received")

	blindedSignature, err := GetTokenObfuscated(msg)
	if err != nil {
		p2log.Error("error converting blinded signature", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}

	var blinded bls.G1Affine
	if _, err := blinded.SetBytes(blindedSignature.GetObfuscated()); err != nil {
		p2log.Error("error converting obfuscated signature", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("error converting obfuscated signature", err))
	}

	currentState.signature = blindedSignature

	p2log.Debug("proceed with the deobfuscation...")

	token := currentState.blindState.Unblind(&blinded)
	tokenSerialized := token.Bytes()
	currentState.state = stateCompleted

	p2log.Info("registration phase completed, token obtained")

	tokenOnEvents := &proto_struct_pow.TokenVerification{
		Token:     tokenSerialized[:],
		M:         currentState.blindState.Msg,
		Challenge: currentState.challenge,
		Signature: currentState.signature,
	}

	b, e := proto.Marshal(tokenOnEvents)
	if e != nil {
		p2log.Error("erron in serialization of token")
		return phases.FillResult(result, nil, 0, true, false, nil, apperr.New("erron in serialization of token"))
	}

	return phases.FillResult(result, nil, 0, true, false, [][]byte{b}, nil)
}

// requestChallenge decodes the payload already received by the router.
func decodeChallenge(payload []byte) (*challengeStruct.Challenge, error) {
	if !CheckSize(phases.PowToken, len(payload)) {
		return nil, apperr.New("challenge received with invalid size")
	}

	challenge := &challengeStruct.Challenge{}
	err := proto.Unmarshal(payload, challenge)
	if err != nil {
		return nil, apperr.Wrap("error unmarshalling registration challenge", err)
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

// GetTokenObfuscated decodes the Signature payload already received by the router.
func GetTokenObfuscated(payload []byte) (*proto_struct_pow.Signature, error) {
	var sig proto_struct_pow.Signature
	if err := proto.Unmarshal(payload, &sig); err != nil {
		return nil, apperr.Wrap("error during token conversion", err)
	}
	return &sig, nil
}

// check the size of the payload in base of the type of the message
// every phase has a CheckSize but is different for the bytecodes checked
func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case phases.Dummy:
		return payloadLen >= 1
	case phases.RegisterTokenReq:
		return payloadLen == 0
	case phases.PowToken:
		return payloadLen >= 56 && payloadLen <= 65
	case phases.ChallengeResponse:
		return payloadLen == 8
	case phases.SignatureRequest:
		return payloadLen == 48
	case phases.TokenEmission:
		return payloadLen >= 1
	case phases.PoWVerified:
		return payloadLen == 0
	case phases.RegistrationError:
		return payloadLen == 0
	default:
		return false
	}
}
