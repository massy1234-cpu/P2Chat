package registration

import (
	pow "P2Chat/cmd/client/internals/network/PoW"
	blindsignature "P2Chat/cmd/client/internals/network/blind_signature"
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/p2log"
	challengeStruct "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	"P2Chat/pkg/apperr"
	"encoding/binary"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	proto "google.golang.org/protobuf/proto"
	"time"
)

// define the registration phase states
type state uint8

const (
	stateAwaitChallenge state = iota // initial state, client request the PoW to the server
	stateAwaitToken                  // the client had resolved the PoW and now wait the Token
	stateCompleted                   // process is completed
	stateFailed                      // process is not completed, some error occured
)

// keep the state of the registration client
type RegistrationState struct {
	Bytecode byte
	Tag      string
}

// this struct contains the only informations that must be saved for the token registration request phase
type RegistrationClient struct {
	state      state
	blindState *blindsignature.BlindState
	token      *bls.G1Affine
	nonce      uint64
	obfuscated *bls.G1Affine
}

// convert the phaseState in the correct struct for each phase
func GetPhaseState[T any](phaseState any) *T {
	value, ok := phaseState.(*T)
	if !ok {
		return nil
	}
	return value
}

func Handler(byteCode byte, msg []byte, state *any) *phases.Result {
	result := &phases.Result{}

	if state == nil {
		p2log.Error("registration state is nil")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration state is nil"))
	}

	if !CheckSize(byteCode, len(msg)) {
		p2log.Error("registration received a payload with invalid size")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration received a payload with invalid size"))
	}

	// not initialized yet -> create the right struct for this phase
	if *state == nil {
		currentState := &RegistrationClient{
			state:      stateAwaitChallenge,
			blindState: nil,
			token:      nil,
		}
		*state = currentState
	}

	currentState := GetPhaseState[RegistrationClient](*state)
	if currentState == nil {
		p2log.Error("registration phase received an invalid state")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration phase received an invalid state"))
	}

	switch currentState.state {
	case stateAwaitChallenge:
		if byteCode != phases.PowToken {
			p2log.Error("registration received an invalid challenge")
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.New("registration received an invalid challenge"))
		}

		// decode the payload
		challenge, err := decodeChallenge(msg)
		if err != nil {
			p2log.Error("registration received an invalid challenge", err)
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, err)
		}

		nonce, err := solveChallenge(challenge)
		if err != nil {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, err)
		}

		blindState, obfuscated, err := blindsignature.CreateAndBlind()
		if err != nil {
			p2log.Error("error creating blind signature request", err)
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("error creating blind signature request", err))
		}

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

		return phases.FillResult(result, bytes, timeWait, false, false, nil)

	case stateAwaitToken:
		if byteCode != phases.TokenEmission {
			p2log.Error("registration received an invalid token emission")
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.New("registration received an invalid token emission"))
		}

		if currentState.blindState == nil {
			p2log.Error("registration blind state is nil")
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.New("registration blind state is nil"))
		}

		blindedSignature, err := GetTokenObfuscated(msg)
		if err != nil {
			p2log.Error("error converting blinded signature", err)
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, err)
		}

		token := currentState.blindState.Unblind(blindedSignature)
		currentState.token = &token
		currentState.state = stateCompleted

		return phases.FillResult(result, nil, 0, true, false, nil)

	case stateCompleted:
		p2log.Warning("registration received a message after completion")
		return phases.FillResult(result, nil, 0, true, false, nil)

	case stateFailed:
		p2log.Warning("registration received a message after failure")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration phase failed"))
	}

	return phases.FillResult(result, nil, 0, false, true, apperr.New("registration reached an invalid state"))
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

// GetTokenObfuscated decodes the payload already received by the router.
func GetTokenObfuscated(payload []byte) (*bls.G1Affine, error) {
	var point bls.G1Affine
	if !CheckSize(phases.TokenEmission, len(payload)) {
		return nil, apperr.New("blinded signature received with invalid size")
	}

	_, err := point.SetBytes(payload)
	if err != nil {
		return nil, apperr.Wrap("error during token conversion", err)
	}

	return &point, nil
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
		return payloadLen == 48
	default:
		return false
	}
}
