package token_registration

import (
	"P2Chat/cmd/client/internals/p2log"
	challengeStruct "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	pow "P2Chat/cmd/server/network/PoW"
	blindsignature "P2Chat/cmd/server/network/blind_signature"
	loadreport "P2Chat/cmd/server/network/load_report"
	"P2Chat/cmd/server/network/phases"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381" // contains the point on the curve
	"google.golang.org/protobuf/proto"
)

type state uint8

const (
	stateAwaitRequest state = iota		// server wait the token registration request
	stateAwaitNonce						// the server had send the PoW and now is waiting the nonce (solution)
	stateAwaitSignature					// the server had convalidated the nonce and now wait the M' for signature (token registration emission)
	stateCompleted
	stateFailed
)

// RegistrationServer keeps the data required by one token registration flow.
type RegistrationServer struct {
	state      	state
	secret     	[]byte
	challenge  	*challengeStruct.Challenge
	level      	pow.Level
	privateKey 	*blindsignature.PrivateKey
	PowPassed	bool
}

// GetPhaseState converts the universal session state to this phase state.
func GetPhaseState[T any](phaseState any) *T {
	value, ok := phaseState.(*T)
	if !ok {
		return nil
	}
	return value
}

// Handler validates each registration message and returns the next protocol action.
func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	if phaseState == nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration state is nil"))
	}

	if !CheckSize(byteCode, len(msg)) {
		p2log.Error("registration received a payload with invalid size")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration received a payload with invalid size"))
	}

	if *phaseState == nil {
		level, err := loadreport.LoadReport()
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, err)
		}

		privateKey := blindsignature.GetCurrentPrivateKey()
		if privateKey == nil {
			return phases.FillResult(result, nil, 0, false, true, apperr.New("blind signature private key is nil"))
		}

		*phaseState = &RegistrationServer{
			state:      stateAwaitRequest,
			level:      level,
			privateKey: privateKey,
			PowPassed: false,
		}
	}

	currentState := GetPhaseState[RegistrationServer](*phaseState)
	if currentState == nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration phase received an invalid state"))
	}

	switch currentState.state {
	case stateAwaitRequest:
		// token request
		if byteCode != phases.RegisterTokenReq {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid registration token request"))
		}
		p2log.Debug("server registration: received RegisterTokenReq, emitting PoW challenge")

		secret := make([]byte, 64)
		if _, err := rand.Read(secret); err != nil {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("error generating registration secret", err))
		}

		challenge, reply, err := issueChallenge(secret, currentState.level)
		if err != nil {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, err)
		}

		currentState.secret = secret
		currentState.challenge = challenge
		currentState.state = stateAwaitNonce
		p2log.Info("server registration: PoW challenge emitted, level: ", currentState.level)
		return phases.FillResult(result, [][]byte{reply}, currentState.level.MaxWaitTime(), false, false, nil)

	case stateAwaitNonce:
		// server receive the nonce 
		if byteCode != phases.ChallengeResponse || currentState.challenge == nil {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid challenge response"))
		}

		nonce, err := receiveNonce(msg)
		if err != nil {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, err)
		}
		p2log.Debug("server registration: received nonce: ", nonce)

		if !pow.Verify(currentState.secret, currentState.challenge, nonce) {
			currentState.state = stateFailed
			p2log.Error("server registration: PoW verification failed")
			return phases.FillResult(result, nil, 0, false, true, apperr.New("challenge not solved"))
		}
		p2log.Info("server registration: PoW verified")

		currentState.state = stateAwaitSignature
		currentState.PowPassed = true
		return phases.FillResult(result, nil, time.Minute, false, false, nil)

	case stateAwaitSignature:
		// server wait the M for the signature = token emission
		if byteCode != phases.SignatureRequest {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid blind signature request"))
		}
		p2log.Debug("server registration: received SignatureRequest, generating blind signature")

		if currentState.PowPassed != true {
			p2log.Error("client did not passed the PoW")
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, fmt.Errorf("the client didnt passed the Pow"))
		}

		reply, err := SignObfuscated(msg, currentState.privateKey)
		if err != nil {
			currentState.state = stateFailed
			return phases.FillResult(result, nil, 0, false, true, err)
		}

		currentState.state = stateCompleted
		p2log.Info("server registration: blind signature sent, token emission complete")
		return phases.FillResult(result, [][]byte{reply}, 0, true, false, nil)

	case stateCompleted:
		p2log.Warning("server registration: message received after completion")
		return phases.FillResult(result, nil, 0, true, false, nil)

	case stateFailed:
		p2log.Warning("server registration: message received after failure")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration phase failed"))
	}

	return phases.FillResult(result, nil, 0, false, true, apperr.New("registration reached an invalid state"))
}

// issueChallenge creates and serializes the challenge reply for the router.
func issueChallenge(secret []byte, level pow.Level) (*challengeStruct.Challenge, []byte, error) {
	challenge, err := pow.Issue(secret, level)
	if err != nil {
		return nil, nil, apperr.Wrap("error creating challenge", err)
	}

	challengeSerialized, err := proto.Marshal(challenge)
	if err != nil {
		return nil, nil, apperr.Wrap("error serializing challenge", err)
	}

	data := append([]byte{phases.PowToken}, challengeSerialized...)
	return challenge, data, nil
}

// receiveNonce decodes the nonce from the payload already validated by the Handler.
func receiveNonce(payload []byte) (uint64, error) {
	return binary.BigEndian.Uint64(payload), nil
}

// ReceiveAndSign validates the blinded point and returns the signed reply for the router.
func SignObfuscated(payload []byte, privateKey *blindsignature.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, apperr.New("blind signature private key is nil")
	}

	var M_obfuscated bls.G1Affine

	_, err := M_obfuscated.SetBytes(payload)
	if err != nil {
		return nil, apperr.Wrap("error with the byte conversion to raw to G1Affine", err)
	}

	signedPoint := privateKey.SignBlind(&M_obfuscated)
	if signedPoint == nil {
		return nil, apperr.New("blind signature failed: private key unlock error")
	}
	signatureSerialized := signedPoint.Bytes()
	return append([]byte{phases.TokenEmission}, signatureSerialized[:]...), nil
}

// check the size of the payload in base of the type of the message
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
