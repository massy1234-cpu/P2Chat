package token_registration

import (
	"P2Chat/cmd/client/internals/p2log"
	challengeStruct "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	pow "P2Chat/cmd/server/internals/network/PoW"
	blindsignature "P2Chat/cmd/server/internals/network/blind_signature"
	"P2Chat/cmd/server/internals/network/dispatcher"
	loadreport "P2Chat/cmd/server/internals/network/load_report"
	"P2Chat/cmd/server/internals/network/phases"
	"P2Chat/cmd/server/internals/proto_generated/PoW/proto_struct_pow"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381" // contains the point on the curve
	"google.golang.org/protobuf/proto"
)

// register the registration phase handler for the RegisterTokenReq bytecode
func init() {
	dispatcher.RegistryByteCode(phases.RegistrationStart, Handler)
}

type state uint8

const (
	stateAwaitRequest   state = iota // server wait the token registration request
	stateAwaitNonce                  // the server had send the PoW and now is waiting the nonce (solution)
	stateAwaitSignature              // the server had convalidated the nonce and now wait the M' for signature (token registration emission)
	stateCompleted
	stateFailed
)

// RegistrationServer keeps the data required by one token registration flow.
type RegistrationServer struct {
	state     state
	secret    []byte
	challenge *challengeStruct.Challenge
	level     pow.Level
	blindKeys *blindsignature.KeysBlindSignature
	PowPassed bool
}

// Handler validates each registration message and returns the next protocol action.
func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}

	currentState, errResult := phases.GetPhase[RegistrationServer](byteCode, msg, phaseState, CheckSize)
	if errResult != nil {
		return errResult
	}

	// not initialized yet -> create the right struct for this phase
	if currentState == nil {
		level, err := loadreport.LoadReport()
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, err)
		}

		keys := blindsignature.GetCurrentKeys()
		if keys == nil {
			return phases.FillResult(result, nil, 0, false, true, apperr.New("blind signature private key is nil"))
		}

		currentState = &RegistrationServer{
			state:     stateAwaitRequest,
			level:     level,
			blindKeys: keys,
			PowPassed: false,
		}
		*phaseState = currentState
	}

	switch currentState.state {
	case stateAwaitRequest:
		return handleRequest(result, currentState, byteCode, msg)

	case stateAwaitNonce:
		return handleNonce(result, currentState, byteCode, msg)

	case stateAwaitSignature:
		return handleSignature(result, currentState, byteCode, msg)

	case stateCompleted:
		p2log.Warning("server registration: message received after completion")
		return phases.FillResult(result, nil, 0, true, false, nil)

	case stateFailed:
		p2log.Warning("server registration: message received after failure")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration phase failed"))
	}

	return phases.FillResult(result, nil, 0, false, true, apperr.New("registration reached an invalid state"))
}

// handleRequest receives the RegisterTokenReq and emits a PoW challenge bound
// to a per-session secret.
func handleRequest(result *phases.Result, currentState *RegistrationServer, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.RegistrationStart {
		currentState.state = stateFailed
		return registrationError(result, apperr.New("invalid registration token request"))
	}
	p2log.Debug("server registration: received RegisterTokenReq, emitting PoW challenge")

	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		currentState.state = stateFailed
		return registrationError(result, apperr.Wrap("error generating registration secret", err))
	}

	issued, err := issueChallenge(secret, currentState.level)
	if err != nil {
		currentState.state = stateFailed
		return registrationError(result, err)
	}

	currentState.secret = secret
	currentState.challenge = issued.Challenge
	currentState.state = stateAwaitNonce
	p2log.Info("server registration: PoW challenge emitted, level: ", currentState.level)
	return phases.FillResult(result, [][]byte{issued.WirePayload}, currentState.level.MaxWaitTime(), false, false, nil)
}

// handleNonce verifies the PoW solution and notifies the client.
func handleNonce(result *phases.Result, currentState *RegistrationServer, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.RegistrationPoWSolution || currentState.challenge == nil {
		currentState.state = stateFailed
		return registrationError(result, apperr.New("invalid challenge response"))
	}

	nonce, err := receiveNonce(msg)
	if err != nil {
		currentState.state = stateFailed
		return registrationError(result, err)
	}
	p2log.Debug("server registration: received nonce: ", nonce)

	if !pow.Verify(currentState.secret, currentState.challenge, nonce) {
		currentState.state = stateFailed
		return registrationError(result, apperr.New("challenge not solved"))
	}
	p2log.Info("server registration: PoW verified")

	currentState.state = stateAwaitSignature
	currentState.PowPassed = true
	p2log.Debug("server registration: notifying the client that the PoW is verified")
	return phases.FillResult(result, [][]byte{[]byte{phases.RegistrationPoWAccepted}}, time.Minute, false, false, nil)
}

// handleSignature signs the blind point M' and emits the token.
func handleSignature(result *phases.Result, currentState *RegistrationServer, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.RegistrationBlindSignatureRequest {
		currentState.state = stateFailed
		return registrationError(result, apperr.New("invalid blind signature request"))
	}
	p2log.Debug("server registration: received SignatureRequest, generating blind signature")

	if currentState.PowPassed != true {
		p2log.Error("client did not passed the PoW")
		currentState.state = stateFailed
		return registrationError(result, fmt.Errorf("the client didnt passed the Pow"))
	}

	sk := currentState.blindKeys.Sk
	reply, err := SignObfuscated(msg, sk)
	if err != nil {
		currentState.state = stateFailed
		return registrationError(result, err)
	}

	currentState.state = stateCompleted
	p2log.Info("server registration: blind signature sent, token emission complete")
	return phases.FillResult(result, [][]byte{reply}, 0, true, false, nil)
}

// registrationError notifies the client of the failure and closes the stream.
func registrationError(result *phases.Result, err error) *phases.Result {
	p2log.Error("server registration failed: ", err)
	return phases.FillResult(result, [][]byte{{phases.RegistrationRejected}}, 0, false, true, err)
}

// IssuedChallenge encapsulates the generated challenge and its wire-ready payload.
type IssuedChallenge struct {
	Challenge   *challengeStruct.Challenge
	WirePayload []byte
}

// issueChallenge creates and serializes the challenge reply for the router.
func issueChallenge(secret []byte, level pow.Level) (*IssuedChallenge, error) {
	challenge, err := pow.Issue(secret, level)
	if err != nil {
		return nil, apperr.Wrap("error creating challenge", err)
	}

	challengeSerialized, err := proto.Marshal(challenge)
	if err != nil {
		return nil, apperr.Wrap("error serializing challenge", err)
	}

	data := append([]byte{phases.RegistrationPoWChallenge}, challengeSerialized...)
	return &IssuedChallenge{
		Challenge:   challenge,
		WirePayload: data,
	}, nil
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

	signedPoint, hash := privateKey.SignBlind(&M_obfuscated)
	if signedPoint == nil {
		return nil, apperr.New("blind signature failed: private key unlock error")
	}
	signatureSerialized := signedPoint.Bytes()

	token := &proto_struct_pow.Signature{
		Obfuscated: signatureSerialized[:],
		HashPk:     hash[:],
	}

	tokenSerialized, err := proto.Marshal(token)
	if err != nil {
		return nil, apperr.New("marshal error in token emission")
	}

	return append([]byte{phases.RegistrationTokenIssued}, tokenSerialized[:]...), nil
}

// check the size of the payload in base of the type of the message
func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case phases.DummyMessage:
		return payloadLen >= 1
	case phases.RegistrationStart:
		return payloadLen == 0
	case phases.RegistrationPoWChallenge:
		return payloadLen >= 56 && payloadLen <= 65
	case phases.RegistrationPoWSolution:
		return payloadLen == 8
	case phases.RegistrationBlindSignatureRequest:
		return payloadLen == 48
	case phases.RegistrationTokenIssued:
		return payloadLen == 48
	case phases.RegistrationPoWAccepted:
		return payloadLen == 0
	case phases.RegistrationRejected:
		return payloadLen == 0
	default:
		return false
	}
}
