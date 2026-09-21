package server_identification

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/database"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/p2log"
	serverproto "P2Chat/cmd/client/internals/proto_generated/server_identification/proto_struct_server"
	idserver "P2Chat/cmd/server/internals/ID_server"
	x25519_keys "P2Chat/cmd/server/internals/keys/x25519"
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	proto "google.golang.org/protobuf/proto"
)

type state uint8

const (
	stateRequest state = iota
	stateAwaitIdentity
	stateCompleted
	stateFailed
)

type IdentificationClient struct {
	Binding  []byte
	Endpoint string
	state    state
	nonce    [32]byte
}

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, errResult := phases.GetPhase[IdentificationClient](byteCode, msg, phaseState, CheckSize)
	if errResult != nil {
		return errResult
	}
	if currentState == nil || len(currentState.Binding) != 32 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("identification requires a 32-byte TLS binding"))
	}
	var phaseResult *phases.Result
	switch currentState.state {
	case stateRequest:
		phaseResult = handleRequest(result, currentState, byteCode, msg)
	case stateAwaitIdentity:
		phaseResult = handleIdentity(result, currentState, byteCode, msg)
	case stateCompleted:
		phaseResult = phases.FillResult(result, nil, 0, false, true, nil, apperr.New("server identification already completed"))
	case stateFailed:
		phaseResult = phases.FillResult(result, nil, 0, false, true, nil, apperr.New("server identification phase failed"))
	default:
		currentState.state = stateFailed
		phaseResult = phases.FillResult(result, nil, 0, false, true, nil, apperr.New("server identification reached an invalid state"))
	}
	if phaseResult.Err != nil {
		currentState.state = stateFailed
	}
	return phaseResult
}

// handleRequest handle the server identification request
func handleRequest(result *phases.Result, currentState *IdentificationClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.ServerIdentityRequest || len(msg) != 0 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid identification start"))
	}
	if _, err := rand.Read(currentState.nonce[:]); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("generate identification nonce", err))
	}
	request, err := proto.Marshal(&serverproto.IdentificationRequest{Nonce: currentState.nonce[:]})
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("serialize identification request", err))
	}
	currentState.state = stateAwaitIdentity
	return phases.FillResult(result, [][]byte{append([]byte{phases.ServerIdentityRequest}, request...)}, 0, false, false, nil, nil)
}

func handleIdentity(result *phases.Result, currentState *IdentificationClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.ServerIdentityResponse {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid identification response"))
	}
	response := &serverproto.ServerID{}
	if err := proto.Unmarshal(msg, response); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("decode server identification", err))
	}
	if response.VersionP2 > 255 || len(response.Id) != 32 ||
		len(response.PubMldsa) != mldsa87.PublicKeySize || len(response.PubX25519) != 32 ||
		len(response.MldsaSign) != mldsa87.SignatureSize || len(response.X25519Sign) != 64 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid server identification fields"))
	}
	hash := sha256.New()
	hash.Write(response.PubMldsa)
	hash.Write(response.PubX25519)
	if !bytes.Equal(hash.Sum(nil), response.Id) {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("server ID does not match its public keys"))
	}
	message := []byte{byte(response.VersionP2)}
	message = append(message, currentState.nonce[:]...)
	message = append(message, currentState.Binding...)

	var publicKey mldsa87.PublicKey
	if err := publicKey.UnmarshalBinary(response.PubMldsa); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("decode server ML-DSA key", err))
	}
	if !(&mldsa_keys.PublicMLDSA{Key: &publicKey}).Verify(message, nil, response.MldsaSign) ||
		!x25519_keys.VerifySignature(response.PubX25519, message, response.X25519Sign) {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid server identification signatures"))
	}
	serverID := &idserver.IDServer{
		VersionP2: uint8(response.VersionP2), ID: response.Id,
		MldsaSign: response.MldsaSign, X25519Sign: response.X25519Sign,
		PubMLDSA: response.PubMldsa, PubX25519: response.PubX25519,
	}
	var exists, changed bool
	var err error
	if currentState.Endpoint == "" {
		exists, err = database.SaveServerID(serverID)
	} else {
		exists, changed, err = database.SaveKnownServer(serverID, currentState.Endpoint)
	}
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if exists {
		p2log.Info("server identity already known: ", fmt.Sprintf("%x", response.Id))
		if changed {
			p2log.Warning("server address changed; identity proof verified: ", currentState.Endpoint)
		}
	} else {
		p2log.Info("new server identity: ", fmt.Sprintf("%x", response.Id))
	}
	currentState.state = stateCompleted
	return phases.FillResult(result, nil, 0, true, false, [][]byte{msg}, nil)
}

func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case phases.ServerIdentityRequest:
		return payloadLen == 0
	case phases.ServerIdentityResponse:
		return payloadLen > 0 && payloadLen <= 8192
	default:
		return false
	}
}
