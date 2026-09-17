package server_identification

import (
	serverproto "P2Chat/cmd/client/internals/proto_generated/server_identification/proto_struct_server"
	idserver "P2Chat/cmd/server/internals/ID_server"
	"P2Chat/cmd/server/internals/network/dispatcher"
	"P2Chat/cmd/server/internals/network/phases"
	"P2Chat/pkg/apperr"

	proto "google.golang.org/protobuf/proto"
)

func init() {
	dispatcher.RegistryByteCode(phases.ServerIdentityRequest, Handler)
}

type IdentificationServer struct {
	Binding   []byte
	completed bool
}

func Handler(byteCode byte, msg []byte, state *any) *phases.Result {
	result := &phases.Result{}
	currentState, errResult := phases.GetPhase[IdentificationServer](byteCode, msg, state, CheckSize)
	if errResult != nil {
		return errResult
	}
	if currentState == nil || len(currentState.Binding) != 32 || currentState.completed {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid server identification state"))
	}
	return handleRequest(result, currentState, msg)
}

func handleRequest(result *phases.Result, currentState *IdentificationServer, msg []byte) *phases.Result {
	request := &serverproto.IdentificationRequest{}
	if err := proto.Unmarshal(msg, request); err != nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("decode identification request", err))
	}
	if len(request.Nonce) != 32 {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid identification nonce size"))
	}

	// use the current ServerID for sign the nonce received from the client and identificate himself
	bundle, err := idserver.CreateIDBundle(currentState.Binding, request.Nonce)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	response := &serverproto.ServerID{
		VersionP2:  uint32(bundle.VersionP2),
		Id:         bundle.ID,
		MldsaSign:  bundle.MldsaSign,
		X25519Sign: bundle.X25519Sign,
		PubMldsa:   bundle.PubMLDSA,
		PubX25519:  bundle.PubX25519,
	}
	serialized, err := proto.Marshal(response)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("serialize server identification", err))
	}
	currentState.completed = true
	return phases.FillResult(result, [][]byte{append([]byte{phases.ServerIdentityResponse}, serialized...)}, 0, true, false, nil)
}

func CheckSize(tag byte, payloadLen int) bool {
	return tag == phases.ServerIdentityRequest && payloadLen >= 34 && payloadLen <= 128
}
