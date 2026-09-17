package getuserbundle

import (
	"P2Chat/cmd/client/internals/proto_generated/bundle_request_structs"
	"P2Chat/cmd/server/database"
	"P2Chat/cmd/server/internals/network/dispatcher"
	"P2Chat/cmd/server/internals/network/phases"
	bundleproto "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"

	"google.golang.org/protobuf/proto"
)

func init() {
	dispatcher.RegistryByteCode(phases.BundleAcquisitionRequest, Handler)
}

type state uint8

const (
	stateAwaitRequest state = iota
	stateAwaitConfirmation
	stateCompleted
	stateFailed
)

type BundleSearched struct {
	state         state
	authenticated bool
	request       *bundle_request_structs.BundleRequest
}

func NewBundleSearched(authenticated bool) *BundleSearched {
	return &BundleSearched{state: stateAwaitRequest, authenticated: authenticated}
}

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, errResult := phases.GetPhase[BundleSearched](byteCode, msg, phaseState, CheckSize)
	if errResult != nil {
		return errResult
	}
	if currentState == nil {
		currentState = NewBundleSearched(false)
		*phaseState = currentState
	}

	switch currentState.state {
	case stateAwaitRequest:
		return handleRequest(result, currentState, msg)
	case stateAwaitConfirmation:
		return handleConfirmation(result, currentState, byteCode)
	case stateCompleted:
		return phases.FillResult(result, nil, 0, true, true, apperr.New("bundle request already completed"))
	case stateFailed:
		return phases.FillResult(result, nil, 0, false, true, apperr.New("bundle request phase failed"))
	default:
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid bundle request state"))
	}
}

func handleRequest(result *phases.Result, currentState *BundleSearched, msg []byte) *phases.Result {
	request := &bundle_request_structs.BundleRequest{}
	if err := proto.Unmarshal(msg, request); err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid bundle request"))
	}
	currentState.request = request

	response := &bundle_request_structs.BundleResponse{}
	if currentState.authenticated {
		if id, err := database.GetValue(append([]byte("nickname:"), request.Nickname...)); err == nil {
			if bundle, err := database.GetValue(id); err == nil {
				payload := &bundleproto.UserBundle{}
				if err := proto.Unmarshal(bundle, payload); err == nil {
					response.Bundle = payload
				}
			}
		}
	}

	serialized, err := proto.Marshal(response)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("error serializing bundle response"))
	}
	currentState.state = stateAwaitConfirmation
	return phases.FillResult(result, [][]byte{append([]byte{phases.BundleAcquisitionResponse}, serialized...)}, 0, false, false, nil)
}

func handleConfirmation(result *phases.Result, currentState *BundleSearched, byteCode byte) *phases.Result {
	if byteCode != phases.BundleAcquisitionConfirmation {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid bundle acquisition confirmation"))
	}
	currentState.state = stateCompleted
	return phases.FillResult(result, nil, 0, true, false, nil)
}

func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case phases.BundleAcquisitionRequest:
		return payloadLen > 0 && payloadLen <= 128
	case phases.BundleAcquisitionConfirmation:
		return payloadLen == 0
	default:
		return false
	}
}
