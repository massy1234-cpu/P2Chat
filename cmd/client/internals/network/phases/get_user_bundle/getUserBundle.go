package getuserbundle

import (
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/proto_generated/bundle_request_structs"
	"P2Chat/pkg/apperr"
	"bytes"

	"google.golang.org/protobuf/proto"
)

type state uint8

const (
	stateAwaitNickname state = iota
	stateAwaitResponse
	stateCompleted
	stateFailed
)

const AcquisitionNickname byte = 0xf1

type BundleSearched struct {
	state    state
	request  *bundle_request_structs.BundleRequest
	response *bundle_request_structs.BundleResponse
}

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, errResult := phases.GetPhase[BundleSearched](byteCode, msg, phaseState, CheckSize)
	if errResult != nil {
		return errResult
	}
	if currentState == nil {
		currentState = &BundleSearched{state: stateAwaitNickname}
		*phaseState = currentState
	}

	switch currentState.state {
	case stateAwaitNickname:
		return SendRequest(byteCode, msg, currentState, result)
	case stateAwaitResponse:
		return handleResponse(byteCode, msg, currentState, result)
	case stateCompleted:
		return phases.FillResult(result, nil, 0, true, true, nil, apperr.New("bundle request already completed"))
	case stateFailed:
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle request phase failed"))
	default:
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid bundle request state"))
	}
}

// SendRequest get the nickname from the local chan and send the request to the server
func SendRequest(byteCode byte, msg []byte, currentState *BundleSearched, result *phases.Result) *phases.Result {
	if byteCode != AcquisitionNickname || len(msg) == 0 {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid local nickname"))
	}
	req := &bundle_request_structs.BundleRequest{}
	req.Nickname = msg
	currentState.request = req
	s, err := proto.Marshal(req)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("error during serialization of proto struct"))
	}

	b := append(
		[]byte{phases.BundleAcquisitionRequest},
		s...,
	)

	currentState.state = stateAwaitResponse
	return phases.FillResult(result, [][]byte{b}, 0, false, false, nil, nil)
}

func handleResponse(byteCode byte, msg []byte, currentState *BundleSearched, result *phases.Result) *phases.Result {
	if byteCode != phases.BundleAcquisitionResponse || len(msg) == 0 {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid bytecode"))
	}

	response, err := decodeResponse(msg)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid response, maybe bytes corruption"))
	}
	if response.Bundle == nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("server had reject the request"))
	}
	currentState.response = response

	if !bytes.Equal(currentState.response.Bundle.Nickname, currentState.request.Nickname) {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid response, nickname not match"))
	}
	bundle, err := proto.Marshal(currentState.response.Bundle)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("error serializing received bundle", err))
	}

	currentState.state = stateCompleted
	return phases.FillResult(result, [][]byte{{phases.BundleAcquisitionConfirmation}}, 0, true, false, [][]byte{bundle}, nil)
}

func decodeResponse(response []byte) (*bundle_request_structs.BundleResponse, error) {
	b := &bundle_request_structs.BundleResponse{}
	err := proto.Unmarshal(response, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case AcquisitionNickname:
		return payloadLen > 0 && payloadLen <= 64
	case phases.BundleAcquisitionResponse:
		return payloadLen > 0 && payloadLen <= 8<<20
	default:
		return false
	}
}
