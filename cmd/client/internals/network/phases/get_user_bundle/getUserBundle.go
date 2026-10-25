package getuserbundle

import (
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/proto_generated/bundle_request_structs"
	"P2Chat/pkg/apperr"

	"google.golang.org/protobuf/proto"
)

type state uint8

const (
	stateAwaitNicknames state = iota
	stateAwaitResponse
	stateCompleted
	stateFailed
)

const AcquisitionBundle byte = 0xf2

type BundleAcquisition struct {
	state     state
	nicknames [][]byte
	response  *ResponseBundles
}

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, errResult := phases.GetPhase[BundleAcquisition](byteCode, msg, phaseState, CheckSize)
	if errResult != nil {
		return errResult
	}
	if currentState == nil {
		currentState = &BundleAcquisition{state: stateAwaitNicknames}
		*phaseState = currentState
	}

	switch currentState.state {
	case stateAwaitNicknames:
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

// SendRequest receives the three nicknames from the local Router and sends
// one batch request to the server.
func SendRequest(byteCode byte, msg []byte, currentState *BundleAcquisition, result *phases.Result) *phases.Result {
	if byteCode != AcquisitionBundle || len(msg) == 0 {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid local bundle request"))
	}

	request := &bundle_request_structs.BundleRequest{}
	if err := proto.Unmarshal(msg, request); err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("decode local bundle request", err))
	}
	if err := validateNicknames(request.GetNicknames()); err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	currentState.nicknames = cloneNicknames(request.GetNicknames())
	currentState.state = stateAwaitResponse
	return phases.FillResult(result, [][]byte{append([]byte{phases.BundleAcquisitionRequest}, msg...)}, 0, false, false, nil, nil)
}

func handleResponse(byteCode byte, msg []byte, currentState *BundleAcquisition, result *phases.Result) *phases.Result {
	if byteCode != phases.BundleAcquisitionResponse || len(msg) == 0 {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid bundle response"))
	}

	response, err := DecodeResponseBundles(msg)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if err := response.ValidateRequested(currentState.nicknames); err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	currentState.response = response
	currentState.state = stateCompleted

	event := append([]byte(nil), msg...)
	return phases.FillResult(result, [][]byte{{phases.BundleAcquisitionConfirmation}}, 0, true, false, [][]byte{event}, nil)
}

func validateNicknames(nicknames [][]byte) error {
	if len(nicknames) != BundleRequestCount {
		return apperr.New("bundle request must contain exactly three nicknames")
	}
	seen := make(map[string]struct{}, BundleRequestCount)
	for _, nickname := range nicknames {
		if len(nickname) == 0 || len(nickname) > 64 {
			return apperr.New("invalid nickname in bundle request")
		}
		value := string(nickname)
		if _, exists := seen[value]; exists {
			return apperr.New("duplicate nickname in bundle request")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func cloneNicknames(nicknames [][]byte) [][]byte {
	cloned := make([][]byte, len(nicknames))
	for index, nickname := range nicknames {
		cloned[index] = append([]byte(nil), nickname...)
	}
	return cloned
}

func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case AcquisitionBundle:
		return payloadLen > 0 && payloadLen <= 512
	case phases.BundleAcquisitionResponse:
		return payloadLen > 0 && payloadLen <= 24<<20
	default:
		return false
	}
}
