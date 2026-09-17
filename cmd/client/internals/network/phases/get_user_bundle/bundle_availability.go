package getuserbundle

import (
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/proto_generated/bundle_request_structs"
	"P2Chat/pkg/apperr"

	"google.golang.org/protobuf/proto"
)

const AvailabilityNickname byte = 0xf2

type availabilityState uint8

const (
	availabilityAwaitNickname availabilityState = iota
	availabilityAwaitResponse
	availabilityCompleted
	availabilityFailed
)

type BundleAvailability struct {
	state    availabilityState
	nickname []byte
}

func AvailabilityHandler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, errResult := phases.GetPhase[BundleAvailability](byteCode, msg, phaseState, availabilityCheckSize)
	if errResult != nil {
		return errResult
	}
	if currentState == nil {
		currentState = &BundleAvailability{state: availabilityAwaitNickname}
		*phaseState = currentState
	}

	switch currentState.state {
	case availabilityAwaitNickname:
		if byteCode != AvailabilityNickname {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid local nickname"))
		}

		request, err := proto.Marshal(&bundle_request_structs.BundleRequest{Nickname: msg})
		if err != nil {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("serialize bundle availability request", err))
		}
		currentState.nickname = append([]byte(nil), msg...)
		currentState.state = availabilityAwaitResponse
		return phases.FillResult(result, [][]byte{append([]byte{phases.BundleAvailabilityRequest}, request...)}, 0, false, false, nil, nil)

	case availabilityAwaitResponse:
		if byteCode != phases.BundleAvailabilityResponse {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid bundle availability response"))
		}

		response := &bundle_request_structs.BundleAvailabilityResponse{}
		if err := proto.Unmarshal(msg, response); err != nil {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("decode bundle availability response", err))
		}
		if string(response.Nickname) != string(currentState.nickname) {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle availability nickname does not match request"))
		}

		currentState.state = availabilityCompleted
		present := byte(0)
		if response.Present {
			present = 1
		}
		return phases.FillResult(result, nil, 0, true, false, [][]byte{{phases.BundleAvailabilityResponse, present}}, nil)

	case availabilityCompleted:
		return phases.FillResult(result, nil, 0, true, true, nil, apperr.New("bundle availability phase already completed"))
	case availabilityFailed:
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle availability phase failed"))
	default:
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid bundle availability state"))
	}
}

func availabilityCheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case AvailabilityNickname:
		return payloadLen > 0 && payloadLen <= 64
	case phases.BundleAvailabilityResponse:
		return payloadLen > 0 && payloadLen <= 128
	default:
		return false
	}
}
