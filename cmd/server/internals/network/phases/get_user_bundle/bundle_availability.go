package getuserbundle

import (
	"P2Chat/cmd/client/internals/proto_generated/bundle_request_structs"
	"P2Chat/cmd/server/database"
	"P2Chat/cmd/server/internals/network/dispatcher"
	"P2Chat/cmd/server/internals/network/phases"
	"P2Chat/pkg/apperr"

	"google.golang.org/protobuf/proto"
)

func init() {
	dispatcher.RegistryByteCode(phases.BundleAvailabilityRequest, AvailabilityHandler)
}

type availabilityState uint8

const (
	availabilityAwaitRequest availabilityState = iota
	availabilityCompleted
	availabilityFailed
)

type BundleAvailability struct {
	state         availabilityState
	authenticated bool
}

func NewBundleAvailability(authenticated bool) *BundleAvailability {
	return &BundleAvailability{state: availabilityAwaitRequest, authenticated: authenticated}
}

func AvailabilityHandler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, errResult := phases.GetPhase[BundleAvailability](byteCode, msg, phaseState, availabilityCheckSize)
	if errResult != nil {
		return errResult
	}
	if currentState == nil {
		currentState = NewBundleAvailability(false)
		*phaseState = currentState
	}

	switch currentState.state {
	case availabilityAwaitRequest:
		if byteCode != phases.BundleAvailabilityRequest {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid bundle availability request"))
		}

		request := &bundle_request_structs.BundleRequest{}
		if err := proto.Unmarshal(msg, request); err != nil {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("decode bundle availability request", err))
		}

		present := false
		if currentState.authenticated {
			_, err := database.GetBundleIDByNickname(request.Nickname)
			present = err == nil
		}
		response, err := proto.Marshal(&bundle_request_structs.BundleAvailabilityResponse{
			Nickname: request.Nickname,
			Present:  present,
		})
		if err != nil {
			currentState.state = availabilityFailed
			return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("serialize bundle availability response", err))
		}

		currentState.state = availabilityCompleted
		return phases.FillResult(result, [][]byte{append([]byte{phases.BundleAvailabilityResponse}, response...)}, 0, true, false, nil)

	case availabilityCompleted:
		return phases.FillResult(result, nil, 0, true, true, apperr.New("bundle availability phase already completed"))
	case availabilityFailed:
		return phases.FillResult(result, nil, 0, false, true, apperr.New("bundle availability phase failed"))
	default:
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid bundle availability state"))
	}
}

func availabilityCheckSize(tag byte, payloadLen int) bool {
	return tag == phases.BundleAvailabilityRequest && payloadLen > 0 && payloadLen <= 128
}
