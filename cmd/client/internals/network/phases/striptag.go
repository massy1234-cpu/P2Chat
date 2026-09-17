package phases

import (
	"P2Chat/pkg/apperr"
	"time"
)

type Result struct {
	IntoWire     [][]byte
	NextDeadline time.Duration
	Completed    bool
	CloseStream  bool
	Err          error
	Events       [][]byte
}

var defaultTime time.Duration = time.Second * 30

func StripTag(msg []byte, expected byte) ([]byte, bool) {
	if len(msg) < 1 || msg[0] != expected {
		return nil, false
	}
	return msg[1:], true
}

func FillResult(result *Result, intoWire [][]byte, nextDeadline time.Duration, completed bool, closeStream bool, events [][]byte, err error) *Result {
	result.IntoWire = intoWire
	if nextDeadline == 0 {
		nextDeadline = defaultTime
	}
	result.NextDeadline = nextDeadline
	result.Completed = completed
	result.CloseStream = closeStream
	result.Events = events
	result.Err = err

	return result
}

// GetPhase performs the common controls shared by every phase handler
// (nil phase state, payload size) and converts the universal state to the
// concrete phase state. It returns nil,nil when the state is not initialized
// yet, leaving the struct creation to the handler.
func GetPhase[T any](byteCode byte, msg []byte, phaseState *any, checkSize func(byte, int) bool) (*T, *Result) {
	result := &Result{}

	if phaseState == nil {
		return nil, FillResult(result, nil, 0, false, true, nil, apperr.New("phase state is nil"))
	}

	// check if the message lenght match with the bytecode
	if !checkSize(byteCode, len(msg)) {
		return nil, FillResult(result, nil, 0, false, true, nil, apperr.New("phase received a payload with invalid size"))
	}

	if *phaseState == nil {
		return nil, nil
	}

	currentState, ok := (*phaseState).(*T)
	if !ok || currentState == nil {
		return nil, FillResult(result, nil, 0, false, true, nil, apperr.New("phase received an invalid state"))
	}

	return currentState, nil
}
