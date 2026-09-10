package phases

import (
	"P2Chat/pkg/apperr"
	"time"
)

type Result struct {
	Replies      [][]byte
	NextDeadline time.Duration
	Completed    bool
	CloseStream  bool
	Err          error
}

func StripTag(msg []byte, expected byte) ([]byte, bool) {
	if len(msg) < 1 || msg[0] != expected {
		return nil, false
	}
	return msg[1:], true
}

func FillResult(result *Result, replies [][]byte, nextDeadline time.Duration, completed bool, closeStream bool, err error) *Result {
	// every waiting state must have an idle timeout: default to 30s if the
	// caller did not set a specific one (see AGENTS.md)
	if nextDeadline == 0 {
		nextDeadline = 30 * time.Second
	}
	result.Replies = replies
	result.NextDeadline = nextDeadline
	result.Completed = completed
	result.CloseStream = closeStream
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
		return nil, FillResult(result, nil, 0, false, true, apperr.New("phase state is nil"))
	}

	if !checkSize(byteCode, len(msg)) {
		return nil, FillResult(result, nil, 0, false, true, apperr.New("phase received a payload with invalid size"))
	}

	if *phaseState == nil {
		return nil, nil
	}

	currentState, ok := (*phaseState).(*T)
	if !ok || currentState == nil {
		return nil, FillResult(result, nil, 0, false, true, apperr.New("phase received an invalid state"))
	}

	return currentState, nil
}
