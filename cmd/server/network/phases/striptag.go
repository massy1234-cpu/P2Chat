package phases

import "time"

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
	result.Replies = replies
	result.NextDeadline = nextDeadline
	result.Completed = completed
	result.CloseStream = closeStream
	result.Err = err

	return result
}
