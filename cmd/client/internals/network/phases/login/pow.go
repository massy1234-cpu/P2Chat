package login

import (
	pow "P2Chat/cmd/client/internals/network/PoW"
	powproto "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	"P2Chat/pkg/apperr"
	"context"
	"encoding/binary"
	"google.golang.org/protobuf/proto"
	"time"
)

func decodeChallenge(msg []byte) (*powproto.Challenge, error) {
	challenge := &powproto.Challenge{}
	if err := proto.Unmarshal(msg, challenge); err != nil {
		return nil, err
	}
	if challenge.Level < 1 || challenge.Level > 5 || len(challenge.Salt) != 16 || len(challenge.Mac) != 32 {
		return nil, apperr.New("invalid PoW parameters")
	}
	return challenge, nil
}

func SolveChallenge(ctx context.Context, msg []byte) ([]byte, error) {
	challenge, err := decodeChallenge(msg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	nonce, err := pow.SolveContext(ctx, challenge)
	if err != nil {
		return nil, err
	}
	return binary.BigEndian.AppendUint64(nil, nonce), nil
}
