package pow

import (
	proto_struct_pow "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/argon2"
)

var (
	ErrNonceExhausted = errors.New("pow: nessuna soluzione trovata entro il limite")
	ErrInvalidLevel   = errors.New("pow: level non valido, deve essere 1-5")
)

type Level uint8

const (
	Level1 Level = 1 // trivial
	Level2 Level = 2 // low
	Level3 Level = 3 // medium
	Level4 Level = 4 // high
	Level5 Level = 5 // maximum
)

type levelParams struct {
	difficulty uint8  // number of zero in the argon KDF
	memoryKB   uint32 // ram
	timeCost   uint32 // iterations
}

var presets = map[Level]levelParams{
	Level1: {difficulty: 8, memoryKB: 8 * 1024, timeCost: 1},    // 8MB, ~1s
	Level2: {difficulty: 9, memoryKB: 16 * 1024, timeCost: 1},   // 16MB, ~3.6s
	Level3: {difficulty: 10, memoryKB: 32 * 1024, timeCost: 1},  // 32MB, ~15s
	Level4: {difficulty: 11, memoryKB: 64 * 1024, timeCost: 2},  // 64MB, ~2.2min
	Level5: {difficulty: 11, memoryKB: 128 * 1024, timeCost: 2}, // 128MB, ~5min
}

// create the levelParams struct in base of the level
func (l Level) params() (levelParams, error) {
	p, ok := presets[l]
	if !ok {
		return levelParams{}, ErrInvalidLevel
	}
	return p, nil
}

const (
	argonThreads = 1       // no parallelism
	argonKeyLen  = 32      // same lenght always
	maxAttempts  = 1 << 24 // covers the worst case (Level5, 24 zero bits)
)

// create the argon2 hash from the challenge and the nonce
func argonHash(c *proto_struct_pow.Challenge, nonce uint64, p levelParams) []byte {
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], nonce)
	return argon2.IDKey(nonceBytes[:], c.Salt[:], p.timeCost, p.memoryKB, argonThreads, argonKeyLen)
}

// count the leading zero bits in the hash, the difficulty is based on this number
func CountZeroBits(hash []byte) uint8 {
	var count uint8

	for _, b := range hash {
		pos := 7
		for pos >= 0 {
			if (b>>pos)&1 != 0 {
				return count
			}
			count++
			pos--
		}
	}

	return count
}

// solve the challenge searching the nonce that create a correct
func Solve(c *proto_struct_pow.Challenge) (uint64, error) {
	return SolveContext(context.Background(), c)
}

func SolveContext(ctx context.Context, c *proto_struct_pow.Challenge) (uint64, error) {
	if c == nil || c.Level < 1 || c.Level > 5 || len(c.Salt) != 16 {
		return 0, ErrInvalidLevel
	}
	p, err := Level(c.Level).params()
	if err != nil {
		return 0, err
	}
	for nonce := uint64(0); nonce < maxAttempts; nonce++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if CountZeroBits(argonHash(c, nonce, p)) >= p.difficulty {
			return nonce, nil
		}
	}
	return 0, ErrNonceExhausted
}
