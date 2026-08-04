package pow

import (
	proto_struct_pow "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
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
	argonThreads = 1	// no parallelism 
	argonKeyLen  = 32	// same lenght always
)

// create a challenge with the level requested, the level must be adjust in base of the 
// server load in that moment
func Issue(secret []byte, level Level) (*proto_struct_pow.Challenge, error) {
	if _, err := level.params(); err != nil {
		return nil, err
	}

	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}

	c := proto_struct_pow.Challenge{
		Timestamp: time.Now().Unix(),
		Salt:      salt[:],
		Level:     uint32(level),
	}
	c.Mac = mac(secret, &c)
	return &c, nil
}


// this bond all the challenge struct with the secret
// is a measure for avoid manomission from the client
func mac(secret []byte, c *proto_struct_pow.Challenge) []byte {
	h := hmac.New(sha256.New, secret)
	var buf [25]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(c.Timestamp))
	copy(buf[8:24], c.Salt)
	buf[24] = byte(c.Level)
	h.Write(buf[:])
	return h.Sum(nil)
}

// create the argon2 hash from the challenge and the nonce
func argonHash(c *proto_struct_pow.Challenge, nonce uint64, p levelParams) []byte {
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], nonce)
	return argon2.IDKey(nonceBytes[:], c.Salt, p.timeCost, p.memoryKB, argonThreads, argonKeyLen)
}

// count the leading zero bits in the hash, the difficulty is based on this number
func CountZeroBits(hash []byte) uint8 {
	var count uint8
	for _, b := range hash {
		if b == 0 {
			count += 8
			continue
		}
		for mask := byte(0x80); mask > 0; mask >>= 1 {
			if b&mask != 0 {
				return count
			}
			count++
		}
		return count
	}
	return count
}

// verify the challenge, first check the mac for avoid manomission and then count the zero bits of the nonce
func Verify(secret []byte, c *proto_struct_pow.Challenge, nonce uint64) bool {
	expected := mac(secret, c)
	if !hmac.Equal(expected, c.Mac) {
		return false
	}

	p, err := Level(c.Level).params()
	if err != nil {
		return false
	}
	return CountZeroBits(argonHash(c, nonce, p)) >= p.difficulty
}