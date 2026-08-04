package pow

import (
	proto_struct_pow "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func TestSolveTiming(t *testing.T) {
	if os.Getenv("POW_TIMING") == "1" {
		t.Skip("set POW_TIMING=1 to run the timing benchmark")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	for level := Level1; level <= Level5; level++ {
		challenge := &proto_struct_pow.Challenge{
			Timestamp: time.Now().Unix(),
			Salt:      salt,
			Level:     uint32(level),
		}

		start := time.Now()
		nonce, err := Solve(challenge)
		elapsed := time.Since(start)

		if err != nil {
			t.Errorf("level %d: %v", level, err)
			continue
		}

		t.Logf("Level %d solved: nonce=%d in %s", level, nonce, elapsed)
	}
}
