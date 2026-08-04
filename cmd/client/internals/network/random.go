package network

import (
	"crypto/rand"
	"math/big"
)

// return a random integer between 0 and max, used for the padding and the delays
func CryptoInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}