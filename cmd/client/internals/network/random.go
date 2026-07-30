package network

import (
	"crypto/rand"
	"math/big"
)

func CryptoInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}