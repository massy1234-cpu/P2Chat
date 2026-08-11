package loadreport

import (
	pow "P2Chat/cmd/server/network/PoW"
	"P2Chat/pkg/apperr"
	"sync/atomic"
)

var numberOfClients *atomic.Uint64 = nil

// connect the atomic counter of the clients with the load report, call this only once at the start
func Init(atomic *atomic.Uint64) {
	numberOfClients = atomic
}

// i estimate the levels for my server (very cheap server with low ram 8GB)
// if the counter is not initialized it returns an error, the caller must abort
func LoadReport() (pow.Level, error) {
	if numberOfClients == nil {
		return pow.Level5, apperr.New("load report not initialized")
	}

	clients := numberOfClients.Load()

	switch {
	case clients < 50:
		return pow.Level1, nil
	case clients < 150:
		return pow.Level2, nil
	case clients < 300:
		return pow.Level3, nil
	case clients < 500:
		return pow.Level4, nil
	default:
		return pow.Level5, nil
	}
}