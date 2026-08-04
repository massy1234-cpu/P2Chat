package loadreport

import (
	pow "P2Chat/cmd/server/network/PoW"
	"sync/atomic"
)

var numberOfClients *atomic.Uint64 = nil

// connect the atomic counter of the clients with the load report, call this only once at the start
func Init(atomic *atomic.Uint64) {
	numberOfClients = atomic
}

// i estimate the levels for my server (very cheap server with low ram 8GB)
func LoadReport() pow.Level {
	if numberOfClients == nil {
		return 5
	}

	clients := numberOfClients.Load()

	switch {
	case clients < 50:
		return pow.Level1
	case clients < 150:
		return pow.Level2
	case clients < 300:
		return pow.Level3
	case clients < 500:
		return pow.Level4
	default:
		return pow.Level5
	}
}