package loadreport

import (
	pow "P2Chat/cmd/server/internals/network/PoW"
	"P2Chat/pkg/apperr"
	"sync/atomic"
)

var numberOfClients *atomic.Uint64 = nil

// Init wires the load report to the registry's live client counter. Must be
// called once at startup. Calling it twice replaces the binding (useful for
// tests).
func Init(atomic *atomic.Uint64) {
	numberOfClients = atomic
}

// LoadReport picks a difficulty level for the PoW based on the number of
// currently connected clients. Returns an error if Init was never called so
// that callers abort instead of silently using a default.
func LoadReport() (pow.Level, error) {
	if numberOfClients == nil {
		return 0, apperr.New("load report not initialized: call loadreport.Init first")
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