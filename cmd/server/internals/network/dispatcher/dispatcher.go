package dispatcher

import (
	"P2Chat/cmd/server/internals/network/phases"
	"P2Chat/pkg/apperr"
	"sync"
)

type Handler func(byteCode byte, msg []byte, state *any) *phases.Result

// registry_handler is the shared, thread-safe bytecode → handler map. Reads
// and writes can happen concurrently from any goroutine, so a sync.Map is
// used instead of a plain map + mutex.
var registry_handler sync.Map

// RegistryByteCode binds a bytecode to its handler. Safe to call concurrently
// from package init() functions or from an explicit setup phase.
func RegistryByteCode(byteCode byte, h Handler) error {
	registry_handler.Store(byteCode, h)
	return nil
}

// Dispatcher returns the handler registered for the given bytecode, or an
// error if no handler is bound. Safe to call concurrently.
func Dispatcher(byteCode byte) (Handler, error) {
	v, ok := registry_handler.Load(byteCode)
	if !ok {
		return nil, apperr.New("bytecode not correct for any phase")
	}
	return v.(Handler), nil
}
