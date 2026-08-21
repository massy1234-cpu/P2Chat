package connection

import (
	"P2Chat/cmd/server/network/session"
	"sync"
	"github.com/hashicorp/yamux"
)

type Connection struct {
	MasterSession  *yamux.Session
	ActiveSessions sync.Map
	DeadSessions   chan uint32
	nextID         uint32
	freeIDs        []uint32
	mu             sync.Mutex
	Once           sync.Once
	Done           chan struct{}
	SessionHandler func(*session.SingleSession, []byte)
}
