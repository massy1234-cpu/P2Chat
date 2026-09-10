package connection

import (
	"P2Chat/cmd/server/internals/network/session"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/yamux"
)

type Connection struct {
	Authed          *atomic.Bool
	Auth            atomic.Pointer[AuthenticatedUser]
	LoginInProgress atomic.Pointer[session.SingleSession]
	Identified      atomic.Bool
	Binding         []byte
	MasterSession   *yamux.Session
	ActiveSessions  sync.Map
	DeadSessions    chan uint32
	nextID          uint32
	freeIDs         []uint32
	mu              sync.Mutex
	Once            sync.Once
	Done            chan struct{}
	SessionHandler  func(*session.SingleSession, []byte)
	SessionStop     chan struct{}
}
