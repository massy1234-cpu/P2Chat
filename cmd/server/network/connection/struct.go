package connection

import (
	"sync"
	"github.com/hashicorp/yamux"
	"P2Chat/cmd/server/network/session"
)

type Client struct {
	ID     []byte
	Authed bool
	Conn   *Connection
}

type Connection struct {
	MasterSession  *yamux.Session
	ActiveSessions sync.Map
	nextID         uint32
	freeIDs        []uint32
	mu             sync.Mutex
	Once           sync.Once
	Done           chan struct{}
	SessionHandler func(*session.SingleSession, []byte)
}
