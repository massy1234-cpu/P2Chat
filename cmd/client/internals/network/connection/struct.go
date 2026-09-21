package connection

import (
	"github.com/cretz/bine/tor"
	"github.com/hashicorp/yamux"
	"sync"
)

type Connection struct {
	Endpoint       string
	ServerID       []byte
	MasterSession  *yamux.Session
	ActiveSessions sync.Map
	DeadSessions   chan uint32
	nextID         uint32
	freeIDs        []uint32
	mu             sync.Mutex
	Once           sync.Once
	Done           chan struct{}
}

type ConnectionManager struct {
	Conn *Connection
	Tor  *tor.Tor
	Once sync.Once
	Done chan struct{}
}
