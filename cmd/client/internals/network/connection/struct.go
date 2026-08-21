package connection

import (
	"sync"
	"github.com/cretz/bine/tor"
	"github.com/hashicorp/yamux"
)

type Connection struct {
	MasterSession  *yamux.Session
	ActiveSessions sync.Map
	DeadSessions   chan uint32
	nextID         uint32
	freeIDs        []uint32
	mu             sync.Mutex
	GlobalOut      chan []byte
	Once           sync.Once
	Done           chan struct{}
}

type ConnectionManager struct {
	Conn      *Connection
	Tor       *tor.Tor
	GlobalOut chan []byte
	Once      sync.Once
	Done      chan struct{}
}