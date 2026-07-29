package structs

import (
	"sync"
	"github.com/hashicorp/yamux"
)

type Client struct {
	ID     []byte				// ID for identify the user in the server
	Authed bool
	Conn   *Connection
}

type Session struct {
	ID        uint32			// ID for identify the session in the sync.Map
	Stream    *yamux.Stream
	Incoming  chan []byte
	Outgoing  chan []byte
	Once      sync.Once
	Done      chan struct{}
	Handler   func(*Session, []byte)
}

type Connection struct {
	MasterSession  *yamux.Session
	ActiveSessions sync.Map
	nextID        uint32
	freeIDs       []uint32
	mu            sync.Mutex
	Once          sync.Once
	Done          chan struct{}
	SessionHandler func(*Session, []byte)
}
