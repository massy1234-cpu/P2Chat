package session

import (
	"sync"
	"sync/atomic"
	"github.com/hashicorp/yamux"
)

type SingleSession struct {
	ID           uint32
	Stream       *yamux.Stream
	Incoming     chan []byte
	Outgoing     chan []byte
	DeadSessions chan<- uint32
	Once         sync.Once
	Done         chan struct{}
	DummyBase    atomic.Int64
	Handler      func(*SingleSession,[]byte)
}
