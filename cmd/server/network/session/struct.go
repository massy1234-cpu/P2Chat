package session

import (
	"sync"
	"github.com/hashicorp/yamux"
)

type SingleSession struct {
	ID       uint32
	Stream   *yamux.Stream
	Incoming chan []byte
	Outgoing chan []byte
	Once     sync.Once
	Done     chan struct{}
}

func NewSession(ID uint32, stream *yamux.Stream) *SingleSession {
	return &SingleSession{
		ID:       ID,
		Stream:   stream,
		Incoming: make(chan []byte),
		Outgoing: make(chan []byte),
		Done:     make(chan struct{}),
	}
}
