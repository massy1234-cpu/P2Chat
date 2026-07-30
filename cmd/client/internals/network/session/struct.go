package session

import (
	"sync"
	"sync/atomic"
	"github.com/hashicorp/yamux"
)

type SingleSession struct {
	ID        uint32
	Tag       string
	Stream    *yamux.Stream
	Incoming  chan []byte
	Outgoing  chan []byte
	GlobalOut chan<- []byte
	Once      sync.Once
	Done      chan struct{}
	DummyBase atomic.Int64
}

func NewSession(ID uint32, stream *yamux.Stream, globalOut chan<- []byte) *SingleSession {
	return &SingleSession{
		ID:        ID,
		Tag:       "",
		Stream:    stream,
		Incoming:  make(chan []byte),
		Outgoing:  make(chan []byte),
		GlobalOut: globalOut,
		Done:      make(chan struct{}),
	}
}