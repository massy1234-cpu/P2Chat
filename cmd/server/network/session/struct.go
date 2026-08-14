package session

import (
	"P2Chat/cmd/server/network/phases"
	"github.com/hashicorp/yamux"
	"sync"
	"sync/atomic"
)

type SingleSession struct {
	ID           uint32
	Tag          string
	Stream       *yamux.Stream
	Incoming     chan []byte
	Outgoing     chan []byte
	DeadSessions chan<- uint32
	Once         sync.Once
	Done         chan struct{}
	DummyBase      atomic.Int64
	Handler        func(byteCode byte, msg []byte, state *any) *phases.Result
	phaseState     any
	WaitGroup      sync.WaitGroup
	NotTransmitted atomic.Int64
	StopRead       chan struct{}
}
