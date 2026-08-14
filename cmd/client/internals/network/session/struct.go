package session

import (
	"P2Chat/cmd/client/internals/network/phases"
	"sync"
	"sync/atomic"
	"github.com/hashicorp/yamux"
)

type SingleSession struct {
	ID           uint32
	Tag          string
	Stream       *yamux.Stream
	Incoming     chan []byte
	Outgoing     chan []byte
	GlobalOut    chan<- []byte
	DeadSessions chan<- uint32
	Once         sync.Once
	Done         chan struct{}
	DummyBase    atomic.Int64
	Handler		 func(byteCode byte,msg []byte,state *any) *phases.Result 		// linked to the correct protocol to handle
	phaseState	 any												// contains the struct that keep in memory the state of the phase
	WaitGroup	 sync.WaitGroup
	StopRead	 chan struct{}
	StopDummy	 chan struct{}
}