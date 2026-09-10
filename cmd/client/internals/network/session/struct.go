package session

import (
	"P2Chat/cmd/client/internals/network/phases"
	"sync"
	"sync/atomic"
	"github.com/hashicorp/yamux"
)

type SingleSession struct {
	ID           uint32					// identificator inside the MAP
	Tag          string					// what the session do 
	Stream       *yamux.Stream			// network channel
	Incoming     chan []byte			// Listener
	Outgoing     chan []byte			// Writer
	Local		 chan []byte			// for router
	Events       chan []byte			// for the orchestrator, per-session, created by the connection
	DeadSessions chan<- uint32			// for allert the connection struct and delete the session
	Once         sync.Once
	Done         chan struct{}
	DummyBase    atomic.Int64
	Handler		 func(byteCode byte,msg []byte,state *any) *phases.Result 		// linked to the correct protocol to handle
	phaseState	 any												// contains the struct that keep in memory the state of the phase
	WaitGroup	 sync.WaitGroup
	StopRead	 chan struct{}
	StopDummy	 chan struct{}
}