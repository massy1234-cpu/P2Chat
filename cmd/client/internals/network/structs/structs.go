package structs

import (
	"sync"
	"github.com/cretz/bine/tor"
	"github.com/hashicorp/yamux"
)

// SingleSession handle the single logical connection with yamux
type SingleSession struct {
	ID        		uint32
	Tag       		string
	Stream    		*yamux.Stream
	Incoming  		chan []byte
	Outgoing  		chan []byte
	GlobalOut 		chan<- []byte
	Once      		sync.Once
	Done      		chan struct{}
}

// Connection handle all the logic connection
type Connection struct {
	MasterSession		*yamux.Session    // the physique TLS connection
	ActiveSessions 		sync.Map          // mapping of all the active sessions
	nextID        		uint32
	freeIDs       		[]uint32
	mu            		sync.Mutex
	GlobalOut     		chan<- []byte
	Once      			sync.Once
	Done      			chan struct{}
}

// ConnectionManager handle all the connections, have the connection with the server and have
// a globalOut that is a chan where all the process put messages that interest the entire application
// but is NOT the ConnectionManager that handle the requests for the application, is handled in another upper layer
type ConnectionManager struct {
	Conn      	*Connection
	Tor			*tor.Tor
	GlobalOut	chan<-[]byte   // the connections can only put and NOT read, is for the manager this chan
	Once      	sync.Once
	Done      	chan struct{}
}