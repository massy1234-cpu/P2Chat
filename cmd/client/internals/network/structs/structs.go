package structs

import (
	"sync"
	"github.com/hashicorp/yamux"
)

// SingleSession handle the single logical connection with yamux
type SingleSession struct {
	ID       uint32
	Tag      string
	Stream   *yamux.Stream
	Incoming chan []byte
	Outgoing chan []byte
	Done     chan struct{}
}


// Connection handle all the logic connection
type Connection struct {
	MasterSession  *yamux.Session
	ActiveSessions sync.Map
	ChanPool       *sync.Pool
}


// ConnectionManager handle all the connections, have the connection with the server and have 
// a globalOut that is a chan where all the process put messages that interest the entire application 
type ConnectionManager struct {
	conn       *Connection
	globalOut  chan []byte // Il canale verso l'esterno dove manda solo il risultato finale
	done       chan struct{}
}