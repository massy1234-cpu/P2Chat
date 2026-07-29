package wrapper

import (
	"P2Chat/cmd/client/internals/network/structs"
	"net"
	"os"
	"sync"
	"time"
	"github.com/cretz/bine/tor"
	"github.com/hashicorp/yamux"
)

// wrap the connection in a struct that can handle sessions
func Wrapper(connection net.Conn,tor *tor.Tor) ( connectionManager *structs.ConnectionManager ) {

	if connection == nil {
		return nil
	}

	// set settings for father connection and also all the other session
	config := yamux.DefaultConfig()
	config.KeepAliveInterval = 15 * time.Second			// 512 KB
	config.MaxStreamWindowSize = 512 * 1024
	config.LogOutput = os.Stdout


	// wrap the connection with yamux
	session, err := yamux.Client(connection,config)
	if err != nil {
		return nil
	}

	// create the Connection
	var globalOut chan<- []byte
	globalOut = make(chan []byte)

	connectionScheme := &structs.Connection{
		MasterSession:		session,
		ActiveSessions: 	sync.Map{},
		Done:				make(chan struct{}),
		GlobalOut:			globalOut,
	}

	go connectionScheme.Listener()

	connectionManager = &structs.ConnectionManager{
		Conn: 		connectionScheme,
		GlobalOut:	globalOut,
		Done:		make(chan struct{}),
	}

	connectionManager.Tor = tor

	return connectionManager
}