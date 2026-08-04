package wrapper

import (
	"P2Chat/cmd/client/internals/network/connection"
	"P2Chat/cmd/client/internals/p2log"
	"net"
	"os"
	"time"
	"github.com/cretz/bine/tor"
	"github.com/hashicorp/yamux"
)

// wrap the connection in a struct that can handle sessions
func Wrapper(netConn net.Conn,tor *tor.Tor) ( connectionManager *connection.ConnectionManager ) {

	if netConn == nil {
		return nil
	}

	// set settings for father connection and also all the other session
	config := yamux.DefaultConfig()
	config.KeepAliveInterval = 15 * time.Second			// 512 KB
	config.MaxStreamWindowSize = 512 * 1024
	config.LogOutput = os.Stdout


	// wrap the connection with yamux
	session, err := yamux.Client(netConn,config)
	if err != nil {
		return nil
	}

	var globalOut chan<- []byte
	globalOut = make(chan []byte, 128)

	connectionScheme := connection.NewConnection(globalOut,session)

	p2log.Debug("wrapper created")

	connectionManager, err = connection.NewConnectionManager(connectionScheme, tor, globalOut)
	if err != nil {
		return nil
	}

	go connectionManager.CheckConnection()

	return connectionManager
}