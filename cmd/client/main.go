package main

import (
	"P2Chat/cmd/client/internals/network/bootstrap"
	"P2Chat/cmd/client/internals/p2chat_errors"
	"P2Chat/cmd/client/internals/p2log"
	"time"
)

func main() {
	// init the connection to the server (TOR + TLS)
	connManager, err := bootstrap.InitializeServerConn("151.64.101.30", 9000)
	if err != nil {
		p2log.Error("error initializing the server connection: ", err)
		return
	}
	defer connManager.Close()

	go p2chat_errors.Watchdog(connManager)

	p2log.Debug("tor initialized correctly")

	p2log.Debug("registration phase initialized correctly")
	
	// start the registration phase (token request): the router drives the state
	// machine (challenge -> PoW -> blind signature) automatically
	if err := connManager.Conn.Registration(); err != nil {
		p2log.Error("error during the registration phase: ", err)
		connManager.Close()
		return
	}

	// wait for the phase to complete, then shut down the connection
	p2log.Info("registration check finished, closing connection")

	time.Sleep(10 * time.Second)

	connManager.Close()
}