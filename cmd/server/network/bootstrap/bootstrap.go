package bootstrap

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/network/client"
	"P2Chat/pkg/apperr"
	"net"
)

// ListenClients is the accept loop: get the registry of clients and stay in
// listen, wait for clients to connect and create a new client on each connection
func ListenClients(listenHandle net.Listener, registry *client.RegistryClients) error {
	if listenHandle == nil {
		p2log.Error("listen handler is nil")
		return apperr.New("listen handler is nil")
	}

	for {
		conn, err := listenHandle.Accept()
		if err != nil {
			p2log.Error("Incoming connection error: ", err)
			continue
		}

		clientScheme := client.NewClient(conn, registry.DeadClients)
		if clientScheme == nil {
			p2log.Error("error creating the client, connection dropped")
			conn.Close()
			continue
		}
		registry.AddClient(clientScheme)
	}
}