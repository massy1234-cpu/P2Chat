package tls

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/network/client"
	//connpkg "P2Chat/cmd/server/network/connection"
	"crypto/tls"
	"net"
)

// listen for TLS connections and for each one create a new client in the registry
func ServerListener() (registry client.RegistryClients,connection net.Conn, err error) {
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion:        tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	tlsConn, err := tls.Listen("tcp", ":8443", config)

	for {
		connection, err := tlsConn.Accept()
		if err != nil {
			p2log.Error("connection incoming error, not accepted, closed")
			continue
		}
		
		registry.AddClient(client)
	}
}
