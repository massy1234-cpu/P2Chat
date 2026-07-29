package tls

import (
	"P2Chat/cmd/server/network/structs"
	"crypto/tls"
	"net"
)

func ServerListener() (connection net.Conn,err error) {
	// same configuration of client
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion:        tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	// open the port and wait for clients
	tlsConn, err := tls.Listen("tcp",":8443",config)

	for {
		// accept all the clients and pass the net.Conn to the func helper
		connection,err := tlsConn.Accept()
		if err != nil {
			continue
    	}
		go structs.NewClient(connection)
	}

}