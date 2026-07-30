package tls

import (
	connpkg "P2Chat/cmd/server/network/connection"
	"crypto/tls"
	"net"
)

func ServerListener() (connection net.Conn, err error) {
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
			continue
		}
		go connpkg.NewClient(connection, nil)
	}
}
