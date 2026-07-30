package network

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/network/connection"
	"P2Chat/cmd/server/network/phases"
	"P2Chat/cmd/server/network/session"
	"P2Chat/pkg/apperr"
	"crypto/tls"
	"net"
)

func dispatchConnection(sess *session.SingleSession, msg []byte) {
	switch msg[0] {
	case 0x01:
		phases.Registration(sess, msg[1:])
	}
}

func InitializeTLS(cert tls.Certificate) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		return apperr.Wrap("error in server TLS initialization", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			p2log.Error("accept error", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(tlsConn net.Conn) {
	client := connection.NewClient(tlsConn, dispatchConnection)
	if client == nil {
		return
	}
	defer client.Conn.Close()
	<-client.Conn.Done
}
