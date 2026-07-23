package network


import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"crypto/tls"
	"fmt"
	"net"
)


// initialize the listener for TLS connections
func InitializeTLS(certificate tls.Certificate) ( error ) {

	// specify to use ML-KEM + X25519 curve
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS13,
	}

	// create the TLS connection with the client with TCP ( SYN/ACK )
	// this accept only NEW connections
	listener,err := tls.Listen("tcp",":8080",config)
	if err != nil {
		listener.Close()
		return apperr.Wrap("error with the listener ",err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			p2log.Error(fmt.Sprint("error in the connection number ",conn.RemoteAddr()),err)
		}
		p2log.Info("new connection accepted",conn.RemoteAddr(),err)
		go handleNewConnection(conn.(*tls.Conn))
	}

}


// handle new connections
func handleNewConnection(connection net.Conn) error {
	connection.Write([]byte("ciao"))
	return nil
}