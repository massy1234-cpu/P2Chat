package tls

import (
	"crypto/tls"
	"net"
)

// initialize the TLS connection on a TOR connection
func TLSonTor(tor net.Conn) (tlsConn *tls.Conn,err error) {

	// set the TLS configuration
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion:        tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	// wrap the Tor connection with TLS (PQ/T hybrid)
	tlsConn = tls.Client(tor, config)

	return tlsConn,nil
}
