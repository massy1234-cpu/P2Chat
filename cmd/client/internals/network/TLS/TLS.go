package TLS

import (
	"P2Chat/cmd/client/internals/network/wrapper"
	"P2Chat/pkg/apperr"
	"crypto/tls"
	"net"
)

// initialize the connection with the server
func TLSConnection(addr string) (connectionScheme *wrapper.Connection,err error) {
	
	// set the TLS configuration
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion:       tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	// create the connection TLS
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return nil, apperr.Wrap("TLS dial", err)
	}

	connectionScheme = wrapper.Wrapper(conn)

	return connectionScheme,nil

}

