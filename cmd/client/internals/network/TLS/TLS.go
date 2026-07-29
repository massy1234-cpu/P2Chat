package tls

import (
	"P2Chat/cmd/client/internals/network/structs"
	"P2Chat/cmd/client/internals/network/tor"
	"P2Chat/cmd/client/internals/network/wrapper"
	"P2Chat/pkg/apperr"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
)

// initialize the TLS connection and return a ConnectionManager type
func ServerInitialize(addr string) (connectionScheme *structs.ConnectionManager, err error) {

	// set the TLS configuration
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion:        tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	// Bootstrap Tor + create dialer
	dialer, torObj, err := tor.InitializeTor()
	if err != nil {
		return nil, apperr.Wrap("error initializing Tor", err)
	}

	// parse address (host:port)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, apperr.Wrap("invalid server address", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, apperr.Wrap("invalid server port", err)
	}

	// establish a Tor connection to the server
	torConn, err := tor.EstablishTor(dialer, strings.TrimSpace(host), port)
	if err != nil {
		return nil, apperr.Wrap("error establishing Tor connection", err)
	}

	// wrap the Tor connection with TLS (PQ/T hybrid)
	tlsConn := tls.Client(torConn, config)

	// wrap with yamux and return ConnectionManager
	connectionScheme = wrapper.Wrapper(tlsConn, torObj)
	if connectionScheme == nil {
		return nil, apperr.New("failed to wrap connection")
	}

	return connectionScheme, nil
}
