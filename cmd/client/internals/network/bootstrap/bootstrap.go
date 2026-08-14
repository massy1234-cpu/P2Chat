package bootstrap

import (
	tls "P2Chat/cmd/client/internals/network/client_tls"
	"P2Chat/cmd/client/internals/network/client_tor"
	"P2Chat/cmd/client/internals/network/connection"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
)

// Initialize all the connection with the server (TLS + TOR)
func InitializeServerConn(address string, port int) (connManager *connection.ConnectionManager,err error) {
	
	// TOR connection
	dialer, torObj, err := client_tor.InitializeTor()
	if err != nil {
		p2log.Error("Error, TOR initialization during server connection, error : ",err)
		return nil,apperr.Wrap("Error, TOR initialization during server connection, error : ",err)
	}	
	torConn,err := client_tor.EstablishTor(dialer,address,port)
	if err != nil {
		p2log.Error("Error during server connection, errror : ",err)
		return nil,apperr.Wrap("Error during server connection, errror : ",err)
	}	
	p2log.Info("Tor connection with the server initialized with success ✅")

	// TLS connection over TOR
 	tlsConn,err := tls.TLSonTor(torConn)
	if err != nil {
		p2log.Error("Error, TLS initialization during server connection, error : ",err)
		return nil,apperr.Wrap("Error, TLS initialization during server connection, error : ",err)
	}
	p2log.Info("TLS connection over TOR with the server initialized with success ✅")

	globalChan := make(chan []byte,128)

	connManagerScheme,err := Wrapper(tlsConn,globalChan,torObj)
	if err != nil {
		p2log.Error("error during the connection manager creation : ",err)
		return nil, apperr.Wrap("error during the connection manager creation",err)
	}

	return connManagerScheme,nil

}