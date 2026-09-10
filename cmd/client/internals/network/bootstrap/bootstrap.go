package bootstrap

import (
	tls "P2Chat/cmd/client/internals/network/client_tls"
	"P2Chat/cmd/client/internals/network/client_tor"
	"P2Chat/cmd/client/internals/network/connection"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"context"
	"net"
	"strconv"
	"time"
)

// Initialize all the connection with the server (TLS + TOR)
func InitializeServerConn(address string, port int) (connManager *connection.ConnectionManager, binding []byte, err error) {

	// TOR connection
	dialer, torObj, err := client_tor.InitializeTor()
	if err != nil {
		p2log.Error("Error, TOR initialization during server connection, error : ", err)
		return nil, nil, apperr.Wrap("Error, TOR initialization during server connection, error : ", err)
	}
	torConn, err := client_tor.EstablishTor(dialer, address, port)
	if err != nil {
		p2log.Error("Error during server connection, errror : ", err)
		torObj.Close()
		return nil, nil, apperr.Wrap("Error during server connection, errror : ", err)
	}
	p2log.Info("Tor connection with the server initialized with success ✅")

	// TLS connection over TOR
	tlsConn, err := tls.TLSonTor(torConn)
	if err != nil {
		p2log.Error("Error, TLS initialization during server connection, error : ", err)
		torConn.Close()
		torObj.Close()
		return nil, nil, apperr.Wrap("Error, TLS initialization during server connection, error : ", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		torObj.Close()
		return nil, nil, apperr.Wrap("server TLS handshake", err)
	}
	state := tlsConn.ConnectionState()
	binding, err = state.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		tlsConn.Close()
		torObj.Close()
		return nil, nil, apperr.Wrap("export server TLS binding", err)
	}
	p2log.Info("TLS connection over TOR with the server initialized with success ✅")

	connManagerScheme, err := Wrapper(tlsConn, torObj)
	if err != nil {
		p2log.Error("error during the connection manager creation : ", err)
		tlsConn.Close()
		torObj.Close()
		return nil, nil, apperr.Wrap("error during the connection manager creation", err)
	}

	connManagerScheme.Conn.Endpoint = net.JoinHostPort(address, strconv.Itoa(port))
	return connManagerScheme, binding, nil

}
