package bootstrap

import (
	"P2Chat/cmd/client/internals/network/connection"
	"P2Chat/pkg/apperr"
	"net"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/hashicorp/yamux"
)

// configure the yamux session and create Connection,ConnectionManager schemes
func Wrapper(tlsConn net.Conn, torObj *tor.Tor) (connManagerScheme *connection.ConnectionManager, err error) {

	config := yamux.DefaultConfig()
	config.KeepAliveInterval = 15 * time.Second
	config.MaxStreamWindowSize = 512 * 1024

	session, err := yamux.Client(tlsConn, config)
	if err != nil {
		return nil, apperr.Wrap("error during the yamux client creation", err)
	}

	connScheme := connection.NewConnection(session)

	connManagerScheme = connection.NewConnectionManager(connScheme, torObj)
	if connManagerScheme == nil {
		return nil, apperr.New("error during the connection manager creation")
	}

	return connManagerScheme, nil
}
