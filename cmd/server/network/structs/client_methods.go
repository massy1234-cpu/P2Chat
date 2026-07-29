package structs

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

func NewClient(connection net.Conn) *Client {
	if connection == nil {
		return nil
	}

	config := yamux.DefaultConfig()
	config.KeepAliveInterval = 15 * time.Second
	config.MaxStreamWindowSize = 512 * 1024
	config.LogOutput = os.Stdout

	session, err := yamux.Server(connection, config)
	if err != nil {
		return nil
	}

	connScheme := &Connection{
		MasterSession:  session,
		ActiveSessions: sync.Map{},
		Done:           make(chan struct{}),
		SessionHandler: clientDispatch,
	}

	go connScheme.Listener()

	return &Client{
		Conn: connScheme,
	}
}

func clientDispatch(sess *Session, msg []byte) {
	byteCode := msg[0]
	msg = msg[1:]

	switch byteCode {
	case  :
		// TODO: registration handler
	}
}
