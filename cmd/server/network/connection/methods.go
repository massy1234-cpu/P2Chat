package connection

import (
	"net"
	"os"
	"sync"
	"time"
	"P2Chat/cmd/server/network/session"
	"github.com/hashicorp/yamux"
)

func NewClient(connection net.Conn, handler func(*session.SingleSession, []byte)) *Client {
	if connection == nil {
		return nil
	}

	config := yamux.DefaultConfig()
	config.KeepAliveInterval = 15 * time.Second
	config.MaxStreamWindowSize = 512 * 1024
	config.LogOutput = os.Stdout

	sess, err := yamux.Server(connection, config)
	if err != nil {
		return nil
	}

	connScheme := &Connection{
		MasterSession:  sess,
		ActiveSessions: sync.Map{},
		Done:           make(chan struct{}),
		SessionHandler: handler,
	}

	connScheme.Init()

	return &Client{
		Conn: connScheme,
	}
}

func (c *Connection) NextID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.freeIDs) > 0 {
		id := c.freeIDs[len(c.freeIDs)-1]
		c.freeIDs = c.freeIDs[:len(c.freeIDs)-1]
		return id
	}
	c.nextID++
	return c.nextID
}

func (c *Connection) ReleaseID(number uint32) {
	c.mu.Lock()
	c.freeIDs = append(c.freeIDs, number)
	c.mu.Unlock()
}

func (c *Connection) Listener() {
	for {
		stream, err := c.MasterSession.AcceptStream()
		if err != nil {
			return
		}
		ID := c.NextID()
		sess := session.NewSession(ID, stream)
		sess.Init()
		c.ActiveSessions.Store(ID, sess)
	}
}

func (c *Connection) ReleaseSession(sess *session.SingleSession) {
	_, loaded := c.ActiveSessions.LoadAndDelete(sess.ID)
	if !loaded {
		return
	}
	c.ReleaseID(sess.ID)
	sess.Close()
}

func (c *Connection) CloseAllSessions() {
	c.ActiveSessions.Range(func(key any, value any) bool {
		c.ReleaseSession(value.(*session.SingleSession))
		return true
	})
}

func (c *Connection) Init() {
	go c.Listener()
}

func (c *Connection) Close() {
	c.Once.Do(func() {
		close(c.Done)
		c.MasterSession.Close()
		c.CloseAllSessions()
	})
}
