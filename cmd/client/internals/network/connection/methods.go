package connection

import (
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/network/session"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"

	"github.com/hashicorp/yamux"
)

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

func (c *Connection) NewSession(stream *yamux.Stream) *session.SingleSession {
	ID := c.NextID()
	sess := session.NewSession(ID, stream, c.GlobalOut)
	sess.Init()
	p2log.Debug("connection listener, new session ID:", ID)
	c.ActiveSessions.Store(ID, sess)
	return sess
}

func (c *Connection) ReleaseSession(sess *session.SingleSession) {
	_, loaded := c.ActiveSessions.LoadAndDelete(sess.ID)
	if !loaded {
		return
	}
	p2log.Debug("session released, ID:", sess.ID)
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
	p2log.Debug("connection init")
}

func (c *Connection) Close() {
	c.Once.Do(func() {
		p2log.Debug("connection closing")
		close(c.Done)
		c.MasterSession.Close()
		c.CloseAllSessions()
	})
}

func (c *Connection) Registration() error {
	newStream, err := c.MasterSession.OpenStream()
	if err != nil {
		p2log.Error("error during registration phase", err)
		return apperr.Wrap("error during the registration phase: ", err)
	}

	sess := c.NewSession(newStream)
	phases.RequestTokenRegistration(sess)

	return nil
}

func (manager *ConnectionManager) Close() {
	manager.Once.Do(func() {
		manager.Conn.Close()
		manager.Tor.Close()
		close(manager.GlobalOut)
		close(manager.Done)
	})
}
