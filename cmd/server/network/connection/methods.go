package connection

import (
	"P2Chat/cmd/server/network/dispatcher"
	"P2Chat/cmd/server/network/phases"
	"P2Chat/cmd/server/network/session"
)

// return the next available ID for a session, reuse the freed IDs if any
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

// put back the ID in the pool for reuse it
func (c *Connection) ReleaseID(number uint32) {
	c.mu.Lock()
	c.freeIDs = append(c.freeIDs, number)
	c.mu.Unlock()
}

// accept the streams from the master session and create a new session with the dispatcher for each one
func (c *Connection) Listener() {
	for {
		stream, err := c.MasterSession.AcceptStream()
		if err != nil {
			return
		}
		ID := c.NextID()
		sess := session.NewSession(ID, stream, c.DeadSessions)
		c.AssignHandler(sess, ID)
	}
}

// AssignHandler attaches the generic dispatcher before the session starts.
func (c *Connection) AssignHandler(sess *session.SingleSession, ID uint32) {
	sess.Handler = func(byteCode byte, msg []byte, state *any) *phases.Result {
		handler, err := dispatcher.Dispatcher(byteCode)
		if err != nil {
			return phases.FillResult(&phases.Result{}, nil, 0, false, true, err)
		}

		sess.Handler = handler
		return handler(byteCode, msg, state)
	}

	c.ActiveSessions.Store(ID, sess)
	sess.Init()
}

// remove the session from the connection and close it
func (c *Connection) ReleaseSession(sess *session.SingleSession) {
	_, loaded := c.ActiveSessions.LoadAndDelete(sess.ID)
	if !loaded {
		return
	}
	c.ReleaseID(sess.ID)
	sess.Close()
}

// close all the active sessions of the connection
func (c *Connection) CloseAllSessions() {
	c.ActiveSessions.Range(func(key any, value any) bool {
		c.ReleaseSession(value.(*session.SingleSession))
		return true
	})
}

// start the goroutines of the connection
func (c *Connection) Init() {
	go c.Listener()
	go c.CheckDeadSessions()
	go c.CheckConnection()
}

// goroutine that read the dead sessions chan and release them from the connection
func (c *Connection) CheckDeadSessions() {
	for {
		select {
		case <-c.Done:
			return
		case ID := <-c.DeadSessions:
			value, loaded := c.ActiveSessions.Load(ID)
			if loaded {
				c.ReleaseSession(value.(*session.SingleSession))
			}
		}
	}
}

// watchdog that close the connection if the master session is closed
func (c *Connection) CheckConnection() {
	select {
	case <-c.Done:
		return
	case <-c.MasterSession.CloseChan():
		c.Close()
	}
}

// close the connection, the master session and all the active sessions
func (c *Connection) Close() {
	c.Once.Do(func() {
		close(c.Done)
		c.MasterSession.Close()
		c.CloseAllSessions()
	})
}

// return true if the connection is already closed
func (c *Connection) IsClosed() bool {
	select {
	case <-c.Done:
		return true
	default:
		return false
	}
}
