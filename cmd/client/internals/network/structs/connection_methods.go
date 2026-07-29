package structs


import "github.com/hashicorp/yamux"


// check if there is an int available for the assignment
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


// this function have to be called from the session before it ends
func (c *Connection) ReleaseID(number uint32) {
	c.mu.Lock()
	c.freeIDs = append(c.freeIDs, number)
	c.mu.Unlock()
}


// a function that listen on loop packets from the server that are NOT caught from a session
// so the packet needs another session in order to be handled. so accept only packet from stream not opened in the client
func (c *Connection) Listener() {
	for {
		// this block the function in order to wait a new packet from the server not handled 
		stream, err := c.MasterSession.AcceptStream()

		if err != nil {
			return
		}

		// create the new session and store in the sync.Map
		c.NewSession(stream)
	}
}

// helper function for Listener
func (c *Connection) NewSession(stream *yamux.Stream) *SingleSession {
	// wrap the stream inside a Session struct with his buffer for recreate a indipedente connection
	ID := c.NextID()
	sess := NewSession(ID, stream, c.GlobalOut) // this cannot pass the tag because i have to read the payload, i will do in a helper function
	c.ActiveSessions.Store(ID, sess)
	return sess
}


// terminate the session, release his ID, remove the session from the AciveSessions map and close the connection
// no need Once cause there is NO concurrency 
func (c *Connection) ReleaseSession(session *SingleSession) {
	// thread-safe
	_,loaded := c.ActiveSessions.LoadAndDelete(session.ID)
	if !loaded {
		return
	}
	c.ReleaseID(session.ID)
	session.Close()
}

func (c *Connection) CloseAllSessions() {
	c.ActiveSessions.Range(func(key any, value any) bool {
		c.ReleaseSession(value.(*SingleSession))
		return true
	})
}


// close the connection and all the sessions
func (c *Connection) Close() {	
	c.Once.Do(func() {
		close(c.Done)
		c.MasterSession.Close()
		c.CloseAllSessions()
	})
}