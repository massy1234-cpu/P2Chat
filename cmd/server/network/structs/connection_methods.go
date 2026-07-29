package structs

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
		sess := NewSession(ID, stream)
		sess.Handler = c.SessionHandler
		c.ActiveSessions.Store(ID, sess)
	}
}

func (c *Connection) ReleaseSession(session *Session) {
	_, loaded := c.ActiveSessions.LoadAndDelete(session.ID)
	if !loaded {
		return
	}
	c.ReleaseID(session.ID)
	session.Close()
}

func (c *Connection) CloseAllSessions() {
	c.ActiveSessions.Range(func(key any, value any) bool {
		c.ReleaseSession(value.(*Session))
		return true
	})
}

func (c *Connection) Close() {
	c.Once.Do(func() {
		close(c.Done)
		c.MasterSession.Close()
		c.CloseAllSessions()
	})
}
