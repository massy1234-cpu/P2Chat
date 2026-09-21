package connection

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/internals/network/dispatcher"
	"P2Chat/cmd/server/internals/network/phases"
	getuserbundle "P2Chat/cmd/server/internals/network/phases/get_user_bundle"
	"P2Chat/cmd/server/internals/network/phases/login"
	"P2Chat/cmd/server/internals/network/phases/server_identification"
	"P2Chat/cmd/server/internals/network/session"
	"P2Chat/pkg/apperr"
	"sync/atomic"
	"time"
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
		select {
		// (+1)
		case c.SessionStop <- struct{}{}:
			stream, err := c.MasterSession.AcceptStream()
			if err != nil {
				p2log.Debug("connection listener stopped, master session closed")
				<-c.SessionStop
				return
			}
			ID := c.NextID()
			sess := session.NewSession(ID, stream, c.DeadSessions)
			p2log.Debug("server connection accepted a new stream, ID:", ID)
			c.AssignHandler(sess, ID)
		case <-c.Done:
			return
		}
	}
}

// AssignHandler attaches the generic dispatcher before the session starts.
func (c *Connection) AssignHandler(sess *session.SingleSession, ID uint32) {
	sess.Handler = func(byteCode byte, msg []byte, state *any) *phases.Result {
		if user := c.Auth.Load(); user != nil {
			user.LastSeen.Store(time.Now().Unix())
		}
		switch byteCode {
		case phases.ServerIdentityRequest, phases.RegistrationStart, phases.BundleRegistrationStart:
		case phases.BundleAcquisitionRequest:
			*state = getuserbundle.NewBundleSearched(c.Authed != nil && c.Authed.Load())
		case phases.BundleAvailabilityRequest:
			*state = getuserbundle.NewBundleAvailability(c.Authed != nil && c.Authed.Load())
		case phases.LoginStart, phases.LoginTokenRedemption:
			if !c.Identified.Load() || c.Auth.Load() != nil || !c.LoginInProgress.CompareAndSwap(nil, sess) {
				return phases.FillResult(&phases.Result{}, nil, 0, false, true, apperr.New("login unavailable on this connection"))
			}
			go func() { <-sess.Done; c.LoginInProgress.CompareAndSwap(sess, nil) }()
			*state = &login.LoginServer{Binding: c.Binding, Authenticate: c.Authenticate, AuthenticateAnonymous: c.AuthenticateAnonymous}
		default:
			if c.Authed == nil || !c.Authed.Load() {
				return phases.FillResult(&phases.Result{}, nil, 0, false, true, apperr.New("authentication required"))
			}
		}
		handler, err := dispatcher.Dispatcher(byteCode)
		if err != nil {
			return phases.FillResult(&phases.Result{}, nil, 0, false, true, err)
		}

		sess.Handler = func(tag byte, payload []byte, phaseState *any) *phases.Result {
			result := handler(tag, payload, phaseState)
			if byteCode == phases.LoginStart || byteCode == phases.LoginTokenRedemption {
				if result.Completed || result.Err != nil || result.CloseStream {
					c.LoginInProgress.CompareAndSwap(sess, nil)
				}
			}
			return result
		}
		if byteCode == phases.ServerIdentityRequest {
			*state = &server_identification.IdentificationServer{Binding: c.Binding}
			sess.Handler = func(tag byte, payload []byte, state *any) *phases.Result {
				result := handler(tag, payload, state)
				if result.Err == nil && result.Completed {
					c.Identified.Store(true)
				}
				return result
			}
			return sess.Handler(byteCode, msg, state)
		}
		return sess.Handler(byteCode, msg, state)
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
	sess.ForceClose()

	// (-1)
	<-c.SessionStop
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
	if c.Authed == nil {
		c.Authed = &atomic.Bool{}
	}
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
		c.ClearAuthentication()
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
