package connection

import (
	"P2Chat/cmd/client/internals/network/phases"
	bundlereg "P2Chat/cmd/client/internals/network/phases/bundle_reg"
	"P2Chat/cmd/client/internals/network/phases/token_registration"
	session "P2Chat/cmd/client/internals/network/session"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"sync"

	"github.com/cretz/bine/tor"
	"github.com/hashicorp/yamux"
)

type Handler func(byteCode byte, msg []byte, state *any) *phases.Result
type PutOnRouter func()

// --- connection ---
// create a new connection with the yamux session and start its goroutines
func NewConnection(globalOut chan []byte,session *yamux.Session) *Connection {

	connectionScheme := &Connection{
		MasterSession:		session,
		ActiveSessions: 	sync.Map{},
		DeadSessions:		make(chan uint32, 64),
		Done:				make(chan struct{}),
		GlobalOut:			globalOut,
	}

	connectionScheme.Init()

	return connectionScheme
}


// watchdog that close the connection if the master session is closed
func (c *Connection) CheckConnection() {
	select {
	case <- c.Done:
		return
	case <- c.MasterSession.CloseChan():
		p2log.Error("connection with the server lost,closing... ")
		c.Close()
	}
}


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

// create a new session linked with the stream but IT WONT START
// have to be started with Init()
func (c *Connection) NewSession(stream *yamux.Stream) *session.SingleSession {
	ID := c.NextID()
	sess := session.NewSession(ID, stream, c.GlobalOut, c.DeadSessions)
	c.ActiveSessions.Store(ID, sess)

	p2log.Debug("connection listener, new session ID:", ID)
	return sess
}

// remove the session from the connection and close it
func (c *Connection) ReleaseSession(ID uint32) {
	value, loaded := c.ActiveSessions.LoadAndDelete(ID)
	if !loaded {
		return
	}

	// if the session is not closed yet i close it 
	sess := value.(*session.SingleSession)
	if !sess.IsClosed() {
		sess.ForceClose()
	}

	p2log.Debug("session released, ID:", ID)
	c.ReleaseID(ID)
}

// close all the active sessions of the connection
func (c *Connection) CloseAllSessions() {
	c.ActiveSessions.Range(func(key any, value any) bool {
		c.ReleaseSession(key.(uint32))
		return true
	})
}

// start the goroutines of the connection
func (c *Connection) Init() {
	p2log.Debug("connection init")
	go c.CheckDeadSessions()
	go c.CheckConnection()
}

// close the connection, the master session and all the active sessions
func (c *Connection) Close() {
	c.Once.Do(func() {
		p2log.Debug("connection closing")
		close(c.Done)
		c.MasterSession.Close()
		c.CloseAllSessions()
	})
}


// goroutine that read the dead sessions chan and release them from the connection
func (c *Connection) CheckDeadSessions() {
	for {
		select {
		case <-c.Done:
			return
		case msg := <-c.DeadSessions:
			c.ReleaseSession(msg)
		}
	}
}

// open a new stream for the registration phase and start the token request flow
func (c *Connection) TokenRegistration() error {
	newStream, err := c.MasterSession.OpenStream()
	if err != nil {
		p2log.Error("error during registration phase", err)
		return apperr.Wrap("error during the registration phase: ", err)
	}

	p2log.Info("opened new stream for the registration phase")

	sess := c.NewSession(newStream)
	sess.Tag = "Registration token request"
	sess.Handler = token_registration.Handler
	sess.Init()

	p2log.Info("registration session started, sending RegisterTokenReq")
	sess.PutOutgoing([]byte{phases.RegisterTokenReq})	// request the registration token to the server  

	return nil
}

// open a new stream for the bundle upload phase and start the flow. It returns
// the session so the orchestrator can inject local events (token, nickname,
// bundle, signed originalM) via the Local chan.
func (c *Connection) BundleUpload() (*session.SingleSession, error) {
	newStream, err := c.MasterSession.OpenStream()
	if err != nil {
		p2log.Error("error during bundle upload phase", err)
		return nil, apperr.Wrap("error during the bundle upload phase: ", err)
	}

	p2log.Info("opened new stream for the bundle upload phase")

	sess := c.NewSession(newStream)
	sess.Tag = "Bundle upload phase"
	sess.Handler = bundlereg.Handler
	sess.Init()

	p2log.Info("Upload bundle phase started")
	// the bundle handler waits for the registration token from the Local chan
	// (injected by the orchestrator via PutRouter) before sending anything
	return sess, nil
}

// --- connection manger ---

// create a new connection manager, it wrap the connection with the tor process and the global out chan
func NewConnectionManager(connection *Connection, tor *tor.Tor, globalOut chan []byte) *ConnectionManager {
	if connection == nil || tor == nil || globalOut == nil {
		return nil
	}

	connectionManager := &ConnectionManager{
		Conn: 		connection,
		Tor: 		tor,
		GlobalOut:	globalOut,
		Done:		make(chan struct{}),
	}
	return connectionManager
}

// watchdog that watch the tor process and the connection, when one exit it close everything
func (manager *ConnectionManager) CheckConnection() {
	var torDone <-chan struct{}

	// this is a goroutiness for Tor process, the wait function wait the exit of Tor 
	// and when it exit close the torDone chan
	if manager.Tor != nil && manager.Tor.Process != nil {
		ch := make(chan struct{})
		torDone = ch
		go func() {
			manager.Tor.Process.Wait()
			close(ch)
		}()
	}

	select {
	case <-torDone:
		p2log.Error("watchdog: tor process exited")
	case <-manager.Done:
		p2log.Debug("watchdog: manager closed")
	case <-manager.Conn.MasterSession.CloseChan():			// CloseChan() is a yamux internal function that manage all types of network closure/error 
		p2log.Error("watchdog: connection to server lost")
	}

	manager.Close()
}

// close the manager, the connection, the tor and all the chans
func (manager *ConnectionManager) Close() {
	manager.Once.Do(func() {
		manager.Conn.Close()
		manager.Tor.Close()
		close(manager.GlobalOut)
		close(manager.Done)
	})
}
