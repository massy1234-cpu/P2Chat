package connection

import (
	"P2Chat/pkg/apperr"
	"sync"
	"sync/atomic"
	"time"
)

type AuthenticatedUser struct {
	BundleID    [32]byte
	PoWVerified bool
	Anonymous   bool
	LoginAt     time.Time
	LastSeen    atomic.Int64
}

func (c *Connection) AuthenticateAnonymous() error {
	activeMu.Lock()
	defer activeMu.Unlock()
	if c.IsClosed() || c.Auth.Load() != nil {
		return apperr.New("connection closed or already authenticated")
	}
	user := &AuthenticatedUser{Anonymous: true, LoginAt: time.Now()}
	user.LastSeen.Store(user.LoginAt.Unix())
	c.Auth.Store(user)
	if c.Authed != nil {
		c.Authed.Store(true)
	}
	return nil
}

var activeMu sync.Mutex
var activeUsers = make(map[[32]byte]map[*Connection]struct{})

func (c *Connection) Authenticate(bundleID []byte, powVerified bool) error {
	if len(bundleID) != 32 {
		return apperr.New("invalid authenticated bundle ID")
	}
	activeMu.Lock()
	defer activeMu.Unlock()
	if c.IsClosed() || c.Auth.Load() != nil {
		return apperr.New("connection closed or already authenticated")
	}
	user := &AuthenticatedUser{PoWVerified: powVerified, LoginAt: time.Now()}
	copy(user.BundleID[:], bundleID)
	user.LastSeen.Store(user.LoginAt.Unix())
	if activeUsers[user.BundleID] == nil {
		activeUsers[user.BundleID] = make(map[*Connection]struct{})
	}
	activeUsers[user.BundleID][c] = struct{}{}
	c.Auth.Store(user)
	if c.Authed != nil {
		c.Authed.Store(true)
	}
	return nil
}

func ActiveConnections(bundleID [32]byte) int {
	activeMu.Lock()
	defer activeMu.Unlock()
	return len(activeUsers[bundleID])
}

func (c *Connection) ClearAuthentication() {
	activeMu.Lock()
	defer activeMu.Unlock()
	if c.Authed != nil {
		c.Authed.Store(false)
	}
	if user := c.Auth.Swap(nil); user != nil {
		if user.Anonymous {
			return
		}
		delete(activeUsers[user.BundleID], c)
		if len(activeUsers[user.BundleID]) == 0 {
			delete(activeUsers, user.BundleID)
		}
	}
}
