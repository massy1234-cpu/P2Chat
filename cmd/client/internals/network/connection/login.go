package connection

import (
	"P2Chat/cmd/client/database"
	x25519 "P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/network/phases/login"
	"P2Chat/cmd/client/internals/protocol/pqxdh"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/awnumar/memguard"
	"time"
)

// Login verifies the server on new connections and returns a memory-only reconnect token.
func (c *Connection) Login(binding []byte, bundle *database.LoginBundle, password, token *memguard.Enclave) (*memguard.Enclave, error) {
	if bundle == nil || password == nil || len(binding) != 32 {
		return nil, apperr.New("missing login credentials")
	}
	c.mu.Lock()
	identified := len(c.ServerID) == 32
	c.mu.Unlock()
	if !identified {
		events, err := c.ServerIdentification(binding)
		if err != nil {
			return nil, err
		}
		select {
		case identity, ok := <-events:
			if !ok || len(identity) == 0 {
				return nil, apperr.New("server identification failed")
			}
		case <-c.Done:
			return nil, apperr.New("connection closed during identification")
		case <-time.After(30 * time.Second):
			return nil, apperr.New("server identification timed out")
		}
	}
	skMLDSA, pkMLDSA, skX25519, err := pqxdh.LoadIKKeys(password, storage.BasePath, bundle.LocalID)
	if err != nil {
		return nil, err
	}
	pkX25519 := x25519.ExtractPublicKey(skX25519)
	if pkX25519 == nil {
		return nil, apperr.New("cannot recover X25519 public key")
	}
	h1, h2 := sha256.Sum256(pkX25519.Bytes()), sha256.Sum256(pkMLDSA.Key)
	id := sha256.Sum256(append(h1[:], h2[:]...))
	if len(bundle.BundleID) == 0 {
		bundle.BundleID = append([]byte(nil), id[:]...)
	}
	if !bytes.Equal(bundle.BundleID, id[:]) {
		return nil, apperr.New("local identity keys do not match registered bundle")
	}
	c.mu.Lock()
	serverID := append([]byte(nil), c.ServerID...)
	c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		stream, err := c.MasterSession.OpenStream()
		if err != nil {
			return nil, apperr.Wrap("open login stream", err)
		}
		sess := c.NewSession(stream)
		ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
		go func() {
			select {
			case <-sess.Done:
				cancel()
			case <-ctx.Done():
			}
		}()
		var nextToken *memguard.Enclave
		current := &login.LoginClient{Binding: binding, ServerID: serverID, BundleID: bundle.BundleID, MLDSA: skMLDSA, X25519: skX25519, Token: token, Context: ctx, SaveToken: func(value *memguard.Enclave) { nextToken = value }}
		sess.Tag = "Login"
		sess.Handler = func(tag byte, payload []byte, state *any) *phases.Result {
			if *state == nil {
				*state = current
			}
			return login.Handler(tag, payload, state)
		}
		sess.Init()
		sess.PutRouter(phases.LoginAccessRequest, nil)
		select {
		case event, ok := <-sess.Events:
			cancel()
			if !ok || len(event) != 1 {
				return nil, apperr.New("login failed; check phase logs")
			}
			if event[0] == 1 {
				if err := database.SaveLoginBundle(serverID, bundle); err != nil {
					return nil, err
				}
				return nextToken, nil
			}
			if token == nil {
				return nil, apperr.New("full login rejected")
			}
			token = nil
		case <-time.After(11 * time.Minute):
			cancel()
			sess.ForceClose()
			return nil, apperr.New("login cancelled or timed out")
		case <-c.Done:
			cancel()
			return nil, apperr.New("connection lost during login")
		}
	}
	return nil, apperr.New("login token rejected")
}
