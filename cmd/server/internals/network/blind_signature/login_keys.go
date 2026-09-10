package blindsignature

import (
	"crypto/sha256"
	"sync"
	"time"
)

type LoginKeys struct {
	Keys      *KeysBlindSignature
	Hash      [32]byte
	ExpiresAt int64
}

var loginMu sync.Mutex
var loginKeys *LoginKeys

// Login signing keys are separate from registration and expire after one day.
func GetLoginKeys() (*LoginKeys, error) {
	loginMu.Lock()
	defer loginMu.Unlock()
	if loginKeys != nil && time.Now().Unix() < loginKeys.ExpiresAt {
		return loginKeys, nil
	}
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	public := pk.Y.Bytes()
	loginKeys = &LoginKeys{Keys: &KeysBlindSignature{Sk: sk, Pk: pk}, Hash: sha256.Sum256(public[:]), ExpiresAt: time.Now().Add(24 * time.Hour).Unix()}
	return loginKeys, nil
}
