package x25519

import (
	"P2Chat/pkg/apperr"
	"crypto/ecdh"

	"github.com/awnumar/memguard"
)

type PrivateX25519 struct {
	Enclave *memguard.Enclave
}

type PublicX25519 struct {
	Key *ecdh.PublicKey
}

func (privateKey *PrivateX25519) Open() (*memguard.LockedBuffer, error) {
	if privateKey == nil || privateKey.Enclave == nil {
		return nil, apperr.New("private X25519 key is nil")
	}
	return privateKey.Enclave.Open()
}

func (privateKey *PrivateX25519) Native() (*ecdh.PrivateKey, error) {
	buffer, err := privateKey.Open()
	if err != nil {
		return nil, apperr.Wrap("open private X25519 key", err)
	}
	defer buffer.Destroy()
	key, err := ecdh.X25519().NewPrivateKey(buffer.Bytes())
	if err != nil {
		return nil, apperr.Wrap("decode private X25519 key", err)
	}
	return key, nil
}

func (publicKey *PublicX25519) Bytes() []byte {
	if publicKey == nil || publicKey.Key == nil {
		return nil
	}
	return publicKey.Key.Bytes()
}
