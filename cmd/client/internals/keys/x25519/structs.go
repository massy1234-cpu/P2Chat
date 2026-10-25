package x25519

import (
	"P2Chat/pkg/apperr"
	"crypto/ecdh"

	"github.com/awnumar/memguard"
	"github.com/vmihailenco/msgpack/v5"
)

type PrivateX25519 struct {
	enclave *memguard.Enclave
}

type PublicX25519 struct {
	key *ecdh.PublicKey
}

func (publicKey *PublicX25519) MarshalMsgpack() ([]byte, error) {
	if publicKey == nil || publicKey.key == nil {
		return nil, apperr.New("public X25519 key is nil")
	}
	return msgpack.Marshal(publicKey.key.Bytes())
}

func (publicKey *PublicX25519) UnmarshalMsgpack(b []byte) error {
	var raw []byte
	if err := msgpack.Unmarshal(b, &raw); err != nil {
		return apperr.Wrap("unmarshal public key raw bytes", err)
	}

	k, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return apperr.Wrap("decode public X25519 key", err)
	}

	publicKey.key = k
	return nil
}

func (privateKey *PrivateX25519) open() (*memguard.LockedBuffer, error) {
	if privateKey == nil || privateKey.enclave == nil {
		return nil, apperr.New("private X25519 key is nil")
	}
	return privateKey.enclave.Open()
}

func (privateKey *PrivateX25519) native() (*ecdh.PrivateKey, error) {
	buffer, err := privateKey.open()
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
	if publicKey == nil || publicKey.key == nil {
		return nil
	}
	return publicKey.key.Bytes()
}

const PublicKeySize = 32
const SignatureSize = 64

func NewPublicKey(data []byte) (*PublicX25519, error) {
	key, err := ecdh.X25519().NewPublicKey(data)
	if err != nil {
		return nil, apperr.Wrap("decode X25519 public key", err)
	}
	return &PublicX25519{key: key}, nil
}
