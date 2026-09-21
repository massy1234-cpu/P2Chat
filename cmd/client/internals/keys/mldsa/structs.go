package mldsa_keys

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/pkg/apperr"

	"github.com/awnumar/memguard"
)

type PrivateMLDSA struct {
	Enclave *memguard.Enclave
}

type PublicMLDSA struct {
	Key *mldsa87.PublicKey
}

func (privateKey *PrivateMLDSA) Open() (*memguard.LockedBuffer, error) {
	if privateKey == nil || privateKey.Enclave == nil {
		return nil, apperr.New("private ML-DSA key is nil")
	}
	return privateKey.Enclave.Open()
}

func (privateKey *PrivateMLDSA) Native() (*mldsa87.PrivateKey, error) {
	buffer, err := privateKey.Open()
	if err != nil {
		return nil, apperr.Wrap("open private ML-DSA key", err)
	}
	defer buffer.Destroy()

	var key mldsa87.PrivateKey
	if err := key.UnmarshalBinaryFromLockedBuffer(buffer); err != nil {
		return nil, apperr.Wrap("decode private ML-DSA key", err)
	}
	return &key, nil
}

func (publicKey *PublicMLDSA) Bytes() []byte {
	if publicKey == nil || publicKey.Key == nil {
		return nil
	}
	return publicKey.Key.Bytes()
}

func (publicKey *PublicMLDSA) Verify(message, context, signature []byte) bool {
	return publicKey != nil && publicKey.Key != nil && mldsa87.Verify(publicKey.Key, message, context, signature)
}

func wipeNativeMLDSA(key *mldsa87.PrivateKey) {
	if key != nil {
		encryption.Wipe(key)
	}
}
