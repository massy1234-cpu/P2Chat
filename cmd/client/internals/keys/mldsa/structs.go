package mldsa_keys

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/pkg/apperr"

	"github.com/awnumar/memguard"
)

type PrivateMLDSA struct {
	enclave *memguard.Enclave
}

type PublicMLDSA struct {
	key *mldsa87.PublicKey
}

func (privateKey *PrivateMLDSA) open() (*memguard.LockedBuffer, error) {
	if privateKey == nil || privateKey.enclave == nil {
		return nil, apperr.New("private ML-DSA key is nil")
	}
	return privateKey.enclave.Open()
}

func (privateKey *PrivateMLDSA) native() (*mldsa87.PrivateKey, error) {
	buffer, err := privateKey.open()
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
	if publicKey == nil || publicKey.key == nil {
		return nil
	}
	return publicKey.key.Bytes()
}

func (publicKey *PublicMLDSA) Verify(message, context, signature []byte) bool {
	return publicKey != nil && publicKey.key != nil && mldsa87.Verify(publicKey.key, message, context, signature)
}

func wipeNativeMLDSA(key *mldsa87.PrivateKey) {
	if key != nil {
		encryption.Wipe(key)
	}
}

const PublicKeySize = mldsa87.PublicKeySize
const SignatureSize = mldsa87.SignatureSize

func NewPublicKey(data []byte) (*PublicMLDSA, error) {
	var key mldsa87.PublicKey
	if err := key.UnmarshalBinary(data); err != nil {
		return nil, apperr.Wrap("decode ML-DSA public key", err)
	}
	return &PublicMLDSA{key: &key}, nil
}
