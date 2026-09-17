package blindsignature

import (
	keyencryption "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/pkg/apperr"
	"math/big"

	"github.com/awnumar/memguard"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

type KeysBlindSignature struct {
	Sk *PrivateKey
	Pk *PublicKey
}

type PrivateKey struct {
	//x fr.Element
	x *memguard.Enclave
}

type PrivateKeyEncrypted struct {
	Key        []byte `msgpack:"key"`
	Nonce      []byte `msgpack:"nonce"`
	Salt       []byte `msgpack:"salt"`
	ArgonLevel int    `msgpack:"argon_level"`
	HSMMethod  uint32 `msgpack:"hsm_method"`
}

type PublicKey struct {
	Y bls.G2Affine
}

type LoginKeys struct {
	Keys      *KeysBlindSignature
	Hash      [32]byte
	ExpiresAt int64
}

// GetPublicKey derives the public key Y = x·G2 from the private key.
func (sk *PrivateKey) GetPublicKey() (*PublicKey, error) {
	if sk == nil || sk.x == nil {
		return nil, apperr.New("private key is nil")
	}
	x := sk.GetX()
	if x == nil {
		return nil, apperr.New("cannot access the private key")
	}
	defer func() { x.SetZero() }()

	_, _, _, g2Gen := bls.Generators()
	var g2GenJac bls.G2Jac
	g2GenJac.FromAffine(&g2Gen)

	var Yj bls.G2Jac
	xBig := new(big.Int)
	x.BigInt(xBig)
	Yj.ScalarMultiplication(&g2GenJac, xBig)
	defer func() { xBig.SetInt64(0) }()

	var Y bls.G2Affine
	Y.FromJacobian(&Yj)

	return &PublicKey{Y: Y}, nil
}

func (sk *PrivateKey) GetX() *fr.Element {
	if sk == nil || sk.x == nil {
		return nil
	}
	var x fr.Element

	buffer, err := sk.x.Open()
	if err != nil {
		return nil
	}
	x.SetBytes(buffer.Bytes())
	defer buffer.Destroy()

	return &x
}

// EncryptKey encrypts the private blind key and returns its storage structure.
func (sk *PrivateKey) EncryptKey(password *memguard.Enclave, level int, useHSM bool) (*PrivateKeyEncrypted, error) {
	if sk == nil || sk.x == nil {
		return nil, apperr.New("private key is nil")
	}

	ciphertext, nonce, salt, method, err := keyencryption.Encrypt(password, sk.x, level, useHSM)
	if err != nil {
		return nil, apperr.Wrap("encrypt blind signature private key", err)
	}

	return &PrivateKeyEncrypted{
		Key:        ciphertext,
		Nonce:      nonce,
		Salt:       salt,
		ArgonLevel: level,
		HSMMethod:  method,
	}, nil
}

// DecryptKey decrypts the stored private blind key into a memguard enclave.
func (sk *PrivateKeyEncrypted) DecryptKey(password *memguard.Enclave) (*PrivateKey, error) {
	if sk == nil {
		return nil, apperr.New("encrypted private key is nil")
	}

	enclave, err := keyencryption.Decrypt(password, sk.Key, sk.Nonce, sk.Salt, sk.ArgonLevel, sk.HSMMethod)
	if err != nil {
		return nil, apperr.Wrap("decrypt blind signature private key", err)
	}

	return &PrivateKey{x: enclave}, nil
}

// SerializeAndEncryptKey encrypts and serializes the private blind key.
func (sk *PrivateKey) SerializeAndEncryptKey(password *memguard.Enclave, level int, useHSM bool) ([]byte, error) {
	encryptedKey, err := sk.EncryptKey(password, level, useHSM)
	if err != nil {
		return nil, err
	}

	serializedKey, err := messagepack.Marshal(encryptedKey)
	if err != nil {
		return nil, apperr.Wrap("serialize blind signature private key", err)
	}

	return serializedKey, nil
}
