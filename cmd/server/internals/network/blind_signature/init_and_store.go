package blindsignature

import (
	"P2Chat/cmd/server/database"
	"P2Chat/pkg/apperr"
	"crypto/sha256"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awnumar/memguard"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

// thread safe, store the current state of keys
var currentKeys atomic.Pointer[KeysBlindSignature]
var mu sync.Mutex
var loginMu sync.Mutex
var loginKeys *LoginKeys

// Init loads the persisted blind-signature key or creates and stores a new one.
func Init(password *memguard.Enclave, level int, useHSM bool) error {
	mu.Lock()
	defer mu.Unlock()

	if currentKeys.Load() != nil {
		return nil
	}
	if err := database.InitSignature(); err != nil {
		return apperr.Wrap("initialize blind signature database", err)
	}

	keys := &KeysBlindSignature{}

	skEncrypted, err := LoadPrivateKeyEncrypted()
	if err != nil {
		return err
	}

	if skEncrypted == nil {
		// there is none blind key for blind signature -> create it
		keys, err = GenerateBlindKeys()
		if err != nil {
			return apperr.Wrap("error during blind key initialization,error: ", err)
		}
		if err := StorePrivateKey(keys.Sk, password, level, useHSM); err != nil {
			return apperr.Wrap("store generated blind signature private key", err)
		}
	} else {
		// there is the private key encrypted
		privateKey, err := skEncrypted.DecryptKey(password)
		if err != nil {
			return apperr.Wrap("decrypt blind signature private key", err)
		}
		pk, err := privateKey.GetPublicKey()
		if err != nil {
			return apperr.Wrap("derive blind signature public key", err)
		}
		keys.Sk = privateKey
		keys.Pk = pk
	}
	currentKeys.Store(keys)
	return nil
}

// Create the Public and Private key for the blind signature
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	var x fr.Element

	// private key is a secret scalar
	_, err := x.SetRandom()
	if err != nil {
		return nil, nil, apperr.Wrap("error in the key creation for blind signature", err)
	}
	scalarBytes := x.Bytes()
	enclave := memguard.NewEnclave(scalarBytes[:])
	memguard.WipeBytes(scalarBytes[:])
	defer func() { x.SetZero() }()

	// return some point that are const in this protocol
	_, _, _, g2Gen := bls.Generators()

	// this is the same point but with X,Y,Z
	var g2GenJac bls.G2Jac
	g2GenJac.FromAffine(&g2Gen)

	// scalar multiplication with x and the points (bond the secret key with the public key)
	var Yj bls.G2Jac
	xBig := new(big.Int)
	defer xBig.SetInt64(0)
	x.BigInt(xBig)
	Yj.ScalarMultiplication(&g2GenJac, xBig)

	// convert the result in the corret format
	var Y bls.G2Affine
	Y.FromJacobian(&Yj)

	return &PrivateKey{x: enclave}, &PublicKey{Y: Y}, nil
}

// GenerateBlindKeys creates a new blind-signature key pair.
func GenerateBlindKeys() (*KeysBlindSignature, error) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	keys := &KeysBlindSignature{
		Sk: privateKey,
		Pk: publicKey,
	}

	return keys, nil
}

// return the current keys, return nil if is NOT initialized
func GetCurrentKeys() *KeysBlindSignature {
	return currentKeys.Load()
}

// return the Private key, return nil if is NOT initialized
func GetCurrentPrivateKey() *PrivateKey {
	keys := currentKeys.Load()
	if keys == nil {
		return nil
	}
	return keys.Sk
}

// return the Public key, return nil if is NOT initialized
func GetCurrentPublicKey() *PublicKey {
	keys := currentKeys.Load()
	if keys == nil {
		return nil
	}
	return keys.Pk
}

// RotateKeys generates and persists a new key before publishing it in memory.
func RotateKeys(password *memguard.Enclave, level int, useHSM bool) error {
	mu.Lock()
	defer mu.Unlock()

	keys, err := GenerateBlindKeys()
	if err != nil {
		return apperr.Wrap("generate rotated blind signature keys", err)
	}
	if err := StorePrivateKey(keys.Sk, password, level, useHSM); err != nil {
		return apperr.Wrap("store rotated blind signature private key", err)
	}
	currentKeys.Store(keys)
	return nil
}

func StorePrivateKey(sk *PrivateKey, password *memguard.Enclave, level int, useHSM bool) error {
	encrypted, err := sk.SerializeAndEncryptKey(password, level, useHSM)
	if err != nil {
		return err
	}
	return database.SaveBlindKey(encrypted)
}

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

func LoadPrivateKeyEncrypted() (*PrivateKeyEncrypted, error) {
	serialized, err := database.LoadBlindKey()
	if err != nil {
		return nil, apperr.Wrap("load encrypted blind private key", err)
	}
	if serialized == nil {
		return nil, nil
	}

	var encrypted PrivateKeyEncrypted
	if err := messagepack.Unmarshal(serialized, &encrypted); err != nil {
		return nil, apperr.Wrap("deserialize encrypted blind private key", err)
	}

	return &encrypted, nil
}
