package blindsignature

import (
	"P2Chat/cmd/server/database"
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/awnumar/memguard"
)

// thread safe, store the current state of keys
var currentKeys atomic.Pointer[KeysBlindSignature]
var Once   sync.Once

// InitBlindSignature generates a fresh blind signature key pair and stores it
// as the current key. It is idempotent: if the keys are already initialized,
// it returns nil without overwriting them. Calling RotateKey() at any point
// is what retires the current key and generates a new one.
func InitBlindSignature() error {
	if IsInitialized() {
		return nil
	}

	PrivateKey, PublicKey, err := GenerateKeyPair()
	if err != nil {
		return apperr.Wrap("error in blind signature initialization", err)
	}

	KeysBlindSignature := &KeysBlindSignature{
		Sk: PrivateKey,
		Pk: PublicKey,
	}
	currentKeys.Store(KeysBlindSignature)

	return nil
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

// pkHash returns the SHA-256 fingerprint of a public key.
func pkHash(pk *PublicKey) [32]byte {
	b := pk.Y.Bytes()
	return sha256.Sum256(b[:])
}

// RotateKey stores the current key (unencrypted, it's expired) in the database
// and generates a new one.
// Retired keys can still verify previously issued tokens via GetPublicKeyByHash.
func RotateKey() error {
	keys := currentKeys.Load()
	if keys == nil {
		return apperr.New("blind signature not initialized")
	}

	pkHash := pkHash(keys.Pk)

	x := keys.Sk.GetX()
	if x == nil {
		return apperr.New("cannot access the retired private key")
	}
	skBytes := x.Bytes()
	defer func() { x.SetZero() }()
	skCopy := append([]byte{}, skBytes[:]...)
	defer memguard.WipeBytes(skCopy)

	if err := database.StoreBlindKey(pkHash[:], skCopy); err != nil {
		return apperr.Wrap("error storing the retired blind key", err)
	}

	return InitBlindSignature()
}

// GetPublicKeyByHash returns the public key whose fingerprint matches hash,
// searching the current key and, if not found, the retired keys stored in the
// database. Returns nil if not found.
func GetPublicKeyByHash(hash []byte) *PublicKey {
	// check current public key
	if pk := GetCurrentPublicKey(); pk != nil {
		h := pkHash(pk)
		if bytes.Equal(h[:], hash) {
			return pk
		}
	}

	// check in the database
	skBytes, err := database.GetBlindKey(hash)
	if err != nil || skBytes == nil {
		return nil
	}

	// get the PrivateKey
	sk := &PrivateKey{x: memguard.NewEnclave(skBytes)}
	memguard.WipeBytes(skBytes)

	pk, err := publicKeyFromPrivateBytes(sk)
	if err != nil {
		return nil
	}
	return pk
}


// SerializeAndSave hashes the signature and stores it in the database to avoid
// reuse of the token. It returns true if the token was not used yet (and is now
// saved), false if it was already present.
func SerializeAndSave(token *bls.G1Affine) (bool, error) {
	serialization := token.Bytes()
	b := sha256.Sum256(serialization[:])
	notUsed, err := database.TokenDeduplication(b)
	return notUsed, err
}
