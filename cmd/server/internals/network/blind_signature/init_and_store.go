package blindsignature

import (
	"P2Chat/cmd/server/database"
	"P2Chat/pkg/apperr"
	"crypto/sha256"
	"sync/atomic"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// thread safe, store the current state of keys
var current atomic.Pointer[KeysBlindSignature]

// initialize current state
func InitBlindSignature() error {
	PrivateKey,PublicKey,err := GenerateKeyPair()
	if err != nil {
		return apperr.Wrap("error in blind signature initialization",err)
	}

	KeysBlindSignature := &KeysBlindSignature{
		sk: PrivateKey,
		pk: PublicKey,
	}
	current.Store(KeysBlindSignature)

	return nil
}

// return the current keys, return nil if is NOT initialized
func GetCurrentKeys() *KeysBlindSignature {
	return current.Load()
}

// return the Private key, return nil if is NOT initialized
func GetCurrentPrivateKey() *PrivateKey {
	keys := current.Load()
	if keys == nil {
		return nil
	}
	return keys.sk
}


// serialize and save the signature into the database for avoid reuse of the token
func SerializeAndSave(token *bls.G1Affine) error {
	serialization := token.Bytes()
	hash := sha256.Sum256(serialization[:])
	err := database.TokenDeduplication(hash)
	
	return err
}