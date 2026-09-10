package database

import (
	"P2Chat/pkg/apperr"
	"errors"

	"github.com/dgraph-io/badger/v4"
)

// TokenDeduplication check if the token is already used,if not save it (false = already used, true = not used)
func TokenDeduplication(b [32]byte) (bool, error) {
	if !IsInitialized() {
		return false, apperr.New("database not initialized")
	}

	var taken bool

	err := db_manager.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(b[:])
		switch {
		case errors.Is(err, badger.ErrKeyNotFound):			// token not used, saved
			return txn.Set(b[:], []byte{1})
		case err != nil:									// database error
			return err
		default:											// already used
			taken = true
			return nil
		}
	})
	if err != nil {
		return false, apperr.Wrap("error in token deduplication: ", err)
	}
	return !taken, nil
}


// The keys stored in this database are not used anymore, are memorized only for garantee support for old sign, data are no encrypted
// keys are stored like PublicKeyHash:PrivateKeyBytes
func StoreBlindKey(pkHash []byte,sk []byte) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}
	err := db_manager.Update(func(txn *badger.Txn) error {
    	return txn.Set(pkHash, sk)					// the value is not important
	})
	return err
}

// GetBlindKey returns the retired private key bytes for the given public key
// hash. Returns nil, nil if not found.
func GetBlindKey(pkHash []byte) ([]byte, error) {
	if !IsInitialized() {
		return nil, apperr.New("database not initialized")
	}
	var value []byte
	err := db_manager.View(func(txn *badger.Txn) error {
		item, err := txn.Get(pkHash)
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return value, nil
}