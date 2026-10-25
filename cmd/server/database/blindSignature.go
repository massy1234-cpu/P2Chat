package database

import (
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"errors"
	"path/filepath"
	"sync"

	"github.com/dgraph-io/badger/v4"
)

var tokenDB *badger.DB
var tokenDBMu sync.RWMutex
var tokenDeduplicationMu sync.Mutex

// for efficiency reasons the token database is separated from the rest of the information into the database
func InitSignature() error {
	tokenDBMu.Lock()
	defer tokenDBMu.Unlock()

	if tokenDB != nil {
		return nil
	}

	db, err := badger.Open(badger.DefaultOptions(filepath.Join(storage.BasePath, tokenDatabaseDirectory)).WithSyncWrites(true))
	if err != nil {
		return apperr.Wrap("error during open token database", err)
	}
	if err := initializeTokenSchema(db); err != nil {
		_ = db.Close()
		return err
	}
	tokenDB = db
	return nil
}

// TokenDeduplication check if the token is already used,if not save it (false = already used, true = not used)
func TokenDeduplication(b [32]byte) (bool, error) {
	tokenDBMu.RLock()
	defer tokenDBMu.RUnlock()

	if tokenDB == nil {
		return false, apperr.New("blind signature database not initialized")
	}

	tokenDeduplicationMu.Lock()
	defer tokenDeduplicationMu.Unlock()

	var taken bool

	err := tokenDB.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(b[:])
		switch {
		case errors.Is(err, badger.ErrKeyNotFound): // token not used, saved
			return txn.Set(b[:], []byte{1})
		case err != nil: // database error
			return err
		default: // already used
			taken = true
			return nil
		}
	})
	if err != nil {
		return false, apperr.Wrap("error in token deduplication: ", err)
	}
	return !taken, nil
}

// into the database is not necessary to save also the public key, we can reconstruct the public key from the secret key
func SaveBlindKey(skEncrypted []byte) error {
	tokenDBMu.RLock()
	defer tokenDBMu.RUnlock()

	if tokenDB == nil {
		return apperr.New("blind signature database not initialized")
	}
	if len(skEncrypted) == 0 {
		return apperr.New("encrypted blind signature private key is empty")
	}

	err := tokenDB.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(keyBlindPrivateKey), skEncrypted)
	})
	if err != nil {
		return apperr.Wrap("save encrypted blind signature private key", err)
	}
	return nil
}

// load the secret encrypted blind key from the database
func LoadBlindKey() (skEncrypted []byte, err error) {
	tokenDBMu.RLock()
	defer tokenDBMu.RUnlock()

	if tokenDB == nil {
		return nil, apperr.New("blind signature database not initialized")
	}

	var serialized []byte
	err = tokenDB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(keyBlindPrivateKey))
		if err != nil {
			return err
		}
		serialized, err = item.ValueCopy(nil)
		return err
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap("load encrypted blind signature private key", err)
	}

	return serialized, nil
}

func CloseSignature() error {
	tokenDBMu.Lock()
	defer tokenDBMu.Unlock()

	if tokenDB == nil {
		return nil
	}
	err := tokenDB.Close()
	tokenDB = nil
	if err != nil {
		return apperr.Wrap("close blind signature database", err)
	}
	return nil
}
