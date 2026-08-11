package database

import (
	"P2Chat/pkg/apperr"
	"github.com/dgraph-io/badger/v4"
)

func TokenDeduplication(hash [32]byte) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}
	err := db_manager.Update(func(txn *badger.Txn) error {
    	return txn.Set(hash[:], []byte{1})					// the value is not important
	})
	return err
}