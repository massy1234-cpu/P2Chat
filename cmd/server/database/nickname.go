package database

import (
	"P2Chat/pkg/apperr"
	"errors"

	"github.com/dgraph-io/badger/v4"
)

// CheckAndReserve returns true if the nickname is already taken, false if the
// nickname was free and is now reserved. The check+reserve is atomic (single
// Update transaction), so two concurrent reservations cannot both succeed.
func CheckAndReserve(nickname string) (bool, error) {
	if !IsInitialized() {
		return false, apperr.New("database not initialized")
	}
	if nickname == "" {
		return false, apperr.New("nickname is empty")
	}
	b := []byte("nickname:" + nickname)

	var taken bool

	err := db_manager.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(b)

		switch {
		case errors.Is(err, badger.ErrKeyNotFound):
			// free: reserve it now (same transaction, atomic)
			return txn.Set(b, []byte{})
		case err != nil:
			return err
		default:
			// already present
			taken = true
			return nil
		}
	})
	if err != nil {
		return false, apperr.Wrap("error in nickname reservation: ", err)
	}

	return taken, nil
}

func DeleteNickname(nickname string) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}
	if nickname == "" {
		return apperr.New("nickname is empty")
	}
	b := []byte("nickname:" + nickname)
	err := db_manager.Update(func(txn *badger.Txn) error {
		return txn.Delete(b)
	})

	return err
}

func AssignID(nickname string, ID []byte) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}
	if nickname == "" || len(ID) != 32 {
		return apperr.New("invalid nickname association")
	}
	b := []byte("nickname:" + nickname)
	err := db_manager.Update(func(txn *badger.Txn) error {
		err := txn.Set(b, ID)
		return err
	})

	return err
}
