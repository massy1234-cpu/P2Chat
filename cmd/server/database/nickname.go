package database

import (
	"P2Chat/pkg/apperr"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
)

func ValidateNickname(nickname string) error {
	if len(nickname) < nicknameMinLength || len(nickname) > nicknameMaxLength {
		return apperr.New(fmt.Sprintf("nickname length must be between %d and %d characters", nicknameMinLength, nicknameMaxLength))
	}
	for i := 0; i < len(nickname); i++ {
		character := nickname[i]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' {
			continue
		}
		return apperr.New("nickname contains invalid characters")
	}
	return nil
}

func GetBundleIDByNickname(nickname []byte) ([]byte, error) {
	return defaultStore.GetBundleIDByNickname(nickname)
}

func (s *Store) GetBundleIDByNickname(nickname []byte) ([]byte, error) {
	if err := ValidateNickname(string(nickname)); err != nil {
		return nil, err
	}
	return s.getValue(nicknameKey(string(nickname)))
}

// CheckAndReserve returns true if the nickname is already taken, false if the
// nickname was free and is now reserved. The check+reserve is atomic (single
// Update transaction), so two concurrent reservations cannot both succeed.
func CheckAndReserve(nickname string) (bool, error) {
	return defaultStore.CheckAndReserve(nickname)
}

func (s *Store) CheckAndReserve(nickname string) (bool, error) {
	if err := ValidateNickname(nickname); err != nil {
		return false, err
	}
	nicknameDBKey := nicknameKey(nickname)
	reservationDBKey := reservationKey(nickname)

	for attempt := 0; attempt < 3; attempt++ {
		var taken bool
		err := s.update(func(txn *badger.Txn) error {
			for _, key := range [][]byte{nicknameDBKey, reservationDBKey} {
				_, err := txn.Get(key)
				switch {
				case err == nil:
					taken = true
					return nil
				case !errors.Is(err, badger.ErrKeyNotFound):
					return err
				}
			}

			entry := badger.NewEntry(reservationDBKey, []byte{1}).WithTTL(nicknameReservationTTL)
			return txn.SetEntry(entry)
		})
		if errors.Is(err, badger.ErrConflict) {
			continue
		}
		if err != nil {
			return false, apperr.Wrap("error in nickname reservation: ", err)
		}
		return taken, nil
	}

	return false, apperr.New("nickname reservation conflict")
}

func deleteNickname(nickname string) error {
	if err := ValidateNickname(nickname); err != nil {
		return err
	}
	err := defaultStore.update(func(txn *badger.Txn) error {
		return txn.Delete(nicknameKey(nickname))
	})

	return err
}

func DeleteReservation(nickname string) error {
	return defaultStore.DeleteReservation(nickname)
}

func (s *Store) DeleteReservation(nickname string) error {
	if err := ValidateNickname(nickname); err != nil {
		return err
	}
	return s.update(func(txn *badger.Txn) error {
		return txn.Delete(reservationKey(nickname))
	})
}

func assignID(nickname string, ID []byte) error {
	if err := ValidateNickname(nickname); err != nil {
		return err
	}
	if len(ID) != 32 {
		return apperr.New("invalid nickname association")
	}
	err := defaultStore.update(func(txn *badger.Txn) error {
		if err := txn.Set(nicknameKey(nickname), ID); err != nil {
			return err
		}
		return txn.Delete(reservationKey(nickname))
	})

	return err
}
