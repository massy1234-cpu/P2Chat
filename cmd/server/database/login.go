package database

import (
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/dgraph-io/badger/v4"
	messagepack "github.com/vmihailenco/msgpack/v5"
	"sync"
	"time"
)

type LoginTokenRecord struct {
	RemainingUses uint32
	ExpiresAt     int64
	LastUsedAt    int64
	BundleID      []byte
}

var loginTokenMu sync.Mutex

// ConsumeLoginToken is called only after signature and account-proof verification.
// Exhausted records remain until expiry so an absent record cannot reset the counter.
func ConsumeLoginToken(keyHash, message, bundleID []byte, expiresAt int64) (uint32, error) {
	if !IsInitialized() || len(keyHash) != 32 || len(message) != 64 || len(bundleID) != 32 || expiresAt <= time.Now().Unix() {
		return 0, apperr.New("invalid or expired login token")
	}
	hash := sha256.Sum256(message)
	key := append([]byte("login:tokens:"), keyHash...)
	key = append(key, hash[:]...)
	loginTokenMu.Lock()
	defer loginTokenMu.Unlock()
	var remaining uint32
	err := db_manager.Update(func(tx *badger.Txn) error {
		record := LoginTokenRecord{RemainingUses: 3, ExpiresAt: expiresAt, BundleID: bundleID}
		item, err := tx.Get(key)
		if err == nil {
			data, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			if err := messagepack.Unmarshal(data, &record); err != nil {
				return err
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		if record.RemainingUses == 0 || record.RemainingUses > 3 || record.ExpiresAt != expiresAt || !bytes.Equal(record.BundleID, bundleID) {
			return apperr.New("login token exhausted or belongs to another bundle")
		}
		record.RemainingUses--
		record.LastUsedAt = time.Now().Unix()
		remaining = record.RemainingUses
		serialized, err := messagepack.Marshal(record)
		if err != nil {
			return err
		}
		return tx.SetEntry(&badger.Entry{Key: key, Value: serialized, ExpiresAt: uint64(expiresAt)})
	})
	return remaining, err
}
