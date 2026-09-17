package database

import (
	"P2Chat/cmd/client/internals/storage"
	pow "P2Chat/cmd/server/internals/network/PoW"
	loadreport "P2Chat/cmd/server/internals/network/load_report"
	"P2Chat/pkg/apperr"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
)

var db_manager *badger.DB = nil
var ticker *time.Ticker

// Init opens the BadgerDB database in <storage.BasePath>/database. It must be
// called once at startup before any other database function. Returns an error
// if the database cannot be opened; callers should abort server startup.
func Init() error {
	if db_manager != nil {
		return nil
	}

	db, err := badger.Open(badger.DefaultOptions(filepath.Join(storage.BasePath, "database")))
	if err != nil {
		return apperr.Wrap("open database", err)
	}
	db_manager = db
	return nil
}

// periodic value log garbage collection; the interval adapts to server load
func GC() {
	ticker = time.NewTicker(time.Duration(getTimeFromLoad()) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		db_manager.RunValueLogGC(0.5)
	}
}

func IsInitialized() bool {
	return db_manager != nil
}

func CloseDB() {
	if ticker != nil {
		ticker.Stop()
		ticker = nil
	}
	if db_manager != nil {
		_ = db_manager.Close()
		db_manager = nil
	}
}

// return the GC interval in seconds; higher load (more writes) -> shorter interval
func getTimeFromLoad() float64 {
	value, err := loadreport.LoadReport()
	if err != nil {
		return 60
	}

	switch value {
	case pow.Level1:
		return 300
	case pow.Level2:
		return 120
	case pow.Level3:
		return 60
	case pow.Level4:
		return 30
	case pow.Level5:
		return 15
	default:
		return 60
	}
}

// GetValue return the value associate to the key into the database
func GetValue(key []byte) ([]byte, error) {
	if !IsInitialized() {
		return nil, apperr.New("database not initialized")
	}
	if len(key) == 0 {
		return nil, apperr.New("database key is empty")
	}
	var value []byte

	err := db_manager.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
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
