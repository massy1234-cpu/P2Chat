package database

import (
	"P2Chat/cmd/client/internals/storage"
	pow "P2Chat/cmd/server/network/PoW"
	loadreport "P2Chat/cmd/server/network/load_report"
	"P2Chat/pkg/apperr"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
)

var db_manager *badger.DB = nil
var ticker *time.Ticker
var once sync.Once

// initialize the database in the folder /database
func Init() error {
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(storage.BasePath,"database")))
	if err != nil {
		return apperr.Wrap("error during database initialization: ",err)
	}
	db_manager = db
	return nil
}

// periodic value log garbage collection; the interval adapts to the server load
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
	once.Do(func(){
		if IsInitialized() {
			db_manager.Close()
			ticker.Stop()
		}
	})
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