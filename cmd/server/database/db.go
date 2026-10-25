package database

import (
	"P2Chat/cmd/client/internals/storage"
	pow "P2Chat/cmd/server/internals/network/PoW"
	loadreport "P2Chat/cmd/server/internals/network/load_report"
	"P2Chat/pkg/apperr"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
)

type Store struct {
	mu     sync.RWMutex
	db     *badger.DB
	ticker *time.Ticker
	gcStop chan struct{}
}

var defaultStore = &Store{}

func Open(path string) (*Store, error) {
	db, err := badger.Open(badger.DefaultOptions(path).WithSyncWrites(true))
	if err != nil {
		return nil, apperr.Wrap("open database", err)
	}
	if err := initializeMainSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Init opens the BadgerDB database in <storage.BasePath>/database. It must be
// called once at startup before any other database function. Returns an error
// if the database cannot be opened; callers should abort server startup.
func Init() error {
	defaultStore.mu.Lock()
	defer defaultStore.mu.Unlock()
	if defaultStore.db != nil {
		return nil
	}

	db, err := badger.Open(badger.DefaultOptions(filepath.Join(storage.BasePath, mainDatabaseDirectory)).WithSyncWrites(true))
	if err != nil {
		return apperr.Wrap("open database", err)
	}
	if err := initializeMainSchema(db); err != nil {
		_ = db.Close()
		return err
	}
	defaultStore.db = db
	return nil
}

func (s *Store) view(fn func(*badger.Txn) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return apperr.New("database not initialized")
	}
	return s.db.View(fn)
}

func (s *Store) update(fn func(*badger.Txn) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return apperr.New("database not initialized")
	}
	return s.db.Update(fn)
}

func (s *Store) getValue(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, apperr.New("database key is empty")
	}
	var value []byte
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		return err
	})
	return value, err
}

// periodic value log garbage collection; the interval adapts to server load
func GC() {
	defaultStore.runGC()
}

func (s *Store) runGC() {
	ticker := time.NewTicker(time.Duration(getTimeFromLoad()) * time.Second)
	stop := make(chan struct{})

	s.mu.Lock()
	if s.db == nil || s.ticker != nil {
		s.mu.Unlock()
		ticker.Stop()
		return
	}
	s.ticker = ticker
	s.gcStop = stop
	s.mu.Unlock()

	for {
		select {
		case <-ticker.C:
			s.mu.RLock()
			if s.db != nil {
				_ = s.db.RunValueLogGC(0.5)
			}
			s.mu.RUnlock()
		case <-stop:
			return
		}
	}
}

func IsInitialized() bool {
	defaultStore.mu.RLock()
	defer defaultStore.mu.RUnlock()
	return defaultStore.db != nil
}

func CloseDB() {
	_ = defaultStore.Close()
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gcStop != nil {
		close(s.gcStop)
		s.gcStop = nil
	}
	if s.ticker != nil {
		s.ticker.Stop()
		s.ticker = nil
	}
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	if err != nil {
		return apperr.Wrap("close database", err)
	}
	return nil
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
