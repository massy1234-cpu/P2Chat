package database

import (
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"path/filepath"

	bbolt "go.etcd.io/bbolt"
)

func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, apperr.Wrap("open database", err)
	}
	if err := createBuckets(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Init opens the bbolt database at <storage.ProjectRoot>/database.db. It must
// be called once at startup before any other database function. Returns an
// error if the database cannot be opened; callers should abort client startup.
func Init() error {
	defaultStore.mu.Lock()
	defer defaultStore.mu.Unlock()
	if defaultStore.db != nil {
		return nil
	}

	db, err := bbolt.Open(filepath.Join(storage.ProjectRoot, "database.db"), 0600, nil)
	if err != nil {
		return apperr.Wrap("open database", err)
	}
	if err := createBuckets(db); err != nil {
		_ = db.Close()
		return err
	}
	defaultStore.db = db
	DB = db
	return nil
}

func CreateBuckets() error {
	return defaultStore.CreateBuckets()
}

func (s *Store) CreateBuckets() error {
	return s.update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketServersName))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(bucketServerBlacklistName))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(bucketPrivateBundlesName))
		if err != nil {
			return err
		}

		return nil
	})
}

func createBuckets(db *bbolt.DB) error {
	return db.Update(func(tx *bbolt.Tx) error {
		for _, name := range []string{bucketServersName, bucketServerBlacklistName, bucketPrivateBundlesName} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) view(fn func(*bbolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return apperr.New("database not initialized")
	}
	return s.db.View(fn)
}

func (s *Store) update(fn func(*bbolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return apperr.New("database not initialized")
	}
	return s.db.Update(fn)
}

func IsInitialized() bool {
	return defaultStore.IsInitialized()
}

func (s *Store) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db != nil
}

func CloseDB() error {
	return defaultStore.Close()
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	if DB == s.db {
		DB = nil
	}
	s.db = nil
	if err != nil {
		return apperr.Wrap("close database", err)
	}
	return nil
}
