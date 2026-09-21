package database

import (
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"path/filepath"

	bbolt "go.etcd.io/bbolt"
)

var DB *bbolt.DB = nil

var (
	bucketServers         = []byte("servers")
	bucketServerBlacklist = []byte("server:blacklist")
	bucketPrivateBundles  = []byte("private:bundles")
)

// Init opens the bbolt database at <storage.ProjectRoot>/database.db. It must
// be called once at startup before any other database function. Returns an
// error if the database cannot be opened; callers should abort client startup.
func Init() error {
	if DB != nil {
		return nil
	}

	db, err := bbolt.Open(filepath.Join(storage.ProjectRoot, "database.db"), 0600, nil)
	if err != nil {
		return apperr.Wrap("open database", err)
	}
	DB = db

	err = CreateBuckets()
	if err != nil {
		CloseDB()
		return err
	}
	return nil
}

func CreateBuckets() error {
	err := DB.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketServers)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(bucketServerBlacklist)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(bucketPrivateBundles)
		if err != nil {
			return err
		}

		return err
	})

	return err
}

func IsInitialized() bool {
	return DB != nil
}

func CloseDB() error {
	if !IsInitialized() {
		return nil
	}
	err := DB.Close()
	DB = nil
	if err != nil {
		return apperr.Wrap("close database", err)
	}
	return nil
}
