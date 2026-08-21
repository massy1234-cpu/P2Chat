package database

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/storage"
	"path/filepath"

	bbolt "go.etcd.io/bbolt"
)

var DB *bbolt.DB = nil

func init() {
    db, err := bbolt.Open(filepath.Join(storage.ProjectRoot, "database.db"), 0600, nil)
	if err != nil {
		p2log.Error("database not initialized, error")
		return
	}
	DB = db
}

func IsInitialized() bool {
	return DB != nil
}