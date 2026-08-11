package database

import (
	"P2Chat/cmd/client/internals/storage"
	"path/filepath"
	bbolt "go.etcd.io/bbolt"
)

var DB *bbolt.DB

func Init() error {
    var err error
    DB, err = bbolt.Open(filepath.Join(storage.ProjectRoot, "database.db"), 0600, nil)
    return err
}