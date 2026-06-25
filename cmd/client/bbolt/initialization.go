package bbolt

import (
	"P2Chat/pkg/apperr"
	database "go.etcd.io/bbolt"
)

const path_database = "/database/"

func OpenOrCreate() error {

	db, err := database.Open(path_database + "database.db", 0600, nil)
	if err != nil {
		apperr.Wrap("error during the creation/opening database",err)
	}
	defer db.Close()

	return nil
}