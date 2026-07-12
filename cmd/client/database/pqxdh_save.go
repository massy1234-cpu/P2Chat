package database

import (
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	"P2Chat/pkg/apperr"
	"encoding/binary"
	bbolt "go.etcd.io/bbolt"
)

func SaveSets(arraySet []structures.SetPair, bundleName string) error {

	var err error
	identifierBytes := []byte(bundleName)

	err = DB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(identifierBytes)
		if err != nil {
			return err
		}

		for i := range len(arraySet) {
			number := make([]byte, 8)
			binary.BigEndian.PutUint64(number, uint64(i))

			if err := bucket.Put(number, arraySet[i].Private); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return apperr.Wrap("error during the saving of the curve sets in the local database", err)
	}

	return nil
}