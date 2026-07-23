package database

import (
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	"P2Chat/pkg/apperr"
	"encoding/binary"
	bbolt "go.etcd.io/bbolt"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

func SaveSets(arraySet [][]byte, bundleName string) error {

	var err error
	identifierBytes := []byte("bundle:"+bundleName)

	err = DB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(identifierBytes)
		if err != nil {
			return err
		}

		for i := range len(arraySet) {
			number := make([]byte, 8)
			binary.BigEndian.PutUint64(number, uint64(i))

			// the database must contains only the private part, not the public
			if err := bucket.Put(number, arraySet[i]); err != nil {
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


// save the private part of the bundle inside the database, serialize the privateBundle inside of it
func SavePrivateBundle(privateBundle *structures.PrivateBundle,bundleName string) error {

	var err error
	
	// identifierBytes will identifier the right bucket
	identifierBytes := []byte("bundle:"+bundleName)

	// privateBundleIdentifier will identify the private bundle inside the bucket 
	privateBundleIdentifier := []byte("Private_Bundle")

	serializedStruct,err := messagepack.Marshal(privateBundle)
	if err != nil{
		return apperr.Wrap("error during serialization of the private struct: ",err)
	}

	err = DB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(identifierBytes)
		if err != nil {
			return err
		}

		// the database must contains only the private part, not the public
		if err := bucket.Put(privateBundleIdentifier,serializedStruct); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return apperr.Wrap("error during the saving of the curve sets in the local database", err)
	}

	return nil
}