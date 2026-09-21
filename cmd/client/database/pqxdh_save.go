package database

import (
	commitmentproto "P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	"P2Chat/pkg/apperr"
	"encoding/binary"
	messagepack "github.com/vmihailenco/msgpack/v5"
	bbolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

var (
	keyPrivateBundle = []byte("private-bundle")
	keyCommitment    = []byte("commitment:rawbytes")
	bucketCurveSets  = []byte("curve-sets")
	bucketKEMSets    = []byte("kem-sets")
)

func SaveSets(arraySet [][]byte, bundleID []byte, setType string) error {

	if !IsInitialized() || len(bundleID) != 32 {
		return apperr.New("invalid private sets storage parameters")
	}

	var setBucketName []byte
	switch setType {
	case "curve":
		setBucketName = bucketCurveSets
	case "kem":
		setBucketName = bucketKEMSets
	default:
		return apperr.New("invalid private set type")
	}

	err := DB.Update(func(tx *bbolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists(bucketPrivateBundles)
		if err != nil {
			return err
		}
		bundle, err := root.CreateBucketIfNotExists(bundleID)
		if err != nil {
			return err
		}
		bucket, err := bundle.CreateBucketIfNotExists(setBucketName)
		if err != nil {
			return err
		}

		for i := range len(arraySet) {
			number := make([]byte, 4)
			binary.BigEndian.PutUint32(number, uint32(i))

			// the database must contains only the private part, not the public
			if err := bucket.Put(number, arraySet[i]); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return apperr.Wrap("error during the saving of the private sets in the local database", err)
	}

	return nil
}

func SaveCommitment(commitment *commitmentproto.CommitmentSchemePrivate, bundleID []byte) error {
	if !IsInitialized() || commitment == nil || len(bundleID) != 32 {
		return apperr.New("invalid commitment storage parameters")
	}
	serialized, err := proto.Marshal(commitment)
	if err != nil {
		return apperr.Wrap("serialize private commitment", err)
	}
	return DB.Update(func(tx *bbolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists(bucketPrivateBundles)
		if err != nil {
			return err
		}
		bundle, err := root.CreateBucketIfNotExists(bundleID)
		if err != nil {
			return err
		}
		return bundle.Put(keyCommitment, serialized)
	})
}

func LoadCommitment(bundleID []byte) (*commitmentproto.CommitmentSchemePrivate, error) {
	if !IsInitialized() || len(bundleID) != 32 {
		return nil, apperr.New("invalid commitment load parameters")
	}
	var commitment *commitmentproto.CommitmentSchemePrivate
	err := DB.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket(bucketPrivateBundles)
		if root == nil {
			return apperr.New("private bundles bucket not found")
		}
		bundle := root.Bucket(bundleID)
		if bundle == nil || bundle.Get(keyCommitment) == nil {
			return apperr.New("private commitment not found")
		}
		stored := &commitmentproto.CommitmentSchemePrivate{}
		if err := proto.Unmarshal(bundle.Get(keyCommitment), stored); err != nil {
			return apperr.Wrap("decode private commitment", err)
		}
		commitment = stored
		return nil
	})
	return commitment, err
}

// save the private part of the bundle inside the database, serialize the privateBundle inside of it
func SavePrivateBundle(privateBundle *structures.PrivateBundle, bundleID []byte) error {

	if !IsInitialized() || privateBundle == nil || privateBundle.ID < 0 || len(bundleID) != 32 {
		return apperr.New("invalid private bundle storage parameters")
	}

	var err error

	serializedStruct, err := messagepack.Marshal(privateBundle)
	if err != nil {
		return apperr.Wrap("error during serialization of the private struct: ", err)
	}

	err = DB.Update(func(tx *bbolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists(bucketPrivateBundles)
		if err != nil {
			return err
		}
		bucket, err := root.CreateBucketIfNotExists(bundleID)
		if err != nil {
			return err
		}

		// the database must contains only the private part, not the public
		if err := bucket.Put(keyPrivateBundle, serializedStruct); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return apperr.Wrap("error during the saving of the private bundle in the local database", err)
	}

	return nil
}

func loadPrivateBundle(tx *bbolt.Tx, bundleID []byte) (*structures.PrivateBundle, error) {
	root := tx.Bucket(bucketPrivateBundles)
	if root == nil {
		return nil, apperr.New("private bundles bucket not found")
	}
	bucket := root.Bucket(bundleID)
	if bucket == nil || bucket.Get(keyPrivateBundle) == nil {
		return nil, apperr.New("private bundle not found")
	}
	privateBundle := &structures.PrivateBundle{}
	if err := messagepack.Unmarshal(bucket.Get(keyPrivateBundle), privateBundle); err != nil {
		return nil, apperr.Wrap("decode private bundle", err)
	}
	if privateBundle.ID < 0 {
		return nil, apperr.New("invalid stored private bundle")
	}
	return privateBundle, nil
}
