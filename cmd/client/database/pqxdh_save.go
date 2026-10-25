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

func SaveSets(arraySet [][]byte, bundleID []byte, setType string) error {
	return defaultStore.SaveSets(arraySet, bundleID, setType)
}

func (s *Store) SaveSets(arraySet [][]byte, bundleID []byte, setType string) error {
	if len(bundleID) != 32 {
		return apperr.New("invalid private sets storage parameters")
	}

	var setBucketName []byte
	switch setType {
	case "curve":
		setBucketName = []byte(bucketCurveSetsName)
	case "kem":
		setBucketName = []byte(bucketKEMSetsName)
	default:
		return apperr.New("invalid private set type")
	}

	err := s.update(func(tx *bbolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte(bucketPrivateBundlesName))
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
	return defaultStore.SaveCommitment(commitment, bundleID)
}

func (s *Store) SaveCommitment(commitment *commitmentproto.CommitmentSchemePrivate, bundleID []byte) error {
	if commitment == nil || len(bundleID) != 32 {
		return apperr.New("invalid commitment storage parameters")
	}
	serialized, err := proto.Marshal(commitment)
	if err != nil {
		return apperr.Wrap("serialize private commitment", err)
	}
	return s.update(func(tx *bbolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte(bucketPrivateBundlesName))
		if err != nil {
			return err
		}
		bundle, err := root.CreateBucketIfNotExists(bundleID)
		if err != nil {
			return err
		}
		return bundle.Put([]byte(keyCommitmentName), serialized)
	})
}

func LoadCommitment(bundleID []byte) (*commitmentproto.CommitmentSchemePrivate, error) {
	return defaultStore.LoadCommitment(bundleID)
}

func (s *Store) LoadCommitment(bundleID []byte) (*commitmentproto.CommitmentSchemePrivate, error) {
	if len(bundleID) != 32 {
		return nil, apperr.New("invalid commitment load parameters")
	}
	var commitment *commitmentproto.CommitmentSchemePrivate
	err := s.view(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(bucketPrivateBundlesName))
		if root == nil {
			return apperr.New("private bundles bucket not found")
		}
		bundle := root.Bucket(bundleID)
		if bundle == nil || bundle.Get([]byte(keyCommitmentName)) == nil {
			return apperr.New("private commitment not found")
		}
		stored := &commitmentproto.CommitmentSchemePrivate{}
		if err := proto.Unmarshal(bundle.Get([]byte(keyCommitmentName)), stored); err != nil {
			return apperr.Wrap("decode private commitment", err)
		}
		commitment = stored
		return nil
	})
	return commitment, err
}

// save the private part of the bundle inside the database, serialize the privateBundle inside of it
func SavePrivateBundle(privateBundle *structures.PrivateBundle, bundleID []byte) error {
	return defaultStore.SavePrivateBundle(privateBundle, bundleID)
}

func (s *Store) SavePrivateBundle(privateBundle *structures.PrivateBundle, bundleID []byte) error {
	if privateBundle == nil || privateBundle.ID < 0 || privateBundle.SPKID < 0 || privateBundle.LastResortID < 0 || len(bundleID) != 32 {
		return apperr.New("invalid private bundle storage parameters")
	}

	var err error

	serializedStruct, err := messagepack.Marshal(privateBundle)
	if err != nil {
		return apperr.Wrap("error during serialization of the private struct: ", err)
	}

	err = s.update(func(tx *bbolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte(bucketPrivateBundlesName))
		if err != nil {
			return err
		}
		bucket, err := root.CreateBucketIfNotExists(bundleID)
		if err != nil {
			return err
		}

		// the database must contains only the private part, not the public
		if err := bucket.Put([]byte(keyPrivateBundleName), serializedStruct); err != nil {
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
	root := tx.Bucket([]byte(bucketPrivateBundlesName))
	if root == nil {
		return nil, apperr.New("private bundles bucket not found")
	}
	bucket := root.Bucket(bundleID)
	if bucket == nil || bucket.Get([]byte(keyPrivateBundleName)) == nil {
		return nil, apperr.New("private bundle not found")
	}
	privateBundle := &structures.PrivateBundle{}
	if err := messagepack.Unmarshal(bucket.Get([]byte(keyPrivateBundleName)), privateBundle); err != nil {
		return nil, apperr.Wrap("decode private bundle", err)
	}
	if privateBundle.ID < 0 || privateBundle.SPKID < 0 || privateBundle.LastResortID < 0 {
		return nil, apperr.New("invalid stored private bundle")
	}
	return privateBundle, nil
}
