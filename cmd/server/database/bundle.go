package database

import (
	bundleStruct "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"
	"encoding/binary"

	"github.com/dgraph-io/badger/v4"
	"google.golang.org/protobuf/proto"
)

// SaveBundle stores the public user bundle and its one-time public sets.
func SaveBundle(bundle *bundleStruct.UserBundle, curvePublicSets, kemPublicSets [][]byte, idBundle [32]byte) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}
	if bundle == nil || bundle.GetPublicBundle() == nil || len(bundle.GetNickname()) == 0 {
		return apperr.New("invalid user bundle")
	}
	bundleSerialized, err := proto.Marshal(bundle)
	if err != nil {
		return apperr.Wrap("serialize user bundle", err)
	}

	return db_manager.Update(func(txn *badger.Txn) error {
		nicknameKey := append([]byte("nickname:"), bundle.GetNickname()...)
		if err := txn.Set(nicknameKey, idBundle[:]); err != nil {
			return err
		}

		if err := txn.Set(idBundle[:], bundleSerialized); err != nil {
			return err
		}

		for i, value := range curvePublicSets {
			if err := txn.Set(publicSetKey(idBundle, "curve", uint32(i)), value); err != nil {
				return err
			}
		}

		for i, value := range kemPublicSets {
			if err := txn.Set(publicSetKey(idBundle, "kem", uint32(i)), value); err != nil {
				return err
			}
		}

		return nil
	})
}

func DeleteAllAssociation(idBundle [32]byte, nickname []byte, curveSetCount, kemSetCount int) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}
	return db_manager.Update(func(txn *badger.Txn) error {
		nicknameKey := append([]byte("nickname:"), nickname...)
		if err := txn.Delete(nicknameKey); err != nil {
			return err
		}
		if err := txn.Delete(idBundle[:]); err != nil {
			return err
		}

		for i := range curveSetCount {
			if err := txn.Delete(publicSetKey(idBundle, "curve", uint32(i))); err != nil {
				return err
			}
		}

		for i := range kemSetCount {
			if err := txn.Delete(publicSetKey(idBundle, "kem", uint32(i))); err != nil {
				return err
			}
		}

		return nil
	})
}

func publicSetKey(idBundle [32]byte, setType string, index uint32) []byte {
	key := make([]byte, 0, len(idBundle)+len(setType)+6)
	key = append(key, idBundle[:]...)
	key = append(key, ':')
	key = append(key, setType...)
	key = append(key, ':')
	var encodedIndex [4]byte
	binary.BigEndian.PutUint32(encodedIndex[:], index)
	return append(key, encodedIndex[:]...)
}
