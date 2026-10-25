package database

import (
	"P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"
	"bytes"
	"errors"

	"github.com/dgraph-io/badger/v4"
	"google.golang.org/protobuf/proto"
)

type prekeyRecord struct {
	key   []byte
	value []byte
}

func SaveBundle(bundle *proto_struct_bundle.UserBundle, idBundle [32]byte) error {
	return defaultStore.SaveBundle(bundle, idBundle)
}

// SaveBundle stores the public bundle and every one-time public set in one
// transaction. The upload envelope and registration proof are not persisted.
func (s *Store) SaveBundle(bundle *proto_struct_bundle.UserBundle, idBundle [32]byte) error {
	if bundle == nil || bundle.GetPublicBundle() == nil {
		return apperr.New("invalid user bundle")
	}
	if err := ValidateNickname(bundle.GetNickname()); err != nil {
		return err
	}

	publicBundle := bundle.GetPublicBundle()
	if publicBundle.GetSpkId() < 0 || publicBundle.GetLastResortId() < 0 {
		return apperr.New("invalid SPK or last-resort identifier")
	}
	if proto.Size(publicBundle) > maxPublicBundleSize {
		return apperr.New("public bundle exceeds maximum size")
	}
	bundleSerialized, err := proto.Marshal(publicBundle)
	if err != nil {
		return apperr.Wrap("serialize public bundle", err)
	}
	records, err := preparePrekeyRecords(idBundle, bundle.GetCurvePublicSets(), bundle.GetKemPublicSets())
	if err != nil {
		return err
	}

	return s.update(func(txn *badger.Txn) error {
		nicknameDBKey := nicknameKey(bundle.GetNickname())
		reservationDBKey := reservationKey(bundle.GetNickname())
		if _, err := txn.Get(reservationDBKey); err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return apperr.New("nickname reservation missing or expired")
			}
			return err
		}
		if _, err := txn.Get(nicknameDBKey); err == nil {
			return apperr.New("nickname already assigned")
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		bundleDBKey := bundleKey(idBundle)
		if _, err := txn.Get(bundleDBKey); err == nil {
			return apperr.New("bundle ID already exists")
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		if err := txn.Set(nicknameDBKey, idBundle[:]); err != nil {
			return err
		}
		if err := txn.Delete(reservationDBKey); err != nil {
			return err
		}
		if err := txn.Set(bundleDBKey, bundleSerialized); err != nil {
			return err
		}
		for _, record := range records {
			if err := txn.Set(record.key, record.value); err != nil {
				return err
			}
		}
		return nil
	})
}

func preparePrekeyRecords(idBundle [32]byte, curveSets []*proto_struct_bundle.CurveSet, kemSets []*proto_struct_bundle.PqkemSet) ([]prekeyRecord, error) {
	if len(curveSets) > maxOneTimeSetsPerType || len(kemSets) > maxOneTimeSetsPerType {
		return nil, apperr.New("too many one-time prekey sets")
	}
	records := make([]prekeyRecord, 0, len(curveSets)+len(kemSets))
	curveIDs := make(map[int32]struct{}, len(curveSets))
	for _, set := range curveSets {
		if set == nil || set.GetIdentifier() < 0 {
			return nil, apperr.New("invalid curve prekey set")
		}
		if _, exists := curveIDs[set.GetIdentifier()]; exists {
			return nil, apperr.New("duplicate curve prekey identifier")
		}
		curveIDs[set.GetIdentifier()] = struct{}{}
		if proto.Size(set) > maxCurveSetSize {
			return nil, apperr.New("curve prekey set exceeds maximum size")
		}
		serialized, err := proto.Marshal(set)
		if err != nil {
			return nil, apperr.Wrap("serialize curve prekey set", err)
		}
		records = append(records, prekeyRecord{key: curvePrekeyKey(idBundle, uint32(set.GetIdentifier())), value: serialized})
	}

	kemIDs := make(map[int32]struct{}, len(kemSets))
	for _, set := range kemSets {
		if set == nil || set.GetIdentifier() < 0 {
			return nil, apperr.New("invalid KEM prekey set")
		}
		if _, exists := kemIDs[set.GetIdentifier()]; exists {
			return nil, apperr.New("duplicate KEM prekey identifier")
		}
		kemIDs[set.GetIdentifier()] = struct{}{}
		if proto.Size(set) > maxKEMSetSize {
			return nil, apperr.New("KEM prekey set exceeds maximum size")
		}
		serialized, err := proto.Marshal(set)
		if err != nil {
			return nil, apperr.Wrap("serialize KEM prekey set", err)
		}
		records = append(records, prekeyRecord{key: kemPrekeyKey(idBundle, uint32(set.GetIdentifier())), value: serialized})
	}
	return records, nil
}

func LoadPublicBundle(bundleID []byte) (*proto_struct_bundle.PublicBundle, error) {
	return defaultStore.LoadPublicBundle(bundleID)
}

func (s *Store) LoadPublicBundle(bundleID []byte) (*proto_struct_bundle.PublicBundle, error) {
	if len(bundleID) != 32 {
		return nil, apperr.New("invalid bundle ID")
	}
	serialized, err := s.getValue(bundleID)
	if err != nil {
		return nil, err
	}
	bundle := &proto_struct_bundle.PublicBundle{}
	if err := proto.Unmarshal(serialized, bundle); err != nil {
		return nil, apperr.Wrap("decode public bundle", err)
	}
	return bundle, nil
}

func BundleExists(bundleID []byte) (bool, error) {
	return defaultStore.BundleExists(bundleID)
}

func (s *Store) BundleExists(bundleID []byte) (bool, error) {
	if len(bundleID) != 32 {
		return false, apperr.New("invalid bundle ID")
	}
	err := s.view(func(txn *badger.Txn) error {
		_, err := txn.Get(bundleID)
		return err
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func DeleteUserData(idBundle [32]byte, nickname []byte) error {
	return defaultStore.DeleteUserData(idBundle, nickname)
}

func (s *Store) DeleteUserData(idBundle [32]byte, nickname []byte) error {
	if err := ValidateNickname(string(nickname)); err != nil {
		return err
	}
	return s.update(func(txn *badger.Txn) error {
		nicknameDBKey := nicknameKey(string(nickname))
		item, err := txn.Get(nicknameDBKey)
		if errors.Is(err, badger.ErrKeyNotFound) {
			return apperr.New("nickname association not found")
		}
		if err != nil {
			return err
		}
		storedID, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		if len(storedID) != len(idBundle) || !bytes.Equal(storedID, idBundle[:]) {
			return apperr.New("nickname and bundle ID do not match")
		}

		if err := txn.Delete(nicknameDBKey); err != nil {
			return err
		}
		if err := txn.Delete(reservationKey(string(nickname))); err != nil {
			return err
		}

		options := badger.DefaultIteratorOptions
		options.Prefix = idBundle[:]
		options.PrefetchValues = false
		iterator := txn.NewIterator(options)
		defer iterator.Close()

		keys := make([][]byte, 0)
		for iterator.Rewind(); iterator.Valid(); iterator.Next() {
			keys = append(keys, iterator.Item().KeyCopy(nil))
		}
		for _, key := range keys {
			if err := txn.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}
