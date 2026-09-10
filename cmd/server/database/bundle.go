package database

import (
	bundleStruct "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"encoding/binary"

	"github.com/dgraph-io/badger/v4"
	"google.golang.org/protobuf/proto"
)

// SaveBundle save the bundle into the database, doing the asignations :
// nickname:name:ID_bundle
// ID_bundle:bundle_bytes
// ID_bundle:curve/kem:one_time_use
func SaveBundle(bundle *bundleStruct.BundleUploadPayload, idBundle [32]byte, nickname []byte) error {

	bundleSerialized, err := proto.Marshal(bundle)
	if err != nil {
		return err
	}

	err = db_manager.Update(func(txn *badger.Txn) error {
		nicknameKey := append([]byte("nickname:"), nickname...)
		err := txn.Set(nicknameKey, idBundle[:])
		if err != nil {
			return err
		}

		err = txn.Set(idBundle[:], bundleSerialized)
		if err != nil {
			return err
		}

		var t [4]byte
		for i, value := range bundle.CurvePublicSets {
			binary.BigEndian.PutUint32(t[:], uint32(i))
			v := make([]byte, 0, len(idBundle)+len(":curve:")+len(t))
			v = append(v, idBundle[:]...)
			v = append(v, []byte(":curve:")...)
			v = append(v, t[:]...)
			err = txn.Set(v, value)
			if err != nil {
				return err
			}
		}

		for i, value := range bundle.KemPublicSets {
			binary.BigEndian.PutUint32(t[:], uint32(i))
			v := make([]byte, 0, len(idBundle)+len(":kem:")+len(t))
			v = append(v, idBundle[:]...)
			v = append(v, []byte(":kem:")...)
			v = append(v, t[:]...)
			err = txn.Set(v, value)
			if err != nil {
				return err
			}
		}

		return err
	})

	return err
}

func DeleteAllAssociation(bundle *bundleStruct.BundleUploadPayload, idBundle [32]byte, nickname []byte) error {
	return db_manager.Update(func(txn *badger.Txn) error {
		nicknameKey := append([]byte("nickname:"), nickname...)
		if err := txn.Delete(nicknameKey); err != nil {
			return err
		}
		if err := txn.Delete(idBundle[:]); err != nil {
			return err
		}

		var t [4]byte
		for i := range bundle.CurvePublicSets {
			binary.BigEndian.PutUint32(t[:], uint32(i))
			v := make([]byte, 0, len(idBundle)+len(":curve:")+len(t))
			v = append(v, idBundle[:]...)
			v = append(v, []byte(":curve:")...)
			v = append(v, t[:]...)
			if err := txn.Delete(v); err != nil {
				return err
			}
		}

		for i := range bundle.KemPublicSets {
			binary.BigEndian.PutUint32(t[:], uint32(i))
			v := make([]byte, 0, len(idBundle)+len(":kem:")+len(t))
			v = append(v, idBundle[:]...)
			v = append(v, []byte(":kem:")...)
			v = append(v, t[:]...)
			if err := txn.Delete(v); err != nil {
				return err
			}
		}

		return nil
	})

}
