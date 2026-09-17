package database

import (
	"P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

// SaveUserBundle save the nickname and his bundle into the database but have to know the server ID. the store into the databse is classified by
// id_server:nickname and then
func SaveUserBundle(userBundle *proto_struct_bundle.UserBundle, idServer []byte) error {
	if userBundle == nil || len(idServer) == 0 || len(userBundle.Nickname) == 0 {
		return apperr.New("invalid user bundle storage parameters")
	}

	s, err := proto.Marshal(userBundle)
	if err != nil {
		return err
	}

	err = DB.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("id_server+nickname:bundlebytes"))
		if b == nil {
			return apperr.New("user bundle bucket not found")
		}

		key := CreateKey(idServer, userBundle.Nickname)

		if CheckNickname(b, key) != nil {
			return apperr.New("user already present")
		}

		return b.Put(key, s)
	})

	return err
}

func CheckNickname(bucket *bbolt.Bucket, key []byte) []byte {
	return bucket.Get(key)
}

func LoadBundle(nickname []byte, idServer []byte) (*proto_struct_bundle.UserBundle, error) {
	if len(idServer) == 0 || len(nickname) == 0 {
		return nil, apperr.New("invalid user bundle lookup parameters")
	}

	var result []byte
	err := DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("id_server+nickname:bundlebytes"))
		if b == nil {
			return apperr.New("user bundle bucket not found")
		}

		key := CreateKey(idServer, nickname)

		raw := b.Get(key)
		if raw == nil {
			return apperr.New("user bundle not found")
		}
		result = append([]byte(nil), raw...)

		return nil
	})
	if err != nil {
		return nil, err
	}
	p := &proto_struct_bundle.UserBundle{}
	if err := proto.Unmarshal(result, p); err != nil {
		return nil, apperr.Wrap("decode stored user bundle", err)
	}
	return p, nil
}

func CreateKey(idServer []byte, nickname []byte) []byte {
	key := []byte{}
	key = append(key, idServer[:]...)
	key = append(key, byte(0))
	key = append(key, nickname...)
	return key
}