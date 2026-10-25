package database

import (
	clientbundle "P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

// SaveUserBundle saves a user bundle under the server where it was obtained.
func SaveUserBundle(userBundle *proto_struct_bundle.UserBundle, idServer []byte, auth bool) error {
	return defaultStore.SaveUserBundle(userBundle, idServer, auth)
}

func (s *Store) SaveUserBundle(userBundle *proto_struct_bundle.UserBundle, idServer []byte, auth bool) error {
	if userBundle == nil || len(idServer) != 32 || len(userBundle.Nickname) == 0 {
		return apperr.New("invalid user bundle storage parameters")
	}

	publicBundleBytes, err := proto.Marshal(userBundle.GetPublicBundle())
	if err != nil {
		return apperr.Wrap("serialize received public bundle for verification", err)
	}
	verificationBundle := &clientbundle.PublicBundle{}
	if err := proto.Unmarshal(publicBundleBytes, verificationBundle); err != nil {
		return apperr.Wrap("decode received public bundle for verification", err)
	}
	valid, err := verificationBundle.VerifyBundle()
	if err != nil {
		return apperr.Wrap("verify received public bundle", err)
	}
	if !valid {
		return apperr.New("invalid received public bundle")
	}

	serialized, err := proto.Marshal(userBundle)
	if err != nil {
		return err
	}

	err = s.update(func(tx *bbolt.Tx) error {
		nickname := []byte(userBundle.Nickname)
		servers := tx.Bucket([]byte(bucketServersName))
		if servers == nil {
			return apperr.New("servers bucket not found")
		}
		server := servers.Bucket(idServer)
		if server == nil || server.Get([]byte(keyServerIdentityName)) == nil {
			return apperr.New("server identity not found")
		}
		b, err := server.CreateBucketIfNotExists([]byte(bucketServerUsersName))
		if err != nil {
			return err
		}

		if CheckNickname(b, nickname) != nil {
			return apperr.New("user already present")
		}

		if err := b.Put(nickname, serialized); err != nil {
			return err
		}

		authKey := append([]byte(prefixUserAuthentication), nickname...)
		if auth {
			return b.Put(authKey, []byte{1})
		}
		return b.Put(authKey, []byte{0})
	})

	return err
}

func CheckNickname(bucket *bbolt.Bucket, key []byte) []byte {
	return bucket.Get(key)
}

func LoadBundle(nickname []byte, idServer []byte) (*proto_struct_bundle.UserBundle, error) {
	return defaultStore.LoadBundle(nickname, idServer)
}

func (s *Store) LoadBundle(nickname []byte, idServer []byte) (*proto_struct_bundle.UserBundle, error) {
	if len(idServer) != 32 || len(nickname) == 0 {
		return nil, apperr.New("invalid user bundle lookup parameters")
	}

	var result []byte
	err := s.view(func(tx *bbolt.Tx) error {
		servers := tx.Bucket([]byte(bucketServersName))
		if servers == nil {
			return apperr.New("servers bucket not found")
		}
		server := servers.Bucket(idServer)
		if server == nil {
			return apperr.New("server identity not found")
		}
		b := server.Bucket([]byte(bucketServerUsersName))
		if b == nil {
			return apperr.New("user bundle bucket not found")
		}

		raw := b.Get(nickname)
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
