package database

import (
	"P2Chat/pkg/apperr"

	bbolt "go.etcd.io/bbolt"
)

func SavePassTokens(serverID []byte, tokens [][]byte) error {
	return defaultStore.SavePassTokens(serverID, tokens)
}

func (s *Store) SavePassTokens(serverID []byte, tokens [][]byte) error {
	if len(serverID) != 32 || len(tokens) != 3 {
		return apperr.New("invalid pass token storage parameters")
	}
	for _, token := range tokens {
		if len(token) == 0 || len(token) > 512 {
			return apperr.New("invalid serialized pass token")
		}
	}
	return s.update(func(tx *bbolt.Tx) error {
		servers := tx.Bucket([]byte(bucketServersName))
		if servers == nil {
			return apperr.New("servers bucket not found")
		}
		server := servers.Bucket(serverID)
		if server == nil || server.Get([]byte(keyServerIdentityName)) == nil {
			return apperr.New("server identity not found")
		}
		if server.Bucket([]byte(bucketPassTokensName)) != nil {
			if err := server.DeleteBucket([]byte(bucketPassTokensName)); err != nil {
				return err
			}
		}
		bucket, err := server.CreateBucket([]byte(bucketPassTokensName))
		if err != nil {
			return err
		}
		for i, token := range tokens {
			if err := bucket.Put([]byte{byte(i + 1)}, token); err != nil {
				return err
			}
		}
		return nil
	})
}

func LoadPassToken(serverID []byte) (*PassToken, error) {
	return defaultStore.LoadPassToken(serverID)
}

func (s *Store) LoadPassToken(serverID []byte) (*PassToken, error) {
	if len(serverID) != 32 {
		return nil, apperr.New("invalid server ID")
	}
	var token *PassToken
	err := s.view(func(tx *bbolt.Tx) error {
		servers := tx.Bucket([]byte(bucketServersName))
		if servers == nil {
			return nil
		}
		server := servers.Bucket(serverID)
		if server == nil {
			return nil
		}
		bucket := server.Bucket([]byte(bucketPassTokensName))
		if bucket == nil {
			return nil
		}
		key, value := bucket.Cursor().First()
		if len(key) != 1 || len(value) == 0 {
			return nil
		}
		token = &PassToken{Slot: key[0], Serialized: append([]byte(nil), value...)}
		return nil
	})
	return token, err
}

func DeletePassToken(serverID []byte, slot byte) error {
	return defaultStore.DeletePassToken(serverID, slot)
}

func (s *Store) DeletePassToken(serverID []byte, slot byte) error {
	if len(serverID) != 32 || slot < 1 || slot > 3 {
		return apperr.New("invalid pass token deletion parameters")
	}
	return s.update(func(tx *bbolt.Tx) error {
		servers := tx.Bucket([]byte(bucketServersName))
		if servers == nil {
			return nil
		}
		server := servers.Bucket(serverID)
		if server == nil {
			return nil
		}
		bucket := server.Bucket([]byte(bucketPassTokensName))
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte{slot})
	})
}
