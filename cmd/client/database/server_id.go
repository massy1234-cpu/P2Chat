package database

import (
	idserver "P2Chat/cmd/server/internals/ID_server"
	"P2Chat/pkg/apperr"
	"bytes"
	"net"
	"time"

	messagepack "github.com/vmihailenco/msgpack/v5"
	bbolt "go.etcd.io/bbolt"
)

// SaveServerID checks whether the verified identity exists before storing it.
func SaveServerID(serverID *idserver.IDServer) (bool, error) {
	return defaultStore.SaveServerID(serverID)
}

func (s *Store) SaveServerID(serverID *idserver.IDServer) (bool, error) {
	if serverID == nil || len(serverID.ID) != 32 {
		return false, apperr.New("invalid server ID")
	}
	identity := *serverID
	identity.MldsaSign, identity.X25519Sign = nil, nil
	serialized, err := messagepack.Marshal(&identity)
	if err != nil {
		return false, apperr.Wrap("serialize server ID", err)
	}
	exists := false
	err = s.update(func(tx *bbolt.Tx) error {
		servers, err := tx.CreateBucketIfNotExists([]byte(bucketServersName))
		if err != nil {
			return err
		}
		bucket := servers.Bucket(serverID.ID)
		if bucket != nil {
			exists = true
			return checkStoredIdentity(bucket.Get([]byte(keyServerIdentityName)), &identity)
		}
		bucket, err = servers.CreateBucket(serverID.ID)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(keyServerIdentityName), serialized)
	})
	if err != nil {
		return false, apperr.Wrap("save server ID", err)
	}
	return exists, nil
}

// ServerRegistrationStatus represents the outcome of verifying and storing a known server.
type ServerRegistrationStatus struct {
	AlreadyExists   bool
	EndpointChanged bool
}

// SaveKnownServer create the buckets for the server identification process and save the IDServer bundle (blacklist, endpoint, id, IP)
func SaveKnownServer(serverID *idserver.IDServer, endpoint string) (*ServerRegistrationStatus, error) {
	return defaultStore.SaveKnownServer(serverID, endpoint)
}

func (s *Store) SaveKnownServer(serverID *idserver.IDServer, endpoint string) (*ServerRegistrationStatus, error) {
	if serverID == nil || len(serverID.ID) != 32 {
		return nil, apperr.New("invalid server identity")
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, apperr.Wrap("invalid server endpoint", err)
	}
	address := ServerAddress{Endpoint: endpoint}
	if ip := net.ParseIP(host); ip != nil {
		address.IP = ip.String()
	}
	identity := *serverID
	identity.MldsaSign, identity.X25519Sign = nil, nil
	serialized, err := messagepack.Marshal(&identity)
	if err != nil {
		return nil, err
	}
	exists := false
	changed := false
	blocked := false
	err = s.update(func(tx *bbolt.Tx) error {
		servers, err := tx.CreateBucketIfNotExists([]byte(bucketServersName))
		if err != nil {
			return err
		}
		blacklist, err := tx.CreateBucketIfNotExists([]byte(bucketServerBlacklistName))
		if err != nil {
			return err
		}

		if blacklist.Get(serverID.ID) != nil {
			return apperr.New("server identity is blacklisted")
		}
		if previous := findServerByEndpoint(servers, endpoint); previous != nil && !bytes.Equal(previous, serverID.ID) {
			blocked = true
			record, err := messagepack.Marshal(struct {
				Reason, Endpoint string
				AddedAt          int64
			}{"endpoint identity changed", endpoint, time.Now().Unix()})
			if err != nil {
				return err
			}
			return blacklist.Put(serverID.ID, record)
		}
		bucket := servers.Bucket(serverID.ID)
		if bucket == nil {
			bucket, err = servers.CreateBucket(serverID.ID)
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte(keyServerIdentityName), serialized); err != nil {
				return err
			}
		} else {
			exists = true
			if err := checkStoredIdentity(bucket.Get([]byte(keyServerIdentityName)), &identity); err != nil {
				return err
			}
		}
		previousEndpoint := bucket.Get([]byte(keyServerEndpointName))
		changed = exists && previousEndpoint != nil && !bytes.Equal(previousEndpoint, []byte(address.Endpoint))
		if !bytes.Equal(previousEndpoint, []byte(address.Endpoint)) {
			if err := bucket.Put([]byte(keyServerEndpointName), []byte(address.Endpoint)); err != nil {
				return err
			}
		}
		if !bytes.Equal(bucket.Get([]byte(keyServerIPName)), []byte(address.IP)) {
			return bucket.Put([]byte(keyServerIPName), []byte(address.IP))
		}
		return nil
	})
	if err != nil {
		return nil, apperr.Wrap("save server endpoint", err)
	}
	if blocked {
		return nil, apperr.New("server identity changed for pinned endpoint")
	}
	return &ServerRegistrationStatus{
		AlreadyExists:   exists,
		EndpointChanged: changed,
	}, nil
}

func SaveLoginBundle(serverID []byte, bundle *LoginBundle) error {
	return defaultStore.SaveLoginBundle(serverID, bundle)
}

func (s *Store) SaveLoginBundle(serverID []byte, bundle *LoginBundle) error {
	if len(serverID) != 32 || bundle == nil || len(bundle.BundleID) != 32 || bundle.LocalID < 0 {
		return apperr.New("invalid login bundle")
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
		privateBundle, err := loadPrivateBundle(tx, bundle.BundleID)
		if err != nil {
			return err
		}
		if privateBundle.ID != bundle.LocalID {
			return apperr.New("login bundle does not match local private bundle")
		}
		return server.Put([]byte(keyLoginBundleName), bundle.BundleID)
	})
}

func LoadLoginBundle(serverID []byte) (*LoginBundle, error) {
	return defaultStore.LoadLoginBundle(serverID)
}

func (s *Store) LoadLoginBundle(serverID []byte) (*LoginBundle, error) {
	if len(serverID) != 32 {
		return nil, apperr.New("invalid server ID")
	}
	var bundle *LoginBundle
	err := s.view(func(tx *bbolt.Tx) error {
		servers := tx.Bucket([]byte(bucketServersName))
		if servers == nil {
			return nil
		}
		server := servers.Bucket(serverID)
		if server == nil || server.Get([]byte(keyLoginBundleName)) == nil {
			return nil
		}
		bundleID := append([]byte(nil), server.Get([]byte(keyLoginBundleName))...)
		if len(bundleID) != 32 {
			return apperr.New("invalid stored login bundle")
		}
		privateBundle, err := loadPrivateBundle(tx, bundleID)
		if err != nil {
			return err
		}
		bundle = &LoginBundle{LocalID: privateBundle.ID, BundleID: bundleID}
		return nil
	})
	return bundle, err
}

func checkStoredIdentity(serialized []byte, identity *idserver.IDServer) error {
	if len(serialized) == 0 {
		return apperr.New("stored server identity is missing")
	}
	stored := &idserver.IDServer{}
	if err := messagepack.Unmarshal(serialized, stored); err != nil {
		return apperr.Wrap("decode stored server identity", err)
	}
	if !bytes.Equal(stored.ID, identity.ID) || !bytes.Equal(stored.PubMLDSA, identity.PubMLDSA) ||
		!bytes.Equal(stored.PubX25519, identity.PubX25519) {
		return apperr.New("server ID matches but stored public identity differs")
	}
	return nil
}

func findServerByEndpoint(servers *bbolt.Bucket, endpoint string) []byte {
	cursor := servers.Cursor()
	for serverID, value := cursor.First(); serverID != nil; serverID, value = cursor.Next() {
		if value != nil {
			continue
		}
		server := servers.Bucket(serverID)
		if server != nil && bytes.Equal(server.Get([]byte(keyServerEndpointName)), []byte(endpoint)) {
			return append([]byte(nil), serverID...)
		}
	}
	return nil
}
