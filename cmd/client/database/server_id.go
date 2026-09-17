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

type ServerAddress struct {
	Endpoint string
	IP       string
}

// SaveServerID checks whether the verified identity exists before storing it.
func SaveServerID(serverID *idserver.IDServer) (bool, error) {
	if !IsInitialized() {
		return false, apperr.New("database not initialized")
	}
	if serverID == nil || len(serverID.ID) != 32 {
		return false, apperr.New("invalid server ID")
	}
	serialized, err := messagepack.Marshal(serverID)
	if err != nil {
		return false, apperr.Wrap("serialize server ID", err)
	}
	exists := false
	err = DB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("server:identities"))
		if err != nil {
			return err
		}
		exists = bucket.Get(serverID.ID) != nil
		return bucket.Put(serverID.ID, serialized)
	})
	if err != nil {
		return false, apperr.Wrap("save server ID", err)
	}
	return exists, nil
}


// SaveKnownServer create the buckets for the server identification process and save the IDServer bundle (blacklist, endpoint, id, IP)
func SaveKnownServer(serverID *idserver.IDServer, endpoint string) (bool, bool, error) {
	if !IsInitialized() || serverID == nil || len(serverID.ID) != 32 {
		return false, false, apperr.New("invalid server identity or database not initialized")
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false, false, apperr.Wrap("invalid server endpoint", err)
	}
	address := ServerAddress{Endpoint: endpoint}
	if ip := net.ParseIP(host); ip != nil {
		address.IP = ip.String()
	}
	identity := *serverID
	identity.MldsaSign, identity.X25519Sign = nil, nil
	serialized, err := messagepack.Marshal(&identity)
	if err != nil {
		return false, false, err
	}
	serializedAddress, err := messagepack.Marshal(address)
	if err != nil {
		return false, false, err
	}
	exists := false
	changed := false
	blocked := false
	err = DB.Update(func(tx *bbolt.Tx) error {
		identities := tx.Bucket([]byte("server:identities"))
		
		endpoints := tx.Bucket([]byte("server:endpoints"))
		
		addresses := tx.Bucket([]byte("server:observed-ip"))
		
		blacklist := tx.Bucket([]byte("server:blacklist"))
		
		if blacklist.Get(serverID.ID) != nil {
			return apperr.New("server identity is blacklisted")
		}
		if previous := endpoints.Get([]byte(endpoint)); previous != nil && !bytes.Equal(previous, serverID.ID) {
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
		exists = identities.Get(serverID.ID) != nil
		previousAddress := addresses.Get(serverID.ID)
		changed = exists && previousAddress != nil && !bytes.Equal(previousAddress, serializedAddress)
		if !exists {
			if err := identities.Put(serverID.ID, serialized); err != nil {
				return err
			}
		}
		if !bytes.Equal(endpoints.Get([]byte(endpoint)), serverID.ID) {
			if err := endpoints.Put([]byte(endpoint), serverID.ID); err != nil {
				return err
			}
		}
		if !bytes.Equal(previousAddress, serializedAddress) {
			return addresses.Put(serverID.ID, serializedAddress)
		}
		return nil
	})
	if err != nil {
		return false, false, apperr.Wrap("save server endpoint", err)
	}
	if blocked {
		return false, false, apperr.New("server identity changed for pinned endpoint")
	}
	return exists, changed, nil
}

type LoginBundle struct {
	LocalID  int
	BundleID []byte
}


func SaveLoginBundle(serverID []byte, bundle *LoginBundle) error {
	if !IsInitialized() || len(serverID) != 32 || bundle == nil || len(bundle.BundleID) != 32 || bundle.LocalID < 0 {
		return apperr.New("invalid login bundle")
	}
	serialized, err := messagepack.Marshal(bundle)
	if err != nil {
		return apperr.Wrap("serialize login bundle", err)
	}
	return DB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("server:login-bundle"))
		if err != nil {
			return err
		}
		return bucket.Put(serverID, serialized)
	})
}

func LoadLoginBundle(serverID []byte) (*LoginBundle, error) {
	if !IsInitialized() {
		return nil, apperr.New("database not initialized")
	}
	var bundle *LoginBundle
	err := DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("server:login-bundle"))
		if bucket == nil || bucket.Get(serverID) == nil {
			return nil
		}
		bundle = &LoginBundle{}
		if err := messagepack.Unmarshal(bucket.Get(serverID), bundle); err != nil {
			return err
		}
		if len(bundle.BundleID) != 32 || bundle.LocalID < 0 {
			return apperr.New("invalid stored login bundle")
		}
		return nil
	})
	return bundle, err
}
