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

var (
	keyServerIdentity = []byte("identity")
	keyServerEndpoint = []byte("endpoint")
	keyServerIP       = []byte("observed-ip")
	keyLoginBundle    = []byte("login-bundle")
	bucketServerUsers = []byte("users")
)

// SaveServerID checks whether the verified identity exists before storing it.
func SaveServerID(serverID *idserver.IDServer) (bool, error) {
	if !IsInitialized() {
		return false, apperr.New("database not initialized")
	}
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
	err = DB.Update(func(tx *bbolt.Tx) error {
		servers, err := tx.CreateBucketIfNotExists(bucketServers)
		if err != nil {
			return err
		}
		bucket := servers.Bucket(serverID.ID)
		if bucket != nil {
			exists = true
			return checkStoredIdentity(bucket.Get(keyServerIdentity), &identity)
		}
		bucket, err = servers.CreateBucket(serverID.ID)
		if err != nil {
			return err
		}
		return bucket.Put(keyServerIdentity, serialized)
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
	exists := false
	changed := false
	blocked := false
	err = DB.Update(func(tx *bbolt.Tx) error {
		servers, err := tx.CreateBucketIfNotExists(bucketServers)
		if err != nil {
			return err
		}
		blacklist, err := tx.CreateBucketIfNotExists(bucketServerBlacklist)
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
			if err := bucket.Put(keyServerIdentity, serialized); err != nil {
				return err
			}
		} else {
			exists = true
			if err := checkStoredIdentity(bucket.Get(keyServerIdentity), &identity); err != nil {
				return err
			}
		}
		previousEndpoint := bucket.Get(keyServerEndpoint)
		changed = exists && previousEndpoint != nil && !bytes.Equal(previousEndpoint, []byte(address.Endpoint))
		if !bytes.Equal(previousEndpoint, []byte(address.Endpoint)) {
			if err := bucket.Put(keyServerEndpoint, []byte(address.Endpoint)); err != nil {
				return err
			}
		}
		if !bytes.Equal(bucket.Get(keyServerIP), []byte(address.IP)) {
			return bucket.Put(keyServerIP, []byte(address.IP))
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
	return DB.Update(func(tx *bbolt.Tx) error {
		servers := tx.Bucket(bucketServers)
		if servers == nil {
			return apperr.New("servers bucket not found")
		}
		server := servers.Bucket(serverID)
		if server == nil || server.Get(keyServerIdentity) == nil {
			return apperr.New("server identity not found")
		}
		privateBundle, err := loadPrivateBundle(tx, bundle.BundleID)
		if err != nil {
			return err
		}
		if privateBundle.ID != bundle.LocalID {
			return apperr.New("login bundle does not match local private bundle")
		}
		return server.Put(keyLoginBundle, bundle.BundleID)
	})
}

func LoadLoginBundle(serverID []byte) (*LoginBundle, error) {
	if !IsInitialized() || len(serverID) != 32 {
		return nil, apperr.New("invalid server ID or database not initialized")
	}
	var bundle *LoginBundle
	err := DB.View(func(tx *bbolt.Tx) error {
		servers := tx.Bucket(bucketServers)
		if servers == nil {
			return nil
		}
		server := servers.Bucket(serverID)
		if server == nil || server.Get(keyLoginBundle) == nil {
			return nil
		}
		bundleID := append([]byte(nil), server.Get(keyLoginBundle)...)
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
		if server != nil && bytes.Equal(server.Get(keyServerEndpoint), []byte(endpoint)) {
			return append([]byte(nil), serverID...)
		}
	}
	return nil
}
