package database

import (
	identityproto "P2Chat/cmd/server/internals/proto_generated/identity/proto_server_identity"
	"P2Chat/pkg/apperr"
	"errors"

	"github.com/dgraph-io/badger/v4"
	proto "google.golang.org/protobuf/proto"
)

var ErrorNotFound error

// SaveID stores the IK keys in the database under the "SERVER_IK" key.
func SaveID(s *identityproto.StoredServerIdentity) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}
	if s == nil {
		return apperr.New("server identity is nil")
	}

	serialized, err := proto.Marshal(s)
	if err != nil {
		return apperr.Wrap("marshal server identity", err)
	}

	err = db_manager.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("SERVER_IK"), serialized)
	})
	if err != nil {
		return apperr.Wrap("save IK into the database", err)
	}

	return nil
}

// LoadID returns the server identity stored as one protobuf message.
func LoadID() (bool, *identityproto.StoredServerIdentity, error) {
	if !IsInitialized() {
		return false, nil, apperr.New("database not initialized")
	}

	var getErr error
	var ikScheme []byte
	getErr = db_manager.View(func(txn *badger.Txn) error {
		val, err := txn.Get([]byte("SERVER_IK"))
		if err != nil {
			return err
		}
		ikScheme, err = val.ValueCopy(nil)
		return err
	})
	if getErr != nil {
		if errors.Is(getErr, badger.ErrKeyNotFound) {
			return false, nil, nil
		}
		return false, nil, apperr.Wrap("error during server load ID", getErr)
	}

	stored := &identityproto.StoredServerIdentity{}
	if err := proto.Unmarshal(ikScheme, stored); err != nil {
		return false, nil, apperr.Wrap("unmarshal stored server identity", err)
	}

	return true, stored, nil
}
