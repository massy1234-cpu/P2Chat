package database

import (
	"P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/cmd/client/internals/proto_generated/x25519/proto_struct_x25519"
	"P2Chat/pkg/apperr"
	"errors"

	"github.com/dgraph-io/badger/v4"
	messagepack "github.com/vmihailenco/msgpack/v5"
	proto "google.golang.org/protobuf/proto"
)

// ikRaw is the msgpack layout stored under "SERVER_IK": each field holds the
// raw serialized bytes that LoadID decodes into the idserver.ProtoCurrentIK struct.
type ikRaw struct {
	MLDSAPrivateKey []byte `msgpack:"mldsaPriv"`
	X25519Private   []byte `msgpack:"x25519Priv"`
	PubMLDSA        []byte `msgpack:"pubMLDSA"`
	PubX25519       []byte `msgpack:"pubX25519"`
}

// struct that contains the IK keys serialized and encrypted 
type ProtoCurrentIK struct {
	MLDSAProtoSerialized		*proto_struct_mldsa.PrivateKeyMLDSA
	X25519ProtoSerialized   	*proto_struct_x25519.PrivateKeyX25519
	PubMLDSA        			[]byte
	PubX25519       			[]byte
}

var ErrorNotFound error

// toRaw converts the proto struct from server_id.go into the raw serialized bytes layout.
func protoToRaw(s *ProtoCurrentIK) (*ikRaw, error) {

	mldsaPriv, err := proto.Marshal(s.MLDSAProtoSerialized)
	if err != nil {
		return nil, apperr.Wrap("marshal ML-DSA private key", err)
	}

	x25519Priv, err := proto.Marshal(s.X25519ProtoSerialized)
	if err != nil {
		return nil, apperr.Wrap("marshal X25519 private key", err)
	}

	return &ikRaw{
		MLDSAPrivateKey: mldsaPriv,
		X25519Private:   x25519Priv,
		PubMLDSA:        s.PubMLDSA,
		PubX25519:       s.PubX25519,
	}, nil
}

// toProto decodes the raw serialized bytes back into the idserver.ProtoCurrentIK struct.
func (raw *ikRaw) toProto() (*ProtoCurrentIK, error) {

	s := &ProtoCurrentIK{}

	s.MLDSAProtoSerialized = &proto_struct_mldsa.PrivateKeyMLDSA{}
	if err := proto.Unmarshal(raw.MLDSAPrivateKey, s.MLDSAProtoSerialized); err != nil {
		return nil, apperr.Wrap("unmarshal ML-DSA private key", err)
	}

	s.X25519ProtoSerialized = &proto_struct_x25519.PrivateKeyX25519{}
	if err := proto.Unmarshal(raw.X25519Private, s.X25519ProtoSerialized); err != nil {
		return nil, apperr.Wrap("unmarshal X25519 private key", err)
	}

	s.PubMLDSA = raw.PubMLDSA
	s.PubX25519 = raw.PubX25519

	return s, nil
}

// SaveID stores the IK keys in the database under the "SERVER_IK" key.
func SaveID(s *ProtoCurrentIK) error {
	if !IsInitialized() {
		return apperr.New("database not initialized")
	}

	raw, err := protoToRaw(s)
	if err != nil {
		return apperr.Wrap("convert IK to raw bytes", err)
	}

	serialized, err := messagepack.Marshal(raw)
	if err != nil {
		return apperr.Wrap("marshal IK for the database", err)
	}

	err = db_manager.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("SERVER_IK"), serialized)
	})
	if err != nil {
		return apperr.Wrap("save IK into the database", err)
	}

	return nil
}


// check into memory if the IK keys are stored, return the scheme as protobuf
func LoadID() (bool, *ProtoCurrentIK, error) {
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

	// convert from []byte to ikRaw struct
	s := &ikRaw{}
	err := messagepack.Unmarshal(ikScheme,s)
	if err != nil {
		return false,nil,apperr.Wrap("error in unserialization from database,maybe data corruption,error : ",err)
	}

	// convert from ikRaw struct to ProtoCurrentIK
	p,err := s.toProto()
	if err != nil {
		return false,nil,apperr.Wrap("error : ",err)
	}

	return true,p,nil
}