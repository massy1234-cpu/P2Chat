package idserver

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/server/database"
	identityproto "P2Chat/cmd/server/internals/proto_generated/identity/proto_server_identity"
	"P2Chat/pkg/apperr"
	"crypto/ecdh"

	"github.com/awnumar/memguard"
	proto "google.golang.org/protobuf/proto"
)

// struct for contains current IK keys loaded from database
type CurrentID struct {
	MLDSAPrivateKey *memguard.Enclave
	X25519Private   *memguard.Enclave
	PubMLDSA        *mldsa87.PublicKey
	PubX25519       *ecdh.PublicKey
}

// global pointer to the IK keys
var currentID *CurrentID

// Init loads or creates the server identity after database.Init().
func Init(level int, password *memguard.Enclave, HSM bool) error {
	res, p, err := database.LoadID()
	if err != nil {
		return apperr.Wrap("error during ID load", err)
	}
	if res {
		id, err := DeserializeIK(p, password)
		if err != nil {
			return apperr.Wrap("deserialize server identity", err)
		}
		currentID = id
		return nil
	}

	mldsaEnclaved, mldsaPublic, err := mldsa_keys.CreateKeys()
	if err != nil {
		return apperr.Wrap("create ML-DSA server keys", err)
	}

	x25519Enclaved, x25519Public, err := x25519.CreateKey()
	if err != nil {
		return apperr.Wrap("create X25519 server keys", err)
	}

	id := &CurrentID{
		MLDSAPrivateKey: mldsaEnclaved,
		X25519Private:   x25519Enclaved,
		PubMLDSA:        mldsaPublic,
		PubX25519:       x25519Public,
	}

	protoCurrent, err := SerializeID(id, level, password, HSM)
	if err != nil {
		return apperr.Wrap("serialize server identity", err)
	}

	if err := database.SaveID(protoCurrent); err != nil {
		return apperr.Wrap("save server identity", err)
	}

	currentID = id
	return nil
}

func GetCurrentID() *CurrentID {
	return currentID
}

// SerializeID get the CurrentIK struct and serialize it
func SerializeID(id *CurrentID, level int, password *memguard.Enclave, HSM bool) (*identityproto.StoredServerIdentity, error) {
	mldsaProto, err := mldsa_keys.EncryptPrivateKey(password, id.MLDSAPrivateKey, level, HSM)
	if err != nil {
		return nil, apperr.Wrap("error during mldsa key serialization", err)
	}

	x25519Proto, err := x25519.EncryptPrivateKey(password, id.X25519Private, level, HSM)
	if err != nil {
		return nil, apperr.Wrap("error during x25519 key serialization", err)
	}

	mldsaPublic := id.PubMLDSA.Bytes()
	x25519Public := id.PubX25519.Bytes()

	scheme := &identityproto.StoredServerIdentity{
		MldsaPrivate:  mldsaProto,
		X25519Private: x25519Proto,
		PubMldsa:      mldsaPublic,
		PubX25519:     x25519Public,
	}

	return scheme, nil
}

// DeserializeIK converts the serialized proto IK back into the CurrentIK struct,
// restoring the private keys into memguard enclaves ready to be used.
func DeserializeIK(s *identityproto.StoredServerIdentity, password *memguard.Enclave) (*CurrentID, error) {
	mldsaEnclaved, err := mldsa_keys.DecodePrivateKey(password, s.MldsaPrivate)
	if err != nil {
		return nil, apperr.Wrap("decode ML-DSA server private key", err)
	}

	x25519Serialized, err := proto.Marshal(s.X25519Private)
	if err != nil {
		return nil, apperr.Wrap("marshal X25519 server private key", err)
	}
	x25519Enclaved, err := x25519.DecryptPrivateKey(password, x25519Serialized)
	if err != nil {
		return nil, apperr.Wrap("decrypt X25519 server private key", err)
	}

	var mldsaPublic mldsa87.PublicKey
	if err := mldsaPublic.UnmarshalBinary(s.PubMldsa); err != nil {
		return nil, apperr.Wrap("decode ML-DSA server public key", err)
	}

	x25519Public, err := ecdh.X25519().NewPublicKey(s.PubX25519)
	if err != nil {
		return nil, apperr.Wrap("decode X25519 server public key", err)
	}

	return &CurrentID{
		MLDSAPrivateKey: mldsaEnclaved,
		X25519Private:   x25519Enclaved,
		PubMLDSA:        &mldsaPublic,
		PubX25519:       x25519Public,
	}, nil
}
