package login

import (
	"P2Chat/cmd/client/database"
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	x25519 "P2Chat/cmd/client/internals/keys/x25519"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	"P2Chat/cmd/client/internals/protocol/pqxdh"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"
	"github.com/awnumar/memguard"
	"google.golang.org/protobuf/proto"
)

// Credentials stay with the orchestrator, never in session channels.
type Credentials struct {
	BundleID []byte
	MLDSA    *mldsa.PrivateMLDSA
	X25519   *x25519.PrivateX25519
}

func LoadIdentity(bundle *database.LoginBundle, password *memguard.Enclave) (*Credentials, error) {
	if bundle == nil || password == nil || bundle.LocalID < 0 {
		return nil, apperr.New("missing login credentials")
	}
	identity, err := pqxdh.LoadIKKeys(password, storage.BasePath, bundle.LocalID)
	if err != nil {
		return nil, err
	}
	pkX25519 := identity.PrivateX25519.PublicKey()
	if pkX25519 == nil {
		return nil, apperr.New("cannot recover X25519 public key")
	}
	h1, h2 := sha256.Sum256(pkX25519.Bytes()), sha256.Sum256(identity.PublicMLDSA.Bytes())
	id := sha256.Sum256(append(h1[:], h2[:]...))
	if len(bundle.BundleID) != 0 && !bytes.Equal(bundle.BundleID, id[:]) {
		return nil, apperr.New("local identity keys do not match registered bundle")
	}
	return &Credentials{BundleID: id[:], MLDSA: identity.PrivateMLDSA, X25519: identity.PrivateX25519}, nil
}

func SignProof(keys *Credentials, message []byte) ([]byte, error) {
	if keys == nil || keys.MLDSA == nil || keys.X25519 == nil {
		return nil, apperr.New("missing login signing keys")
	}
	proof := &loginproto.LoginProof{}
	var err error
	proof.MldsaSignature, err = keys.MLDSA.Sign(message, nil, false)
	if err != nil {
		return nil, err
	}
	proof.X25519Signature, err = keys.X25519.Sign(message)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(proof)
}
