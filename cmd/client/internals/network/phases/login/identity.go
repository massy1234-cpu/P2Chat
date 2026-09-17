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
	BundleID      []byte
	MLDSA, X25519 *memguard.Enclave
}

func LoadIdentity(bundle *database.LoginBundle, password *memguard.Enclave) (*Credentials, error) {
	if bundle == nil || password == nil || bundle.LocalID < 0 {
		return nil, apperr.New("missing login credentials")
	}
	skMLDSA, pkMLDSA, skX25519, err := pqxdh.LoadIKKeys(password, storage.BasePath, bundle.LocalID)
	if err != nil {
		return nil, err
	}
	pkX25519 := x25519.ExtractPublicKey(skX25519)
	if pkX25519 == nil {
		return nil, apperr.New("cannot recover X25519 public key")
	}
	h1, h2 := sha256.Sum256(pkX25519.Bytes()), sha256.Sum256(pkMLDSA.Key)
	id := sha256.Sum256(append(h1[:], h2[:]...))
	if len(bundle.BundleID) != 0 && !bytes.Equal(bundle.BundleID, id[:]) {
		return nil, apperr.New("local identity keys do not match registered bundle")
	}
	return &Credentials{BundleID: id[:], MLDSA: skMLDSA, X25519: skX25519}, nil
}

func SignProof(keys *Credentials, message []byte) ([]byte, error) {
	if keys == nil || keys.MLDSA == nil || keys.X25519 == nil {
		return nil, apperr.New("missing login signing keys")
	}
	proof := &loginproto.LoginProof{}
	var err error
	proof.MldsaSignature, err = mldsa.Sign(keys.MLDSA, message, nil, false)
	if err != nil {
		return nil, err
	}
	proof.X25519Signature, err = x25519.Sign(keys.X25519, message)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(proof)
}

// EncodeParameters contains only public connection and account data.
func EncodeParameters(binding, serverID, bundleID []byte, fast bool) ([]byte, error) {
	if len(binding) != 32 || len(serverID) != 32 || len(bundleID) != 32 {
		return nil, apperr.New("invalid login parameters")
	}
	data := append([]byte(nil), binding...)
	data = append(data, serverID...)
	data = append(data, bundleID...)
	if fast {
		return append(data, 1), nil
	}
	return append(data, 0), nil
}
