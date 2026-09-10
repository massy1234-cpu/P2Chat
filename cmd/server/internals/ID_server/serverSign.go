package idserver

import (
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/p2version"
	"P2Chat/pkg/apperr"
	"crypto/sha256"
)

type IDServer struct {
	VersionP2  uint8  // p2chat version of the server
	ID         []byte // hash(public mldsa | public x25519)
	MldsaSign  []byte
	X25519Sign []byte
	PubMLDSA   []byte
	PubX25519  []byte
}

// CreateIDbundle create the IDServer struct that identify the server with the client
// this function receives the local TLS binding and a nonce received from the client
// this avoid MIMT attack because the server have to sign the TLS binding with the private key and avoid a server impersonification cause the sign of the
// random nonce received from the client
func CreateIDBundle(binding []byte, nonce []byte) (*IDServer, error) {
	if len(binding) != 32 || len(nonce) != 32 {
		return nil, apperr.New("invalid server identification binding or nonce")
	}
	serverID := GetCurrentID()
	if serverID == nil {
		return nil, apperr.New("server IK not initialized")
	}

	// ID = hash(public mldsa | public x25519)
	pubMLDSA := serverID.PubMLDSA.Bytes()
	pubX25519 := serverID.PubX25519.Bytes()

	hash := sha256.New()
	hash.Write(pubMLDSA)
	hash.Write(pubX25519)
	id := hash.Sum(nil)

	// sign the []byte (p2version, nonce, tls binding)
	bytes := signatureCompose([]byte{p2version.GetVersion()}, nonce, binding)

	mldsaSign, err := mldsa_keys.Sign(serverID.MLDSAPrivateKey, bytes, nil, false)
	if err != nil {
		return nil, apperr.Wrap("sign server ID with ML-DSA", err)
	}

	x25519Sign, err := x25519.Sign(serverID.X25519Private, bytes)
	if err != nil {
		return nil, apperr.Wrap("sign server ID with X25519", err)
	}

	return &IDServer{
		VersionP2:  p2version.GetVersion(),
		ID:         id,
		MldsaSign:  mldsaSign,
		X25519Sign: x25519Sign,
		PubMLDSA:   pubMLDSA,
		PubX25519:  pubX25519,
	}, nil
}

func signatureCompose(parts ...[]byte) []byte {
	var result []byte

	for _, part := range parts {
		result = append(result, part...)
	}

	return result
}
