package structures

import (
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	mlkem "P2Chat/cmd/client/internals/keys/mlkem"
	"P2Chat/cmd/client/internals/keys/x25519"
)

type DecodedPublicBundle struct {
	ID           int32
	IKMLDSA      *mldsa.PublicMLDSA
	IKX25519     *x25519.PublicX25519
	SPKID        int
	LastResortID int
	SPK          *x25519.PublicX25519
	LastResort   *mlkem.PublicMLKEM
}

// private bundle stored in the database. IK_MLDSA is NOT here:
// it lives in the separate IK database with its own encryption layer
// (Argon2id + AES-256-GCM) and is referenced by ID when needed
type PrivateBundle struct {
	ID                int
	SPKID             int
	LastResortID      int
	SPK               []byte
	Last_resort_PQKEM []byte
}

// this 2 type (StoredPrivate(Curve/kem)Set) are used for store the key into the database, using
// MessagePack for the serialization
type StoredPrivateCurveSet struct {
	Identifier int
	X25519_key []byte
}

type StoredPrivatekemSet struct {
	Identifier int
	Pqkem_key  []byte
}

type PrivateCurveSet struct {
	Identifier int
	Key        *x25519.PrivateX25519
}

type PrivatekemSet struct {
	Identifier int
	Key        *mlkem.PrivateMLKEM
}

type PublicCurveSet struct {
	Identifier int
	Key        *x25519.PublicX25519
}

type PublickemSet struct {
	Identifier int
	Key        *mlkem.PublicMLKEM
}

type OneTimeKeys struct {
	X25519key PublicCurveSet
	Mlkemkey  PublickemSet
}
