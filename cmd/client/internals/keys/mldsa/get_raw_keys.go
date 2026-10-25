package mldsa_keys

import (
	hsm "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
)

// DecodePublicKey converts the packed public-key bytes from the protobuf payload into an operational ML-DSA object
func DecodePublicKey(publicKey *struct_mldsa.PublicKeyMLDSA) (*PublicMLDSA, error) {
	if publicKey == nil {
		return nil, apperr.New("public ML-DSA payload is nil")
	}
	return NewPublicKey(publicKey.GetKey())

}

// DecodePrivateKey decrypts the stored private-key payload and returns it sealed
// in a private object whose methods open the enclave internally. It derives the AES
// key via Argon2id or decrypts through the HSM, depending on how the key was protected.
func DecodePrivateKey(password *memguard.Enclave, privateKey *struct_mldsa.PrivateKeyMLDSA) (*PrivateMLDSA, error) {
	if password == nil {
		return nil, apperr.New("password is nil")
	}
	if privateKey == nil {
		return nil, apperr.New("private key is nil")
	}

	if privateKey.ArgonParams == nil {
		return nil, apperr.New("argon parameters are nil")
	}

	plaintext, err := hsm.Decrypt(password, privateKey.Key, &hsm.EncryptParams{
		Nonce:      privateKey.Nonce,
		Salt:       privateKey.ArgonParams.Salt,
		ArgonLevel: int(privateKey.ArgonParams.Level),
		HSMMethod:  privateKey.HsmMethod,
	})
	if err != nil {
		return nil, apperr.Wrap("decrypt ML-DSA private key", err)
	}
	return &PrivateMLDSA{enclave: plaintext}, nil
}

// DecodePairKeys decodes the public key and decrypts the private key together.
func DecodePairKeys(publicKey *struct_mldsa.PublicKeyMLDSA, privateKey *struct_mldsa.PrivateKeyMLDSA, password *memguard.Enclave) (*PublicMLDSA, *PrivateMLDSA, error) {
	rawPublicKey, err := DecodePublicKey(publicKey)
	if err != nil {
		return nil, nil, apperr.Wrap("decode ml-dsa87 public key from file", err)
	}

	rawPrivateKey, err := DecodePrivateKey(password, privateKey)
	if err != nil {
		return nil, nil, apperr.Wrap("decode ml-dsa87 private key from file", err)
	}

	return rawPublicKey, rawPrivateKey, nil
}
