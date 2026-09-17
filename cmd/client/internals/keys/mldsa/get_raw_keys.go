package mldsa_keys

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	hsm "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
)

// DecodePublicKey converts the packed public-key bytes from the protobuf payload into a raw ML-DSA public key
func DecodePublicKey(publicKey *struct_mldsa.PublicKeyMLDSA) (*mldsa87.PublicKey, error) {
	var rawKey mldsa87.PublicKey

	err := rawKey.UnmarshalBinary(publicKey.Key)
	if err != nil {
		return nil, apperr.Wrap("convert bytes in public key", err)
	}

	return &rawKey, nil

}

// DecodePrivateKey decrypts the stored private-key payload and returns it sealed
// in a memguard Enclave until the caller explicitly opens it. It derives the AES
// key via Argon2id or decrypts through the HSM, depending on how the key was protected.
func DecodePrivateKey(password *memguard.Enclave, privateKey *struct_mldsa.PrivateKeyMLDSA) (*memguard.Enclave, error) {
	if password == nil {
		return nil, apperr.New("password is nil")
	}
	if privateKey == nil {
		return nil, apperr.New("private key is nil")
	}

	if privateKey.ArgonParams == nil {
		return nil, apperr.New("argon parameters are nil")
	}

	plaintext, err := hsm.Decrypt(password, privateKey.Key, privateKey.Nonce, privateKey.ArgonParams.Salt, int(privateKey.ArgonParams.Level), privateKey.HsmMethod)
	if err != nil {
		return nil, apperr.Wrap("decrypt ML-DSA private key", err)
	}
	return plaintext, nil
}

// DecodePairKeys decodes the public key and decrypts the private key together.
func DecodePairKeys(publicKey *struct_mldsa.PublicKeyMLDSA, privateKey *struct_mldsa.PrivateKeyMLDSA, password *memguard.Enclave) (*mldsa87.PublicKey, *memguard.Enclave, error) {
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
