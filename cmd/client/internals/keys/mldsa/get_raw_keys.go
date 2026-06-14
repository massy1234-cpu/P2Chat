package mldsa_keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/encryption"
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

// DecodePrivateKey decrypts the stored private-key payload and returns it sealed in a memguard Enclave until the caller explicitly opens it.
func DecodePrivateKey(privateKey *struct_mldsa.PrivateKeyMLDSA, aesKey *memguard.LockedBuffer, level int, salt []byte) (*memguard.Enclave, error) {
	bytes := privateKey.Key

	plaintext, err := encryption.DecryptAes256(aesKey, privateKey.Nonce, bytes)

	if err != nil {
		return nil, apperr.Wrap("Decrypt private key", err)
	}

	enclave := memguard.NewEnclave(plaintext.Bytes())
	defer plaintext.Destroy()

	return enclave, nil
}

// DecodePairKeys decodes the public key and decrypts the private key together.
func DecodePairKeys(publicKey *struct_mldsa.PublicKeyMLDSA, privateKey *struct_mldsa.PrivateKeyMLDSA, aesKey *memguard.LockedBuffer, level int, salt []byte) (*mldsa87.PublicKey, *memguard.Enclave, error) {
	rawPublicKey, err := DecodePublicKey(publicKey)
	if err != nil {
		return nil, nil, apperr.Wrap("decode ml-dsa87 public key from file", err)
	}

	rawPrivateKey, err := DecodePrivateKey(privateKey, aesKey, level, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("decode ml-dsa87 private key from file", err)
	}

	return rawPublicKey, rawPrivateKey, nil
}
