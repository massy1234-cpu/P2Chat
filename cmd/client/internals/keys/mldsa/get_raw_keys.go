package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	mldsadatacontrol "P2Chat/cmd/client/internals/datacontrol/mldsa"
	"P2Chat/cmd/client/internals/encryption"
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/pkg/apperr"
	"encoding/base64"

	"github.com/awnumar/memguard"
)

// Decode the ml-dsa87 public key in a raw type ready for Verify()
func DecodePublicKeyMLDSA(publicKey *mldsadatacontrol.PublicKeyMLDSA) (*mldsa87.PublicKey, error) {
	var rawKey mldsa87.PublicKey

	//convert base64 in bytes
	bytes, err := base64.StdEncoding.DecodeString(publicKey.PublicKeyMLDSABase64)
	if err != nil {
		return nil, apperr.Wrap("decode base64 in bytes", err)
	}

	//convert bytes in mldsa87.PublicKey type
	err = rawKey.UnmarshalBinary(bytes)
	if err != nil {
		return nil, apperr.Wrap("convert bytes in public key", err)
	}

	return &rawKey, nil

}

// Decode the ml-dsa87 private key in a raw type ready for toSign()
func DecodePrivateKeyMLDSA(privateKey *pb.PrivateKeyMLDSA, aesKey *memguard.LockedBuffer, level int, salt []byte) (*memguard.Enclave, error) {
	bytes := privateKey.Key

	plaintext, err := encryption.DecryptAes256(aesKey, privateKey.Nonce, bytes)
	defer aesKey.Destroy()

	if err != nil {
		return nil, apperr.Wrap("Decrypt private key", err)
	}

	enclave := memguard.NewEnclave(plaintext.Bytes())
	defer plaintext.Destroy()

	return enclave, nil
}

// Decode the ml-dsa87 pair of keys
func DecodePairKeysMLDSA(publicKey *mldsadatacontrol.PublicKeyMLDSA, privateKey *pb.PrivateKeyMLDSA, aesKey *memguard.LockedBuffer, level int, salt []byte) (*mldsa87.PublicKey, *memguard.Enclave, error) {
	rawPublicKey, err := DecodePublicKeyMLDSA(publicKey)
	if err != nil {
		return nil, nil, apperr.Wrap("decode ml-dsa87 public key from file", err)
	}

	rawPrivateKey, err := DecodePrivateKeyMLDSA(privateKey, aesKey, level, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("decode ml-dsa87 private key from file", err)
	}

	return rawPublicKey, rawPrivateKey, nil
}
