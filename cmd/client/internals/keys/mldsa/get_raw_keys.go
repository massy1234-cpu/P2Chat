package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/encryption"
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/pkg/apperr"

	"github.com/awnumar/memguard"
)

// DecodePublicKeyMLDSA converts the packed public-key bytes from the protobuf
// payload into a raw ML-DSA public key ready for verification.
func DecodePublicKeyMLDSA(publicKey *pb.PublicKeyMLDSA) (*mldsa87.PublicKey, error) {
	var rawKey mldsa87.PublicKey

	err := rawKey.UnmarshalBinary(publicKey.Key)
	if err != nil {
		return nil, apperr.Wrap("convert bytes in public key", err)
	}

	return &rawKey, nil

}

// DecodePrivateKeyMLDSA decrypts the stored private-key payload and returns it
// sealed in a memguard Enclave until the caller explicitly opens it.
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

// DecodePairKeysMLDSA decodes the public key and decrypts the private key together.
func DecodePairKeysMLDSA(publicKey *pb.PublicKeyMLDSA, privateKey *pb.PrivateKeyMLDSA, aesKey *memguard.LockedBuffer, level int, salt []byte) (*mldsa87.PublicKey, *memguard.Enclave, error) {
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
