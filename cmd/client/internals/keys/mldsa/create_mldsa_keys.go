package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	datacontrol "P2Chat/cmd/client/internals/datacontrol/mldsa"
	mldsaencryption "P2Chat/cmd/client/internals/encryption/mldsa"
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/cmd/client/internals/p2version"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"time"
)

// CreateMLDSAKeys generates an ML-DSA-87 keypair, encrypts the private key,
// builds the protobuf payloads, and optionally stores them on disk.
func CreateMLDSAKeys(level int, password *memguard.LockedBuffer, store bool) (*pb.PrivateKeyMLDSA, *pb.PublicKeyMLDSA, error) {

	//Generation of the keys
	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, nil, apperr.Wrap("generate ML-DSA keypair", err)
	}
	defer privateKeyExposed.Destroy()

	privateKey, err := privateKeyExposed.LockedBuffer()
	if err != nil {
		return nil, nil, apperr.Wrap("pack ML-DSA private key into protected memory", err)
	}
	defer privateKey.Destroy()

	//encrypt private key ML-DSA-87
	rawKeyEncrypted, nonce, salt, err := mldsaencryption.EncryptPrivateKey(password, privateKey, level)
	if err != nil {
		return nil, nil, apperr.Wrap("protect private key", err)
	}

	var packedPublic [mldsa87.PublicKeySize]byte
	publicKey.Pack(&packedPublic)

	privateKeyStruct, publicKeyStruct, err := fillKeyPairMLDSA(level, "ML-DSA-87", rawKeyEncrypted, packedPublic[:], nonce, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("build generated key payloads", err)
	}

	if store {
		err = StoreKeysMLDSA(privateKeyStruct, publicKeyStruct)
		if err != nil {
			return nil, nil, apperr.Wrap("store generated keys", err)
		}
	}

	return privateKeyStruct, publicKeyStruct, nil

}

// fillKeyPairMLDSA builds both protobuf payloads from already prepared raw key data.
func fillKeyPairMLDSA(level int, algorithm string, rawKeyEncrypted []byte, rawKeyPublic []byte, nonce []byte, salt []byte) (*pb.PrivateKeyMLDSA, *pb.PublicKeyMLDSA, error) {

	privateKeyMLDSA, err := fillPrivateKeyMLDSA(level, algorithm, rawKeyEncrypted, nonce, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("build private key payload", err)
	}

	publicKeyMLDSA, err := fillPublicKeyMLDSA(algorithm, rawKeyPublic)
	if err != nil {
		return nil, nil, apperr.Wrap("build public key payload", err)
	}

	return privateKeyMLDSA, publicKeyMLDSA, nil
}

// StoreKeysMLDSA persists the generated ML-DSA key payloads in the data directory.
func StoreKeysMLDSA(privateKey *pb.PrivateKeyMLDSA, publicKey *pb.PublicKeyMLDSA) error {

	//save keys on file
	err := datacontrol.SavePairKeyMLDSA(privateKey, publicKey)
	if err != nil {
		return apperr.Wrap("save keys ", err)
	}

	return nil
}

// fillPrivateKeyMLDSA fills the protobuf payload for the encrypted ML-DSA private key.
func fillPrivateKeyMLDSA(level int, algorithm string, rawKeyEncrypted []byte, nonce []byte, salt []byte) (*pb.PrivateKeyMLDSA, error) {

	privateKeyStruct := &pb.PrivateKeyMLDSA{}

	privateKeyStruct.Algorithm = algorithm
	privateKeyStruct.ArgonParams = argon.CreateArgonParams(level)
	privateKeyStruct.Key = rawKeyEncrypted
	privateKeyStruct.Nonce = nonce
	privateKeyStruct.P2ChatVersion = p2version.MagicByte()
	privateKeyStruct.Timestamp = time.Now().Unix()
	privateKeyStruct.ArgonParams.Salt = salt

	return privateKeyStruct, nil
}

// fillPublicKeyMLDSA fills the protobuf payload for the packed ML-DSA public key.
func fillPublicKeyMLDSA(algoritm string, rawPublicKey []byte) (*pb.PublicKeyMLDSA, error) {

	publicKeyStruct := &pb.PublicKeyMLDSA{}
	publicKeyStruct.Algorithm = algoritm
	publicKeyStruct.P2ChatVersion = string(p2version.MagicByte())
	publicKeyStruct.Timestamp = uint32(time.Now().Unix())
	publicKeyStruct.Key = rawPublicKey

	return publicKeyStruct, nil
}
