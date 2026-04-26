package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/mldsa/argon"
	"P2Chat/cmd/client/internals/mldsa/datacontrol"
	mldsaencryption "P2Chat/cmd/client/internals/mldsa/encryption"
	pb "P2Chat/cmd/client/internals/mldsa/gen/mldsapb"
	"P2Chat/cmd/client/internals/p2version"
	"P2Chat/pkg/apperr"
	"encoding/base64"
	"github.com/awnumar/memguard"
	"time"
)

// Generate the pair of ml-dsa87 keys and choose if save on file
func CreateMLDSAKeys(level int, password *memguard.LockedBuffer, store bool) (*pb.PrivateKeyMLDSA, *datacontrol.PublicKeyMLDSA, error) {

	//Generation of the keys
	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, nil, apperr.Wrap("generate ML-DSA keypair", err)
	}

	privateKey := memguard.NewBuffer(privateKeyExposed.Scheme().PrivateKeySize())
	rawPrivate := privateKeyExposed.Bytes()

	copy(privateKey.Bytes(), rawPrivate)
	memguard.WipeBytes(rawPrivate)
	defer privateKeyExposed.Destroy()

	//encrypt private key ML-DSA-87
	rawKeyEncrypted, nonce, salt, err := mldsaencryption.EncryptPrivateKey(password, privateKey, level)
	if err != nil {
		return nil, nil, apperr.Wrap("protect private key", err)
	}

	privateKeyStruct, publicKeyStruct, err := fillKeyPairMLDSA(level, "ML-DSA-87", rawKeyEncrypted, publicKey.Bytes(), nonce, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("build generated key payloads", err)
	}

	if store {
		err = StoreKeysMLDSA(privateKeyStruct, *publicKeyStruct)
		if err != nil {
			return nil, nil, apperr.Wrap("store generated keys", err)
		}
	}

	return privateKeyStruct, publicKeyStruct, nil

}

// Create both key payloads starting from the generated raw data.
func fillKeyPairMLDSA(level int, algorithm string, rawKeyEncrypted []byte, rawKeyPublic []byte, nonce []byte, salt []byte) (*pb.PrivateKeyMLDSA, *datacontrol.PublicKeyMLDSA, error) {

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

// Receive the keys and saves in the "data" folder
func StoreKeysMLDSA(privateKey *pb.PrivateKeyMLDSA, publicKey datacontrol.PublicKeyMLDSA) error {

	//save keys on file
	err := datacontrol.SavePairKeyMLDSA(privateKey, publicKey)
	if err != nil {
		return apperr.Wrap("save keys ", err)
	}

	return nil
}

// Create a proto struct and fill with ml-dsa87 private key params
func fillPrivateKeyMLDSA(level int, algorithm string, rawKeyEncrypted []byte, nonce []byte, salt []byte) (*pb.PrivateKeyMLDSA, error) {

	privateKeyStruct := &pb.PrivateKeyMLDSA{}

	privateKeyStruct.Algorithm = algorithm
	privateKeyStruct.ArgonParams = argon.CreateArgonParams(level)
	privateKeyStruct.Ciphertext = rawKeyEncrypted
	privateKeyStruct.Nonce = nonce
	privateKeyStruct.P2ChatVersion = p2version.MagicByte()
	privateKeyStruct.Timestamp = time.Now().Unix()

	privateKeyStruct.ArgonParams.Salt = salt

	return privateKeyStruct, nil
}

// Create the json struct and fill with the ml-dsa87 public key params
func fillPublicKeyMLDSA(algoritm string, rawPublicKey []byte) (*datacontrol.PublicKeyMLDSA, error) {

	var publicKey datacontrol.PublicKeyMLDSA
	publicKey.Algorithm = algoritm
	publicKey.P2ChatVersion = string(p2version.MagicByte())
	publicKey.Timestamp = time.Now().String()
	publicKey.PublicKeyMLDSABase64 = base64.StdEncoding.EncodeToString(rawPublicKey)

	return &publicKey, nil
}
