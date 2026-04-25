package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/cmd/client/internals/datacontrol"
	"P2Chat/cmd/client/internals/encryption"
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"P2Chat/cmd/client/internals/p2version"
	"P2Chat/pkg/apperr"
	"encoding/base64"
	"github.com/awnumar/memguard"
	"time"
)

//Generate the pair of ml-dsa87 keys and choose if save on file
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
	privateKeyExposed.Destroy()

	//encrypt private key ML-DSA-87
	rawKeyEncrypted, nonce, salt, err := encryption.EncryptPrivateKey(password, privateKey, level)
	if err != nil {
		return nil, nil,apperr.Wrap("protect private key", err)
	}

	var privateKeyStruct *pb.PrivateKeyMLDSA
	var publicKeyStruct *datacontrol.PublicKeyMLDSA

	if store {
		privateKeyStruct, publicKeyStruct, err = StoreKeys(level, rawKeyEncrypted, publicKey.Bytes(), nonce, salt)
		if err != nil {
			return nil, nil,apperr.Wrap("store generated keys", err)
		}
	}

	return privateKeyStruct, publicKeyStruct, nil

}

//Receive the keys and saves in the "data" folder
func StoreKeys(level int, rawKeyPrivateEncrypted []byte, rawKeyPublic []byte, nonce []byte, salt []byte) ( *pb.PrivateKeyMLDSA, *datacontrol.PublicKeyMLDSA, error ) {

	//PrivateKey struct
	privateKeyMLDSA, err := fillPrivateKeyMLDSA(level, "ML-DSA-87", rawKeyPrivateEncrypted, nonce, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("build private key payload", err)
	}

	//PublicKey struct
	publicKeyMLDSA, err := fillPublicKeyMLDSA("ML-DSA-87", rawKeyPublic)
	if err != nil {
		return nil, nil, apperr.Wrap("build public key payload", err)
	}

	//save keys on file
	err = datacontrol.SavePairKeyMLDSA(privateKeyMLDSA,*publicKeyMLDSA)

	return privateKeyMLDSA, publicKeyMLDSA, nil
}

//Create the proto struct for the ml-dsa87 private key
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

//Create the json struct for the ml-dsa87 public key
func fillPublicKeyMLDSA(algoritm string, rawPublicKey []byte) ( *datacontrol.PublicKeyMLDSA, error ) {

	var publicKey datacontrol.PublicKeyMLDSA
	publicKey.Algorithm = algoritm
	publicKey.P2ChatVersion = string(p2version.MagicByte())
	publicKey.Timestamp = time.Now().String()
	publicKey.PublicKeyMLDSABase64 = base64.StdEncoding.EncodeToString(rawPublicKey)

	return &publicKey, nil
}
