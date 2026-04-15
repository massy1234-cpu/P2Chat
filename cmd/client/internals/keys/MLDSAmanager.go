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

func CreateKeys(level int, password *memguard.LockedBuffer) error {

	//Generation of the keys
	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return apperr.Wrap("generate ML-DSA keypair", err)
	}

	privateKey := memguard.NewBuffer(privateKeyExposed.Scheme().PrivateKeySize())
	rawPrivate := privateKeyExposed.Bytes()
	copy(privateKey.Bytes(), rawPrivate)
	memguard.WipeBytes(rawPrivate)
	privateKeyExposed.Destroy()

	//encrypt private key ML-DSA-87
	rawKeyEncrypted, nonce, salt, err := encryption.EncryptPrivateKeyMLDSA(password, privateKey, level)
	if err != nil {
		return apperr.Wrap("protect private key", err)
	}

	err = StoreKeys(level, rawKeyEncrypted, publicKey.Bytes(), nonce, salt)
	if err != nil {
		return apperr.Wrap("store generated keys", err)
	}

	return nil

}

// function that create the keys ( protect the memory with memguard ) and save the keys in the data folder
func StoreKeys(level int, rawKeyPrivateEncrypted []byte, rawKeyPublic []byte, nonce []byte, salt []byte) error {

	//PrivateKey struct
	privateKeyMLDSA, err := fillPrivateKeyMLDSA(level, "ML-DSA-87", rawKeyPrivateEncrypted, nonce, salt)
	if err != nil {
		return apperr.Wrap("build private key payload", err)
	}

	//PublicKey struct
	publicKeyMLDSA := fillPublicKeyMLDSA("ML-DSA-87", rawKeyPublic)

	//save keys on file
	err = datacontrol.SavePrivateKeyMLDSA(privateKeyMLDSA)
	if err != nil {
		return err
	}

	err = datacontrol.SavePublicKeyMLDSA(*publicKeyMLDSA)
	if err != nil {
		return err
	}

	return nil
}

func fillPrivateKeyMLDSA(level int, algorithm string, rawKeyEncrypted []byte, nonce []byte, salt []byte) (*pb.PrivateKeyMLDSA, error) {

	privateKeyStruct := &pb.PrivateKeyMLDSA{}
	argonParams := argon.CreateArgonParams(level)

	privateKeyStruct.Algorithm = algorithm
	privateKeyStruct.ArgonParams = argon.CreateArgonParams(level)
	privateKeyStruct.Ciphertext = rawKeyEncrypted
	privateKeyStruct.Nonce = nonce
	privateKeyStruct.P2ChatVersion = p2version.MagicByte()
	privateKeyStruct.Timestamp = time.Now().Unix()

	argonParams.Salt = salt

	privateKeyStruct.ArgonParams = argonParams

	return privateKeyStruct, nil
}

func fillPublicKeyMLDSA(algoritm string, rawPublicKey []byte) *datacontrol.PublicKeyMLDSA {

	var publicKey datacontrol.PublicKeyMLDSA
	publicKey.Algorithm = algoritm
	publicKey.P2ChatVersion = string(p2version.MagicByte())
	publicKey.Timestamp = time.Now().String()
	publicKey.PublicKeyMLDSABase64 = base64.StdEncoding.EncodeToString(rawPublicKey)

	return &publicKey
}
