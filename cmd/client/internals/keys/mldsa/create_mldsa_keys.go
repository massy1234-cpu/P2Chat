package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	mldsadata "P2Chat/cmd/client/internals/datacontrol/mldsa_data"
	mldsaencryption "P2Chat/cmd/client/internals/encryption/mldsa_encryption"
	struct_mldsa "P2Chat/cmd/client/internals/generated_proto_files/mldsa/proto_struct_mldsa"
	"P2Chat/cmd/client/internals/p2version"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"time"
)

// CreateKeys generates an ML-DSA-87 keypair, encrypts the private key,
// builds the protobuf payloads, and optionally stores them on disk.
func CreateKeys(level int, password *memguard.LockedBuffer, store bool) (*struct_mldsa.PrivateKeyMLDSA, *struct_mldsa.PublicKeyMLDSA, error) {

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

	privateKeyStruct, publicKeyStruct, err := fillKeyPair(level, "ML-DSA-87", rawKeyEncrypted, packedPublic[:], nonce, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("build generated key payloads", err)
	}

	if store {
		err = StoreKeys(privateKeyStruct, publicKeyStruct)
		if err != nil {
			return nil, nil, apperr.Wrap("store generated keys", err)
		}
	}

	return privateKeyStruct, publicKeyStruct, nil

}

// fillKeyPair builds both protobuf payloads from already prepared raw key data.
func fillKeyPair(level int, algorithm string, rawKeyEncrypted []byte, rawKeyPublic []byte, nonce []byte, salt []byte) (*struct_mldsa.PrivateKeyMLDSA, *struct_mldsa.PublicKeyMLDSA, error) {

	privateKeyMLDSA, err := fillPrivateKey(level, algorithm, rawKeyEncrypted, nonce, salt)
	if err != nil {
		return nil, nil, apperr.Wrap("build private key payload", err)
	}

	publicKeyMLDSA, err := fillPublicKey(algorithm, rawKeyPublic)
	if err != nil {
		return nil, nil, apperr.Wrap("build public key payload", err)
	}

	return privateKeyMLDSA, publicKeyMLDSA, nil
}

// StoreKeys persists the generated ML-DSA key payloads in the data directory.
func StoreKeys(privateKey *struct_mldsa.PrivateKeyMLDSA, publicKey *struct_mldsa.PublicKeyMLDSA) error {

	// set the checksum of both keys
	err := privateKey.SetChecksum()
	if err != nil {
		return apperr.Wrap("error doing the checksum of private key",err)
	}

	publicKey.SetChecksum()
	if err != nil {
		return apperr.Wrap("error doing the checksum of public key",err)
	}
	
	//save keys on file
	err = mldsadata.SavePairKey(privateKey, publicKey)
	if err != nil {
		return apperr.Wrap("save keys ", err)
	}

	return nil
}

// fillPrivateKey fills the protobuf payload for the encrypted ML-DSA private key.
func fillPrivateKey(level int, algorithm string, rawKeyEncrypted []byte, nonce []byte, salt []byte) (*struct_mldsa.PrivateKeyMLDSA, error) {

	privateKeyStruct := &struct_mldsa.PrivateKeyMLDSA{}

	privateKeyStruct.Algorithm = algorithm
	privateKeyStruct.ArgonParams = argon.CreateArgonParams(level)
	privateKeyStruct.Key = rawKeyEncrypted
	privateKeyStruct.Nonce = nonce
	privateKeyStruct.P2ChatVersion = p2version.MagicByte()
	privateKeyStruct.Timestamp = time.Now().Unix()
	privateKeyStruct.ArgonParams.Salt = salt

	return privateKeyStruct, nil
}

// fillPublicKey fills the protobuf payload for the packed ML-DSA public key.
func fillPublicKey(algoritm string, rawPublicKey []byte) (*struct_mldsa.PublicKeyMLDSA, error) {

	publicKeyStruct := &struct_mldsa.PublicKeyMLDSA{}
	publicKeyStruct.Algorithm = algoritm
	publicKeyStruct.P2ChatVersion = string(p2version.MagicByte())
	publicKeyStruct.Timestamp = uint32(time.Now().Unix())
	publicKeyStruct.Key = rawPublicKey

	return publicKeyStruct, nil
}
