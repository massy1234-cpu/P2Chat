package mldsa_keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	hsm "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	mldsaencryption "P2Chat/cmd/client/internals/encryption/mldsa_encryption"
	"P2Chat/cmd/client/internals/p2version"
	data "P2Chat/cmd/client/internals/storage"
	mldsadata "P2Chat/cmd/client/internals/storage/mldsa_data"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"github.com/awnumar/memguard"
	"time"
)


// fillKeyPair builds both protobuf payloads from already prepared raw key data.
func fillKeyPair(level int, algorithm string, rawKeyEncrypted []byte, rawKeyPublic []byte, nonce []byte, salt []byte, hsmMethod uint32) (*struct_mldsa.PrivateKeyMLDSA, *struct_mldsa.PublicKeyMLDSA, error) {

	privateKeyMLDSA, err := fillPrivateKey(level, algorithm, rawKeyEncrypted, nonce, salt, hsmMethod)
	if err != nil {
		return nil, nil, apperr.Wrap("build private key payload", err)
	}

	publicKeyMLDSA, err := fillPublicKey(algorithm, rawKeyPublic)
	if err != nil {
		return nil, nil, apperr.Wrap("build public key payload", err)
	}

	return privateKeyMLDSA, publicKeyMLDSA, nil
}

// StoreKeys persists the generated ML-DSA key payloads in the given directory.
func StoreKeys(privateKey *struct_mldsa.PrivateKeyMLDSA, publicKey *struct_mldsa.PublicKeyMLDSA, pathDir string) error {

	// set the checksum of both keys
	err := privateKey.SetChecksum()
	if err != nil {
		return apperr.Wrap("error doing the checksum of private key",err)
	}

	err = publicKey.SetChecksum()
	if err != nil {
		return apperr.Wrap("error doing the checksum of public key",err)
	}
	
	//save keys on file
	err = mldsadata.SavePairKey(privateKey, publicKey, pathDir)
	if err != nil {
		return apperr.Wrap("save keys ", err)
	}

	return nil
}

// fillPrivateKey fills the protobuf payload for the encrypted ML-DSA private key.
func fillPrivateKey(level int, algorithm string, rawKeyEncrypted []byte, nonce []byte, salt []byte, hsmMethod uint32) (*struct_mldsa.PrivateKeyMLDSA, error) {

	privateKeyStruct := &struct_mldsa.PrivateKeyMLDSA{}

	privateKeyStruct.Algorithm = algorithm
	privateKeyStruct.Key = rawKeyEncrypted
	privateKeyStruct.Nonce = nonce
	privateKeyStruct.P2ChatVersion = p2version.MagicByte()
	privateKeyStruct.Timestamp = time.Now().Unix()
	privateKeyStruct.HsmMethod = hsmMethod

	privateKeyStruct.ArgonParams = argon.CreateArgonParams(level)
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


// CreateKeys generates an ML-DSA-87 keypair, encrypts the private key,
// builds the protobuf payloads, and optionally stores them on disk.
// HSM bool is the parameters that decide if add another layer of security using hardware security.
// Returns the protobuf structs and the raw private key enclave for immediate use (e.g. signing).
func CreateKeys(level int, password *memguard.Enclave, store bool, HSM bool) (*struct_mldsa.PrivateKeyMLDSA, *struct_mldsa.PublicKeyMLDSA, *memguard.Enclave, error) {

	// generation of the keys
	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("generate ML-DSA keypair", err)
	}
	defer privateKeyExposed.Destroy()

	// put the private key inside an Enclave and wipe the bytes after
	privateKey := memguard.NewEnclave(privateKeyExposed.Bytes())
	defer memguard.WipeBytes(privateKeyExposed.Bytes())

	// encrypt private key ML-DSA-87 with or without HSM
	var rawKeyEncrypted, nonce, salt []byte
	var hsmMethod uint32

	if HSM {
		salt = make([]byte, 16)
		if _, err = rand.Read(salt); err != nil {
			return nil, nil, nil, apperr.Wrap("generate salt", err)
		}

		plaintext, openErr := privateKey.Open()
		if openErr != nil {
			return nil, nil, nil, apperr.Wrap("open private key enclave", openErr)
		}
		defer plaintext.Destroy()

		rawKeyEncrypted, nonce, err = hsm.EncryptHSM(password, plaintext)
		if err != nil {
			return nil, nil, nil, apperr.Wrap("HSM encryption failed", err)
		}
		hsmMethod = uint32(hsm.WhichOS())
	} else {
		passwordBuffer,err := password.Open()
		if err != nil {
			return nil,nil, nil, apperr.Wrap("error during opening the password enclave",err)
		}
		defer passwordBuffer.Destroy()
		rawKeyEncrypted, nonce, salt, err = mldsaencryption.EncryptPrivateKey(passwordBuffer, privateKey, level)
		if err != nil {
			return nil, nil, nil, apperr.Wrap("protect private key", err)
		}
	}

	// serialize the key
	var packedPublic [mldsa87.PublicKeySize]byte
	publicKey.Pack(&packedPublic)

	privateKeyStruct, publicKeyStruct, err := fillKeyPair(level, "ML-DSA-87", rawKeyEncrypted, packedPublic[:], nonce, salt, hsmMethod)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("build generated key payloads", err)
	}

	if store {
		err = StoreKeys(privateKeyStruct, publicKeyStruct, data.BasePath)
		if err != nil {
			return nil, nil, nil, apperr.Wrap("store generated keys", err)
		}
	}

	return privateKeyStruct, publicKeyStruct, privateKey, nil

}
