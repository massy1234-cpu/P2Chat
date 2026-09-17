package mldsa_keys

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	hsm "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/cmd/client/internals/p2version"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	mldsadata "P2Chat/cmd/client/internals/storage/mldsa_data"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
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
		return apperr.Wrap("error doing the checksum of private key", err)
	}

	err = publicKey.SetChecksum()
	if err != nil {
		return apperr.Wrap("error doing the checksum of public key", err)
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
func fillPublicKey(algorithm string, rawPublicKey []byte) (*struct_mldsa.PublicKeyMLDSA, error) {

	publicKeyStruct := &struct_mldsa.PublicKeyMLDSA{}
	publicKeyStruct.Algorithm = algorithm
	publicKeyStruct.P2ChatVersion = string(p2version.MagicByte())
	publicKeyStruct.Timestamp = uint32(time.Now().Unix())
	publicKeyStruct.Key = rawPublicKey

	return publicKeyStruct, nil
}

// CreateKeys generates a raw ML-DSA-87 keypair. No encryption.
func CreateKeys() (*memguard.Enclave, *mldsa87.PublicKey, error) {

	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, nil, apperr.Wrap("generate ML-DSA keypair", err)
	}
	defer privateKeyExposed.Destroy()

	privateKey := memguard.NewEnclave(privateKeyExposed.Bytes())

	var packed [mldsa87.PublicKeySize]byte
	publicKey.Pack(&packed)

	var pubCopy mldsa87.PublicKey
	if err := pubCopy.UnmarshalBinary(packed[:]); err != nil {
		return nil, nil, apperr.Wrap("copy public key", err)
	}

	return privateKey, &pubCopy, nil

}

// EncryptPrivateKey encrypts an ML-DSA private key and wraps it in a protobuf struct.
// level must be between 1 and 3. If useHSM is true the private key is protected by the
// hardware security module of the platform (SE on darwin, TPM on linux/windows);
// otherwise it is protected by Argon2id + AES-256-GCM derived from the password.
func EncryptPrivateKey(password *memguard.Enclave, privateKey *memguard.Enclave, level int, useHSM bool) (*struct_mldsa.PrivateKeyMLDSA, error) {
	rawKeyEncrypted, nonce, salt, hsmMethod, err := hsm.Encrypt(password, privateKey, level, useHSM)
	if err != nil {
		return nil, apperr.Wrap("protect ML-DSA private key", err)
	}

	return fillPrivateKey(level, "ML-DSA-87", rawKeyEncrypted, nonce, salt, hsmMethod)

}

// NewPublicKey wraps raw ML-DSA public key bytes in a protobuf struct.
func NewPublicKey(rawPublicKey *mldsa87.PublicKey) (*struct_mldsa.PublicKeyMLDSA, error) {

	var packed [mldsa87.PublicKeySize]byte
	rawPublicKey.Pack(&packed)
	return fillPublicKey("ML-DSA-87", packed[:])

}

// SerializePrivateKey marshals the private key struct to msgpack.
func SerializePrivateKey(privateKey *struct_mldsa.PrivateKeyMLDSA) ([]byte, error) {

	serialized, err := messagepack.Marshal(privateKey)
	if err != nil {
		return nil, apperr.Wrap("marshal ML-DSA private key", err)
	}

	return serialized, nil

}
