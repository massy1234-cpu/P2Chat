package mlkem

import (
	HSM "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/pkg/apperr"
	"crypto/mlkem"
	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

// every key have a different nonce, the key is shared between buckets
type PrivateKEM struct {
	PrivateKeyEncrypted []byte `msgpack:"private_key_encrypted"`
	Nonce               []byte `msgpack:"nonce"`
	Salt                []byte `msgpack:"salt"`
	ArgonLevel          int    `msgpack:"argon_level"`
	EncryptMethod       uint32 `msgpack:"encrypt_method"` // 0 = nessuno, 1 = SE, 2 = TPM
}

// generate the private key ML-KEM 768
func CreateKey() (privateKeyEnclaved *memguard.Enclave, publicKey *mlkem.EncapsulationKey768, err error) {

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, apperr.Wrap("error during generation of ml-kem 768 keys", err)
	}
	defer memguard.WipeBytes(dk.Bytes())

	// put the private key in a secure area of RAM
	privateKeyEnclaved = memguard.NewEnclave(dk.Bytes())

	publicKey = dk.EncapsulationKey()

	return privateKeyEnclaved, publicKey, nil

}

// get the public key from the private key
func ExtractPublicKey(privateKeyEnclaved *memguard.Enclave) (publicKey *mlkem.EncapsulationKey768) {

	buffer, err := privateKeyEnclaved.Open()
	if err != nil {
		return nil
	}
	defer buffer.Destroy()

	key, err := mlkem.NewDecapsulationKey768(buffer.Bytes())
	if err != nil {
		return nil
	}

	return key.EncapsulationKey()

}

// use the public key to create the secret and chipertext
func EncapsulateSecret(publicKey *mlkem.EncapsulationKey768) (secretLocked *memguard.Enclave, ciphertext []byte, err error) {

	// create the secret and the chipetext (secret incapsulated)
	secret, ciphertext := publicKey.Encapsulate()

	// put the secret in a secure encrypted RAM memory
	secretLocked = memguard.NewEnclave(secret)
	memguard.WipeBytes(secret)

	return secretLocked, ciphertext, nil
}

// get the secret from the ciphertext
func DecapsulateChipertext(privateKey *mlkem.DecapsulationKey768, ciphertext []byte) (secretLocked *memguard.Enclave, err error) {

	// get the shared secret
	secret, err := privateKey.Decapsulate(ciphertext)

	secretLocked = memguard.NewEnclave(secret)
	memguard.WipeBytes(secret)

	return secretLocked, nil
}

// EncryptPrivateKey encrypts the key based on useHSM bool and returns the filled struct.
// If useHSM is true, uses EncryptHSM (auto-detects SE on darwin, TPM on linux/windows).
// If useHSM is false, uses Argon2id + AES-256-GCM.
func EncryptPrivateKey(password *memguard.Enclave, privateKey *memguard.Enclave, level int, useHSM bool) (*PrivateKEM, error) {
	ciphertext, params, err := HSM.Encrypt(password, privateKey, level, useHSM)
	if err != nil {
		return nil, apperr.Wrap("protect ML-KEM private key", err)
	}

	scheme := &PrivateKEM{
		PrivateKeyEncrypted: ciphertext,
		Nonce:               params.Nonce,
		Salt:                params.Salt,
		ArgonLevel:          params.ArgonLevel,
		EncryptMethod:       params.HSMMethod,
	}

	return scheme, nil

}

// SerializePrivateKey marshals the filled PrivateKEM struct to bytes.
func SerializePrivateKey(scheme *PrivateKEM) ([]byte, error) {

	bytes, err := messagepack.Marshal(scheme)
	if err != nil {
		return nil, apperr.Wrap("error during serialization of the private mlkem key", err)
	}

	return bytes, nil

}
