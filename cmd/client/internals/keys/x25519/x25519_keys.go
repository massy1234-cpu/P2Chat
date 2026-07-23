package x25519

import (
	"P2Chat/cmd/client/internals/encryption"
	HSM "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/pkg/apperr"
	"crypto/ecdh"
	"crypto/rand"

	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

type PrivateX25519 struct {
	PrivateKeyEncrypted []byte `msgpack:"privateKeyEncrypted"`
	Nonce []byte `msgpack:"nonce"`
	EncryptMethod int `msgpack:"encryptMethod"`
}


// generate the private key X25519 (Curve) and put in an enclave
func CreateKey() (privateKeyEnclaved *memguard.Enclave,publicKey *ecdh.PublicKey,err error) {

	// generate the key
	privateKey,err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the creation of the X25519 private key",err)
	
	}
	defer memguard.WipeBytes(privateKey.Bytes())

	publicKey = privateKey.PublicKey()
	privateKeyEnclaved = memguard.NewEnclave(privateKey.Bytes())

	return privateKeyEnclaved,publicKey,nil

}


// Get the public key using the private key
func ExtractPublicKey(privateKeyEnclaved *memguard.Enclave) (publicKey *ecdh.PublicKey) {

	buffer, err := privateKeyEnclaved.Open()
	if err != nil {
		return nil
	}
	defer buffer.Destroy()

	key, err := ecdh.X25519().NewPrivateKey(buffer.Bytes())
	if err != nil {
		return nil
	}

	return key.PublicKey()

}


// derivate the shared_secret with the public key of the other user in the comunication
func DerivateSecret(privateKey *ecdh.PrivateKey, RemotePublicKey *ecdh.PublicKey) (shared_secret *memguard.Enclave,err error) {

	secret,err := privateKey.ECDH(RemotePublicKey)
	if err != nil {
		return nil, apperr.Wrap("error during the derivation of the shared secret with X25519 key",err)
	}

	shared_secret = memguard.NewEnclave(secret)
	memguard.WipeBytes(secret)

	return shared_secret,nil

}


// EncryptPrivateKey encrypts the key based on useHSM bool and returns the filled struct.
// If useHSM is true, uses EncryptHSM (auto-detects SE on darwin, TPM on linux/windows).
// If useHSM is false, uses Argon2id + AES-256-GCM.
func EncryptPrivateKey(password *memguard.Enclave, privateKey *memguard.Enclave, useHSM bool) (*PrivateX25519, error) {

	var ciphertext, nonce []byte
	var method int
	var err error

	buffer, keyErr := privateKey.Open()
	if keyErr != nil {
		return nil, apperr.Wrap("error ", keyErr)
	}
	defer buffer.Destroy()

	if useHSM {
		ciphertext, nonce, err = HSM.EncryptHSM(password, buffer)
		if err != nil {
			return nil, apperr.Wrap("hsm encrypt error", err)
		}
		method = HSM.WhichOS()
	} else {
		pwdBuf, pwdErr := password.Open()
		if pwdErr != nil {
			return nil, apperr.Wrap("open password enclave", pwdErr)
		}
		defer pwdBuf.Destroy()

		ciphertext, nonce, err = encryption.EncryptAes256(pwdBuf, buffer.Bytes())
		if err != nil {
			return nil, apperr.Wrap("error ", err)
		}
	}

	scheme := &PrivateX25519{
		PrivateKeyEncrypted: ciphertext,
		Nonce:               nonce,
		EncryptMethod:       method,
	}

	return scheme, nil

}

// SerializePrivateKey marshals the filled PrivateX25519 struct to bytes.
func SerializePrivateKey(scheme *PrivateX25519) ([]byte, error) {

	serializedKey, err := messagepack.Marshal(scheme)
	if err != nil {
		return nil, apperr.Wrap("error during serialization ", err)
	}

	return serializedKey, nil

}

// DecryptPrivateKey decrypts a serialized PrivateX25519 key and returns the raw key in a memguard Enclave.
func DecryptPrivateKey(password *memguard.Enclave, serialized []byte) (*memguard.Enclave, error) {

	var scheme PrivateX25519
	if err := messagepack.Unmarshal(serialized, &scheme); err != nil {
		return nil, apperr.Wrap("unmarshal private x25519 key", err)
	}

	var plaintext *memguard.LockedBuffer

	switch scheme.EncryptMethod {
	case 0:
		pwdBuf, err := password.Open()
		if err != nil {
			return nil, apperr.Wrap("open password enclave", err)
		}
		defer pwdBuf.Destroy()

		plaintext, err = encryption.DecryptAes256(pwdBuf, scheme.Nonce, scheme.PrivateKeyEncrypted)
		if err != nil {
			return nil, apperr.Wrap("decrypt x25519 private key", err)
		}
	case 1, 2:
		var err error
		plaintext, err = HSM.DecryptHSM(password, scheme.PrivateKeyEncrypted, scheme.Nonce, scheme.EncryptMethod)
		if err != nil {
			return nil, apperr.Wrap("decrypt x25519 private key with HSM", err)
		}
	default:
		return nil, apperr.New("unknown encrypt method for x25519 private key")
	}

	enclave := memguard.NewEnclave(plaintext.Bytes())
	plaintext.Destroy()
	return enclave, nil

}