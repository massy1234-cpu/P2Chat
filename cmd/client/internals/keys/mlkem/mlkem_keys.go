package mlkem

import (
	"P2Chat/cmd/client/internals/encryption"
	HSM "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/pkg/apperr"
	"crypto/mlkem"
	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

// every key have a different nonce, the key is shared between buckets
type PrivateKEM struct {
	privateKeyEncrypted []byte
	nonce []byte
	encryptMethod int 			// 0 = nessuno, 1 = SE, 2 = TPM
}


// generate the private key ML-KEM 768
func CreateKey() (privateKeyEnclaved *memguard.Enclave,publicKey *mlkem.EncapsulationKey768,err error) {

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, apperr.Wrap("error during generation of ml-kem 768 keys",err)
	}
	defer memguard.WipeBytes(dk.Bytes())

	// put the private key in a secure area of RAM
	privateKeyEnclaved = memguard.NewEnclave(dk.Bytes())

	publicKey = dk.EncapsulationKey()

	return privateKeyEnclaved,publicKey,nil

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
func EncapsulateSecret(publicKey *mlkem.EncapsulationKey768) (secretLocked *memguard.Enclave,ciphertext []byte, err error) {

	// create the secret and the chipetext (secret incapsulated)
	secret, ciphertext := publicKey.Encapsulate()

	// put the secret in a secure encrypted RAM memory
	secretLocked = memguard.NewEnclave(secret)
	memguard.WipeBytes(secret)

	return secretLocked, ciphertext, nil
}


// get the secret from the ciphertext
func DecapsulateChipertext(privateKey *mlkem.DecapsulationKey768,ciphertext []byte) (secretLocked *memguard.Enclave, err error) {

	// get the shared secret
	secret, err := privateKey.Decapsulate(ciphertext)

	secretLocked = memguard.NewEnclave(secret)
	memguard.WipeBytes(secret)

	return secretLocked, nil
}


// EncryptPrivateKey encrypts the key based on useHSM bool and returns the filled struct.
// If useHSM is true, uses EncryptHSM (auto-detects SE on darwin, TPM on linux/windows).
// If useHSM is false, uses Argon2id + AES-256-GCM.
func EncryptPrivateKey(password *memguard.Enclave, privateKey *memguard.Enclave, useHSM bool) (*PrivateKEM, error) {

	var ciphertext, nonce []byte
	var method int
	var err error

	buffer, keyErr := privateKey.Open()
	if keyErr != nil {
		return nil, apperr.Wrap("error opening enclave", keyErr)
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
			return nil, apperr.Wrap("error during encryption of the private key", err)
		}
	}

	scheme := &PrivateKEM{
		privateKeyEncrypted: ciphertext,
		nonce:               nonce,
		encryptMethod:       method,
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