package mlkem

import (
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/pkg/apperr"
	"crypto/mlkem"
	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

// every key have a different nonce, the key is shared between buckets
type PrivateKEM struct {
	privateKeyEncrypted []byte
	nonce []byte
}


// generate the private key ML-KEM 768
func CreateKey() (privateKeyEnclaved *memguard.Enclave,err error) {

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, apperr.Wrap("error during generation of ml-kem 768 keys",err)
	}

	// put the private key in a secure area of RAM
	privateKeyEnclaved = memguard.NewEnclave(dk.Bytes())
	memguard.WipeBytes(dk.Bytes())

	return privateKeyEnclaved,nil

}


// get the public key from the private key
func ExtractPublicKey(privateKey *mlkem.DecapsulationKey768) (publicKey *mlkem.EncapsulationKey768){

	return privateKey.EncapsulationKey()

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


// encrypt and serialize the key
func SerializePrivateKey(key *memguard.LockedBuffer,privateKey *memguard.LockedBuffer) ( serializedKey []byte, err error ) {

	// encrypt the key
	chipertext, nonce, err := encryption.EncryptAes256(key,privateKey)
	if err != nil {
		return nil, apperr.Wrap("error during Serilization of the private key",err)
	}

	scheme := PrivateKEM{
		privateKeyEncrypted :	chipertext,
		nonce : 				nonce,
	}

	
	bytes,err := messagepack.Marshal(scheme)
	if err != nil {
		return nil,apperr.Wrap("error during serialization of the private mlkem key",err)
	}

	return bytes,nil

}