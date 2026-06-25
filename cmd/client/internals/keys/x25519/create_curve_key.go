package x25519

import (
	"P2Chat/pkg/apperr"
	"crypto/ecdh"
	"crypto/rand"

	"github.com/awnumar/memguard"
)

type PrivateX25519 struct {
	privateKeyEncrypted []byte
	nonce []byte
}


// generate the private key X25519 (Curve) and put in an enclave
func CreateKey() (privateKeyEnclaved *memguard.Enclave,err error) {

	// generate the key
	privateKey,err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, apperr.Wrap("error during the creation of the X25519 private key",err)
	}

	privateKeyEnclaved = memguard.NewEnclave(privateKey.Bytes())

	memguard.WipeBytes(privateKey.Bytes())
	return privateKeyEnclaved,nil

}


// Get the public key using the private key 
func ExtractPublicKey(privateKey *ecdh.PrivateKey) (publicKey *ecdh.PublicKey) {

	return privateKey.PublicKey()

}



func Encrypt()