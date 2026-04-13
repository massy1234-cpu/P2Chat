package crypto

import (
	"fmt"
	"crypto/rand"
	"github.com/awnumar/memguard"
	"crypto/aes"
	"crypto/cipher"
)

func GenerateSalt(lenght int) ( []byte, error ) {
	salt := make([]byte, lenght)
	_, err := rand.Read(salt) //creation of salt

	if err != nil {
		return nil,fmt.Errorf("Generator Salt -> failed to generate salt %w", err)
	}

	return salt[:], nil
}

func EncryptAes256(passwordHashed *memguard.LockedBuffer, byteToEncrypt *memguard.LockedBuffer)([]byte, error){

	block, err := aes.NewCipher(passwordHashed.Bytes())
	if err != nil {
		return nil, fmt.Errorf("AES New Chiper : error %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Chiper New GCM : error %w", err)
	}

	//creating nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)

	if err != nil {
		return nil, fmt.Errorf("Encrypt Creating Nounce : error %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, byteToEncrypt.Bytes() , nil)

	return ciphertext, nil
}