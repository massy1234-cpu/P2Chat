package crypto

import (
	"P2Chat/pkg/apperr"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/awnumar/memguard"
)

func GenerateSalt(lenght int) ([]byte, error) {
	salt := make([]byte, lenght)
	_, err := rand.Read(salt) //creation of salt

	if err != nil {
		return nil, apperr.Wrap("generate salt", err)
	}

	return salt[:], nil
}

func EncryptAes256(passwordHashed *memguard.LockedBuffer, byteToEncrypt *memguard.LockedBuffer) ([]byte, error) {

	block, err := aes.NewCipher(passwordHashed.Bytes())
	if err != nil {
		return nil, apperr.Wrap("create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperr.Wrap("create AES-GCM", err)
	}

	//creating nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)

	if err != nil {
		return nil, apperr.Wrap("generate nonce", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, byteToEncrypt.Bytes(), nil)

	return ciphertext, nil
}
