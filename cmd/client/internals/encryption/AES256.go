package encryption

import (
	"P2Chat/pkg/apperr"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/awnumar/memguard"
)

//the key in the encrypt and decrypt must be 32 bytes

func EncryptAes256(aesKey *memguard.LockedBuffer, byteToEncrypt *memguard.LockedBuffer) ([]byte, []byte, error) {

	//aesKey.Bytes() return a reference to the protect memory area, so when i wipebytes the password i wipe also the aesKey
	password := make([]byte, len(aesKey.Bytes()))
	copy(password, aesKey.Bytes())
	block, err := aes.NewCipher(password)
	if err != nil {
		return nil, nil, apperr.Wrap("create AES cipher", err)
	}
	defer memguard.WipeBytes(password)

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, apperr.Wrap("create AES-GCM", err)
	}

	//creating nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)

	if err != nil {
		return nil, nil, apperr.Wrap("generate nonce", err)
	}

	//Seal encrpyt the byte, include the nonce and append a tag that garanteee integrity
	ciphertext := gcm.Seal(nil, nonce, byteToEncrypt.Bytes(), nil)

	return ciphertext, nonce, nil
}


func DecryptAes256(aesKey *memguard.LockedBuffer, nonce []byte, byteToDecypt []byte) (*memguard.LockedBuffer, error) {
	
password := make([]byte, len(aesKey.Bytes()))
	copy(password, aesKey.Bytes())
	block, err := aes.NewCipher(password)
	if err != nil {
		return nil, apperr.Wrap("create AES cipher", err)
	}
	defer memguard.WipeBytes(password)

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperr.Wrap("create AES-GCM", err)
	}

	//decryption *critical phase*
	plaintext, err := gcm.Open(nil, nonce, byteToDecypt, nil)

	//if error is 99% of time the password incorrect
	if err != nil {
		return nil, apperr.Wrap("decrypt payload (wrong password or corrupted data)", err)
	}

	plaintextSecured := memguard.NewBuffer(len(plaintext))
	copy(plaintextSecured.Bytes(), plaintext)
	
	defer memguard.WipeBytes(plaintext)

	return plaintextSecured, nil
}
