package encryption

import (
	"P2Chat/pkg/apperr"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/awnumar/memguard"
)

//the key in the encrypt and decrypt must be 32 bytes

func EncryptAes256(key *memguard.LockedBuffer, byteToEncrypt *memguard.LockedBuffer) ([]byte, []byte, error) {

	//the check for the minimum lenght of the key is do on another func

	//cannot wipe directly aeskey.Bytes()
	aesKey := make([]byte, len(key.Bytes()))
	copy(aesKey, key.Bytes())
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, apperr.Wrap("create AES cipher", err)
	}
	defer memguard.WipeBytes(aesKey)

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


func DecryptAes256(key *memguard.LockedBuffer, nonce []byte, byteToDecypt []byte) (*memguard.LockedBuffer, error) {
	
	aesKey := make([]byte, len(key.Bytes()))
	copy(aesKey, key.Bytes())
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, apperr.Wrap("create AES cipher", err)
	}
	defer memguard.WipeBytes(aesKey)

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
