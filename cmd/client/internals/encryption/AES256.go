package encryption

import (
	"fmt"
	"crypto/rand"
	"github.com/awnumar/memguard"
	"crypto/aes"
	"crypto/cipher"
)

func EncryptAes256(passwordHashed *memguard.LockedBuffer, byteToEncrypt *memguard.LockedBuffer)([]byte, error){

	password := passwordHashed.Bytes()
	block, err := aes.NewCipher(password)
	memguard.WipeBytes(password)
	if err != nil {
		return nil, fmt.Errorf("AES Encrypt : Error new Chiper %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Encrpyt Chiper New GCM : error %w", err)
	}

	//creating nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)

	if err != nil {
		return nil, fmt.Errorf("Encrypt Creating Nounce : error %w", err)
	}

	//Seal encrpyt the byte, include the nonce and append a tag that garanteee integrity
	ciphertext := gcm.Seal(nonce, nonce, byteToEncrypt.Bytes() , nil)

	return ciphertext, nil
}


func DecryptAes256(passwordHashed *memguard.LockedBuffer, nonce []byte, byteToDecypt []byte)(*memguard.Enclave,error){
	password := passwordHashed.Bytes()
	block, err := aes.NewCipher(password)
	memguard.WipeBytes(password)
	if err != nil {
		return nil, fmt.Errorf("AES Decrypt : Error new Chiper %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Decrypt Chiper New GCM : error %w", err)
	}


	//decryption *critical phase*
	plaintext, err := gcm.Open(nil, nonce, byteToDecypt, nil)
	
	//if error is 99% of time the password incorrect
	if err != nil {
		return nil, fmt.Errorf("Decrypt Error : Password incorrect or data corruption %w", err)
	}

	plaintextSecured := memguard.NewBuffer(len(plaintext))
	copy(plaintextSecured.Bytes(), plaintext[:])
	plaintextEnclaved := plaintextSecured.Seal()

	return plaintextEnclaved,nil
}