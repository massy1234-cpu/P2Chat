//the key in the encrypt and decrypt func must to be 32 bytes of lenght

package encryption

import (
	"P2Chat/pkg/apperr"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/awnumar/memguard"
)

//Encrypt bytes with a 32bytes key in a *memguard.LockedBuffer memory
func EncryptAes256(key *memguard.LockedBuffer, byteToEncrypt *memguard.LockedBuffer) ([]byte, []byte, error) {
	
	//check key
	if key == nil {
		return nil, nil, apperr.New("key is null")
	}

	//check if bytes are not null
	if byteToEncrypt == nil {
		return nil, nil, apperr.New("byte to encrpyt are null")
	}

	//copy
	plainKey := ReturnCopy(key, 0)
	defer memguard.WipeBytes(plainKey)

	plainBytes := ReturnCopy(byteToEncrypt, 0)
	defer memguard.WipeBytes(plainBytes)

	//check lenght key
	if len(plainKey) != 32 {
		return nil, nil, apperr.New("key lenght is not correct")
	}

	block, err := aes.NewCipher(plainKey)
	if err != nil {
		return nil, nil, apperr.Wrap("create AES cipher", err)
	}

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
	ciphertext := gcm.Seal(nil, nonce, plainBytes, nil)

	return ciphertext, nonce, nil
}


func DecryptAes256(key *memguard.LockedBuffer, nonce []byte, byteToDecypt []byte) (*memguard.LockedBuffer, error) {
	
	if key == nil {
		return nil, apperr.New("wrong key as param")
	}

	plainKey := ReturnCopy(key, 0)
	defer memguard.WipeBytes(plainKey)
	
	//check lenght of key
	if len(plainKey) != 32 {
		return nil, apperr.New("wrong key as param")
	}

	//check nonce's lenght or if is null
	if nonce == nil || len(nonce) != 12 {
		return nil, apperr.New("nonce wrong")
	}

	//check if byte to decrypt are not null
	if byteToDecypt == nil {
		return nil, apperr.New("byte to decrypt are null")
	}

	block, err := aes.NewCipher(plainKey)
	if err != nil {
		return nil, apperr.Wrap("create AES cipher", err)
	}

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
