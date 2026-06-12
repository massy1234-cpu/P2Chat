// EncryptAes256 and DecryptAes256 expect a 32-byte AES-256 key.

package encryption

import (
	"P2Chat/pkg/apperr"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/awnumar/memguard"
)

// EncryptAes256 encrypts protected plaintext with AES-256-GCM and returns ciphertext and nonce.
func EncryptAes256(key *memguard.LockedBuffer, byteToEncrypt *memguard.LockedBuffer) ([]byte, []byte, error) {
	
	//check key
	if key == nil {
		return nil, nil, apperr.New("key is null")
	}

	//check if bytes are not null
	if byteToEncrypt == nil {
		return nil, nil, apperr.New("byte to encrpyt are null")
	}

	//check lenght key
	if len(key.Bytes()) != 32 {
		return nil, nil, apperr.New("key lenght is not correct")
	}

	block, err := aes.NewCipher(key.Bytes())
	if err != nil {
		return nil, nil, apperr.Wrap("create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, apperr.Wrap("create AES-GCM", err)
	}

	// creating nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)

	if err != nil {
		return nil, nil, apperr.Wrap("generate nonce", err)
	}

	// Seal encrypt the byte, include the nonce and append a tag that shows integrity
	ciphertext := gcm.Seal(nil, nonce, byteToEncrypt.Bytes(), nil)

	return ciphertext, nonce, nil
}

// DecryptAes256 decrypts AES-256-GCM ciphertext and moves the plaintext back into protected memory.
func DecryptAes256(key *memguard.LockedBuffer, nonce []byte, byteToDecypt []byte) (*memguard.LockedBuffer, error) {

	if key == nil {
		return nil, apperr.New("wrong key as param")
	}

	//check lenght of key
	if len(key.Bytes()) != 32 {
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

	block, err := aes.NewCipher(key.Bytes())
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
