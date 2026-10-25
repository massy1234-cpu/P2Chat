// EncryptAes256 and DecryptAes256 expect a 32-byte AES-256 key.

package encryption

import (
	"P2Chat/pkg/apperr"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/awnumar/memguard"
)

// CreateCipherAes validates the key and creates an AES-256-GCM cipher.
func CreateCipherAes(key []byte) (cipher.AEAD, error) {
	
	if len(key) != 32 {
		return nil, apperr.New("key length is not correct")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, apperr.Wrap("create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperr.Wrap("create AES-GCM", err)
	}

	return gcm, nil
}


// EncryptedPayload encapsulates an AES-256-GCM ciphertext with its required nonce.
type EncryptedPayload struct {
	Ciphertext []byte `msgpack:"ciphertext"`
	Nonce      []byte `msgpack:"nonce"`
}

// EncryptAes256 encrypts plaintext with AES-256-GCM and returns an EncryptedPayload.
func EncryptAes256(key *memguard.LockedBuffer, byteToEncrypt []byte) (*EncryptedPayload, error) {

	if key == nil {
		return nil, apperr.New("aes key is nil")
	}

	if byteToEncrypt == nil {
		return nil, apperr.New("byte to encrypt are null")
	}

	gcm, err := CreateCipherAes(key.Bytes())
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, apperr.Wrap("generate nonce", err)
	}

	ciphertext := gcm.Seal(nil, nonce, byteToEncrypt, nil)

	return &EncryptedPayload{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

// DecryptAes256 decrypts AES-256-GCM ciphertext and moves the plaintext back into protected memory.
func DecryptAes256(key *memguard.LockedBuffer, payload *EncryptedPayload) (*memguard.LockedBuffer, error) {

	if key == nil {
		return nil, apperr.New("aes key is nil")
	}

	if payload == nil {
		return nil, apperr.New("encrypted payload is nil")
	}

	//check nonce's length or if is null
	if payload.Nonce == nil || len(payload.Nonce) != 12 {
		return nil, apperr.New("nonce wrong")
	}

	//check if byte to decrypt are not null
	if payload.Ciphertext == nil {
		return nil, apperr.New("byte to decrypt are null")
	}

	gcm, err := CreateCipherAes(key.Bytes())
	if err != nil {
		return nil, err
	}

	//decryption : *critical phase*
	plaintext, err := gcm.Open(nil, payload.Nonce, payload.Ciphertext, nil)

	//if error is 99% of time the password incorrect
	if err != nil {
		return nil, apperr.Wrap("decrypt payload (wrong password or corrupted data)", err)
	}

	plaintextSecured := memguard.NewBuffer(len(plaintext))
	copy(plaintextSecured.Bytes(), plaintext)

	defer memguard.WipeBytes(plaintext)

	return plaintextSecured, nil
}
