package encryption

import (
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
)

//Encrypt a generic private key in a safe memory area. private key in the area MUST TO BE like []bytes
func EncryptPrivateKey(password *memguard.LockedBuffer, privateKey *memguard.LockedBuffer, level int) ([]byte, []byte, []byte, error) {

	//Generate salt
	salt, err := GenerateSalt()
	if err != nil {
		return nil, nil, nil, apperr.Wrap("generate salt", err)
	}

	//KDF of password with argon2id
	aesKey, err := argon.HashWithArgon(level, password, salt)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("derive encryption key with argon2id", err)
	}

	//the ciphertext contains the tag for integrity ( checksum )
	rawKeyEncrypted, nonce, err := EncryptAes256(aesKey, privateKey)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("encrypt private key", err)
	}

	return rawKeyEncrypted, nonce, salt, nil
}
