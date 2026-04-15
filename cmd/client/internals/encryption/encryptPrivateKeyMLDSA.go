package encryption

import (
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
)

func EncryptPrivateKeyMLDSA(password *memguard.LockedBuffer, privateKey *memguard.LockedBuffer, level int) ([]byte, []byte, []byte, error) {

	//create salt
	salt, err := GenerateSalt()
	if err != nil {
		return nil, nil, nil, apperr.Wrap("generate salt", err)
	}

	//hashing password with argon2id
	passwordHashed, err := argon.HashWithArgon(level, password, salt)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("derive encryption key with argon2id", err)
	}

	//Structure of ciphertext
	//[ciphertext + tag]
	rawKeyEncrypted, nonce, err := EncryptAes256(passwordHashed, privateKey)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("encrypt private key", err)
	}

	return rawKeyEncrypted, nonce, salt, nil
}
