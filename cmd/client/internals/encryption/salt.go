package encryption

import (
	"P2Chat/pkg/apperr"
	"crypto/rand"
)

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt) //creation of salt

	if err != nil {
		return nil, apperr.Wrap("generate salt", err)
	}

	return salt[:], nil
}
