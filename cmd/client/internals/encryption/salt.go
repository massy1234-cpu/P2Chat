package encryption

import (
	"P2Chat/pkg/apperr"
	"crypto/rand"
)

func GenerateSalt(number int) ([]byte, error) {
	
	salt := make([]byte, number)

	// creation of salt
	_, err := rand.Read(salt)

	if err != nil {
		return nil, apperr.Wrap("generate salt", err)
	}

	return salt[:], nil
}
