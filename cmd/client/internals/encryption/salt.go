package encryption

import (
	"fmt"
	"crypto/rand"
)

func GenerateSalt(lenght int) ( []byte, error ) {
	salt := make([]byte, lenght)
	_, err := rand.Read(salt) //creation of salt

	if err != nil {
		return nil,fmt.Errorf("Generator Salt -> failed to generate salt %w", err)
	}

	return salt[:], nil
}