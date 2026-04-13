package datacontrol

import (
	"P2Chat/cmd/client/internals/version"
	"P2Chat/cmd/client/internals/encryption"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/awnumar/memguard"
)

func LoadPrivateKey(password *memguard.LockedBuffer) (*memguard.Enclave, error) {
	
	_, err := os.Stat("data/SK.dat")
	if err != nil {
		return nil, fmt.Errorf("Loading Private Key : path doesn't match valid file %w", err)
	}

	//reading the file
	data, err := os.ReadFile("data/SK.dat")
	if err != nil {
		return nil, fmt.Errorf("Loading Private Key : file is not valid %w", err)
	}

	//check version number of the file
	if !(bytes.Equal(version.MagicByte(), data[:5])) {
		return nil, fmt.Errorf("Loading Private Key : version of the file not match with this version")
	}

	//check checksum alldata
	checksum := sha256.Sum256(data[:32])
	if !(bytes.Equal(checksum[:], data[32:])) {
		return nil, fmt.Errorf("Loading Private Key : checksum doesnt match , possible data corruption")
	}

	//decrypt Private Key and control if the password was correct
	ciphertext := data[5:32]
	nonce := data[5:17]
	plaintext, err := encryption.DecryptAes256(password, nonce, ciphertext)

	if err != nil{
		return nil, fmt.Errorf("Loading Private Key : Error in the decryption of key %w", err)
	}
    
	return plaintext, nil
}
