package encryption

import (
	"P2Chat/pkg/apperr"
	"bytes"
	"encoding/binary"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/blake2b"
)

// Return a 32 bytes array, the cryptographic fingerprint of the data combine with a random salt 
func Commitment(publicKey []byte, salt []byte, secret *memguard.LockedBuffer ) ( []byte, error  ) {
	
	//Create object
	hash,err := blake2b.New(32,nil)
	if err != nil {
		return nil,apperr.Wrap("commitment creation blake2b object failed",err)
	}

	// Write Salt
	binary.Write(hash, binary.BigEndian, uint32(len(salt)))
	hash.Write(salt)

	// Write public key
	err = binary.Write(hash, binary.BigEndian, uint32(len(publicKey)))
	if err != nil {
		return nil, apperr.Wrap("errore nella scrittura della public key nel commitment scheme",err)
	}
	hash.Write(publicKey)

	// Write secret 
	plainSecret := secret.Bytes()
	binary.Write(hash, binary.BigEndian, uint32(len(plainSecret)))
	hash.Write(plainSecret)


	return hash.Sum(nil), nil

}


// Verify the commitment if match with the secret, require also the same salt 
func VerifyCommitment(hash []byte, key []byte, salt []byte, secret *memguard.LockedBuffer) ( bool,error ) {
	hashCreated, err := Commitment(key,salt,secret)
	if err != nil {
		return false, apperr.Wrap("create commitment for verify hash",err)
	}

	if !bytes.Equal(hash,hashCreated) {
		return false, nil
	}
	
	return true, nil

}
