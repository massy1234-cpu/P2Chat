package encryption

import (
	"P2Chat/pkg/apperr"
	"bytes"
	"encoding/binary"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/blake2b"
)

//Create an hash with the key and the secret ( for better security secret must to be hashed with argon )
func Commitment(key []byte, salt []byte, secret *memguard.LockedBuffer ) ( []byte, error  ) {
	//Create object
	hash,err := blake2b.New(32,nil)
	if err != nil {
		return nil,apperr.Wrap("commitment creation blake2b object failed",err)
	}

	//Write Salt
	binary.Write(hash, binary.BigEndian, uint32(len(salt)))
	hash.Write(salt)

	//Write pk
	binary.Write(hash, binary.BigEndian, uint32(len(key)))
	hash.Write(key)


	plainSecret := ReturnCopy(secret, 0)

	//Write secret 
	binary.Write(hash, binary.BigEndian, uint32(len(plainSecret)))
	hash.Write(plainSecret)
	
	//destroy plainsecret
	defer memguard.WipeBytes(plainSecret)


	return hash.Sum(nil), nil

}


//Verify the commitment hash 
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
