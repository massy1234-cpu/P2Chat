package mldsapb

import (
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
)

func (privateKey *PrivateKeyMLDSA) Hashing() ( []byte,error ) {
	
	// clone the original struct for do a correct checksum
	clone := proto.Clone(privateKey).(*PrivateKeyMLDSA)
	clone.Hash = []byte{}

	bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, apperr.Wrap("hashing private key mldsa",err)
	}
	
	checksum := sha256.Sum256(bytes)

	return checksum[:], nil
}


func (publicKey *PublicKeyMLDSA) Hashing() ( []byte,error ) {
	
	// clone the original struct for do a correct checksum
	clone := proto.Clone(publicKey).(*PublicKeyMLDSA)
	clone.Hash = []byte{}

	bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, apperr.Wrap("hashing public key mldsa",err)
	}
	
	checksum := sha256.Sum256(bytes)

	return checksum[:],nil
}

func (publicKey *PublicKeyMLDSA) SetChecksum() error {
	
	// generate checksum
	hash, err := publicKey.Hashing()
	if err != nil {
		return apperr.Wrap("hashing public key mldsa",err)
	}

	// set checksum
	publicKey.Hash = hash

	return nil
}

func (privateKey *PrivateKeyMLDSA) SetChecksum() error {
	
	// generate checksum
	hash, err := privateKey.Hashing()
	if err != nil {
		return apperr.Wrap("hashing public key mldsa",err)
	}

	// set checksum
	privateKey.Hash = hash

	return nil
}

func (privateKey *PrivateKeyMLDSA) VerifyChecksum() ( bool, error ){
	
	//calculate checksum
	checksum, err := privateKey.Hashing()
	if err != nil {
		return false, apperr.Wrap("verify checksum private key mldsa failed",err)
	}

	// match cheksum
	if bytes.Equal(checksum,privateKey.Hash) {
		return true,nil
	}else{
		return false,nil
	}
}

func (publicKey *PublicKeyMLDSA) VerifyChecksum() ( bool, error ){
	
	//calculate checksum
	checksum, err := publicKey.Hashing()
	if err != nil {
		return false, apperr.Wrap("verify checksum public key mldsa failed",err)
	}

	// match cheksum
	if bytes.Equal(checksum,publicKey.Hash) {
		return true,nil
	}else{
		return false,nil
	}
}