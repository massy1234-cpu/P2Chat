package proto_struct_mldsa

import (
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"
	"google.golang.org/protobuf/proto"
)

// NOTE : this function protect only in case of error or malfunction NOT in case of intentional tampering
func Hashing(data proto.Message) ([]byte,error) {
	
	if data == nil {
		return nil, apperr.New("nil proto message")
	}

	// clone the original struct for do a correct checksum without the parameter hash 
	clone := proto.Clone(data)
	
	// cast to generic message to specific protobuf struct
	switch m := clone.(type) {
		case *PrivateKeyMLDSA:
			m.Checksum = nil
		case *PublicKeyMLDSA:
			m.Checksum = nil
		default:
			return nil, apperr.New("unsupported proto message")
	}

	// convert the struct in bytes
	bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, apperr.Wrap("hashing private key mldsa",err)
	}
	
	// hash
	checksum := sha256.Sum256(bytes)

	return checksum[:], nil
}


// Match the Hash parameter of the proto struct with the an hash calculate for check errors
func VerifyChecksum(data proto.Message,hash_parameter []byte) (bool,error) {
	
	if data == nil {
		return false, apperr.New("nil proto message")
	}

	// do the hash
	checksum, err := Hashing(data)
	if err != nil {
		return false, apperr.Wrap("verify checksum private key mldsa failed",err)
	}

	// match the hash
	if bytes.Equal(checksum,hash_parameter) {
		return true,nil
	}else{
		return false,nil
	}

}


func SetChecksum(data proto.Message) error {
	
	if data == nil {
		return apperr.New("nil proto message")
	}
		
	// generate checksum
	hash,err := Hashing(data)
	if err != nil {
		return err
	}

	switch m := data.(type) {
		case *PrivateKeyMLDSA :
			m.Checksum = hash
		case *PublicKeyMLDSA :
			m.Checksum = hash
		default :
			return apperr.New("protobuf struct not defined")
	}

	return nil
}

func (privateKey *PrivateKeyMLDSA) Hashing() ( []byte,error ) {
	
	if privateKey == nil {
		return nil, apperr.New("nil private key mldsa")
	}
		
	hash,err := Hashing(privateKey)
	return hash,err

}


func (publicKey *PublicKeyMLDSA) Hashing() ( []byte,error ) {
	
	if publicKey == nil {
		return nil, apperr.New("nil public key mldsa")
	}
		
	hash,err := Hashing(publicKey)
	return hash,err
}

func (publicKey *PublicKeyMLDSA) SetChecksum() error {
	
	if publicKey == nil {
		return apperr.New("nil public key mldsa")
	}
		
	return SetChecksum(publicKey)
}

func (privateKey *PrivateKeyMLDSA) SetChecksum() error {
	
	if privateKey == nil {
		return apperr.New("nil private key mldsa")
	}
		
	return SetChecksum(privateKey)
}

func (privateKey *PrivateKeyMLDSA) VerifyChecksum() ( bool, error ){
	
	if privateKey == nil {
		return false, apperr.New("nil private key mldsa")
	}

	boolean, err := VerifyChecksum(privateKey,privateKey.Checksum)
	return boolean,err

}

func (publicKey *PublicKeyMLDSA) VerifyChecksum() ( bool, error ){
	
	if publicKey == nil {
		return false, apperr.New("nil public key mldsa")
	}
		
	boolean, err := VerifyChecksum(publicKey,publicKey.Checksum)
	return boolean,err

}
