package proto_struct_x25519

import (
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"
	"google.golang.org/protobuf/proto"
)

// NOTE : this function protect only in case of error or malfunction NOT in case of intentional tampering
func Hashing(data proto.Message) ([]byte, error) {

	if data == nil {
		return nil, apperr.New("nil proto message")
	}

	// clone the original struct for do a correct checksum without the parameter hash
	clone := proto.Clone(data)

	// cast to generic message to specific protobuf struct
	switch m := clone.(type) {
	case *PrivateKeyX25519:
		m.Checksum = nil
	default:
		return nil, apperr.New("unsupported proto message")
	}

	// convert the struct in bytes
	bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, apperr.Wrap("hashing private key x25519", err)
	}

	// hash
	checksum := sha256.Sum256(bytes)

	return checksum[:], nil
}

// VerifyChecksum compares the checksum parameter with an hash calculated on the payload
func VerifyChecksum(data proto.Message, hashParameter []byte) (bool, error) {

	if data == nil {
		return false, apperr.New("nil proto message")
	}

	checksum, err := Hashing(data)
	if err != nil {
		return false, apperr.Wrap("verify checksum private key x25519 failed", err)
	}

	if bytes.Equal(checksum, hashParameter) {
		return true, nil
	}
	return false, nil
}

func SetChecksum(data proto.Message) error {

	if data == nil {
		return apperr.New("nil proto message")
	}

	hash, err := Hashing(data)
	if err != nil {
		return err
	}

	switch m := data.(type) {
	case *PrivateKeyX25519:
		m.Checksum = hash
	default:
		return apperr.New("protobuf struct not defined")
	}

	return nil
}

func (privateKey *PrivateKeyX25519) Hashing() ([]byte, error) {

	if privateKey == nil {
		return nil, apperr.New("nil private key x25519")
	}

	return Hashing(privateKey)
}

func (privateKey *PrivateKeyX25519) SetChecksum() error {

	if privateKey == nil {
		return apperr.New("nil private key x25519")
	}

	return SetChecksum(privateKey)
}

func (privateKey *PrivateKeyX25519) VerifyChecksum() (bool, error) {

	if privateKey == nil {
		return false, apperr.New("nil private key x25519")
	}

	boolean, err := VerifyChecksum(privateKey, privateKey.Checksum)
	return boolean, err
}
