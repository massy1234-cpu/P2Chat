package mldsa_data

import (
	data "P2Chat/cmd/client/internals/storage"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"google.golang.org/protobuf/proto"
)

// Return a *struct_mldsa.PrivateKeyMLDSA type after reading the file SK.bin (secret key)
func LoadPrivateKeyFromFile(pathDir string, nameFile string) (*struct_mldsa.PrivateKeyMLDSA, error) {

	//read byte from file
	streamByte, err := data.LoadByteFromFile(pathDir, nameFile)
	if err != nil {
		return nil, apperr.Wrap("reading file", err)
	}

	//converting into a proto struct
	privateKeyStruct := &struct_mldsa.PrivateKeyMLDSA{}

	err = proto.Unmarshal(streamByte, privateKeyStruct)
	if err != nil {
		return nil, apperr.Wrap("converting byte in struct", err)
	}

	// check integrity
	integrity, err := privateKeyStruct.VerifyChecksum()
	if err != nil {
		return nil, apperr.Wrap("checking integrity private key mldsa", err)
	}

	if !integrity {
		return nil, apperr.New("integrity of private key mldsa is compromised")
	}

	return privateKeyStruct, nil
}

// Return a *struct_mldsa.PublicKeyMLDSA type after reading the file PK.bin (public key)
func LoadPublicKeyFromFile(pathDir string, nameFile string) (*struct_mldsa.PublicKeyMLDSA, error) {

	//read byte from file
	streamByte, err := data.LoadByteFromFile(pathDir, nameFile)
	if err != nil {
		return nil, apperr.Wrap("reading file", err)
	}

	//converting into a proto struct
	publicKeyStruct := &struct_mldsa.PublicKeyMLDSA{}

	err = proto.Unmarshal(streamByte, publicKeyStruct)
	if err != nil {
		return nil, apperr.Wrap("converting byte in struct", err)
	}

	// check integrity
	integrity, err := publicKeyStruct.VerifyChecksum()
	if err != nil {
		return nil, apperr.Wrap("checking integrity public key mldsa", err)
	}

	if !integrity {
		return nil, apperr.New("integrity of private key mldsa is compromised")
	}

	return publicKeyStruct, nil
}

// Load the keys ml-dsa87
func LoadKeys() (*struct_mldsa.PrivateKeyMLDSA, *struct_mldsa.PublicKeyMLDSA, error) {

	privateKey, err := LoadPrivateKeyFromFile("data/", "SK.bin")
	if err != nil {
		return nil, nil, apperr.Wrap("Load private key ml-dsa87 from file", err)
	}

	publicKey, err := LoadPublicKeyFromFile("data/", "PK.bin")
	if err != nil {
		return nil, nil, apperr.Wrap("Load public key ml-dsa87 from file", err)
	}

	return privateKey, publicKey, nil

}
