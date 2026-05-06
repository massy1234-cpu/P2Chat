package datacontrol

import (
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/pkg/apperr"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
)

// Read and return the bytes readed in the path specified
func LoadByteFromFile(pathDir string, nameFile string) ([]byte, error) {

	fullPath := filepath.Join(pathDir, nameFile)

	//check if file exist and eventually read it
	streamByte, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.Wrap("file not exist", err)
		}
		return nil, apperr.Wrap("checking file", err)
	}

	return streamByte, nil
}

// Return a *pb.PrivateKeyMLDSA type after reading the file SK.bin
func LoadPrivateKeyMLDSAFromFile(pathDir string, nameFile string) (*pb.PrivateKeyMLDSA, error) {

	//read byte from file
	streamByte, err := LoadByteFromFile(pathDir, nameFile)
	if err != nil {
		return nil, apperr.Wrap("reading file", err)
	}

	//converting into a proto struct
	privateKeyStruct := &pb.PrivateKeyMLDSA{}

	err = proto.Unmarshal(streamByte, privateKeyStruct)
	if err != nil {
		return nil, apperr.Wrap("converting byte in struct", err)
	}

	// check integrity
	integrity, err := privateKeyStruct.VerifyChecksum()
	if err != nil {
		return nil, apperr.Wrap("checking integrity private key mldsa",err)
	}

	if !integrity {
		return nil, apperr.New("integrity of private key mldsa is compromised")
	}

	return privateKeyStruct, nil
}

// Return a *pb.PublicKeyMLDSA type after reading the file PK.bin
func LoadPublicKeyMLDSAFromFile(pathDir string, nameFile string) (*pb.PublicKeyMLDSA, error) {

	//read byte from file
	streamByte, err := LoadByteFromFile(pathDir, nameFile)
	if err != nil {
		return nil, apperr.Wrap("reading file", err)
	}

	//converting into a proto struct
	publicKeyStruct := &pb.PublicKeyMLDSA{}
	
	err = proto.Unmarshal(streamByte, publicKeyStruct)
	if err != nil {
		return nil, apperr.Wrap("converting byte in struct", err)
	}

	// check integrity
	integrity, err := publicKeyStruct.VerifyChecksum()
	if err != nil {
		return nil, apperr.Wrap("checking integrity public key mldsa",err)
	}

	if !integrity {
		return nil, apperr.New("integrity of private key mldsa is compromised")
	}


	return publicKeyStruct, nil
}

// Load the keys ml-dsa87
func LoadKeysMLDSA() (*pb.PrivateKeyMLDSA, *pb.PublicKeyMLDSA, error) {

	privateKey, err := LoadPrivateKeyMLDSAFromFile("data/", "SK.bin")
	if err != nil {
		return nil, nil, apperr.Wrap("Load private key ml-dsa87 from file", err)
	}

	publicKey, err := LoadPublicKeyMLDSAFromFile("data/", "PK.bin")
	if err != nil {
		return nil, nil, apperr.Wrap("Load public key ml-dsa87 from file", err)
	}

	return privateKey, publicKey, nil

}
