package datacontrol

import (
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/pkg/apperr"
	"encoding/json"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"
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
	PrivateKeyStruct := &pb.PrivateKeyMLDSA{}

	err = proto.Unmarshal(streamByte, PrivateKeyStruct)
	if err != nil {
		return nil, apperr.Wrap("converting byte in struct", err)
	}

	return PrivateKeyStruct, nil
}

// Return a PublicKeyMLDSA type after reading the file PK.bin
func LoadPublicKeyMLDSAFromFile(pathDir string, nameFile string) (*PublicKeyMLDSA, error) {

	//read byte from file
	streamByte, err := LoadByteFromFile(pathDir, nameFile)
	if err != nil {
		return nil, apperr.Wrap("reading file", err)
	}

	//converting into a struct
	var PublicKeyMLDSA PublicKeyMLDSA
	err = json.Unmarshal(streamByte, &PublicKeyMLDSA)
	if err != nil {
		return nil, apperr.Wrap("converting byte in struct", err)
	}

	return &PublicKeyMLDSA, nil
}

// Load the keys ml-dsa87
func LoadKeysMLDSA() (*pb.PrivateKeyMLDSA, *PublicKeyMLDSA, error) {

	privateKey, err := LoadPrivateKeyMLDSAFromFile("data/", "SK.bin")
	if err != nil {
		return nil, nil, apperr.Wrap("Load private key ml-dsa87 from file", err)
	}

	publicKey, err := LoadPublicKeyMLDSAFromFile("data/", "PK.json")
	if err != nil {
		return nil, nil, apperr.Wrap("Load public key ml-dsa87 from file", err)
	}

	return privateKey, publicKey, nil

}
