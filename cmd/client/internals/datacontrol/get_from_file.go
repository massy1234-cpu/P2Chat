package datacontrol

import (
	//"fmt"
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"P2Chat/pkg/apperr"
	"encoding/json"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"
)

func LoadByteFromFile(pathDir string, nameFile string)([]byte, error){

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

func LoadPrivateKeyMLDSAFromFile(pathDir string, nameFile string)(*pb.PrivateKeyMLDSA, error){

	//read byte from file
	streamByte, err := LoadByteFromFile("data/", "SK.bin")
	if err != nil {
		return nil, apperr.Wrap("reading file", err)
	}

	//converting into a proto struct
	PrivateKeyStruct := &pb.PrivateKeyMLDSA{}

	err = proto.Unmarshal(streamByte, PrivateKeyStruct)
	if err != nil {
		apperr.Wrap("converting byte in struct", err)
	}

	return PrivateKeyStruct, nil
}

func LoadPublicKeyMLDSAFromFile(pathDir string, nameFile string)(*PublicKeyMLDSA, error){

	//read byte from file
	streamByte, err := LoadByteFromFile("data/", "PK.json")
	if err != nil {
		return nil, apperr.Wrap("reading file", err)
	}

	//converting into a struct
	var PublicKeyMLDSA PublicKeyMLDSA
	err = json.Unmarshal(streamByte, &PublicKeyMLDSA)

	return &PublicKeyMLDSA, nil
}