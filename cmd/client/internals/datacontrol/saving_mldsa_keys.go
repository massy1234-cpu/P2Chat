package datacontrol

import (
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"P2Chat/pkg/apperr"
	"encoding/json"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
)

type PublicKeyMLDSA struct {
	Algorithm            string `json:"Algorithm"`
	P2ChatVersion        string `json:"P2Chat Version"`
	Timestamp            string `json:"Timestamp"`
	PublicKeyMLDSABase64 string `json:"Public Key raw ( base 64 )"`
}

func SaveBytesOnFile(dataFile []byte, pathDir string, nameFile string) error {

	//check dir
	err := os.MkdirAll(pathDir, 0700) //need execution
	if err != nil {
		return apperr.Wrap("create data directory", err)
	}

	//write data and put permission only to the root
	fullPath := filepath.Join(pathDir, nameFile)
	err = os.WriteFile(fullPath, dataFile, 0600)
	if err != nil {
		return apperr.Wrap("write data file", err)
	}

	err = os.Chmod(fullPath, 0600)
	if err != nil {
		return apperr.Wrap("set file permissions", err)
	}

	//0600 -> read and write only owner

	return nil

}

func SavePrivateKeyMLDSA(privateKey *pb.PrivateKeyMLDSA) error {

	streamByte, err := proto.Marshal(privateKey)
	if err != nil {
		return apperr.Wrap("marshal private key", err)
	}

	err = SaveBytesOnFile(streamByte, "data/", "SK.bin")
	if err != nil {
		return apperr.Wrap("persist private key", err)
	}

	return nil

}

func SavePublicKeyMLDSA(publicKey PublicKeyMLDSA) error {

	streamByte, err := json.MarshalIndent(publicKey, "", " ")
	if err != nil {
		return apperr.Wrap("marshal public key", err)
	}

	err = SaveBytesOnFile(streamByte, "data/", "PK.json")
	if err != nil {
		return apperr.Wrap("persist public key", err)
	}

	return nil

}
