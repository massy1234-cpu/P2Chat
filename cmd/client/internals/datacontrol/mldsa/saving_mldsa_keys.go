package datacontrol

import (
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/pkg/apperr"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
)

// Save generic bytes on file
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

// Save the private key ml-dsa87 on the file
func SavePrivateKeyMLDSA(privateKey *pb.PrivateKeyMLDSA) error {

	// set checksum
	err := privateKey.SetChecksum()
	if err != nil {
		return apperr.Wrap("set checksum private key mldsa",err)
	}

	// convert key in bytes
	streamByte, err := proto.Marshal(privateKey)
	if err != nil {
		return apperr.Wrap("marshal private key", err)
	}

	// write bytes
	err = SaveBytesOnFile(streamByte, "data/", "SK.bin")
	if err != nil {
		return apperr.Wrap("persist private key", err)
	}

	return nil

}

// Save the public key ml-dsa87 on the file
func SavePublicKeyMLDSA(publicKey *pb.PublicKeyMLDSA) error {

	// set checksum
	err := publicKey.SetChecksum()
	if err != nil {
		return apperr.Wrap("set checksum public key mldsa",err)
	}

	// convert key in bytes
	streamByte, err := proto.Marshal(publicKey)
	if err != nil {
		return apperr.Wrap("marshal public key", err)
	}

	// write bytes
	err = SaveBytesOnFile(streamByte, "data/", "PK.bin")
	if err != nil {
		return apperr.Wrap("persist public key", err)
	}

	return nil

}

// Save the pair ok ml-dsa87 keys on file
func SavePairKeyMLDSA(privateKey *pb.PrivateKeyMLDSA, publicKey *pb.PublicKeyMLDSA) error {
	
	err := SavePrivateKeyMLDSA(privateKey)
	if err != nil {
		return apperr.Wrap("Saving private key ml-dsa87", err)
	}

	err = SavePublicKeyMLDSA(publicKey)
	if err != nil {
		return apperr.Wrap("Saving public key ml-dsa87", err)
	}

	return nil
}
