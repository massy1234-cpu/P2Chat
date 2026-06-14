package storage

import (
	"P2Chat/pkg/apperr"
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

// Read and return the bytes
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