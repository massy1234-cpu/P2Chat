package crypto

import (
	"P2Chat/cmd/server/internals/version"
	"P2Chat/pkg/apperr"
	"crypto/sha256"
	"os"
	"path/filepath"
)

func saveDataOnFile(dataFile []byte, pathDir string, nameFile string) error {

	//check dir
	err := os.MkdirAll(pathDir, 0700)
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

func createKeyStructure(salt []byte, data []byte, secretOrNot bool) []byte {

	var dataFile []byte

	if secretOrNot {
		//saving PrivateKey
		//structure of SK
		//[magicbyte][salt][nonce][Ciphertext][alldata checksum]

		dataFile = make([]byte, 0, len(version.MagicByte())+len(salt)+len(data))

		dataFile = append(dataFile, version.MagicByte()...)
		dataFile = append(dataFile, salt...)
		dataFile = append(dataFile, data...)

		//checksum for all dataFile
		checksumDataFile := sha256.Sum256(dataFile)

		dataFile = append(dataFile, checksumDataFile[:]...)

	} else {
		//saving PublicKey
		//structure of PK
		//[Public Key][checksum]

		checksumDataFile := sha256.Sum256(data)
		dataFile = make([]byte, 0, len(data)+len(checksumDataFile))

		dataFile = append(dataFile, version.MagicByte()...)
		dataFile = append(dataFile, data...)
		dataFile = append(dataFile, checksumDataFile[:]...)

	}

	return dataFile

}
