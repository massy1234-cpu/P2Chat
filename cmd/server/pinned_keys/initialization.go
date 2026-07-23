package pinnedkeys

import (
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"fmt"
	"os"
	"path/filepath"
	"github.com/awnumar/memguard"
)

const pathName = "pinned_keys"

// check if the keys pinned are already created else it create it 
func Initialize(level int, password *memguard.Enclave, store bool, HSM bool) error {
	memguard.CatchInterrupt()

	if _, err := os.Stat(filepath.Join(storage.BasePath,pathName, "SK.bin")); err == nil {
		if _, err := os.Stat(filepath.Join(storage.BasePath,pathName, "PK.bin")); err == nil {
			fmt.Println("ML-DSA-87 keys already exist ")
			return nil
		}
	}

	// if the pinned key are NOT present the app create it 
	// NB: the user that want to use this APP have to find a method to distrubuite the public MLDSA
	// between users ( for now, i will implement an alternative to this method ) 
	_, _, _, err := mldsa_keys.CreateKeys(level, password, store, HSM, "pinned_keys")
	if err != nil {
		return apperr.Wrap("create ML-DSA keys", err)
	}

	fmt.Println("ML-DSA-87 keys generated and saved")
	return nil

}