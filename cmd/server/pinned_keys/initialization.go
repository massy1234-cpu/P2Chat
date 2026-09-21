package pinnedkeys

import (
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"fmt"
	"github.com/awnumar/memguard"
	"os"
	"path/filepath"
)

const pathName = "pinned_keys"

// check if the keys pinned are already created else it create it
func Initialize(level int, password *memguard.Enclave, store bool, HSM bool) error {
	memguard.CatchInterrupt()

	if _, err := os.Stat(filepath.Join(storage.BasePath, pathName, "SK.bin")); err == nil {
		if _, err := os.Stat(filepath.Join(storage.BasePath, pathName, "PK.bin")); err == nil {
			fmt.Println("ML-DSA-87 keys already exist ")
			return nil
		}
	}

	// if the pinned key are NOT present the app create it
	// NB: the user that want to use this APP have to find a method to distrubuite the public MLDSA
	// between users ( for now, i will implement an alternative to this method )
	rawPriv, rawPub, err := mldsa_keys.CreateKeys()
	if err != nil {
		return apperr.Wrap("create ML-DSA keys", err)
	}

	privateKeyStruct, err := rawPriv.Encrypt(password, level, HSM)
	if err != nil {
		return apperr.Wrap("encrypt ML-DSA private key", err)
	}

	publicKeyStruct, err := rawPub.Serialize()
	if err != nil {
		return apperr.Wrap("create ML-DSA public key", err)
	}

	if store {
		if err := mldsa_keys.StoreKeys(privateKeyStruct, publicKeyStruct, filepath.Join(storage.BasePath, pathName)); err != nil {
			return apperr.Wrap("store ML-DSA keys", err)
		}
	}

	fmt.Println("ML-DSA-87 keys generated and saved")
	return nil

}
