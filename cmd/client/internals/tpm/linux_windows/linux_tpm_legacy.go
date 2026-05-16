package linux_windows
/*

this is only a file for visualize the old library tpm-legacy, in the file linux_tpm.go i use the modern library

package tpm

import (
	"P2Chat/pkg/apperr"
	"github.com/google/go-tpm/tpm2"
	"os"
	"strconv"
	"strings"
)

// check if there is a TPM in the
func AvailableTPM() bool {

	// check the tpmrm0 ( tpm manager )
	_, err := os.Stat("/dev/tpmrm0")
	if err == nil {
		return true
	} else {
		return false
	}

}

// get tpm version from file
func StatusTPM() (bool, error) {

	if AvailableTPM() {
		
		// read the file that contains the version of the TPM
		data, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major")
		if err != nil {
			return false, apperr.Wrap("reading version tpm ", err)
		}

		// eliminate spaces
		version := strings.TrimSpace(string(data))

		// convert the in an int type
		v, err := strconv.Atoi(version)
		if err != nil {
			return false, apperr.Wrap("number not valid in tpm version", err)
		}
		return v >= 2, nil
	} else {
		return false, apperr.New("TPM is not available in this machine")
	}

}

func CreateTPMSecret() (){

	var tpmDev string
	
	// open connection with the TPM manager
	tpmDev = "/dev/tpmrm0"
	tpm, err := tpm2.OpenTPM(tpmDev)
	if err != nil {
		apperr.Wrap("errore apertura TPM: %v", err)
	}
	defer tpm.Close()

	// define the parent template
	primaryTemplate := tpm2.Public{
    Type:       tpm2.AlgRSA,
    NameAlg:    tpm2.AlgSHA256,
    Attributes: tpm2.FlagStorageDefault,
    RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128, 
			},
			KeyBits: 2048,
		},
	}

	primaryHandle, _, err := tpm2.CreatePrimary(
		tpmDev,             // the TPM file descriptor
		tpm2.HandleOwner,   // hierarchy: Owner (TPM_RH_OWNER)
		tpm2.PCRSelection{},// no PCR binding for now
		"",                 // hierarchy auth (empty = no password on hierarchy)
		"",                 // key auth (empty = no password on this key)
		primaryTemplate,    // the template that describes the key
	)
	if err != nil {
		apperr.Wrap("CreatePrimary failed", err)
		return
	}
	defer tpm2.FlushContext(tpmDev, primaryHandle)


	hmacTemplate := tpm2.Public{
		Type:    tpm2.AlgKeyedHash,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |
					tpm2.FlagFixedParent |
					tpm2.FlagSensitiveDataOrigin |
					tpm2.FlagUserWithAuth |
					tpm2.FlagSign,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:  tpm2.AlgHMAC,
			Hash: tpm2.AlgSHA256,
		},
	}

	private, public, err := tpm2.Create(
		tpmDev,             // TPM file descriptor
		primaryHandle,      // parent key that will seal this key
		tpm2.PCRSelection{},// no PCR binding
		"",                 // key auth password (empty for now)
		"",                 // sensitive data (not used here)
		hmacTemplate,       // blueprint for the HMAC key
	)
	if err != nil {
		return nil, apperr.Wrap("Create HMAC key failed: %w", err)
	}



}
*/
