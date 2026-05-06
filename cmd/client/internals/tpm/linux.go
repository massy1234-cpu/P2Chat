// for testing i need a container with linux env
// for this implementation i will use

package tpm

import (
	"P2Chat/pkg/apperr"
	"os"
	"strconv"
	"strings"
	"github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpm2/transport"
)


// check if there is a TPM in the 
func AvailableTpm() ( bool ) {

	// check the tpmrm0 ( tpm manager )
	_,err := os.Stat("/dev/tpmrm0")
	if err == nil {
		return true
	}else{
		return false
	}

}


// get tpm version from file
func StatusTPM() ( bool, error ) {

	if AvailableTpm() {
		// read the file that contains the version of the TPM
		data, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major")
		if err != nil {
			return false, apperr.Wrap("reading version tpm ",err)
		}

		version := strings.TrimSpace(string(data))

		v, err := strconv.Atoi(version)
		if err != nil {
			return false,apperr.Wrap("number not valid in tpm version",err)
		}
		return v >= 2,nil
	}else{
		return false, apperr.New("TPM is not available in this machine")
	}

}


func CreateTPMSecret() {

	// open connection with the TPM
	tpm, err := transport.OpenTPM("/dev/tpmrm0")
    if err != nil {
        apperr.Wrap("errore apertura TPM: %v", err)
    }
    defer tpm.Close()

	
}