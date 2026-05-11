// tpm usage for linux systems
package linux

import (
	datacontrol "P2Chat/cmd/client/internals/datacontrol/mldsa"
	"P2Chat/pkg/apperr"
	"os"
	"strconv"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// primaryTemplate is package-level so CreateTPMResponse and UnsealSecret always use the
// identical template — CreatePrimary is deterministic: same template + same TPM = same key.
// i use the same primaryTemplate for all the TPM operations
var primaryTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgRSA,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		Restricted:          true,
		Decrypt:             true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
		Symmetric: tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgAES,
			KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
			Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
		},
		Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
		KeyBits: 2048,
	}),
}

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

// CreateTPMResponse generates a TPM-bound sealed secret and returns the blob pair
// (OutPrivate + OutPublic) that must be persisted to disk. The secret never leaves
// the TPM during this call.
func CreateTPMResponse() (*tpm2.CreateResponse, error) {

	// open connection with TPM
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, apperr.Wrap("errore apertura TPM", err)
	}
	defer tpm.Close()

	primaryResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, apperr.Wrap("CreatePrimary failed", err)
	}
	defer tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm)

	// TPMAlgNull scheme = sealed blob, TPM generates the secret internally
	secretTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
		}),
	}

	parentHandle := tpm2.NamedHandle{
		Handle: primaryResp.ObjectHandle,
		Name:   primaryResp.Name,
	}

	// createResp contains the public and private blob — secret is sealed inside OutPrivate
	createResp, err := tpm2.Create{
		ParentHandle: parentHandle,
		InPublic:     tpm2.New2B(secretTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, apperr.Wrap("Create sealed secret failed", err)
	}

	return createResp, nil
}

// UnsealSecret recreates the primary key from the package-level template (deterministic),
// loads the child blob, unseals the secret, and immediately wraps it in a memguard
// LockedBuffer (mlock — no swap to disk). The raw bytes are zeroed before returning.
// NOTE : the function assume that the primaryTemplate is always the same as like previously defined
func UnsealSecret(private tpm2.TPM2BPrivate, public tpm2.TPM2BPublic ) (*memguard.LockedBuffer, error) {

	// open the connection
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, apperr.Wrap("apertura TPM", err)
	}
	defer tpm.Close()

	// same template = same primary key on the same physical TPM chip
	primaryResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, apperr.Wrap("CreatePrimary failed", err)
	}
	defer tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm)

	// load the child blob — TPM verifies the cryptographic binding to the primary
	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryResp.ObjectHandle,
			Name:   primaryResp.Name,
		},
		// load the blobs
		InPrivate: private,
		InPublic:  public,
	}.Execute(tpm)
	if err != nil {
		return nil, apperr.Wrap("Load failed", err)
	}

	// flush is used cause of the very limited memory of tpm
	defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(tpm)

	// unseal — this is the only moment the secret touches RAM
	unsealResp, err := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
		},
	}.Execute(tpm)
	if err != nil {
		return nil, apperr.Wrap("Unseal failed", err)
	}

	// immediately move into memguard (mlock) then wipe the bytes
	buf := memguard.NewBuffer(len(unsealResp.OutData.Buffer))
	copy(buf.Bytes(), unsealResp.OutData.Buffer)
	memguard.WipeBytes(unsealResp.OutData.Buffer)

	return buf, nil
}


// func that store the blobs produced to a file ( privateBlob.bin, publicBlob.bin )
func StoreBlobs(private tpm2.TPM2BPrivate, public tpm2.TPM2BPublic) error {
	
	// serialize in bytes the blobs
	privateStremBlob := tpm2.Marshal(private)
	publicStreamBlob := tpm2.Marshal(public)

	// write the stream bytes into the files
	err := datacontrol.SaveBytesOnFile(privateStremBlob,"/data/blobs","privateBlob.bin")
	if err != nil {
		return apperr.Wrap("Error writing private blob on file",err)
	}

	err = datacontrol.SaveBytesOnFile(publicStreamBlob,"/data/blobs","publicBlob.bin")
	if err != nil {
		return apperr.Wrap("Error writing public blob on file",err)
	}

	return nil
}

