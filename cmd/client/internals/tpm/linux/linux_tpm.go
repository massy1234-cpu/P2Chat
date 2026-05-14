// tpm usage for linux systems
package linux

import (
	datacontrol "P2Chat/cmd/client/internals/datacontrol/mldsa"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// persistend handler ( optimization )
const persistentHandle = tpm2.TPMHandle(0x81000001) 

// primaryTemplate is package-level so CreateTPMResponse and UnsealSecret always use the
// identical primary template — CreatePrimary is deterministic: same template + same TPM = same key.
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

// Get tpm version from file
func AvailableTPM() (bool, error) {
	
	// the better way to understand if the TPM is available and understand if the app can use it, is try to open it
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return false, apperr.Wrap("TPM not usable or not available", err)
	}
	defer tpm.Close()
	return true, nil

}


// Check if the TPM has stored the primary template in the memory ( NV ) and return the public key
func EnsurePrimaryNV(tpm transport.TPM) ( *tpm2.ReadPublicResponse, bool, error ) {                                                                                     
																			
	// check if the primary template handler exist in the NV, reading his public key
	PublicRead, err := tpm2.ReadPublic{ObjectHandle: persistentHandle}.Execute(tpm)
	if err == nil {                                                             
		return PublicRead, true, nil                
	}else{
		return nil, false, nil
	}
}


// CreateTPMResponse generates a TPM-bound sealed secret and returns the blob pair
// (OutPrivate + OutPublic) that must be persisted to disk to be recreated later 
func CreateTPMResponse() (*tpm2.CreateResponse, error) {

	// check if tpm is available
	if res,err := AvailableTPM();res == false {
		return nil, apperr.Wrap("Cannot use tpm secret ",err)
	}

	// open connection with TPM
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, apperr.Wrap("errore apertura TPM", err)
	}
	defer tpm.Close()

	var parentHandle tpm2.NamedHandle

	// check if primary template is persistent in NV memory
	pubResp, res, err := EnsurePrimaryNV(tpm) 
	if ( res == true && err == nil ) {

		// create the handler
		parentHandle = tpm2.NamedHandle{
			Handle: persistentHandle,
			Name:   pubResp.Name,
		}

	}else{

		// if primary template is not in NV memory, i create it
		primaryResp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(primaryTemplate),
		}.Execute(tpm)
		if err != nil {
			return nil, apperr.Wrap("CreatePrimary failed", err)
		}

		// PersistPrimaryNV store the primary template ( public key + parameters ) in NV memory
		if err := PersistPrimaryNV(tpm, primaryResp); err != nil {
			tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm)
			return nil, err
		}
		tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm)

		parentHandle = tpm2.NamedHandle{
			Handle: persistentHandle,
			Name:   primaryResp.Name,
		}

	}


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

	var parentHandle tpm2.NamedHandle

	// check if primary template is persistent in NV memory
	pubResp, res, err := EnsurePrimaryNV(tpm) 
	if ( res == true && err == nil ) {

		// create the handler
		parentHandle = tpm2.NamedHandle{
			Handle: persistentHandle,
			Name:   pubResp.Name,
		}

	}else{
		// same template = same primary key on the same physical TPM chip
		primaryResp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(primaryTemplate),
		}.Execute(tpm)
		if err != nil {
			return nil, apperr.Wrap("CreatePrimary failed", err)
		}

		if err := PersistPrimaryNV(tpm, primaryResp); err != nil {
			tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm)
			return nil, err
		}
		tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm)

		parentHandle = tpm2.NamedHandle{
			Handle: persistentHandle,
			Name:   primaryResp.Name,
		}
	}

	// load the child blob — TPM verifies the cryptographic binding to the primary
	loadResp, err := tpm2.Load{
		ParentHandle: parentHandle,
		
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


// PersistPrimaryNV stores the primary key handle into NV at persistentHandle so future
// calls skip CreatePrimary and reuse the already-computed key directly.
func PersistPrimaryNV(tpm transport.TPM, primary *tpm2.CreatePrimaryResponse) error {
	_, err := tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: tpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		PersistentHandle: persistentHandle,
	}.Execute(tpm)
	return apperr.Wrap("EvictControl failed", err)
}


// Function that delete the public key and parameters stored in the NV at the persistentHandle address
func DeletePrimaryNV(tpm transport.TPM) error {                                                                                                                                                                           
	
	// check if template is stored in NV
	pub, exists, _ := EnsurePrimaryNV(tpm)                                                                                                                                                                        
	
	// if not exist - nothing to do
	if !exists {                                                                                                                                                                                                          
		return nil
	}                                                                                                                                                                                                                     

	// delete the 
	_, err := tpm2.EvictControl{                                                                                                                                                                                          
		Auth: tpm2.TPMRHOwner,                                                                                                                                                                                          
		ObjectHandle: tpm2.NamedHandle{
			Handle: persistentHandle,                                                                                                                                                                                     
			Name:   pub.Name,
		},                                                                                                                                                                                                                
		PersistentHandle: persistentHandle,                                                                                                                                                                             
	}.Execute(tpm)
	return apperr.Wrap("EvictControl failed", err)
} 
