//go:build linux || windows

package HSM

import (
	TPM "P2Chat/cmd/client/internals/HSM/TPM"
	"P2Chat/pkg/apperr"
	"crypto/hmac"
	"crypto/sha256"

	"github.com/awnumar/memguard"
	"github.com/google/go-tpm/tpm2"
)

func Inizialize() (*tpm2.CreateResponse,error) {

	// Create the primary template in memory and create the public and private blob
	response,err := TPM.CreateResponse()
	if err != nil && response != nil {
		return nil,apperr.Wrap("cannot use TPM encryption: ",err)
	}

	// Save the blob 
	TPM.StoreBlobs(response.OutPrivate,response.OutPublic)

	return response,nil
}


// Extract the secret from the blobs
func WrapSecret(privateBlob *tpm2.TPM2BPrivate,publicBlob *tpm2.TPM2BPublic) (*memguard.Enclave,error) {

	if privateBlob == nil || publicBlob == nil{
		return nil, apperr.New("response is null, cannot wrap the secret")
	}
	
	// Unseal the secret with the TPM
	secretEnclave,err := TPM.UnsealSecret(*privateBlob,*publicBlob)
	if err != nil {
		return nil, apperr.Wrap("the secret is not valid: ",err)
	}

	if secretEnclave == nil || err != nil{
		return nil, apperr.New("error during catch the secret in the enclave")
	}
	
	return secretEnclave,nil

}

// Function that combine togheter a undetermined number of secret to derivate an HASH
func Combine(secrets ...*memguard.Enclave) (*memguard.Enclave,error) {

	// create the container
	secretsCombined := hmac.New(sha256.New,nil)

	// create the hmac(secret1,secret2...)
	for i := range secrets{
		LockedBuffer,err := secrets[i].Open()
		if err != nil {
			return nil,apperr.Wrap("error during the combination of the secrets: ",err)
		}
		secretsCombined.Write(LockedBuffer.Bytes())
	}

	// create the sha256
	sha := secretsCombined.Sum(nil)
	shaEnclave := memguard.NewEnclave(sha)
	defer memguard.WipeBytes(sha)

	if shaEnclave == nil {
		return nil,apperr.New("error during the combination of the secrets: ")
	}
	defer secretsCombined.Reset()

	return shaEnclave,nil
}