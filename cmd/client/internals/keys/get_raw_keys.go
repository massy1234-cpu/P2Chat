package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/datacontrol"
	"P2Chat/cmd/client/internals/encryption"
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"P2Chat/pkg/apperr"
	"encoding/base64"
	"github.com/awnumar/memguard"
)

func DecodePublicKeyMLDSA(publicKey *datacontrol.PublicKeyMLDSA)(*mldsa87.PublicKey,error) {
	var rawKey mldsa87.PublicKey

	//convert base64 in bytes
	bytes,err := base64.StdEncoding.DecodeString(publicKey.PublicKeyMLDSABase64)
	if err != nil {
		return nil, apperr.Wrap("decode base64 in bytes",err)
	}

	//convert bytes in mldsa87.PublicKey type
	err = rawKey.UnmarshalBinary(bytes)
	if err != nil {
		return nil, apperr.Wrap("copnvert bytes in public key",err)
	}

	return &rawKey, nil

}


//return the raw private key in memguard.Enclave for reuse 
func DecodePrivateKeyMLDSA(privateKey *pb.PrivateKeyMLDSA, aesKey *memguard.LockedBuffer, level int, salt []byte)(*memguard.Enclave, error) {
	bytes := privateKey.Ciphertext

	plaintext,err := encryption.DecryptAes256(aesKey,privateKey.Nonce,bytes)
	defer aesKey.Destroy()

	if err != nil {
		return nil, apperr.Wrap("Decrypt private key",err)
	}

	enclave := memguard.NewEnclave(plaintext.Bytes())
	defer plaintext.Destroy()

	return enclave, nil
}