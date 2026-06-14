//go:build darwin

package HSM

import (
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"google.golang.org/protobuf/proto"
	SE "P2Chat/cmd/client/internals/HSM/SE"
)

// Chiper a privateKey inside the TPM
func EncryptKey(privateKey *struct_mldsa.PrivateKeyMLDSA) ([]byte, error ){

	if !SE.Available() {
		return nil, apperr.New("SE not available in this device")
	}

	// convert the struct in bytes
	streamByte, err := proto.Marshal(privateKey)
	if err != nil {
		return nil,apperr.Wrap("marshal private key", err)
	}

	cryptedBytes,err := SE.Encrypt(streamByte)
	if err != nil {
		return nil, apperr.Wrap("error during encryption with SE: ",err)
	}
	
	return cryptedBytes,nil
}