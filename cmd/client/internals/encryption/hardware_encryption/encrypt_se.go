//go: build darwin

package hardware_encryption

import (
	struct_mldsa "P2Chat/cmd/client/internals/generated_proto_files/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"google.golang.org/protobuf/proto"
	macos "P2Chat/cmd/client/internals/hardware_security/macos"
)

func SEEncrypt(privateKey *struct_mldsa.PrivateKeyMLDSA) ([]byte, error ){

	if !macos.Available() {
		return nil, apperr.New("SE not available in this device")
	}

	// convert the struct in bytes
	streamByte, err := proto.Marshal(privateKey)
	if err != nil {
		return nil,apperr.Wrap("marshal private key", err)
	}

	cryptedBytes,err := macos.Encrypt(streamByte)
	if err != nil {
		return nil, apperr.Wrap("error during encryption with SE: ",err)
	}
	
	return cryptedBytes,nil
}