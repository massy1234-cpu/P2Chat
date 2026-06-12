package mldsa_data

import (
	struct_mldsa "P2Chat/cmd/client/internals/generated_proto_files/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"google.golang.org/protobuf/proto"
	data "P2Chat/cmd/client/internals/datacontrol"
	
)

// save the private key ml-dsa87 on file
func SavePrivateKey(privateKey *struct_mldsa.PrivateKeyMLDSA) error {

	// convert key in bytes
	streamByte, err := proto.Marshal(privateKey)
	if err != nil {
		return apperr.Wrap("marshal private key", err)
	}

	// write bytes
	err = data.SaveBytesOnFile(streamByte, "data/", "SK.bin")
	if err != nil {
		return apperr.Wrap("persist private key", err)
	}

	return nil

}

// save the public key ml-dsa87 on file
func SavePublicKey(publicKey *struct_mldsa.PublicKeyMLDSA) error {

	// convert key in bytes
	streamByte, err := proto.Marshal(publicKey)
	if err != nil {
		return apperr.Wrap("marshal public key", err)
	}

	// write bytes
	err = data.SaveBytesOnFile(streamByte, "data/", "PK.bin")
	if err != nil {
		return apperr.Wrap("persist public key", err)
	}

	return nil

}

// Save the pair ok ml-dsa87 keys on file
func SavePairKey(privateKey *struct_mldsa.PrivateKeyMLDSA, publicKey *struct_mldsa.PublicKeyMLDSA) error {

	err := SavePrivateKey(privateKey)
	if err != nil {
		return apperr.Wrap("Saving private key ml-dsa87", err)
	}

	err = SavePublicKey(publicKey)
	if err != nil {
		return apperr.Wrap("Saving public key ml-dsa87", err)
	}

	return nil
}
