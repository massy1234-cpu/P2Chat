package keys

import (
	"P2Chat/cmd/client/internals/datacontrol"
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"P2Chat/pkg/apperr"
)

func LoadKeysMLDSA()(*pb.PrivateKeyMLDSA, *datacontrol.PublicKeyMLDSA, error){

	privateKey,err := datacontrol.LoadPrivateKeyMLDSAFromFile("data/", "SK.bin")
	if err != nil {
		apperr.Wrap("Load private key ml-dsa87 from file", err)
	}

	publicKey, err := datacontrol.LoadPublicKeyMLDSAFromFile("data/", "PK.bin")
	if err != nil {
		apperr.Wrap("Load public key ml-dsa87 from file", err)
	}

	return privateKey, publicKey, nil

}