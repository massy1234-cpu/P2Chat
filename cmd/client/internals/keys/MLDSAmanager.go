package keys

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/cmd/client/internals/datacontrol"
	"P2Chat/cmd/client/internals/encryption"
	"fmt"
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"github.com/awnumar/memguard"
)



func CreateKeys() (error) {

	//Generation of the keys
	publicKey, privateKey, err := mldsa87.GenerateKey(nil)

	if err != nil {
		return fmt.Errorf("Errore nella creazione delle chiavi... %w", err)
	}

	//delete the struct and other variablesin memory and keep only bytes 
	privateKeySecured := memguard.NewBuffer(mldsa87.PrivateKeySize)

	rawBytes := privateKey.Bytes()
	copy(privateKeySecured.Bytes(), rawBytes)
	privateKey.Destroy()
	memguard.WipeBytes(rawBytes)

	pass := memguard.NewBuffer(len("prova"))

	err = protectAndStoreKeys(pass, 3, privateKeySecured, *publicKey)

	return err

}


//function that create the keys ( protect the memory with memguard ) and save the keys in the data folder
func protectAndStoreKeys(password *memguard.LockedBuffer, level int, privateKey *memguard.LockedBuffer, publicKey mldsa87.PublicKey) (error) {

	//creation of struct for the privatekey ML-DSA and argonparams
	privateKeyMLDSA := &pb.PrivateKeyMLDSA{}
	argon

	defer password.Destroy()

	salt, err := encryption.GenerateSalt(16) //minimum number of byte for a secure derivation
	if err != nil {
		return fmt.Errorf("Encrypt : failed to create salt -> %w", err)
	}

	passwordHashed, err := argon.HashWithArgon(level, password, salt)
	defer passwordHashed.Destroy()
	if err != nil {
		return fmt.Errorf("Encrypt : failed to hashing password with Argon -> %w", err)
	}


	//Structure of ciphertext
	//[nonce + ciphertext + checksum]
	ciphertext, err := encryption.EncryptAes256(passwordHashed, privateKey)
	defer privateKey.Destroy() 

	if err != nil {
		return fmt.Errorf("Encrypt : failed to encrypt with AES256 -> %w", err)
	}
	

	//da qui va cambiato 
	dataFile := datacontrol.CreateKeyStructure(salt, ciphertext, true)

	err = datacontrol.SaveDataOnFile(dataFile, "data", "SK.dat")
	if err != nil {
		return fmt.Errorf("Encrypt : failed to save SK -> %w", err)
	}


	dataFile = datacontrol.CreateKeyStructure(nil, publicKey.Bytes(), false)

	err = datacontrol.SaveDataOnFile(dataFile, "data", "PK.dat")
	if err != nil {
		return fmt.Errorf("Encrypt : failed to save PK -> %w", err)
	}


	return nil
}