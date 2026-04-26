package mldsa

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
)

func CreateKeys() error {

	//Generation of the keys
	publicKey, privateKey, err := mldsa87.GenerateKey(nil)

	if err != nil {
		return apperr.Wrap("generate ML-DSA keypair", err)
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

func protectAndStoreKeys(password *memguard.LockedBuffer, level int, privateKey *memguard.LockedBuffer, publicKey mldsa87.PublicKey) error {
	defer password.Destroy()
	defer privateKey.Destroy()

	salt, err := GenerateSalt(16) //minimum number of byte for a secure derivation
	if err != nil {
		return apperr.Wrap("generate salt", err)
	}

	passwordHashed, err := hashWithArgon(level, password, salt)
	if err != nil {
		return apperr.Wrap("derive encryption key with argon2id", err)
	}
	defer passwordHashed.Destroy()

	//Structure of ciphertext
	//[nonce][ciphertext + checksum
	ciphertext, err := EncryptAes256(passwordHashed, privateKey)
	if err != nil {
		return apperr.Wrap("encrypt private key", err)
	}

	dataFile := createKeyStructure(salt, ciphertext, true)

	err = saveDataOnFile(dataFile, "data", "SK.dat")
	if err != nil {
		return apperr.Wrap("persist private key", err)
	}

	dataFile = createKeyStructure(nil, publicKey.Bytes(), false)

	err = saveDataOnFile(dataFile, "data", "PK.dat")
	if err != nil {
		return apperr.Wrap("persist public key", err)
	}

	return nil
}
