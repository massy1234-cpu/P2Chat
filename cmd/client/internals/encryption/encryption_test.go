package encryption

import (
	"P2Chat/cmd/client/internals/argon"
	"bytes"
	"testing"
	"github.com/awnumar/memguard"
)

//Simple test that encrypt and decrypt text 
func TestEncryptionAndDecryption(t *testing.T) {

	password := Encaps("password")
	secret := Encaps("really important secret!!!")


	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("error during generating salt")
	}

	aesKey, err := argon.HashWithArgon(3, password, salt)
	if err != nil{
		t.Fatalf("error during create aeskey")
	}

	ciphertext, nonce, err := EncryptAes256(aesKey,secret )
	if err != nil {
		t.Fatalf("error during encrypting")
	}

	plaintext, err := DecryptAes256(aesKey, nonce, ciphertext)
	if err != nil {
		t.Fatal("error during decrypt",err)
	}

	if !( bytes.Equal(plaintext.Bytes(), secret.Bytes() ) ) {
		t.Fatalf("error, decrypt failed")
	}

}

//Encrypt and Decrypt strings with fuzz ( randomic inputs )
func FuzzEncryptAndDecrypt(f *testing.F) {
	f.Add([]byte("password"), []byte("secret"))
	f.Add([]byte("password2"), []byte("secret2"))

	f.Fuzz(func(t *testing.T, password []byte, plain []byte){
		
		//func doesnt accept password that are nil
		if len(password) == 0 {
			t.Skip()
		}


		pass := memguard.NewBuffer(len(password))
		copy(pass.Bytes(), password)

		secret := memguard.NewBuffer(len(plain))
		copy(secret.Bytes(), plain)

		salt, err := GenerateSalt()
		if err != nil {
			t.Fatal("error during generating salt", err)
		}

		aesKey, err := argon.HashWithArgon(3, pass, salt)
		if err != nil{
			t.Fatal("error during create aeskey", err, len(password))
		}

		ciphertext, nonce, err := EncryptAes256(aesKey,secret )
		if err != nil {
			t.Fatal("error during encrypting", err)
		}

		plaintext, err := DecryptAes256(aesKey, nonce, ciphertext)
		if err != nil {
			t.Fatal("error during decrypt",err)
		}

		if !( bytes.Equal(plaintext.Bytes(), secret.Bytes() ) ) {
			t.Fatalf("error, decrypt failed")
		}
	})
}


//Test the case we want to decrypt something with a wrong password
func TestEncryptFailed(t *testing.T){

	password := Encaps("password_correct")
	secret := Encaps("really important secret!!!")


	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("error during generating salt")
	}

	aesKey, err := argon.HashWithArgon(3, password, salt)
	if err != nil{
		t.Fatalf("error during create aeskey")
	}

	ciphertext, nonce, err := EncryptAes256(aesKey,secret )
	if err != nil {
		t.Fatalf("error during encrypting")
	}

	//tries to decrypt with wrong password
	aesKey, err = argon.HashWithArgon(3, Encaps("wrong_password"), salt)
	_, err = DecryptAes256(aesKey, nonce, ciphertext)
	if err != nil {
		t.Log("wrong password detected, decrypt failed")
	}
}