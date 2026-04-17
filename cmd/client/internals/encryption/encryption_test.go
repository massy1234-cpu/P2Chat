package encryption

import (
	"P2Chat/cmd/client/internals/argon"
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/awnumar/memguard"
)

func TestEncryptionAndDecryption(t *testing.T) {

	a := []byte("password")
	s := []byte("that's a really important secret!")

	pass := memguard.NewBuffer(len(a))
	copy(pass.Bytes(), a)

	secret := memguard.NewBuffer(len(s))
	copy(secret.Bytes(), s)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("error during generating salt")
	}

	aesKey, err := argon.HashWithArgon(3, pass, salt)
	if err != nil{
		t.Fatalf("error during create aeskey")
	}

	ciphertext, nonce, err := EncryptAes256(aesKey,secret )
	if err != nil {
		t.Fatalf("error during encrypting")
	}
	fmt.Println("cipertext ( base64 ) : ", base64.RawStdEncoding.EncodeToString(ciphertext))

	plaintext, err := DecryptAes256(aesKey, nonce, ciphertext)
	if err != nil {
		t.Fatal("error during decrypt",err)
	}
	fmt.Println("plaintext ( base64 ) : ", string(plaintext.Bytes()))

	if !( bytes.Equal(plaintext.Bytes(), secret.Bytes() ) ) {
		t.Fatalf("error, decrypt failed")
	}



}