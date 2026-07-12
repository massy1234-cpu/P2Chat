package main

import (
	"P2Chat/cmd/client/internals/errors"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"fmt"
	"github.com/awnumar/memguard"
)

func main() {
	go func() {
		errors.Watchdog()
	}()

	password := memguard.NewBuffer(len("prova"))
	copy(password.Bytes(), []byte("prova"))
	passwordEnc := memguard.NewEnclave(password.Bytes())
	password.Destroy()

	_, _, _, err := mldsa_keys.CreateKeys(3, passwordEnc, true, false)

	fmt.Println(err)
}
