package main

import (
	"P2Chat/cmd/client/internals/errors"
	keys "P2Chat/cmd/client/internals/keys/mldsa"
	"fmt"
	"github.com/awnumar/memguard"
)

func main() {
	go func() {
		//OS error detection
		errors.Watchdog()
	}()

	password := memguard.NewBuffer(len("prova"))
	copy(password.Bytes(), []byte("prova"))
	_, _, err := keys.CreateMLDSAKeys(3, password, true)

	fmt.Println(err)

}
