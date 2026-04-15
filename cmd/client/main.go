package main

import (
	"P2Chat/cmd/client/internals/errors"
	"P2Chat/cmd/client/internals/keys"
	"fmt"
	"github.com/awnumar/memguard"
)

func main(){
	go func(){
		//OS error detection
		errors.Watchdog()
	}()


	password := memguard.NewBuffer(len("prova"))
	copy(password.Bytes(), []byte("prova"))
	err := keys.CreateKeys(3, password)

	fmt.Println(err)

}