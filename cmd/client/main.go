package main

import (
	"P2Chat/cmd/client/internals/errors"
	"P2Chat/cmd/client/internals/keys"
	"P2Chat/cmd/client/internals/argon"
	"fmt"
)

func main(){
	go func(){
		//OS error detection
		errors.Watchdog()
	}()


	err := keys.CreateKeys()

	if err != nil {
		fmt.Println("Errore : %w", err)
	}

	_, hash, err := argon.ExtractParams()
	fmt.Print(hash)
	fmt.Print(err)

}