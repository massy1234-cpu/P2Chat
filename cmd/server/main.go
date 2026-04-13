package main

import (
	"P2Chat/cmd/server/internals/errors"
)

func main(){
	go func(){
		//OS error detection
		errors.Watchdog()
	}()
}