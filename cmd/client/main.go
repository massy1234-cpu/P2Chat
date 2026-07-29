package main

import (
	"P2Chat/cmd/client/internals/errors"
	network "P2Chat/cmd/client/internals/network/TLS"
	"P2Chat/cmd/client/internals/storage"
	"fmt"
	"path/filepath"
)

func main() {
	storage.BasePath = filepath.Join(storage.ProjectRoot, "cmd", "client", "data")

	go func() {
		errors.Watchdog()
	}()

	if _, err := network.ServerInitialize("localhost:8080"); err != nil {
		fmt.Println("TLS error:", err)
	}
}
