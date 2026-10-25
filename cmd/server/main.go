package main

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/database"
	"P2Chat/cmd/server/internals/network/client"
	_ "P2Chat/cmd/server/internals/network/phases/bundle_reg"
	_ "P2Chat/cmd/server/internals/network/phases/get_user_bundle"
	_ "P2Chat/cmd/server/internals/network/phases/login"
	_ "P2Chat/cmd/server/internals/network/phases/nickname_catalog"
	_ "P2Chat/cmd/server/internals/network/phases/server_identification"
	_ "P2Chat/cmd/server/internals/network/phases/token_registration"
	serverstart "P2Chat/cmd/server/internals/network/server_start"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

func main() {
	password, err := readPassword()
	if err != nil {
		p2log.Error("error reading server password: ", err)
		return
	}
	registry, ln, err := serverstart.ServerStart("0.0.0.0", 9000, password)
	if err != nil {
		p2log.Error("server error: ", err)
		return
	}

	// periodic value log garbage collection, scales with server load
	go database.GC()
	defer database.CloseDB()

	// watchdog that closes everything correctly on keyboard interruption
	go waitForShutdown(ln, registry)

	// block forever, the accept loop runs in a goroutine inside ServerStart
	select {}
}

// readPassword reads the server password without terminal echo and seals it
// immediately after wiping the temporary input slice.
func readPassword() (*memguard.Enclave, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("standard input is not a terminal")
	}

	fmt.Print("Server password: ")
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	if len(input) == 0 {
		memguard.WipeBytes(input)
		return nil, fmt.Errorf("server password is empty")
	}

	buffer := memguard.NewBufferFromBytes(input)
	memguard.WipeBytes(input)
	return buffer.Seal(), nil
}

// waitForShutdown blocks until a keyboard interrupt (SIGINT/SIGTERM) arrives,
// then shuts down the server cleanly: stops accepting, closes all connected
// clients, closes the database and purges the locked memory before exiting.
func waitForShutdown(ln net.Listener, registry *client.RegistryClients) {
	watchdog := make(chan os.Signal, 1)
	signal.Notify(watchdog, syscall.SIGINT, syscall.SIGTERM)
	sig := <-watchdog

	p2log.Warning("server interrupted with ", sig, ", shutting down")
	memguard.Purge()
	ln.Close()       // stop accepting new clients
	registry.Close() // close all the connected clients
	database.CloseDB()
	p2log.Info("server closed gracefully")
	os.Exit(0)
}
