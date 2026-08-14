package p2chat_errors

import (
	"P2Chat/cmd/client/internals/network/connection"
	"P2Chat/cmd/client/internals/p2log"
	"os"
	"os/signal"
	"syscall"

	"github.com/awnumar/memguard"
)

func Watchdog(manager *connection.ConnectionManager){
	watchdog := make(chan os.Signal, 1)
	signal.Notify(watchdog, syscall.SIGINT, syscall.SIGTERM, syscall.SIGSEGV, syscall.SIGBUS)//notify watchdog when one of these comes in
	sig := <-watchdog
	memguard.Purge() //cleanup all the memory
	End(manager)
	p2log.Error("application closed with " , sig)
	os.Exit(1)
}

// bisogna pensare anche ad un file che liberi tutte le risorse, tra cui anche quelle usate per il TPM
func End(manager *connection.ConnectionManager) {
	manager.Close()
}