package errors

import (
	"os"
	"os/signal"
	"syscall"
	"github.com/awnumar/memguard"
)

func Watchdog(){
	watchdog := make(chan os.Signal, 1)
	signal.Notify(watchdog, syscall.SIGINT, syscall.SIGTERM, syscall.SIGSEGV, syscall.SIGBUS)//notify watchdog when one of these comes in
	<-watchdog
	memguard.Purge() //cleanup all the memory
	os.Exit(1)
}