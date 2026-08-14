package main

import (
	"P2Chat/cmd/client/internals/p2log"
	serverstart "P2Chat/cmd/server/network/server_start"
)

func main() {
	if err := serverstart.ServerStart("0.0.0.0", 9000); err != nil {
		p2log.Error("server error: ", err)
		return
	}

	// block forever, the accept loop runs in a goroutine inside ServerStart
	select {}
}