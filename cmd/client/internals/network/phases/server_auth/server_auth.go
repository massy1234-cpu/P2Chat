package serverauth

import (
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/network/phases/login"
)

type ServerAuth = login.LoginClient

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	return login.Handler(byteCode, msg, phaseState)
}
