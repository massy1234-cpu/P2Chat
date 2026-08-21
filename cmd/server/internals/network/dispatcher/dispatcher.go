package dispatcher

import (
	"P2Chat/cmd/server/network/phases"
	"P2Chat/cmd/server/network/phases/token_registration"
	"P2Chat/pkg/apperr"
)

type Handler func(byteCode byte, msg []byte, state *any) *phases.Result

// route the messages in base of the first byte tag of the message
func Dispatcher(byteCode byte) (Handler, error) {

	switch byteCode {
	case phases.RegisterTokenReq:
		return token_registration.Handler, nil
	default:
		return nil, apperr.New("bytecode not correct for any phase")
	}
}
