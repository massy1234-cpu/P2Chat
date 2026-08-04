package phases

import (
	loadreport "P2Chat/cmd/server/network/load_report"
	"P2Chat/cmd/server/network/session"
)

// route the messages in base of the first byte tag of the message
func Dispatcher(session *session.SingleSession,msg []byte){
	if len(msg) < 1 {
		return
	}

	switch msg[0] {
	case RegisterTokenReq:
		RequestTokenRegistration(session,loadreport.LoadReport())
	default:
		return
	}
}