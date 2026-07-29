package registration

import (
	"P2Chat/cmd/client/internals/network/structs"
	"P2Chat/pkg/apperr"
)

const byteCode = 0x01

// request to the server a registration request, the connection must be open already
func RequestRegistration(connectionManager *structs.ConnectionManager) error {

	// new stream for registration
	newStream,err := connectionManager.Conn.MasterSession.OpenStream()
	if err != nil {
		return apperr.Wrap("error during the registration phase: ",err)
	}

	// create the Session struct and store it 
	session := connectionManager.Conn.NewSession(newStream)

	session.Outgoing <- []byte("ciao")

	return nil

}