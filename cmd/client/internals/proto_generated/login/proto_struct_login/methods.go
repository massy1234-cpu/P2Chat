package proto_struct_login

import "encoding/binary"

// SigningMessage binds both identity signatures to this server, TLS session
// and the three blind pass-token requests.
func SigningMessage(serverID, binding, bundleID []byte, nonce *LoginNonce, blinded [][]byte) []byte {
	message := append([]byte("P2Chat/login/v1"), byte(nonce.Version))
	message = binary.BigEndian.AppendUint64(message, uint64(nonce.Timestamp))
	message = append(message, serverID...)
	message = append(message, binding...)
	message = append(message, bundleID...)
	message = append(message, nonce.Nonce...)
	for _, point := range blinded {
		message = append(message, point...)
	}
	return message
}
