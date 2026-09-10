package proto_struct_login

import "encoding/binary"

// SigningMessage binds both identity signatures to this server and TLS session.
func SigningMessage(serverID, binding, bundleID []byte, nonce *LoginNonce, blinded []byte) []byte {
	message := append([]byte("P2Chat/login/v1"), byte(nonce.Version))
	message = binary.BigEndian.AppendUint64(message, uint64(nonce.Timestamp))
	message = append(message, serverID...)
	message = append(message, binding...)
	message = append(message, bundleID...)
	message = append(message, nonce.Nonce...)
	return append(message, blinded...)
}
