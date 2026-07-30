package phases

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/network/session"
	"crypto/rand"
)

const byteCode = 0x01

func RequestTokenRegistration(sess *session.SingleSession) error {
	
	// create the request and wait for PoW from server
	packet := PacketRegistration()
	sess.PutOutgoing(packet)

	


	return nil
}


func PacketRegistration() (packet []byte) {
	packet = make([]byte, network.CryptoInt(500)+250)
	packet[1] = byteCode
	rand.Read(packet[1:])
	return packet
}
