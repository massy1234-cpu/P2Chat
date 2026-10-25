package transmission

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"net"
	"time"
)

// insert the padding in the message
func CreatePadding(data []byte, maxPad int) (padded []byte, padLen int) {
	padLen = network.CryptoInt(maxPad) + 250
	if padLen == 0 {
		return data, 0
	}
	padded = make([]byte, len(data)+padLen)
	copy(padded, data)
	rand.Read(padded[len(data):])
	return padded, padLen
}

// create the header of the packet
func CreateHeader(totalSize int, padLen int, checksum [32]byte) []byte {
	header := Header{TotalSize: uint32(totalSize), PadLen: uint16(padLen), Checksum: checksum}
	return header.Bytes()
}

// write the message into the connection ( this function also create the header and the padding )
func WriteMessage(conn net.Conn, data []byte) error {

	packet := NewPacket(data)
	newData := packet.Bytes()

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	n, err := conn.Write(newData)
	if n < len(newData) || err != nil {
		p2log.Error("data transmission error")
		return apperr.New("data transmission error")
	}

	return nil

}
