package transmission

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"
)

// insert the padding in the message 
func CreatePadding(data []byte, maxPad int) (padded []byte, padLen int) {
	padLen = network.CryptoInt(maxPad)+250
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
	header := make([]byte, 38)
	binary.BigEndian.PutUint32(header[:4], uint32(totalSize))
	binary.BigEndian.PutUint16(header[4:6], uint16(padLen))
	copy(header[6:], checksum[:])
	return header
}


// write the message into the connection ( this function also create the header and the padding )
func WriteMessage(conn net.Conn, data []byte) error {

	totalelenght, padLen := CreatePadding(data, 500)
	checksum := sha256.Sum256(data)
	header := CreateHeader(len(totalelenght), padLen, checksum)

	newData := make([]byte, len(header)+len(totalelenght))
	copy(newData[:38], header)
	copy(newData[38:], totalelenght)

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	n, err := conn.Write(newData)
	if n < len(newData) || err != nil {
		p2log.Error("data transmission error")
		return apperr.New("data transmission error")
	}

	return nil

}