package transmission

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"
)

// the data put in this function doesnt need any header, the header is put in this function
func WriteMessage(conn net.Conn, data []byte) error {

	// create the header
	header := CreateHeader(data)

	// put header and data together 
	newData := make([]byte,len(data) + len(header))
	copy(newData[:36], header)
	copy(newData[36:],data)

	// time limit for transmission
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	n,err := conn.Write(newData)
	if n < len(newData) || err != nil {
		p2log.Error("data transmission error")
		return apperr.New("data transmission error")
	}

	return nil

}


// create a header composed from 4 byte of lenght + 32 byte of checksum
// the rest like byte code must be put in payload
func CreateHeader(data []byte) (header []byte) {
	lenght := len(data)
	checksum := sha256.Sum256(data)

	header = make([]byte, 36)
	binary.BigEndian.PutUint32(header[:4],uint32(lenght))
	copy(header[4:],checksum[:])

	return header
}