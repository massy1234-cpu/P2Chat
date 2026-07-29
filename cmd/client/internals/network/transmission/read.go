package transmission

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// this is the dimension ONLY of the packet on the wire, is different
// from the config.MaxStreamWindowSize in yamux
const MaxMessageSize = 64 * 1024


// read all the package incoming from the connection
// i can use net.Conn because yamux use net.Conn inside the wrap
// return the data, and verify the checksum 
func ReadMessage(conn net.Conn) (data []byte, err error) {

	// set a tieout for avoid infinite loop read
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// --> in the stack, no GC
	var header [36]byte				

	// read the header of the package
	_, err = io.ReadFull(conn, header[:])
	if err != nil {
		p2log.Error("Packet NOT received correctly",err)
        return nil,err 
    }

	sizeBytes := header[0:4]
	checksum := header[4:]

    size := binary.BigEndian.Uint32(sizeBytes)


	// understand if the size is too much larger
	if size > MaxMessageSize {
		p2log.Error("Packet is too much larger, possible attacker ",err)
        return nil, apperr.New("max lenght exceeded")
	}


	// create a buffer that contains all the data, does not contains the lenght
    buf := make([]byte, size)
    _, err = io.ReadFull(conn, buf)
	if err != nil {
        p2log.Error("Packet NOT received correctly",err)
        return nil, err 
    }

	if !(MatchChecksum(buf,checksum)) {
		p2log.Error("error in the checksum match")
		return nil, apperr.New("error, packet is corrupt, possible manomission")
	}

    return buf,nil

}


func MatchChecksum(data []byte, checksum []byte) bool {

	hash := sha256.Sum256(data)
	return bytes.Equal(hash[:],checksum)

}