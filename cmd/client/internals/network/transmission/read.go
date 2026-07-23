package transmission

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"encoding/binary"
	"io"
	"net"
	"time"
)

const MaxMessageSize = 64 * 1024 		// ( 64KB )


// read all the package incoming from the connection
func ReadMessage(conn net.Conn) ([]byte,error) {

	// set a tieout for avoid infinite loop read
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// --> in the stack, no GC
	var header [4]byte				

	// read the lenght of the incoming package
	_, err := io.ReadFull(conn, header[:])
	if err != nil {
		p2log.Error("Packet NOT received correctly",err)
        return nil, err 
    }
    size := binary.BigEndian.Uint32(header[:])

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
    return buf, nil

}