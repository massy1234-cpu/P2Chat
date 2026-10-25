package transmission

import (
	"P2Chat/cmd/client/internals/p2log"
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"time"
)

const MaxMessageSize = 64 * 1024

// read a message from the connection, it removes the padding and verify the checksum, the header is read first
func ReadMessage(conn net.Conn) (data []byte, err error) {

	conn.SetReadDeadline(time.Now().Add(10 * time.Minute))

	var rawHeader [HeaderSize]byte

	_, err = io.ReadFull(conn, rawHeader[:])
	if err != nil {
		p2log.Error("Packet NOT received correctly", err)
		return nil, err
	}

	header := parseHeader(rawHeader)
	if err := header.Validate(); err != nil {
		if header.TotalSize > MaxMessageSize && uint32(header.PadLen) < header.TotalSize {
			p2log.Error("Packet is too much larger, possible attacker ", err)
		}
		return nil, err
	}

	buf := make([]byte, header.TotalSize)
	_, err = io.ReadFull(conn, buf)

	if err != nil {
		p2log.Warning("connection closed, read error:", err)
		return nil, err
	}

	dataLen := header.TotalSize - uint32(header.PadLen)
	packet := Packet{Header: header, Payload: buf[:dataLen], Padding: buf[dataLen:]}
	if err := packet.Validate(); err != nil {
		p2log.Error("error in the checksum match")
		return nil, err
	}
	data = packet.Payload

	return data, nil

}

// compare the sha256 of the data with the checksum received in the header
func MatchChecksum(data []byte, checksum []byte) bool {

	hash := sha256.Sum256(data)
	return bytes.Equal(hash[:], checksum)

}
