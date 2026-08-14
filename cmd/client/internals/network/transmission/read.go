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

const MaxMessageSize = 64 * 1024

// read a message from the connection, it removes the padding and verify the checksum, the header is read first
func ReadMessage(conn net.Conn) (data []byte, err error) {

	conn.SetReadDeadline(time.Now().Add(30 * time.Minute))

	var header [38]byte

	_, err = io.ReadFull(conn, header[:])
	if err != nil {
		p2log.Warning("Packet NOT received correctly", err)
		return nil, err
	}

	totalSize := binary.BigEndian.Uint32(header[:4])
	padLen := binary.BigEndian.Uint16(header[4:6])
	checksum := header[6:]

	if totalSize == 0 {
		return nil, apperr.New("empty packet")
	}

	if uint32(padLen) >= totalSize {
		return nil, apperr.New("invalid padding length")
	}

	if totalSize > MaxMessageSize {
		p2log.Error("Packet is too much larger, possible attacker ", err)
		return nil, apperr.New("max lenght exceeded")
	}

	buf := make([]byte, totalSize)
	_, err = io.ReadFull(conn, buf)

	if err != nil {
		p2log.Warning("Packet NOT received correctly", err)
		return nil, err
	}

	dataLen := totalSize - uint32(padLen)
	data = buf[:dataLen]

	if !MatchChecksum(data, checksum) {
		p2log.Error("error in the checksum match")
		return nil, apperr.New("error, packet is corrupt, possible manomission")
	}

	return data, nil

}

// compare the sha256 of the data with the checksum received in the header
func MatchChecksum(data []byte, checksum []byte) bool {

	hash := sha256.Sum256(data)
	return bytes.Equal(hash[:], checksum)

}
