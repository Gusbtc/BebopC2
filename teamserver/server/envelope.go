package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const maxEnvelopeSize = 10 * 1024 * 1024 // 10 MB

// WriteEnvelope writes a length-prefixed message to conn.
// Wire format: [4 bytes LE length][payload bytes].
func WriteEnvelope(conn net.Conn, data []byte) error {
	buf := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := conn.Write(buf)
	return err
}

// ReadEnvelope reads a length-prefixed message from conn.
// Returns error if payload exceeds maxEnvelopeSize.
func ReadEnvelope(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	dataLen := binary.LittleEndian.Uint32(lenBuf)
	if dataLen > maxEnvelopeSize {
		return nil, fmt.Errorf("envelope too large: %d bytes (max %d)", dataLen, maxEnvelopeSize)
	}
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}
