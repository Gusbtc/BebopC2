package protocol

import (
	"encoding/binary"
	"fmt"
)

const (
	TaskNOP  uint8 = 0
	TaskExit uint8 = 1
	TaskSet  uint8 = 2
	TaskRun  uint8 = 12
	TaskFileStage uint8 = 3
	TaskFileExfil uint8 = 4
)

const (
	FlagNone         uint16 = 0
	FlagError        uint16 = 1
	FlagRunning      uint16 = 2
	FlagFragmented   uint16 = 4
	FlagLastFragment uint16 = 8
)

const (
	CodeExitNormal uint8 = 0
)

type TaskHeader struct {
	Type       uint8
	Code       uint8
	Flags      uint16
	Label      uint32
	Identifier uint32
	Length     uint32
}

type Message struct {
	Header TaskHeader
	Data   []byte
}

func EncodeHeader(h TaskHeader) []byte {
	b := make([]byte, 16)
	b[0] = h.Type
	b[1] = h.Code
	binary.LittleEndian.PutUint16(b[2:], h.Flags)
	binary.LittleEndian.PutUint32(b[4:], h.Label)
	binary.LittleEndian.PutUint32(b[8:], h.Identifier)
	binary.LittleEndian.PutUint32(b[12:], h.Length)
	return b
}

func DecodeHeader(b []byte) (TaskHeader, error) {
	if len(b) < 16 {
		return TaskHeader{}, fmt.Errorf("protocol: header too short: %d bytes", len(b))
	}
	return TaskHeader{
		Type:       b[0],
		Code:       b[1],
		Flags:      binary.LittleEndian.Uint16(b[2:]),
		Label:      binary.LittleEndian.Uint32(b[4:]),
		Identifier: binary.LittleEndian.Uint32(b[8:]),
		Length:     binary.LittleEndian.Uint32(b[12:]),
	}, nil
}

func NewNOP() Message {
	return Message{Header: TaskHeader{Type: TaskNOP, Length: 0}, Data: []byte{}}
}
