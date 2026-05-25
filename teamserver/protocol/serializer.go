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

type InlineAssemblyResult struct {
	ExitCode      int32
	DurationMS    uint32
	Truncated     bool
	Stdout        string
	Stderr        string
	Exception     string
	Mode          string
	BridgeVersion string
	Diagnostics   string
}

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

// EncodeExecAssemblyReq serializes an EXEC-ASSEMBLY-REQ:
// [4B shellcode_len][shellcode][4B spawnto_len][spawnto UTF-8]
func EncodeExecAssemblyReq(shellcode []byte, spawnto string) []byte {
	b := make([]byte, 4+len(shellcode)+4+len(spawnto))
	binary.LittleEndian.PutUint32(b[:4], uint32(len(shellcode)))
	copy(b[4:], shellcode)
	off := 4 + len(shellcode)
	binary.LittleEndian.PutUint32(b[off:], uint32(len(spawnto)))
	copy(b[off+4:], spawnto)
	return b
}

// DecodeExecAssemblyReq deserializes an EXEC-ASSEMBLY-REQ.
func DecodeExecAssemblyReq(b []byte) (shellcode []byte, spawnto string, err error) {
	if len(b) < 8 {
		return nil, "", fmt.Errorf("DecodeExecAssemblyReq: need at least 8 bytes, got %d", len(b))
	}
	scLen := binary.LittleEndian.Uint32(b[:4])
	if uint32(len(b)) < 4+scLen+4 {
		return nil, "", fmt.Errorf("DecodeExecAssemblyReq: truncated shellcode")
	}
	shellcode = b[4 : 4+scLen]
	off := 4 + scLen
	spawntoLen := binary.LittleEndian.Uint32(b[off:])
	if uint32(len(b)) < off+4+spawntoLen {
		return nil, "", fmt.Errorf("DecodeExecAssemblyReq: truncated spawnto")
	}
	spawnto = string(b[off+4 : off+4+spawntoLen])
	return shellcode, spawnto, nil
}

// EncodeBOFReq serializes a BOF task:
// [4B obj_len][COFF object][4B args_len][packed args]
func EncodeBOFReq(obj, args []byte) []byte {
	b := make([]byte, 0, 4+len(obj)+4+len(args))
	b = appendBytes32(b, obj)
	b = appendBytes32(b, args)
	return b
}

// EncodeInlineAssemblyBOFArgs serializes the argument buffer consumed by
// the internal inline-assembly BOF:
// [4B bridge_len][bridge][4B assembly_len][assembly][4B argc][args...]
func EncodeInlineAssemblyBOFArgs(bridgeBytes, assemblyBytes []byte, args []string) []byte {
	total := 4 + len(bridgeBytes) + 4 + len(assemblyBytes) + 4
	for _, arg := range args {
		total += 4 + len(arg)
	}
	b := make([]byte, 0, total)
	b = appendBytes32(b, bridgeBytes)
	b = appendBytes32(b, assemblyBytes)
	b = appendUint32(b, uint32(len(args)))
	for _, arg := range args {
		b = appendBytes32(b, []byte(arg))
	}
	return b
}

func EncodeInlineAssemblyReq(bridgeBytes, assemblyBytes []byte, args []string, mode uint32) []byte {
	total := 4 + 4 + len(bridgeBytes) + 4 + len(assemblyBytes) + 4
	for _, arg := range args {
		total += 4 + len(arg)
	}

	b := make([]byte, 0, total)
	b = appendUint32(b, mode)
	b = appendBytes32(b, bridgeBytes)
	b = appendBytes32(b, assemblyBytes)
	b = appendUint32(b, uint32(len(args)))
	for _, arg := range args {
		b = appendBytes32(b, []byte(arg))
	}
	return b
}

func DecodeInlineAssemblyReq(b []byte) (mode uint32, bridgeBytes, assemblyBytes []byte, args []string, err error) {
	dec := payloadDecoder{name: "DecodeInlineAssemblyReq", data: b}

	mode, err = dec.uint32("mode")
	if err != nil {
		return 0, nil, nil, nil, err
	}
	if mode != InlineModeDirect && mode != InlineModeBridge {
		return 0, nil, nil, nil, fmt.Errorf("%s: invalid mode %d", dec.name, mode)
	}
	bridgeBytes, err = dec.bytes32("bridge bytes")
	if err != nil {
		return 0, nil, nil, nil, err
	}
	assemblyBytes, err = dec.bytes32("assembly bytes")
	if err != nil {
		return 0, nil, nil, nil, err
	}

	argc, err := dec.uint32("argc")
	if err != nil {
		return 0, nil, nil, nil, err
	}
	maxArgs := dec.remaining() / 4
	if int64(argc) > int64(maxArgs) {
		return 0, nil, nil, nil, fmt.Errorf("%s: argc %d exceeds remaining capacity %d", dec.name, argc, maxArgs)
	}

	args = make([]string, 0, argc)
	for i := uint32(0); i < argc; i++ {
		argBytes, argErr := dec.bytes32(fmt.Sprintf("arg[%d]", i))
		if argErr != nil {
			return 0, nil, nil, nil, argErr
		}
		args = append(args, string(argBytes))
	}
	if dec.remaining() != 0 {
		return 0, nil, nil, nil, fmt.Errorf("%s: trailing %d bytes", dec.name, dec.remaining())
	}

	return mode, bridgeBytes, assemblyBytes, args, nil
}

func EncodeInlineAssemblyResult(r InlineAssemblyResult) []byte {
	total := 4 + 4 + 1
	total += 4 + len(r.Stdout)
	total += 4 + len(r.Stderr)
	total += 4 + len(r.Exception)
	total += 4 + len(r.Mode)
	total += 4 + len(r.BridgeVersion)
	total += 4 + len(r.Diagnostics)

	b := make([]byte, 0, total)
	b = appendUint32(b, uint32(r.ExitCode))
	b = appendUint32(b, r.DurationMS)
	if r.Truncated {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = appendString32(b, r.Stdout)
	b = appendString32(b, r.Stderr)
	b = appendString32(b, r.Exception)
	b = appendString32(b, r.Mode)
	b = appendString32(b, r.BridgeVersion)
	b = appendString32(b, r.Diagnostics)
	return b
}

func DecodeInlineAssemblyResult(b []byte) (InlineAssemblyResult, error) {
	dec := payloadDecoder{name: "DecodeInlineAssemblyResult", data: b}

	exitCode, err := dec.int32("exit code")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	durationMS, err := dec.uint32("duration_ms")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	truncated, err := dec.byte("truncated")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	stdout, err := dec.string32("stdout")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	stderr, err := dec.string32("stderr")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	exception, err := dec.string32("exception")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	mode, err := dec.string32("mode")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	bridgeVersion, err := dec.string32("bridge version")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	diagnostics, err := dec.string32("diagnostics")
	if err != nil {
		return InlineAssemblyResult{}, err
	}
	if dec.remaining() != 0 {
		return InlineAssemblyResult{}, fmt.Errorf("%s: trailing %d bytes", dec.name, dec.remaining())
	}

	return InlineAssemblyResult{
		ExitCode:      exitCode,
		DurationMS:    durationMS,
		Truncated:     truncated != 0,
		Stdout:        stdout,
		Stderr:        stderr,
		Exception:     exception,
		Mode:          mode,
		BridgeVersion: bridgeVersion,
		Diagnostics:   diagnostics,
	}, nil
}

func appendUint32(dst []byte, v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return append(dst, buf...)
}

func appendBytes32(dst, v []byte) []byte {
	dst = appendUint32(dst, uint32(len(v)))
	return append(dst, v...)
}

func appendString32(dst []byte, s string) []byte {
	return appendBytes32(dst, []byte(s))
}

type payloadDecoder struct {
	name string
	data []byte
	off  int
}

func (d *payloadDecoder) uint32(field string) (uint32, error) {
	if len(d.data)-d.off < 4 {
		return 0, fmt.Errorf("%s: truncated %s length/value", d.name, field)
	}
	v := binary.LittleEndian.Uint32(d.data[d.off : d.off+4])
	d.off += 4
	return v, nil
}

func (d *payloadDecoder) int32(field string) (int32, error) {
	v, err := d.uint32(field)
	if err != nil {
		return 0, err
	}
	return int32(v), nil
}

func (d *payloadDecoder) byte(field string) (byte, error) {
	if len(d.data)-d.off < 1 {
		return 0, fmt.Errorf("%s: truncated %s", d.name, field)
	}
	v := d.data[d.off]
	d.off++
	return v, nil
}

func (d *payloadDecoder) bytes32(field string) ([]byte, error) {
	n, err := d.uint32(field)
	if err != nil {
		return nil, err
	}
	if uint32(len(d.data)-d.off) < n {
		return nil, fmt.Errorf("%s: truncated %s bytes", d.name, field)
	}
	v := d.data[d.off : d.off+int(n)]
	d.off += int(n)
	return v, nil
}

func (d *payloadDecoder) string32(field string) (string, error) {
	v, err := d.bytes32(field)
	if err != nil {
		return "", err
	}
	return string(v), nil
}

func (d *payloadDecoder) remaining() int {
	return len(d.data) - d.off
}
