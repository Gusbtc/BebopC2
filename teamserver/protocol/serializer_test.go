package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"

	"c2/models"
)

func TestEncodeDecodeImplantMetadata_RoundTrip(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	original := &models.ImplantMetadata{
		ID:          0xDEADBEEF,
		SessionKey:  sessionKey,
		Sleep:       10,
		Jitter:      25,
		Username:    "operator",
		Hostname:    "WIN10-TARGET",
		ProcessName: "explorer.exe",
		ProcessID:   4321,
		Arch:        1,
		Platform:    2,
		Integrity:   2,
	}

	encoded := EncodeImplantMetadata(original)
	got, err := DecodeImplantMetadata(encoded)
	if err != nil {
		t.Fatalf("DecodeImplantMetadata: %v", err)
	}

	if got.ID != original.ID {
		t.Fatalf("ID: want %d, got %d", original.ID, got.ID)
	}
	if !bytes.Equal(got.SessionKey, original.SessionKey) {
		t.Fatal("SessionKey mismatch")
	}
	if got.Hostname != original.Hostname {
		t.Fatalf("Hostname: want %q, got %q", original.Hostname, got.Hostname)
	}
	if got.Sleep != original.Sleep {
		t.Fatalf("Sleep: want %d, got %d", original.Sleep, got.Sleep)
	}
	if got.Jitter != original.Jitter {
		t.Fatalf("Jitter: want %d, got %d", original.Jitter, got.Jitter)
	}
	if got.Username != original.Username {
		t.Fatalf("Username: want %q, got %q", original.Username, got.Username)
	}
	if got.ProcessName != original.ProcessName {
		t.Fatalf("ProcessName: want %q, got %q", original.ProcessName, got.ProcessName)
	}
	if got.ProcessID != original.ProcessID {
		t.Fatalf("ProcessID: want %d, got %d", original.ProcessID, got.ProcessID)
	}
	if got.Arch != original.Arch {
		t.Fatalf("Arch: want %d, got %d", original.Arch, got.Arch)
	}
	if got.Platform != original.Platform {
		t.Fatalf("Platform: want %d, got %d", original.Platform, got.Platform)
	}
	if got.Integrity != original.Integrity {
		t.Fatalf("Integrity: want %d, got %d", original.Integrity, got.Integrity)
	}
}

// TestEncodeDecodeImplantMetadata_AbsentStrings verifies that empty strings
// are encoded as absent (0x00) and decoded back as empty.
func TestEncodeDecodeImplantMetadata_AbsentStrings(t *testing.T) {
	sessionKey := make([]byte, 32)
	original := &models.ImplantMetadata{
		ID:         1,
		SessionKey: sessionKey,
		// Username, Hostname, ProcessName intentionally empty
		Sleep: 30,
		Arch:  1,
	}

	encoded := EncodeImplantMetadata(original)
	got, err := DecodeImplantMetadata(encoded)
	if err != nil {
		t.Fatalf("DecodeImplantMetadata: %v", err)
	}

	if got.Username != "" {
		t.Fatalf("Username: want empty, got %q", got.Username)
	}
	if got.Hostname != "" {
		t.Fatalf("Hostname: want empty, got %q", got.Hostname)
	}
	if got.ProcessName != "" {
		t.Fatalf("ProcessName: want empty, got %q", got.ProcessName)
	}
	if got.Sleep != 30 {
		t.Fatalf("Sleep: want 30, got %d", got.Sleep)
	}
	if got.Arch != 1 {
		t.Fatalf("Arch: want 1, got %d", got.Arch)
	}
}

func TestEncodeDecodeRunReq(t *testing.T) {
	cmd := "whoami"
	encoded := EncodeRunReq(cmd)
	if len(encoded) != 4+len(cmd) {
		t.Fatalf("want %d bytes, got %d", 4+len(cmd), len(encoded))
	}
	n := binary.LittleEndian.Uint32(encoded[:4])
	if n != uint32(len(cmd)) {
		t.Fatalf("want length prefix %d, got %d", len(cmd), n)
	}
	if string(encoded[4:]) != cmd {
		t.Fatalf("want %q, got %q", cmd, string(encoded[4:]))
	}
}

func TestDecodeRunRep(t *testing.T) {
	output := "root\n"
	encoded := EncodeRunReq(output) // same wire format
	got, err := DecodeRunRep(encoded)
	if err != nil {
		t.Fatalf("DecodeRunRep: %v", err)
	}
	if got != output {
		t.Fatalf("want %q, got %q", output, got)
	}
}

func TestDecodeRunRep_TooShort(t *testing.T) {
	_, err := DecodeRunRep([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for input shorter than 4 bytes")
	}
}

func TestDecodeRunRep_Truncated(t *testing.T) {
	// length prefix says 10 bytes but only 2 bytes follow
	b := make([]byte, 6)
	binary.LittleEndian.PutUint32(b[:4], 10)
	copy(b[4:], "ab")
	_, err := DecodeRunRep(b)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

func TestEncodeSetSleepReq(t *testing.T) {
	b := EncodeSetSleepReq(60, 20)
	if len(b) != 8 {
		t.Fatalf("want 8 bytes, got %d", len(b))
	}
	if binary.LittleEndian.Uint32(b[:4]) != 60 {
		t.Fatal("interval mismatch")
	}
	if binary.LittleEndian.Uint32(b[4:]) != 20 {
		t.Fatal("jitter mismatch")
	}
}

func TestEncodeDecodeInteractiveReq(t *testing.T) {
	host := "10.0.0.1"
	port := uint16(4443)
	encoded := EncodeInteractiveReq(host, port)

	gotHost, gotPort, err := DecodeInteractiveReq(encoded)
	if err != nil {
		t.Fatalf("DecodeInteractiveReq: %v", err)
	}
	if gotHost != host {
		t.Errorf("host = %q, want %q", gotHost, host)
	}
	if gotPort != port {
		t.Errorf("port = %d, want %d", gotPort, port)
	}
}

func TestDecodeInteractiveReqTruncated(t *testing.T) {
	_, _, err := DecodeInteractiveReq([]byte{0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}

func TestEncodeDecodeShellInput(t *testing.T) {
	input := []byte("whoami\r\n")
	encoded := EncodeShellInput(input)
	got, err := DecodeShellInput(encoded)
	if err != nil {
		t.Fatalf("DecodeShellInput: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("got %q, want %q", got, input)
	}
}

func TestDecodeShellInputTruncated(t *testing.T) {
	_, err := DecodeShellInput([]byte{0xFF, 0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}

func TestInlineAssemblyConstants(t *testing.T) {
	if TaskInlineAssembly != 15 {
		t.Fatalf("TaskInlineAssembly = %d, want 15", TaskInlineAssembly)
	}
	if CodeInlineAssembly != 0 {
		t.Fatalf("CodeInlineAssembly = %d, want 0", CodeInlineAssembly)
	}
	if InlineModeAuto != 0 {
		t.Fatalf("InlineModeAuto = %d, want 0", InlineModeAuto)
	}
	if InlineModeBridge != 1 {
		t.Fatalf("InlineModeBridge = %d, want 1", InlineModeBridge)
	}
	if InlineModeDirect != 2 {
		t.Fatalf("InlineModeDirect = %d, want 2", InlineModeDirect)
	}
}

func TestEncodeBOFReqFixture(t *testing.T) {
	got := EncodeBOFReq([]byte{0x64, 0x86, 0x00}, []byte{0x03, 0x00, 0x00, 0x00, 'o', 'n', 'e'})
	want := []byte{
		0x03, 0x00, 0x00, 0x00, 0x64, 0x86, 0x00,
		0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 'o', 'n', 'e',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture mismatch:\n got: %v\nwant: %v", got, want)
	}
}

func TestEncodeDecodeInlineAssemblyReq(t *testing.T) {
	bridgeBytes := []byte{0x41, 0x42, 0x43}
	assemblyBytes := []byte{0x90, 0xC3}
	args := []string{"alpha", "", "sp ace", "unicode-ok"}

	encoded := EncodeInlineAssemblyReq(bridgeBytes, assemblyBytes, args, InlineModeBridge)
	mode, gotBridge, gotAssembly, gotArgs, err := DecodeInlineAssemblyReq(encoded)
	if err != nil {
		t.Fatalf("DecodeInlineAssemblyReq: %v", err)
	}

	if mode != InlineModeBridge {
		t.Fatalf("mode = %d, want %d", mode, InlineModeBridge)
	}
	if !bytes.Equal(gotBridge, bridgeBytes) {
		t.Fatalf("bridge bytes mismatch: got %v want %v", gotBridge, bridgeBytes)
	}
	if !bytes.Equal(gotAssembly, assemblyBytes) {
		t.Fatalf("assembly bytes mismatch: got %v want %v", gotAssembly, assemblyBytes)
	}
	if len(gotArgs) != len(args) {
		t.Fatalf("args len = %d, want %d", len(gotArgs), len(args))
	}
	for i := range args {
		if gotArgs[i] != args[i] {
			t.Fatalf("arg[%d] = %q, want %q", i, gotArgs[i], args[i])
		}
	}
}

func TestEncodeInlineAssemblyReqFixture(t *testing.T) {
	got := EncodeInlineAssemblyReq([]byte{0xAA, 0xBB}, []byte{0xCC}, []string{"go", ""}, InlineModeDirect)
	want := []byte{
		0x02, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB,
		0x01, 0x00, 0x00, 0x00, 0xCC,
		0x02, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x67, 0x6F,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture mismatch:\n got: %v\nwant: %v", got, want)
	}
}

func TestEncodeInlineAssemblyBOFArgsFixture(t *testing.T) {
	got := EncodeInlineAssemblyBOFArgs([]byte{0xAA, 0xBB}, []byte{0xCC}, []string{"go", ""})
	want := []byte{
		0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB,
		0x01, 0x00, 0x00, 0x00, 0xCC,
		0x02, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x67, 0x6F,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture mismatch:\n got: %v\nwant: %v", got, want)
	}
}

func TestDecodeInlineAssemblyReqMalformed(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "too short for mode",
			payload: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "truncated bridge bytes",
			payload: func() []byte {
				b := make([]byte, 8)
				binary.LittleEndian.PutUint32(b[:4], InlineModeDirect)
				binary.LittleEndian.PutUint32(b[4:], 3)
				return b
			}(),
		},
		{
			name: "truncated arg bytes",
			payload: func() []byte {
				b := make([]byte, 0, 24)
				b = appendUint32LE(b, InlineModeDirect)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 1)
				b = appendUint32LE(b, 4)
				b = append(b, 'o', 'k')
				return b
			}(),
		},
		{
			name: "invalid mode",
			payload: func() []byte {
				b := make([]byte, 0, 16)
				b = appendUint32LE(b, 99)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				return b
			}(),
		},
		{
			name: "argc exceeds possible remaining args",
			payload: func() []byte {
				b := make([]byte, 0, 20)
				b = appendUint32LE(b, InlineModeDirect)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0x40000000)
				return b
			}(),
		},
		{
			name: "legacy auto mode rejected",
			payload: func() []byte {
				b := make([]byte, 0, 16)
				b = appendUint32LE(b, InlineModeAuto)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				return b
			}(),
		},
		{
			name: "trailing bytes rejected",
			payload: func() []byte {
				b := EncodeInlineAssemblyReq([]byte{0x01}, []byte{0x02}, []string{"x"}, InlineModeBridge)
				return append(b, 0xFF)
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := DecodeInlineAssemblyReq(tt.payload)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEncodeDecodeInlineAssemblyResult(t *testing.T) {
	want := InlineAssemblyResult{
		ExitCode:      -7,
		DurationMS:    1234,
		Truncated:     true,
		Stdout:        "stdout text",
		Stderr:        "stderr text",
		Exception:     "exception text",
		Mode:          "bridge",
		BridgeVersion: "1.2.3",
		Diagnostics:   "diag text",
	}

	encoded := EncodeInlineAssemblyResult(want)
	got, err := DecodeInlineAssemblyResult(encoded)
	if err != nil {
		t.Fatalf("DecodeInlineAssemblyResult: %v", err)
	}

	if got != want {
		t.Fatalf("result mismatch: got %#v want %#v", got, want)
	}
}

func TestEncodeInlineAssemblyResultFixture(t *testing.T) {
	got := EncodeInlineAssemblyResult(InlineAssemblyResult{
		ExitCode:      -2,
		DurationMS:    5,
		Truncated:     true,
		Stdout:        "A",
		Stderr:        "",
		Exception:     "B",
		Mode:          "D",
		BridgeVersion: "1",
		Diagnostics:   "",
	})
	want := []byte{
		0xFE, 0xFF, 0xFF, 0xFF,
		0x05, 0x00, 0x00, 0x00,
		0x01,
		0x01, 0x00, 0x00, 0x00, 0x41,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x42,
		0x01, 0x00, 0x00, 0x00, 0x44,
		0x01, 0x00, 0x00, 0x00, 0x31,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture mismatch:\n got: %v\nwant: %v", got, want)
	}
}

func TestDecodeInlineAssemblyResultMalformed(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "too short for header",
			payload: make([]byte, 8),
		},
		{
			name: "truncated stdout bytes",
			payload: func() []byte {
				b := make([]byte, 0, 32)
				b = appendInt32LE(b, 0)
				b = appendUint32LE(b, 10)
				b = append(b, 0)
				b = appendUint32LE(b, 5)
				b = append(b, 'o', 'k')
				return b
			}(),
		},
		{
			name: "missing trailing diagnostics length",
			payload: func() []byte {
				b := make([]byte, 0, 64)
				b = appendInt32LE(b, 1)
				b = appendUint32LE(b, 20)
				b = append(b, 1)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				b = appendUint32LE(b, 0)
				return b
			}(),
		},
		{
			name: "trailing bytes rejected",
			payload: func() []byte {
				b := EncodeInlineAssemblyResult(InlineAssemblyResult{})
				return append(b, 0xEE)
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeInlineAssemblyResult(tt.payload)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func appendUint32LE(dst []byte, v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return append(dst, buf...)
}

func appendInt32LE(dst []byte, v int32) []byte {
	return appendUint32LE(dst, uint32(v))
}
