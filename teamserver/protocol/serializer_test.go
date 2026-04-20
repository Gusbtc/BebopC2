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
