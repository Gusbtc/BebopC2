package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeHeader_RoundTrip(t *testing.T) {
	h := TaskHeader{Type: TaskRun, Code: 0, Flags: FlagNone, Label: 42, Identifier: 7, Length: 128}
	b := EncodeHeader(h)
	if len(b) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(b))
	}
	got, err := DecodeHeader(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != h {
		t.Fatalf("expected %+v, got %+v", h, got)
	}
}

func TestDecodeHeader_TooShort(t *testing.T) {
	_, err := DecodeHeader([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short input, got nil")
	}
}

func TestEncodeHeader_LittleEndian(t *testing.T) {
	h := TaskHeader{Label: 0x01020304}
	b := EncodeHeader(h)
	// bytes 4-7 must be little-endian: 04 03 02 01
	want := []byte{0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(b[4:8], want) {
		t.Fatalf("expected %x, got %x", want, b[4:8])
	}
}

func TestNewNOP(t *testing.T) {
	msg := NewNOP()
	if msg.Header.Type != TaskNOP {
		t.Fatalf("expected type 0 (NOP), got %d", msg.Header.Type)
	}
	if len(msg.Data) != 0 {
		t.Fatalf("expected empty data, got %d bytes", len(msg.Data))
	}
	if msg.Header.Length != 0 {
		t.Fatalf("expected Length 0, got %d", msg.Header.Length)
	}
}
