package server

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	payload := []byte("hello session mode")
	errCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- WriteEnvelope(conn, payload)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got, err := ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
}

func TestEnvelopeEmpty(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		defer conn.Close()
		WriteEnvelope(conn, []byte{})
	}()

	conn, _ := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	defer conn.Close()

	got, err := ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d bytes", len(got))
	}
}
