package server

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"c2/models"
	"c2/protocol"
)

func TestSessionListener_InlineAssemblyStoresStructuredResultAndPublishesEvent(t *testing.T) {
	s, dbPath := newTestStoreWithPath(t)
	hub := NewHub()
	sl := NewSessionListener(4444, s, &nopPersister{}, hub, nil)

	sessionKey := make([]byte, 32)
	s.RegisterBeacon(&models.ImplantMetadata{
		ID:         220,
		SessionKey: sessionKey,
		Sleep:      5,
		Hostname:   "session-host",
	})
	s.QueueTask(&models.Task{Label: 88, BeaconID: 220, Type: protocol.TaskInlineAssembly, Status: models.TaskStatusPending})
	s.GetNextTask(220)

	events := hub.Subscribe()
	defer hub.Unsubscribe(events)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		sl.handleSession(serverConn)
		close(done)
	}()

	writeUint32(t, clientConn, 220)
	writeByte(t, clientConn, protocol.ConnSession)
	writeEnvelopeWithPlaintext(t, clientConn, sessionKey, encodeSessionConfirm(220))

	inline := protocol.InlineAssemblyResult{
		ExitCode:      9,
		DurationMS:    222,
		Truncated:     false,
		Stdout:        "hello stdout",
		Stderr:        "hello stderr",
		Exception:     "managed exception",
		Mode:          "direct",
		BridgeVersion: "",
		Diagnostics:   "diag detail",
	}
	writeEnvelopeWithPlaintext(t, clientConn, sessionKey, encodeInlineAssemblyResultMessage(88, 6, inline))
	clientConn.Close()

	select {
	case <-done:
	case <-timeAfter(t):
		t.Fatal("session listener did not exit")
	}

	if status := fetchTaskStatus(t, dbPath, 220, protocol.TaskInlineAssembly); status != models.TaskStatusCompleted {
		t.Fatalf("task status = %s, want %s", status, models.TaskStatusCompleted)
	}

	results := s.GetResults(220)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	got := results[0]
	if got.Type != protocol.TaskInlineAssembly || got.Flags != 6 {
		t.Fatalf("identity mismatch: %#v", got)
	}
	if got.ExitCode != inline.ExitCode || got.DurationMS != inline.DurationMS || got.Truncated != inline.Truncated {
		t.Fatalf("metadata mismatch: %#v", got)
	}
	if got.Stdout != inline.Stdout || got.Stderr != inline.Stderr || got.Exception != inline.Exception {
		t.Fatalf("streams mismatch: %#v", got)
	}
	if got.Mode != inline.Mode || got.BridgeVersion != inline.BridgeVersion || got.Diagnostics != inline.Diagnostics {
		t.Fatalf("mode mismatch: %#v", got)
	}
	for _, want := range []string{
		"Exit Code: 9",
		"Duration: 222 ms",
		"Truncated: false",
		"Stdout:\nhello stdout",
		"Stderr:\nhello stderr",
		"Exception:\nmanaged exception",
		"Diagnostics:\ndiag detail",
	} {
		if !strings.Contains(got.Output, want) {
			t.Fatalf("output missing %q in %q", want, got.Output)
		}
	}

	evt := waitForHubEvent(t, events, "results", "add")
	data, ok := evt.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event data type = %T, want map[string]interface{}", evt.Data)
	}
	if data["type"] != protocol.TaskInlineAssembly || data["flags"] != uint16(6) {
		t.Fatalf("event identity mismatch: %#v", data)
	}
	if data["mode"] != inline.Mode || data["bridge_version"] != inline.BridgeVersion {
		t.Fatalf("event mode mismatch: %#v", data)
	}
	if data["exit_code"] != inline.ExitCode || data["duration_ms"] != inline.DurationMS || data["truncated"] != inline.Truncated {
		t.Fatalf("event metadata mismatch: %#v", data)
	}
}

func TestSessionListener_InlineAssemblyBOFStoresStructuredTextResult(t *testing.T) {
	s, dbPath := newTestStoreWithPath(t)
	hub := NewHub()
	sl := NewSessionListener(4444, s, &nopPersister{}, hub, nil)

	sessionKey := make([]byte, 32)
	s.RegisterBeacon(&models.ImplantMetadata{
		ID:         222,
		SessionKey: sessionKey,
		Sleep:      5,
		Hostname:   "session-host",
	})
	s.QueueTask(&models.Task{
		Label:      90,
		BeaconID:   222,
		Type:       protocol.TaskBOF,
		Identifier: inlineAssemblyBOFIdentifier,
		Status:     models.TaskStatusPending,
	})
	s.GetNextTask(222)

	events := hub.Subscribe()
	defer hub.Unsubscribe(events)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		sl.handleSession(serverConn)
		close(done)
	}()

	writeUint32(t, clientConn, 222)
	writeByte(t, clientConn, protocol.ConnSession)
	writeEnvelopeWithPlaintext(t, clientConn, sessionKey, encodeSessionConfirm(222))

	output := "[inline-assembly]\r\nExit: 0\r\nDuration: 55ms\r\nTruncated: false\r\n\r\nSTDOUT:\r\nsession ok\r\n"
	writeEnvelopeWithPlaintext(t, clientConn, sessionKey, encodeBOFRunMessage(90, 0, output))
	clientConn.Close()

	select {
	case <-done:
	case <-timeAfter(t):
		t.Fatal("session listener did not exit")
	}

	if status := fetchTaskStatus(t, dbPath, 222, protocol.TaskBOF); status != models.TaskStatusCompleted {
		t.Fatalf("task status = %s, want %s", status, models.TaskStatusCompleted)
	}
	results := s.GetResults(222)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	got := results[0]
	if got.Type != protocol.TaskInlineAssembly || got.Stdout != "session ok" || got.ExitCode != 0 {
		t.Fatalf("result mismatch: %#v", got)
	}
	evt := waitForHubEvent(t, events, "results", "add")
	data, ok := evt.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event data type = %T", evt.Data)
	}
	if data["type"] != protocol.TaskInlineAssembly || data["stdout"] != "session ok" {
		t.Fatalf("event mismatch: %#v", data)
	}
}

func TestSessionListener_InlineAssemblyDecodeFailureStoresFallbackAndCompletesTask(t *testing.T) {
	s, dbPath := newTestStoreWithPath(t)
	hub := NewHub()
	sl := NewSessionListener(4444, s, &nopPersister{}, hub, nil)

	sessionKey := make([]byte, 32)
	s.RegisterBeacon(&models.ImplantMetadata{
		ID:         221,
		SessionKey: sessionKey,
		Sleep:      5,
		Hostname:   "session-host",
	})
	s.QueueTask(&models.Task{Label: 89, BeaconID: 221, Type: protocol.TaskInlineAssembly, Status: models.TaskStatusPending})
	s.GetNextTask(221)

	events := hub.Subscribe()
	defer hub.Unsubscribe(events)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		sl.handleSession(serverConn)
		close(done)
	}()

	writeUint32(t, clientConn, 221)
	writeByte(t, clientConn, protocol.ConnSession)
	writeEnvelopeWithPlaintext(t, clientConn, sessionKey, encodeSessionConfirm(221))
	writeEnvelopeWithPlaintext(t, clientConn, sessionKey, encodeInlineAssemblyMalformedMessage(89, 7))
	clientConn.Close()

	select {
	case <-done:
	case <-timeAfter(t):
		t.Fatal("session listener did not exit")
	}

	if status := fetchTaskStatus(t, dbPath, 221, protocol.TaskInlineAssembly); status != models.TaskStatusCompleted {
		t.Fatalf("task status = %s, want %s", status, models.TaskStatusCompleted)
	}

	results := s.GetResults(221)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	got := results[0]
	if got.Type != protocol.TaskInlineAssembly || got.Flags != 7 {
		t.Fatalf("identity mismatch: %#v", got)
	}
	if got.ExitCode != -1 || got.Mode != "decode-error" {
		t.Fatalf("fallback mismatch: %#v", got)
	}
	if !strings.Contains(got.Exception, "DecodeInlineAssemblyResult") {
		t.Fatalf("exception = %q", got.Exception)
	}
	for _, want := range []string{"Exit Code: -1", "Exception:", "DecodeInlineAssemblyResult"} {
		if !strings.Contains(got.Output, want) {
			t.Fatalf("output missing %q in %q", want, got.Output)
		}
	}

	evt := waitForHubEvent(t, events, "results", "add")
	data, ok := evt.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event data type = %T, want map[string]interface{}", evt.Data)
	}
	if data["exit_code"] != int32(-1) || data["mode"] != "decode-error" {
		t.Fatalf("event fallback mismatch: %#v", data)
	}
	if !strings.Contains(data["exception"].(string), "DecodeInlineAssemblyResult") {
		t.Fatalf("event exception = %#v", data["exception"])
	}
}

func writeUint32(t *testing.T, conn net.Conn, v uint32) {
	t.Helper()
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Write uint32: %v", err)
	}
}

func writeByte(t *testing.T, conn net.Conn, b byte) {
	t.Helper()
	if _, err := conn.Write([]byte{b}); err != nil {
		t.Fatalf("Write byte: %v", err)
	}
}

func writeEnvelopeWithPlaintext(t *testing.T, conn net.Conn, sessionKey, plaintext []byte) {
	t.Helper()
	encrypted, err := protocol.Encrypt(sessionKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := WriteEnvelope(conn, encrypted); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
}

func encodeSessionConfirm(beaconID uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, beaconID)
	return buf
}

func encodeInlineAssemblyResultMessage(label uint32, flags uint16, inline protocol.InlineAssemblyResult) []byte {
	payload := protocol.EncodeInlineAssemblyResult(inline)
	hdr := protocol.EncodeHeader(protocol.TaskHeader{
		Type:   protocol.TaskInlineAssembly,
		Flags:  flags,
		Label:  label,
		Length: uint32(len(payload)),
	})
	return append(hdr, payload...)
}

func encodeInlineAssemblyMalformedMessage(label uint32, flags uint16) []byte {
	payload := []byte{0x01, 0x02, 0x03}
	hdr := protocol.EncodeHeader(protocol.TaskHeader{
		Type:   protocol.TaskInlineAssembly,
		Flags:  flags,
		Label:  label,
		Length: uint32(len(payload)),
	})
	return append(hdr, payload...)
}

func encodeBOFRunMessage(label uint32, flags uint16, output string) []byte {
	payload := protocol.EncodeRunReq(output)
	hdr := protocol.EncodeHeader(protocol.TaskHeader{
		Type:   protocol.TaskBOF,
		Flags:  flags,
		Label:  label,
		Length: uint32(len(payload)),
	})
	return append(hdr, payload...)
}

func timeAfter(t *testing.T) <-chan time.Time {
	t.Helper()
	return time.After(2 * time.Second)
}
