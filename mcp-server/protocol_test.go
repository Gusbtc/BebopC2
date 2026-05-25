package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

func TestInitializeResponse(t *testing.T) {
	server := NewServer(nil, false)
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":7,"method":"initialize"}` + "\n")
	var out bytes.Buffer

	if err := server.Serve(in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	line, err := bufio.NewReader(&out).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.JSONRPC != "2.0" {
		t.Fatalf("jsonrpc = %q, want 2.0", response.JSONRPC)
	}
	if string(response.ID) != "7" {
		t.Fatalf("id = %s, want 7", response.ID)
	}
	if response.Error != nil {
		t.Fatalf("unexpected error: %+v", response.Error)
	}
	if response.Result.ProtocolVersion == "" {
		t.Fatal("protocolVersion is empty")
	}
}

func TestUnknownMethodReturnsError(t *testing.T) {
	server := NewServer(nil, false)
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":"abc","method":"missing"}` + "\n")
	var out bytes.Buffer

	if err := server.Serve(in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	line, err := bufio.NewReader(&out).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var response rpcResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected error")
	}
	if response.Error.Code != -32601 {
		t.Fatalf("error code = %d, want -32601", response.Error.Code)
	}
}

func TestParseErrorIncludesNullID(t *testing.T) {
	server := NewServer(nil, false)
	in := bytes.NewBufferString("{bad json\n")
	var out bytes.Buffer

	if err := server.Serve(in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	var response rpcResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if string(response.ID) != "null" {
		t.Fatalf("id = %s, want null", response.ID)
	}
	if response.Error == nil || response.Error.Code != -32700 {
		t.Fatalf("error = %#v, want parse error", response.Error)
	}
}

func TestInitializedNotificationHasNoResponse(t *testing.T) {
	server := NewServer(nil, false)
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	var out bytes.Buffer

	if err := server.Serve(in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	if out.Len() != 0 {
		t.Fatalf("notification produced response: %q", out.String())
	}
}

func TestServeReportsScannerErrors(t *testing.T) {
	server := NewServer(nil, false)
	in := bytes.NewBuffer(make([]byte, maxScannerBuffer+1))
	var out bytes.Buffer

	if err := server.Serve(in, &out); err == nil {
		t.Fatal("expected scanner error")
	}
}
