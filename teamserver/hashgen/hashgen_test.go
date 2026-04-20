// teamserver/hashgen/hashgen_test.go
package hashgen_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"c2/hashgen"
)

func TestDJB2_EmptyString(t *testing.T) {
	if got := hashgen.DJB2(""); got != 5381 {
		t.Fatalf("DJB2(\"\") = %d, want 5381", got)
	}
}

func TestDJB2_CaseSensitive(t *testing.T) {
	if hashgen.DJB2("WinHttpOpen") == hashgen.DJB2("winhttpopen") {
		t.Fatal("DJB2 must be case-sensitive")
	}
}

func TestDJB2_GoldenValue(t *testing.T) {
	cases := []struct {
		input string
		want  uint32
	}{
		{"WinHttpOpen", 0x11DA2C19},
		{"BCryptGenRandom", 0x79A5A35C},
	}
	for _, tc := range cases {
		if got := hashgen.DJB2(tc.input); got != tc.want {
			t.Errorf("DJB2(%q) = 0x%08X, want 0x%08X", tc.input, got, tc.want)
		}
	}
}

func TestGenerate_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	if err := hashgen.Generate(dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "api_hashes.h")); err != nil {
		t.Fatalf("api_hashes.h not created: %v", err)
	}
}

func TestGenerate_ContainsAllFunctions(t *testing.T) {
	dir := t.TempDir()
	if err := hashgen.Generate(dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "api_hashes.h"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	required := []string{
		"HASH_WinHttpOpen", "HASH_WinHttpConnect", "HASH_WinHttpOpenRequest",
		"HASH_WinHttpSendRequest", "HASH_WinHttpReceiveResponse", "HASH_WinHttpQueryHeaders",
		"HASH_WinHttpReadData", "HASH_WinHttpCloseHandle", "HASH_WinHttpSetOption", "HASH_WinHttpQueryDataAvailable",
		"HASH_BCryptGenRandom", "HASH_BCryptOpenAlgorithmProvider", "HASH_BCryptCloseAlgorithmProvider",
		"HASH_BCryptSetProperty", "HASH_BCryptGenerateSymmetricKey", "HASH_BCryptDestroyKey",
		"HASH_BCryptEncrypt", "HASH_BCryptDecrypt", "HASH_BCryptCreateHash",
		"HASH_BCryptHashData", "HASH_BCryptFinishHash", "HASH_BCryptDestroyHash",
		"HASH_CryptStringToBinaryA", "HASH_CryptDecodeObjectEx", "HASH_CryptImportPublicKeyInfoEx2",
		"HASH_CreateProcessWithLogonW", "HASH_RegOpenKeyExA", "HASH_RegQueryValueExA",
		"HASH_RegCloseKey", "HASH_LoadLibraryA", "HASH_CreateProcessA",
		"HASH_VirtualAlloc", "HASH_VirtualFree",
	}
	for _, name := range required {
		if !strings.Contains(content, name) {
			t.Errorf("missing %s in api_hashes.h", name)
		}
	}
}

func TestGenerate_HashesNonZero(t *testing.T) {
	dir := t.TempDir()
	if err := hashgen.Generate(dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "api_hashes.h"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "0x00000000UL") {
		t.Fatal("a hash resolved to 0x00000000 — DJB2 seed is 5381, this should never happen")
	}
}

func TestGenerate_BadDir(t *testing.T) {
	if err := hashgen.Generate("/does/not/exist/path"); err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}
