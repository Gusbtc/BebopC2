package builder

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidation(t *testing.T) {
	base := BuildParams{
		ServerHost: "192.168.1.1",
		ServerPort: 8080,
		SleepMS:    5000,
		JitterPct:  20,
		BeaconSrc:  "/tmp/noop",
	}
	cases := []struct {
		name    string
		mutate  func(*BuildParams)
		wantErr string
	}{
		{"valid", func(p *BuildParams) {}, ""},
		{"empty host", func(p *BuildParams) { p.ServerHost = "" }, "server_host"},
		{"host with semicolon", func(p *BuildParams) { p.ServerHost = "a;rm -rf /" }, "server_host"},
		{"host with quote", func(p *BuildParams) { p.ServerHost = `a"b` }, "server_host"},
		{"port zero", func(p *BuildParams) { p.ServerPort = 0 }, "server_port"},
		{"port too high", func(p *BuildParams) { p.ServerPort = 65536 }, "server_port"},
		{"sleep too low", func(p *BuildParams) { p.SleepMS = 999 }, "sleep_ms"},
		{"sleep too high", func(p *BuildParams) { p.SleepMS = 259200001 }, "sleep_ms"},
		{"jitter negative", func(p *BuildParams) { p.JitterPct = -1 }, "jitter_pct"},
		{"jitter over 100", func(p *BuildParams) { p.JitterPct = 101 }, "jitter_pct"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			err := validate(p)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestConfigH(t *testing.T) {
	p := BuildParams{ServerHost: "10.0.0.1", ServerPort: 4444, SleepMS: 10000, JitterPct: 30}
	s := configH(p)
	if strings.Contains(s, "SERVER_HOST") {
		t.Errorf("configH must not include SERVER_HOST (now in obf_strings.h):\n%s", s)
	}
	if strings.Contains(s, "USER_AGENT") {
		t.Errorf("configH must not include USER_AGENT (now in obf_strings.h):\n%s", s)
	}
	if !strings.Contains(s, "4444") {
		t.Errorf("missing SERVER_PORT in:\n%s", s)
	}
	if !strings.Contains(s, "10000") {
		t.Errorf("missing SLEEP_MS in:\n%s", s)
	}
	if !strings.Contains(s, "30") {
		t.Errorf("missing JITTER_PCT in:\n%s", s)
	}
}

func TestConfigH_UseHTTPS(t *testing.T) {
	p := BuildParams{
		ServerHost: "10.0.0.1", ServerPort: 8443,
		SleepMS: 5000, JitterPct: 10,
		UseHTTPS: true, IgnoreCertErrors: true,
	}
	s := configH(p)
	if !strings.Contains(s, "#define USE_HTTPS") {
		t.Errorf("missing USE_HTTPS in:\n%s", s)
	}
	if !strings.Contains(s, "#define IGNORE_CERT_ERRORS") {
		t.Errorf("missing IGNORE_CERT_ERRORS in:\n%s", s)
	}
}

func TestConfigH_UseHTTPS_RealCert(t *testing.T) {
	p := BuildParams{
		ServerHost: "evil.example.com", ServerPort: 443,
		SleepMS: 5000, JitterPct: 0,
		UseHTTPS: true, IgnoreCertErrors: false,
	}
	s := configH(p)
	if !strings.Contains(s, "#define USE_HTTPS") {
		t.Errorf("missing USE_HTTPS in:\n%s", s)
	}
	if strings.Contains(s, "IGNORE_CERT_ERRORS") {
		t.Errorf("IGNORE_CERT_ERRORS must not appear when using a real cert:\n%s", s)
	}
}

func TestConfigH_HTTP_NoHTTPSFlags(t *testing.T) {
	p := BuildParams{
		ServerHost: "10.0.0.1", ServerPort: 8080,
		SleepMS: 5000, JitterPct: 10,
		UseHTTPS: false, IgnoreCertErrors: false,
	}
	s := configH(p)
	if strings.Contains(s, "USE_HTTPS") {
		t.Errorf("USE_HTTPS must not appear for HTTP beacon:\n%s", s)
	}
}

func TestBuildIntegration(t *testing.T) {
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not in PATH — skipping integration test")
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	beaconSrc := filepath.Join(filepath.Dir(filename), "..", "..", "beacon")

	data, err := Build(BuildParams{
		ServerHost: "127.0.0.1",
		ServerPort: 8080,
		SleepMS:    5000,
		JitterPct:  20,
		BeaconSrc:  beaconSrc,
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(data) < 1024 {
		t.Fatalf("beacon.exe suspiciously small: %d bytes", len(data))
	}
	if data[0] != 'M' || data[1] != 'Z' {
		t.Fatalf("output is not a PE executable (no MZ header)")
	}
}
