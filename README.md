<p align="center">
  <img src="operator-client/static/img/logo_bepop.png" alt="BEBOP C2 Logo" width="400">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.2-amber?style=for-the-badge&labelColor=black" alt="Version">
  <img src="https://img.shields.io/badge/Win32-blue?style=for-the-badge&logo=c&labelColor=black" alt="Win32">
  <img src="https://img.shields.io/badge/Golang-Teamserver-00ADD8?style=for-the-badge&logo=go&labelColor=black" alt="Go">
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge&labelColor=black" alt="License">
</p>

---

Asynchronous C2 framework for red team operations. Go teamserver, C beacon for Windows, browser-based operator console.

<p align="center">
  <img src="operator-client/static/img/graph_sessions.png" alt="Session graph view" width="900">
</p>

<p align="center">
  <img src="operator-client/static/img/table_sessions.png" alt="Session table view" width="900">
</p>

The beacon is native Win32 with no CRT API dependencies in the IAT. All Windows APIs are resolved at runtime through PEB walking and DJB2 hashing. Communication is binary-over-HTTP with AES-256-CBC + HMAC-SHA256 using derived sub-keys (HKDF). The operator console gives you terminals, session maps, and an event log from any browser.

## How it works

```
         OPERATOR NETWORK                              TARGET NETWORK
  ┌─────────────────────────────────┐           ┌─────────────────────────┐
  │                                 │           │                         │
  │  ┌──────────┐   ┌────────────┐  │  HTTP/S   │  ┌─────────┐            │
  │  │ Operator │──>│ Teamserver │──┼──── // ───┼─>│ Beacon  │──[WinAPI]  │
  │  │ Browser  │   └──────┬─────┘  │           │  └─────────┘            │
  │  └──────────┘          │        │           │                         │
  │                   ┌────┴─────┐  │           │                         │
  │                   │ Builder  │  │           │                         │
  │                   │ (MinGW)  │  │           │                         │
  │                   └──────────┘  │           │                         │
  └─────────────────────────────────┘           └─────────────────────────┘

  Registration:  Beacon ──[RSA-OAEP(session_key + metadata)]──> Teamserver
  Checkin loop:  Beacon ──[beacon_id]──> Teamserver ──[AES(task)]──> Beacon
  Results:       Beacon ──[AES(output)]──> Teamserver
  Sleep:         Beacon sleeps with jitter between checkins
```

## Architecture

### Teamserver (Go)

Single binary, no external dependencies. Manages beacon state, queues tasks, serves the operator UI, and cross-compiles beacons on the fly via MinGW.

- Asynchronous task queue per beacon
- Thread-safe in-memory store with JSON persistence and session restore on startup (load previous session or reset)
- RSA keypair generated at startup, kept in memory
- Multiple listeners on different ports and protocols
- On-demand beacon compilation with per-build string obfuscation
- HKDF domain separation for AES and HMAC sub-keys

### Beacon (C / Win32)

Lightweight implant for Windows x64. Communicates over WinHTTP, uses Windows CNG for crypto.

- All Windows APIs resolved via PEB walk + DJB2 hash (zero suspicious IAT entries)
- Anonymous pipes capture output from spawned processes
- Native command implementations (ls, ps, whoami, netstat, ipconfig, arp, drives, services, privs, env, clipboard, reg_query, reg_set, runas) via WinAPI, no `cmd.exe` unless explicitly requested
- Integrity-level detection (Medium / High / SYSTEM) reported on registration
- File transfer with chunked 64KB streaming (upload and download)

### Operator console (web)

Browser-based UI with a terminal-centric workflow. Vanilla HTML/CSS/JS served by the operator-client binary. No build step.

- Tabbed terminals with persistent command history and output across tab switches
- Event log with timestamped entries (new sessions, kills, task dispatches, connection changes)
- Session map as a force-directed graph with zoom/pan, plus table and grid views
- Resizable panels between terminal and event log
- Loot tab for exfiltrated file management (download, delete)
- Toast notifications on new beacon callbacks
- Context menus on beacon rows

## Evasion

### API hashing

Windows API functions are resolved at runtime through DJB2 hashing and PEB walking. The IAT contains only MinGW CRT functions (memcpy, strlen, etc.). Nothing from WinHTTP, BCrypt, Advapi32, User32, or kernel32 that reveals beacon behavior. The hash table is generated at build time by the teamserver.

### String obfuscation

All hardcoded strings (API paths, hostnames, command names, User-Agent, DLL names) are encrypted with an 8-byte rotating XOR key at compile time. Decrypted in memory just before use. The obfuscation generator runs as part of the build pipeline so each compiled beacon gets a fresh key.

DLL names passed to LoadLibraryA (winhttp.dll, bcrypt.dll, advapi32.dll, etc.) are also XOR-encrypted and decrypted on the stack at runtime. No DLL names appear as plaintext in the binary.

### Shellcode generation

.bin payloads via Donut. Position-independent shellcode for direct memory injection without writing to disk.

### Traffic

AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) with HKDF domain separation (separate sub-keys for encryption and authentication). Session keys are established through RSA-OAEP during registration. Jitter (0-100%) and configurable sleep intervals break periodic beacon patterns.

## Protocol

All beacon-to-teamserver traffic uses a custom binary protocol over HTTP, based on the [OST C2 Spec](https://github.com/rasta-mouse/OST-C2-Spec).

```
Task header (16 bytes, little-endian):
  [0]     Type       uint8    NOP=0, Exit=1, Set=2, FileStage=3, FileExfil=4, Run=12
  [1]     Code       uint8    subtype
  [2:4]   Flags      uint16   0=ok, 1=error, 4=fragmented, 8=last
  [4:8]   Label      uint32   correlates request/response
  [8:12]  Identifier uint32   fragment ordering
  [12:16] Length     uint32   payload size

Wire format:
  [0:16]  IV              16 bytes, random per message
  [16:48] HMAC-SHA256     over IV + ciphertext (derived HMAC key)
  [48:]   AES-CBC         ciphertext (derived AES key)
```

Registration uses RSA-OAEP to deliver the beacon's session key and metadata. After that, everything is AES-CBC.

## Setup

### Teamserver

```bash
chmod +x setup-teamserver.sh
./setup-teamserver.sh
```

### Operator console

```bash
chmod +x setup-operator.sh
./setup-operator.sh
```

The beacon is compiled on demand from the operator console's Build page. It handles listener selection, sleep interval, jitter, and output format (EXE or shellcode). No manual beacon build needed.

## Project layout

```
teamserver/
  server/          HTTP handlers, routing, listeners
  store/           In-memory beacon/task/result store with TTL cleanup
  models/          Beacon, Task, Result, Listener, Event, Terminal types
  protocol/        Binary serialization + crypto (HKDF key derivation)
  obfgen/          Build-time XOR string obfuscation
  hashgen/         DJB2 API hash generator
  builder/         Cross-compilation pipeline
  persist/         JSON state persistence
  ui/              Terminal UI helpers

beacon/
  src/
    main.c         Entry point, checkin loop
    comms/http.c   WinHTTP communication
    protocol/      AES-CBC + HMAC-SHA256 via CNG, HKDF sub-keys
    exec/          Process execution (exec.c) + native commands (builtin.c)
    resolve/       PEB walking + DJB2 hash resolution (~100 APIs)
    transfer/      File upload/download with 64KB chunked streaming
  include/         Headers, config, generated hash tables, XOR strings

operator-client/
  static/
    pages/         HTML (sessions, listeners, build, interact, loot)
    css/           Stylesheet
    js/            Application logic (xterm.js terminal)
    img/           Assets
```

## Roadmap

### Done
- [x] Multiple HTTP/HTTPS listeners with auto-cert and custom headers
- [x] API hashing via PEB walk + DJB2 (~100 APIs, zero in IAT)
- [x] XOR string obfuscation (commands, paths, User-Agent, DLL names)
- [x] Shellcode generation via Donut
- [x] Native Win32 recon commands (20+ builtins)
- [x] Session map, tabbed terminals, event log
- [x] File transfer (upload/download with 64KB chunked streaming)
- [x] HKDF domain separation for AES and HMAC sub-keys
- [x] Full IAT cleanup (all beacon APIs resolved dynamically)

### Next
- [ ] Ekko sleep masking (RC4 image encryption, VirtualProtect RW/RX toggle)
- [ ] Direct syscalls to bypass EDR hooks (SysWhispers-style)
- [ ] BOF loader for in-memory Beacon Object Files
- [ ] SQLite persistence (replace JSON)
- [ ] SOCKS5 proxy through beacon for pivoting
- [ ] Multi-operator support with authentication and roles
- [ ] Malleable C2 profiles (configurable HTTP headers, URIs, body encoding)
- [ ] Beacon staging (minimal stager that downloads full beacon)

### Later
- [ ] execute-assembly for .NET tooling
- [ ] ETW patching (EtwEventWrite in-memory patch)
- [ ] AMSI bypass (AmsiScanBuffer patch)
- [ ] DNS and SMB transport channels
- [ ] Token manipulation for lateral movement
- [ ] Screenshot and keylogger tasking
- [ ] Linux beacon

---

## Disclaimer

For educational and authorized security testing only. You are responsible for how you use this software.

---

<p align="center">
  <i>"See you space cowboy..."</i>
</p>
