#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/setup-common.sh
source "$ROOT_DIR/scripts/setup-common.sh"
cd "$ROOT_DIR"

TEAMSERVER_HOST="127.0.0.1"
TEAMSERVER_PORT="8080"
SESSION_PORT="4443"
BEACON_SRC="./beacon"
START_AFTER_BUILD=1
SKIP_DOTNET=0
SKIP_BEACON_VERIFY=0

usage() {
    cat <<'EOF'
BEBOP // TEAMSERVER SETUP

Usage:
  ./setup-teamserver.sh [options]

Network:
  --host <ip|name>          Public host/IP embedded in generated beacons (default: 127.0.0.1)
  --port <port>             Teamserver HTTP/API port (default: 8080)
  --session-port <port>     Session-mode TCP port; use 0 to disable (default: 4443)
  --beacon-src <path>       Windows beacon source path for builder (default: ./beacon)

Setup:
  --skip-deps               Do not install missing system dependencies
  --skip-dotnet             Do not rebuild managed bridge; use bundled Runtime.Loader.dll
  --skip-beacon-verify      Skip local Windows beacon verification build
  --no-start                Build and prepare only; do not start teamserver
  --help                    Show this help

Examples:
  ./setup-teamserver.sh --host 10.10.14.3 --port 8080 --session-port 4443
  ./setup-teamserver.sh --host c2.example.com --port 8443 --no-start
EOF
}

require_port() {
    local name="$1" value="$2"
    [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be a number"
    [ "$value" -ge 0 ] && [ "$value" -le 65535 ] || die "$name must be between 0 and 65535"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --host)
            [ "$#" -ge 2 ] || die "--host requires a value"
            TEAMSERVER_HOST="$2"
            shift 2
            ;;
        --port)
            [ "$#" -ge 2 ] || die "--port requires a value"
            TEAMSERVER_PORT="$2"
            shift 2
            ;;
        --session-port)
            [ "$#" -ge 2 ] || die "--session-port requires a value"
            SESSION_PORT="$2"
            shift 2
            ;;
        --beacon-src)
            [ "$#" -ge 2 ] || die "--beacon-src requires a value"
            BEACON_SRC="$2"
            shift 2
            ;;
        --skip-deps)
            SETUP_SKIP_DEPS=1
            shift
            ;;
        --skip-dotnet)
            SKIP_DOTNET=1
            shift
            ;;
        --skip-beacon-verify)
            SKIP_BEACON_VERIFY=1
            shift
            ;;
        --no-start)
            START_AFTER_BUILD=0
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

require_port "--port" "$TEAMSERVER_PORT"
require_port "--session-port" "$SESSION_PORT"
[ -n "$TEAMSERVER_HOST" ] || die "--host cannot be empty"

log_header "BEBOP // TEAMSERVER SETUP"
printf '  %bhost%b         %s\n' "$GRAY" "$RESET" "$TEAMSERVER_HOST"
printf '  %bhttp port%b    %s\n' "$GRAY" "$RESET" "$TEAMSERVER_PORT"
printf '  %bsession port%b %s\n' "$GRAY" "$RESET" "$SESSION_PORT"
printf '  %bbeacon src%b   %s\n' "$GRAY" "$RESET" "$BEACON_SRC"

dry_run_exit_if_requested

prepare_gocache

log_section "checking dependencies..."
ensure_base_tools
ensure_go "1.25.0"
ensure_command x86_64-w64-mingw32-gcc mingw "mingw-w64 gcc"
ensure_command nasm nasm nasm
ensure_command cmake cmake cmake
ensure_donut_module
if has_cmd musl-gcc; then
    log_ok "musl-gcc"
else
    log_warn "musl-gcc not found; Linux beacon will use gcc when possible"
    install_tool_packages musl || true
    has_cmd musl-gcc && log_ok "musl-gcc installed" || true
fi
ensure_mbedtls

log_section "preparing managed bridge..."
mkdir -p teamserver/resources
if [ "$SKIP_DOTNET" = "0" ] && ensure_dotnet; then
    pushd managed-bridge/Bebop.ManagedBridge >/dev/null
    dotnet build -c Release >/dev/null
    popd >/dev/null
else
    log_warn "managed bridge rebuild skipped; using bundled DLL if present"
fi

BRIDGE_DLL=""
for candidate in \
    "managed-bridge/Bebop.ManagedBridge/bin/Release/net48/Runtime.Loader.dll" \
    "managed-bridge/Bebop.ManagedBridge/bin/Release/Runtime.Loader.dll" \
    "teamserver/resources/Runtime.Loader.dll"; do
    if [ -f "$candidate" ]; then
        BRIDGE_DLL="$candidate"
        break
    fi
done
[ -n "$BRIDGE_DLL" ] || die "Runtime.Loader.dll not found. Install .NET SDK 8.0+ or restore teamserver/resources/Runtime.Loader.dll."
cp "$BRIDGE_DLL" teamserver/resources/Runtime.Loader.dll
log_ok "teamserver/resources/Runtime.Loader.dll"

log_section "building inline-assembly BOF loader..."
x86_64-w64-mingw32-gcc -c modules/inline-assembly/InlineAssembly.Loader.c \
    -o teamserver/resources/InlineAssembly.Loader.x64.obj \
    -Os -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables \
    -fno-exceptions -fno-builtin
log_ok "teamserver/resources/InlineAssembly.Loader.x64.obj"

log_section "checking built-in BOF library..."
mkdir -p teamserver/resources/bofs
if [ -f teamserver/resources/bofs/manifest.json ]; then
    BOF_CHECK_OUTPUT="$(python3 - <<'PY'
import json
import os
import sys

root = "teamserver/resources/bofs"
with open(os.path.join(root, "manifest.json"), "r", encoding="utf-8") as f:
    manifest = json.load(f)

missing = []
for entry in manifest:
    name = entry.get("name", "")
    file_name = entry.get("file", "")
    if not name or not file_name:
        print("ERROR:invalid built-in BOF manifest entry")
        sys.exit(1)
    if not os.path.exists(os.path.join(root, file_name)):
        missing.append(file_name)

if missing:
    print("WARN:" + ", ".join(missing))
else:
    print("OK")
PY
)"
    case "$BOF_CHECK_OUTPUT" in
        OK)
            log_ok "built-in BOF objects ready"
            ;;
        WARN:*)
            log_warn "built-in BOF objects missing: ${BOF_CHECK_OUTPUT#WARN:}"
            ;;
        ERROR:*)
            die "${BOF_CHECK_OUTPUT#ERROR:}"
            ;;
        *)
            die "built-in BOF manifest check failed"
            ;;
    esac
else
    log_warn "teamserver/resources/bofs/manifest.json not found"
fi

log_section "resolving Go modules..."
(cd teamserver && go mod download)
log_ok "modules ready"

log_section "building teamserver..."
mkdir -p bin
(cd teamserver && go build -o ../bin/teamserver .)
log_ok "bin/teamserver"

log_section "preparing MCP HTTP signing secret..."
MCP_HOME="$HOME/.bebop"
MCP_TOKEN_FILE="$MCP_HOME/mcp.token"
mkdir -p "$MCP_HOME"
chmod 700 "$MCP_HOME" 2>/dev/null || true
if [ ! -s "$MCP_TOKEN_FILE" ]; then
    (
        umask 077
        if has_cmd openssl || install_tool_packages openssl; then
            openssl rand -hex 32 > "$MCP_TOKEN_FILE"
        else
            python3 - <<'PY' > "$MCP_TOKEN_FILE"
import secrets
print(secrets.token_hex(32))
PY
        fi
    )
fi
chmod 600 "$MCP_TOKEN_FILE"
log_ok "$MCP_TOKEN_FILE"

if [ "$SKIP_BEACON_VERIFY" = "0" ]; then
    log_section "verifying Windows beacon build..."
    rm -rf beacon/build-mingw
    (cd beacon && cmake -B build-mingw -DCMAKE_TOOLCHAIN_FILE="$PWD/mingw64.cmake" >/dev/null && cmake --build build-mingw >/dev/null)
    log_ok "beacon/build-mingw/beacon"
fi

log_section "verifying Linux beacon build..."
LINUX_BUILD_LOG="$(mktemp)"
if (cd beacon-linux && cmake -B build >"$LINUX_BUILD_LOG" 2>&1 && cmake --build build >>"$LINUX_BUILD_LOG" 2>&1); then
    rm -f "$LINUX_BUILD_LOG"
    log_ok "beacon-linux/build/beacon.elf"
else
    cat "$LINUX_BUILD_LOG" >&2
    rm -f "$LINUX_BUILD_LOG"
    log_warn "Linux beacon verification skipped or failed; teamserver can still start"
fi

if [ "$START_AFTER_BUILD" = "0" ]; then
    log_ok "ready; start with: ./bin/teamserver -host $TEAMSERVER_HOST -port $TEAMSERVER_PORT -session-port $SESSION_PORT -beacon-src $BEACON_SRC"
    exit 0
fi

log_section "starting teamserver..."
log_ok "http 0.0.0.0:$TEAMSERVER_PORT"
if [ "$SESSION_PORT" != "0" ]; then
    log_ok "session 0.0.0.0:$SESSION_PORT"
fi
exec ./bin/teamserver -host "$TEAMSERVER_HOST" -port "$TEAMSERVER_PORT" -session-port "$SESSION_PORT" -beacon-src "$BEACON_SRC"
