#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    printf 'check failed: %s\n' "$*" >&2
    exit 1
}

[ -f "$ROOT_DIR/scripts/setup-common.sh" ] || fail "scripts/setup-common.sh missing"

bash -n "$ROOT_DIR/scripts/setup-common.sh"
bash -n "$ROOT_DIR/setup-teamserver.sh"
bash -n "$ROOT_DIR/setup-operator.sh"

"$ROOT_DIR/setup-teamserver.sh" --help | grep -q -- '--no-start' || fail "teamserver help missing --no-start"
"$ROOT_DIR/setup-teamserver.sh" --help | grep -q -- '--skip-deps' || fail "teamserver help missing --skip-deps"
"$ROOT_DIR/setup-teamserver.sh" --help | grep -q -- '--skip-dotnet' || fail "teamserver help missing --skip-dotnet"
"$ROOT_DIR/setup-teamserver.sh" --help | grep -q -- '--host' || fail "teamserver help missing --host"
"$ROOT_DIR/setup-teamserver.sh" --help | grep -q -- '--port' || fail "teamserver help missing --port"
"$ROOT_DIR/setup-teamserver.sh" --help | grep -q -- '--session-port' || fail "teamserver help missing --session-port"
"$ROOT_DIR/setup-operator.sh" --help | grep -q -- '--no-start' || fail "operator help missing --no-start"
"$ROOT_DIR/setup-operator.sh" --help | grep -q -- '--skip-deps' || fail "operator help missing --skip-deps"
"$ROOT_DIR/setup-operator.sh" --help | grep -q -- '--host' || fail "operator help missing --host"
"$ROOT_DIR/setup-operator.sh" --help | grep -q -- '--port' || fail "operator help missing --port"
if "$ROOT_DIR/setup-operator.sh" --help | grep -q -- '--teamserver'; then
    fail "operator setup must not expose --teamserver"
fi
if grep -Eq 'print\("  \[(ok|warn|!!)\]' "$ROOT_DIR/setup-teamserver.sh" "$ROOT_DIR/setup-operator.sh"; then
    fail "setup scripts must use colored log helpers instead of raw status prints"
fi

SETUP_DRY_RUN=1 "$ROOT_DIR/setup-teamserver.sh" --skip-deps --skip-dotnet --no-start --host 10.10.10.10 --port 8081 --session-port 4444 >/dev/null
SETUP_DRY_RUN=1 "$ROOT_DIR/setup-operator.sh" --skip-deps --no-start --host 0.0.0.0 --port 9091 >/dev/null

printf 'setup script checks passed\n'
