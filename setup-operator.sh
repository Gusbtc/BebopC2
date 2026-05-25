#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/setup-common.sh
source "$ROOT_DIR/scripts/setup-common.sh"
cd "$ROOT_DIR"

OPERATOR_HOST="127.0.0.1"
OPERATOR_PORT="9090"
START_AFTER_BUILD=1

usage() {
    cat <<'EOF'
BEBOP // OPERATOR CLIENT SETUP

Usage:
  ./setup-operator.sh [options]

Network:
  --host <ip|name>          Operator client bind host (default: 127.0.0.1)
  --port <port>             Operator client web UI port (default: 9090)

Setup:
  --skip-deps               Do not install missing system dependencies
  --no-start                Build only; do not start operator client
  --help                    Show this help

Examples:
  ./setup-operator.sh --host 0.0.0.0 --port 9090
  ./setup-operator.sh --port 9443
EOF
}

require_port() {
    local name="$1" value="$2"
    [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be a number"
    [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || die "$name must be between 1 and 65535"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --host)
            [ "$#" -ge 2 ] || die "--host requires a value"
            OPERATOR_HOST="$2"
            shift 2
            ;;
        --port)
            [ "$#" -ge 2 ] || die "--port requires a value"
            OPERATOR_PORT="$2"
            shift 2
            ;;
        --skip-deps)
            SETUP_SKIP_DEPS=1
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

require_port "--port" "$OPERATOR_PORT"
[ -n "$OPERATOR_HOST" ] || die "--host cannot be empty"

log_header "BEBOP // OPERATOR CLIENT SETUP"
printf '  %bbind host%b  %s\n' "$GRAY" "$RESET" "$OPERATOR_HOST"
printf '  %bweb port%b   %s\n' "$GRAY" "$RESET" "$OPERATOR_PORT"

dry_run_exit_if_requested

prepare_gocache

log_section "checking dependencies..."
ensure_base_tools
ensure_go "1.22.0"

log_section "resolving Go modules..."
(cd operator-client && go mod download)
log_ok "modules ready"

log_section "building operator client..."
mkdir -p bin
(cd operator-client && go build -o ../bin/operator-client .)
log_ok "bin/operator-client"

if [ "$START_AFTER_BUILD" = "0" ]; then
    log_ok "ready; start with: ./bin/operator-client -host $OPERATOR_HOST -port $OPERATOR_PORT"
    exit 0
fi

log_section "starting operator client..."
log_ok "web $OPERATOR_HOST:$OPERATOR_PORT"
exec ./bin/operator-client -host "$OPERATOR_HOST" -port "$OPERATOR_PORT"
