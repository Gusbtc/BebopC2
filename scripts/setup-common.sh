#!/usr/bin/env bash

AMBER=${AMBER:-'\033[38;5;214m'}
GREEN=${GREEN:-'\033[38;5;77m'}
RED=${RED:-'\033[38;5;203m'}
GRAY=${GRAY:-'\033[38;5;245m'}
BOLD=${BOLD:-'\033[1m'}
RESET=${RESET:-'\033[0m'}

if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    AMBER=''
    GREEN=''
    RED=''
    GRAY=''
    BOLD=''
    RESET=''
fi

: "${SETUP_DRY_RUN:=0}"
: "${SETUP_SKIP_DEPS:=0}"
: "${GO_BOOTSTRAP_VERSION:=1.25.4}"

PKG_MANAGER=''
PKG_UPDATED=0

setup_root_dir() {
    local source_dir
    source_dir="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
    cd "$source_dir"
    pwd
}

log_header() {
    printf '\n%b%b%s%b\n\n' "$AMBER" "$BOLD" "$1" "$RESET"
}

log_section() {
    printf '\n%b%s%b\n' "$AMBER" "$1" "$RESET"
}

log_ok() {
    printf '  %b[ok]%b %s\n' "$GREEN" "$RESET" "$1"
}

log_warn() {
    printf '  %b[warn]%b %s\n' "$AMBER" "$RESET" "$1"
}

log_err() {
    printf '  %b[!!]%b %s\n' "$RED" "$RESET" "$1" >&2
}

die() {
    log_err "$1"
    exit 1
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

run_quiet() {
    "$@" >/dev/null 2>&1
}

need_root_prefix() {
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi
    if has_cmd sudo; then
        printf 'sudo'
        return 0
    fi
    die "root privileges required. Install sudo or run setup as root."
}

detect_pkg_manager() {
    if [ -n "$PKG_MANAGER" ]; then
        printf '%s\n' "$PKG_MANAGER"
        return 0
    fi
    if has_cmd apt-get; then PKG_MANAGER='apt'
    elif has_cmd dnf; then PKG_MANAGER='dnf'
    elif has_cmd yum; then PKG_MANAGER='yum'
    elif has_cmd pacman; then PKG_MANAGER='pacman'
    elif has_cmd zypper; then PKG_MANAGER='zypper'
    elif has_cmd apk; then PKG_MANAGER='apk'
    else PKG_MANAGER='unknown'
    fi
    printf '%s\n' "$PKG_MANAGER"
}

pkg_update_once() {
    local pm root
    pm="$(detect_pkg_manager)"
    [ "$PKG_UPDATED" -eq 0 ] || return 0
    root="$(need_root_prefix)"
    case "$pm" in
        apt) DEBIAN_FRONTEND=noninteractive $root apt-get update -y >/dev/null ;;
        pacman) $root pacman -Sy --noconfirm >/dev/null ;;
        zypper) $root zypper --non-interactive refresh >/dev/null ;;
        apk) $root apk update >/dev/null ;;
        dnf|yum|unknown) ;;
    esac
    PKG_UPDATED=1
}

install_packages() {
    local packages="$*"
    local pm root
    [ -n "$packages" ] || return 1
    if [ "$SETUP_SKIP_DEPS" = "1" ]; then
        return 1
    fi
    pm="$(detect_pkg_manager)"
    [ "$pm" != "unknown" ] || return 1
    root="$(need_root_prefix)"
    pkg_update_once
    case "$pm" in
        apt) DEBIAN_FRONTEND=noninteractive $root apt-get install -y $packages >/dev/null ;;
        dnf) $root dnf install -y $packages >/dev/null ;;
        yum) $root yum install -y $packages >/dev/null ;;
        pacman) $root pacman -S --needed --noconfirm $packages >/dev/null ;;
        zypper) $root zypper --non-interactive install -y $packages >/dev/null ;;
        apk) $root apk add --no-cache $packages >/dev/null ;;
    esac
}

packages_for_tool() {
    local key="$1" pm
    pm="$(detect_pkg_manager)"
    case "$key:$pm" in
        base:apt) printf 'curl ca-certificates tar gzip build-essential pkg-config' ;;
        base:dnf|base:yum) printf 'curl ca-certificates tar gzip gcc gcc-c++ make pkgconf-pkg-config' ;;
        base:pacman) printf 'curl ca-certificates tar gzip base-devel pkgconf' ;;
        base:zypper) printf 'curl ca-certificates tar gzip gcc gcc-c++ make pkg-config' ;;
        base:apk) printf 'curl ca-certificates tar gzip build-base pkgconf' ;;
        go:apt) printf 'golang-go' ;;
        go:dnf|go:yum) printf 'golang' ;;
        go:pacman|go:apk) printf 'go' ;;
        go:zypper) printf 'go' ;;
        mingw:apt) printf 'mingw-w64' ;;
        mingw:dnf|mingw:yum) printf 'mingw64-gcc' ;;
        mingw:pacman) printf 'mingw-w64-gcc' ;;
        mingw:zypper) printf 'mingw64-cross-gcc' ;;
        mingw:apk) printf 'mingw-w64-gcc' ;;
        nasm:*) printf 'nasm' ;;
        cmake:*) printf 'cmake' ;;
        musl:apt) printf 'musl-tools' ;;
        musl:dnf|musl:yum) printf 'musl-gcc' ;;
        musl:pacman) printf 'musl' ;;
        musl:zypper) printf 'musl-devel' ;;
        musl:apk) printf 'musl-dev gcc' ;;
        mbedtls:apt) printf 'libmbedtls-dev' ;;
        mbedtls:dnf|mbedtls:yum) printf 'mbedtls-devel' ;;
        mbedtls:pacman) printf 'mbedtls' ;;
        mbedtls:zypper) printf 'mbedtls-devel' ;;
        mbedtls:apk) printf 'mbedtls-dev' ;;
        python:apt|python:dnf|python:yum|python:pacman|python:zypper) printf 'python3' ;;
        python:apk) printf 'python3 py3-pip' ;;
        donut:apt) printf 'python3-donut' ;;
        dotnet:apt|dotnet:dnf|dotnet:yum|dotnet:pacman|dotnet:zypper|dotnet:apk) printf 'dotnet-sdk-8.0' ;;
        openssl:*) printf 'openssl' ;;
        *) return 1 ;;
    esac
}

install_tool_packages() {
    local key="$1"
    local packages
    packages="$(packages_for_tool "$key" || true)"
    [ -n "$packages" ] || return 1
    install_packages $packages
}

ensure_command() {
    local cmd="$1" key="$2" label="$3"
    if has_cmd "$cmd"; then
        log_ok "$label"
        return 0
    fi
    log_warn "$label not found; installing"
    install_tool_packages "$key" || die "$label not found. Install it manually and retry."
    has_cmd "$cmd" || die "$label install finished but command '$cmd' is still unavailable."
    log_ok "$label installed"
}

version_ge() {
    local actual="$1" required="$2"
    local a_major a_minor a_patch r_major r_minor r_patch rest
    actual="${actual#go}"
    required="${required#go}"
    a_major="${actual%%.*}"
    rest="${actual#*.}"
    a_minor="${rest%%.*}"
    rest="${rest#*.}"
    a_patch="${rest%%[^0-9]*}"
    r_major="${required%%.*}"
    rest="${required#*.}"
    r_minor="${rest%%.*}"
    rest="${rest#*.}"
    r_patch="${rest%%[^0-9]*}"
    a_patch="${a_patch:-0}"
    r_patch="${r_patch:-0}"
    [[ "$a_major" =~ ^[0-9]+$ && "$a_minor" =~ ^[0-9]+$ && "$a_patch" =~ ^[0-9]+$ ]] || return 1
    [[ "$r_major" =~ ^[0-9]+$ && "$r_minor" =~ ^[0-9]+$ && "$r_patch" =~ ^[0-9]+$ ]] || return 1
    if [ "$a_major" -gt "$r_major" ]; then return 0; fi
    if [ "$a_major" -lt "$r_major" ]; then return 1; fi
    if [ "$a_minor" -gt "$r_minor" ]; then return 0; fi
    if [ "$a_minor" -lt "$r_minor" ]; then return 1; fi
    [ "$a_patch" -ge "$r_patch" ]
}

go_version() {
    go env GOVERSION 2>/dev/null | sed 's/^go//' || go version | awk '{print $3}' | sed 's/^go//'
}

go_ok() {
    local min_version="$1" current
    has_cmd go || return 1
    current="$(go_version)"
    version_ge "$current" "$min_version"
}

install_go_tarball() {
    local arch go_arch url dest archive profile_line
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) go_arch='amd64' ;;
        aarch64|arm64) go_arch='arm64' ;;
        armv6l) go_arch='armv6l' ;;
        *) die "unsupported Go bootstrap architecture: $arch" ;;
    esac
    ensure_command curl base curl
    ensure_command tar base tar
    dest="$HOME/.local/bebop"
    archive="/tmp/go${GO_BOOTSTRAP_VERSION}.linux-${go_arch}.tar.gz"
    url="https://go.dev/dl/go${GO_BOOTSTRAP_VERSION}.linux-${go_arch}.tar.gz"
    mkdir -p "$dest"
    log_warn "installing Go ${GO_BOOTSTRAP_VERSION} under $dest"
    curl -fsSL "$url" -o "$archive"
    rm -rf "$dest/go"
    tar -C "$dest" -xzf "$archive"
    export PATH="$dest/go/bin:$PATH"
    profile_line='export PATH="$HOME/.local/bebop/go/bin:$PATH"'
    add_profile_line "$profile_line" "Go toolchain installed by Bebop setup"
}

ensure_go() {
    local min_version="$1"
    if go_ok "$min_version"; then
        log_ok "go $(go_version)"
        return 0
    fi
    if has_cmd go; then
        log_warn "Go $(go_version) found; Go $min_version+ required"
    else
        log_warn "go not found; installing"
    fi
    install_tool_packages go || true
    if go_ok "$min_version"; then
        log_ok "go $(go_version)"
        return 0
    fi
    if [ "$SETUP_SKIP_DEPS" = "1" ]; then
        die "Go $min_version+ required. Install Go or rerun without --skip-deps."
    fi
    install_go_tarball
    go_ok "$min_version" || die "Go $min_version+ install failed."
    log_ok "go $(go_version)"
}

add_profile_line() {
    local line="$1" comment="$2" profile
    for profile in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$profile" ] && ! grep -Fq "$line" "$profile"; then
            printf '\n# %s\n%s\n' "$comment" "$line" >> "$profile"
        fi
    done
}

use_dotnet_path() {
    local candidate dotnet_dir
    for candidate in \
        "${DOTNET_ROOT:+$DOTNET_ROOT/dotnet}" \
        "$HOME/.dotnet/dotnet" \
        "/usr/share/dotnet/dotnet" \
        "/usr/local/bin/dotnet" \
        "/usr/bin/dotnet"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            dotnet_dir="$(dirname "$candidate")"
            export DOTNET_ROOT="$dotnet_dir"
            export PATH="$dotnet_dir:$PATH"
            return 0
        fi
    done
    return 1
}

dotnet_ok() {
    local sdk_version major
    has_cmd dotnet || use_dotnet_path || return 1
    while IFS= read -r sdk_version; do
        major="${sdk_version%%.*}"
        [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 8 ] && return 0
    done < <(dotnet --list-sdks 2>/dev/null)
    major="$(dotnet --version 2>/dev/null | cut -d. -f1 || true)"
    [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 8 ]
}

ensure_dotnet() {
    if dotnet_ok; then
        log_ok "dotnet"
        return 0
    fi
    [ "$SETUP_SKIP_DEPS" = "1" ] && return 1
    log_warn ".NET SDK 8.0+ not found; installing"
    install_tool_packages dotnet || true
    if dotnet_ok; then
        log_ok "dotnet installed"
        return 0
    fi
    ensure_command curl base curl
    mkdir -p "$HOME/.dotnet"
    curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
    bash /tmp/dotnet-install.sh --channel 8.0 --install-dir "$HOME/.dotnet" >/dev/null
    export DOTNET_ROOT="$HOME/.dotnet"
    export PATH="$HOME/.dotnet:$PATH"
    add_profile_line 'export DOTNET_ROOT="$HOME/.dotnet"; export PATH="$HOME/.dotnet:$PATH"' ".NET SDK installed by Bebop setup"
    dotnet_ok
}

mbedtls_ok() {
    local triplet
    [ -f /usr/include/mbedtls/aes.h ] || [ -f /usr/local/include/mbedtls/aes.h ] || return 1
    compgen -G "/usr/lib/*/libmbedtls.so*" >/dev/null && return 0
    compgen -G "/usr/lib/*/libmbedtls.a" >/dev/null && return 0
    compgen -G "/usr/local/lib/libmbedtls.so*" >/dev/null && return 0
    compgen -G "/usr/local/lib/libmbedtls.a" >/dev/null && return 0
    triplet="$(gcc -dumpmachine 2>/dev/null || true)"
    [ -n "$triplet" ] && compgen -G "/usr/lib/$triplet/libmbedtls.*" >/dev/null && return 0
    return 1
}

ensure_mbedtls() {
    if mbedtls_ok; then
        log_ok "mbedTLS development files"
        return 0
    fi
    log_warn "mbedTLS development files not found; installing"
    install_tool_packages mbedtls || die "mbedTLS development files not found. Install libmbedtls-dev/mbedtls-devel/mbedtls-dev."
    mbedtls_ok || die "mbedTLS install finished but headers/libs are still unavailable."
    log_ok "mbedTLS development files installed"
}

ensure_donut_module() {
    ensure_command python3 python python3
    if python3 -c "import donut" >/dev/null 2>&1; then
        log_ok "python3-donut"
        return 0
    fi
    log_warn "python3-donut not found; trying distro package"
    install_tool_packages donut || true
    if python3 -c "import donut" >/dev/null 2>&1; then
        log_ok "python3-donut installed"
        return 0
    fi
    log_warn "python3-donut unavailable on this distro; execute-assembly shellcode output will be disabled until installed"
    return 0
}

prepare_gocache() {
    export GOCACHE="${GOCACHE:-/tmp/bebop-gocache}"
    mkdir -p "$GOCACHE"
}

ensure_base_tools() {
    ensure_command curl base curl
    ensure_command tar base tar
}

dry_run_exit_if_requested() {
    [ "$SETUP_DRY_RUN" = "1" ] || return 0
    log_warn "dry run enabled; parsed options only"
    exit 0
}
