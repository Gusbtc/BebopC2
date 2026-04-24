#!/bin/bash
set -e

AMBER='\033[38;5;214m'
GREEN='\033[38;5;77m'
RED='\033[38;5;203m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "\n${AMBER}${BOLD}BEBOP // TEAMSERVER SETUP${RESET}\n"

install_if_missing() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}[ok]${RESET} $1"
    else
        echo -e "  ${RED}[!!]${RESET} $1 not found — installing $2..."
        sudo apt install -y $2 >/dev/null 2>&1
        if command -v "$1" &>/dev/null; then
            echo -e "  ${GREEN}[ok]${RESET} $1 installed"
        else
            echo -e "  ${RED}[!!]${RESET} failed to install $2. Install manually and retry."
            exit 1
        fi
    fi
}

echo -e "${AMBER}checking dependencies...${RESET}"

if ! command -v go &>/dev/null; then
    echo -e "  ${RED}[!!]${RESET} go not found — install from https://go.dev/dl/"
    exit 1
else
    echo -e "  ${GREEN}[ok]${RESET} go"
fi

install_if_missing x86_64-w64-mingw32-gcc mingw-w64
install_if_missing nasm nasm
install_if_missing cmake cmake

echo ""
echo -e "${AMBER}resolving go modules...${RESET}"
cd teamserver
go mod tidy 2>&1 | tail -5
echo -e "  ${GREEN}[ok]${RESET} modules ready"

echo ""
echo -e "${AMBER}building teamserver...${RESET}"
mkdir -p ../bin
go build -o ../bin/teamserver .
echo -e "  ${GREEN}[ok]${RESET} bin/teamserver"

echo ""
echo -e "${GREEN}${BOLD}ready.${RESET} starting teamserver on port 8080..."
echo ""
cd ..
exec ./bin/teamserver -port 8080
