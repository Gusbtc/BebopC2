#!/bin/bash
set -e

AMBER='\033[38;5;214m'
GREEN='\033[38;5;77m'
RED='\033[38;5;203m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "\n${AMBER}${BOLD}BEBOP // OPERATOR CLIENT SETUP${RESET}\n"

echo -e "${AMBER}checking dependencies...${RESET}"

if ! command -v go &>/dev/null; then
    echo -e "  ${RED}[!!]${RESET} go not found — install from https://go.dev/dl/"
    exit 1
else
    echo -e "  ${GREEN}[ok]${RESET} go"
fi

echo ""
echo -e "${AMBER}resolving go modules...${RESET}"
cd operator-client
go mod tidy 2>&1 | tail -5
echo -e "  ${GREEN}[ok]${RESET} modules ready"

echo ""
echo -e "${AMBER}building operator client...${RESET}"
mkdir -p ../bin
go build -o ../bin/operator-client .
echo -e "  ${GREEN}[ok]${RESET} bin/operator-client"

echo ""
echo -e "${GREEN}${BOLD}ready.${RESET} starting operator client on port 9090..."
echo ""
cd ..
exec ./bin/operator-client -port 9090
