#!/bin/bash
# Demo: Password Generation
# Shows various password generation options

# Get script directory and set up vaultic path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULTIC="$SCRIPT_DIR/../target/release/vaultic"

clear
echo "========================================"
echo "   Vaultic - Password Generation"
echo "========================================"
echo ""
sleep 1

echo "# Generate a default 20-character password"
echo -e "\033[1;32m$\033[0m vaultic generate"
sleep 0.5
$VAULTIC generate
sleep 2

echo ""
echo "# Generate a 32-character password"
echo -e "\033[1;32m$\033[0m vaultic generate --length 32"
sleep 0.5
$VAULTIC generate --length 32
sleep 2

echo ""
echo "# Generate without symbols (alphanumeric only)"
echo -e "\033[1;32m$\033[0m vaultic generate --no-symbols"
sleep 0.5
$VAULTIC generate --no-symbols
sleep 2

echo ""
echo "# Generate a short PIN-style code"
echo -e "\033[1;32m$\033[0m vaultic generate --length 6 --no-uppercase --no-lowercase --no-symbols"
sleep 0.5
$VAULTIC generate --length 6 --no-uppercase --no-lowercase --no-symbols
sleep 2

echo ""
echo "========================================"
echo "   All passwords include entropy analysis!"
echo "========================================"
sleep 2
