#!/bin/bash
# Demo: Vaultic Quick Start
# This script demonstrates the core workflow

# Get script directory and set up vaultic path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULTIC="$SCRIPT_DIR/../target/release/vaultic"
DEMO_VAULT=/tmp/vaultic_demo

# Clean up demo vault
rm -rf $DEMO_VAULT

# Typing simulation - shows clean command but runs with full path
type_cmd() {
    local display_cmd="$1"
    local run_cmd="$2"
    echo -e "\n\033[1;32m$\033[0m $display_cmd"
    sleep 0.5
    eval "$run_cmd"
    sleep 1
}

clear
echo "========================================"
echo "   Vaultic - Password Manager Demo"
echo "========================================"
echo ""
sleep 2

echo "# First, let's initialize a new vault"
type_cmd "vaultic init --name 'My Vault' --password 'demo-password-123!'" \
         "$VAULTIC --vault $DEMO_VAULT init --name 'My Vault' --password 'demo-password-123!'"

echo ""
echo "# Unlock the vault (creates a 15-minute session)"
type_cmd "vaultic unlock --password 'demo-password-123!'" \
         "$VAULTIC --vault $DEMO_VAULT unlock --password 'demo-password-123!'"

echo ""
echo "# Add some password entries"
type_cmd "vaultic add 'GitHub' -u 'developer@example.com' -p 'gh-secret-token' --url 'https://github.com' --tags 'dev,code'" \
         "$VAULTIC --vault $DEMO_VAULT add 'GitHub' -u 'developer@example.com' -p 'gh-secret-token' --url 'https://github.com' --tags 'dev,code'"

echo ""
type_cmd "vaultic add 'AWS Console' -u 'admin@company.com' --generate --url 'https://aws.amazon.com' --tags 'cloud,work'" \
         "$VAULTIC --vault $DEMO_VAULT add 'AWS Console' -u 'admin@company.com' --generate --url 'https://aws.amazon.com' --tags 'cloud,work'"

echo ""
echo "# List all entries"
type_cmd "vaultic list" \
         "$VAULTIC --vault $DEMO_VAULT list"

echo ""
echo "# Check vault status"
type_cmd "vaultic status" \
         "$VAULTIC --vault $DEMO_VAULT status"

echo ""
echo "# Lock the vault when done"
type_cmd "vaultic lock" \
         "$VAULTIC --vault $DEMO_VAULT lock"

echo ""
echo "# Verify it's locked"
type_cmd "vaultic status" \
         "$VAULTIC --vault $DEMO_VAULT status"

echo ""
echo "========================================"
echo "   Demo Complete!"
echo "========================================"
sleep 2
