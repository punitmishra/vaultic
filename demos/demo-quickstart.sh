#!/bin/bash
# Demo: Vaultic Quick Start
# This script demonstrates the core workflow

# Set up demo environment
export VAULTIC_HOME=/tmp/vaultic_demo
rm -rf $VAULTIC_HOME

# Typing simulation
type_cmd() {
    echo -e "\n\033[1;32m$\033[0m $1"
    sleep 0.5
    eval "$1"
    sleep 1
}

clear
echo "========================================"
echo "   Vaultic - Password Manager Demo"
echo "========================================"
echo ""
sleep 2

echo "# First, let's initialize a new vault"
type_cmd "vaultic init --name 'My Vault' --password 'demo-password-123!'"

echo ""
echo "# Unlock the vault (creates a 15-minute session)"
type_cmd "vaultic unlock --password 'demo-password-123!'"

echo ""
echo "# Add some password entries"
type_cmd "vaultic add 'GitHub' -u 'developer@example.com' -p 'gh-secret-token' --url 'https://github.com' --tags 'dev,code'"

echo ""
type_cmd "vaultic add 'AWS Console' -u 'admin@company.com' --generate --url 'https://aws.amazon.com' --tags 'cloud,work'"

echo ""
echo "# List all entries"
type_cmd "vaultic list"

echo ""
echo "# Check vault status"
type_cmd "vaultic status"

echo ""
echo "# Lock the vault when done"
type_cmd "vaultic lock"

echo ""
echo "# Verify it's locked"
type_cmd "vaultic status"

echo ""
echo "========================================"
echo "   Demo Complete!"
echo "========================================"
sleep 2
