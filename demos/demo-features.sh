#!/bin/bash
# Demo: Vaultic Full Features Showcase
# Demonstrates all major features of Vaultic

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULTIC="$SCRIPT_DIR/../target/release/vaultic"
DEMO_VAULT=/tmp/vaultic_features_demo

# Clean up
rm -rf $DEMO_VAULT

# Typing simulation
type_cmd() {
    local display_cmd="$1"
    local run_cmd="$2"
    echo -e "\n\033[1;32m$\033[0m $display_cmd"
    sleep 0.3
    eval "$run_cmd"
    sleep 0.8
}

clear
echo "╔════════════════════════════════════════════╗"
echo "║     Vaultic - Full Features Demo           ║"
echo "╚════════════════════════════════════════════╝"
sleep 2

echo ""
echo "━━━ 1. VAULT INITIALIZATION ━━━"
type_cmd "vaultic init --name 'Demo Vault' --password 'SecureP@ss123!'" \
         "$VAULTIC --vault $DEMO_VAULT init --name 'Demo Vault' --password 'SecureP@ss123!'"

type_cmd "vaultic unlock --password 'SecureP@ss123!'" \
         "$VAULTIC --vault $DEMO_VAULT unlock --password 'SecureP@ss123!'"

echo ""
echo "━━━ 2. ADDING ENTRIES WITH CUSTOM FIELDS ━━━"
type_cmd "vaultic add 'GitHub' -u 'dev@example.com' -p 'gh-token-123' --url 'https://github.com' --tags 'dev,code' --favorite" \
         "$VAULTIC --vault $DEMO_VAULT add 'GitHub' -u 'dev@example.com' -p 'gh-token-123' --url 'https://github.com' --tags 'dev,code' --favorite"

type_cmd "vaultic add 'AWS Console' -u 'admin@company.com' --generate --tags 'cloud,work' --field 'Account ID=123456789' --notes 'Production account'" \
         "$VAULTIC --vault $DEMO_VAULT add 'AWS Console' -u 'admin@company.com' --generate --tags 'cloud,work' --field 'Account ID=123456789' --notes 'Production account'"

type_cmd "vaultic add 'Personal Gmail' -u 'user@gmail.com' -p 'weak123' --tags 'personal,email'" \
         "$VAULTIC --vault $DEMO_VAULT add 'Personal Gmail' -u 'user@gmail.com' -p 'weak123' --tags 'personal,email'"

type_cmd "vaultic add 'Bank Portal' -u 'john.doe' --generate --tags 'finance' --favorite --field 'Security Q=Mothers maiden name'" \
         "$VAULTIC --vault $DEMO_VAULT add 'Bank Portal' -u 'john.doe' --generate --tags 'finance' --favorite --field 'Security Q=Mothers maiden name'"

echo ""
echo "━━━ 3. LISTING & FILTERING ━━━"
type_cmd "vaultic list" \
         "$VAULTIC --vault $DEMO_VAULT list"

type_cmd "vaultic list --favorites" \
         "$VAULTIC --vault $DEMO_VAULT list --favorites"

type_cmd "vaultic list --tags 'work,cloud'" \
         "$VAULTIC --vault $DEMO_VAULT list --tags 'work,cloud'"

echo ""
echo "━━━ 4. PASSWORD GENERATION ━━━"
type_cmd "vaultic generate --length 24 --symbols" \
         "$VAULTIC --vault $DEMO_VAULT generate --length 24 --symbols"

echo ""
echo "━━━ 5. VAULT HEALTH CHECK ━━━"
type_cmd "vaultic health" \
         "$VAULTIC --vault $DEMO_VAULT health"

type_cmd "vaultic health --verbose" \
         "$VAULTIC --vault $DEMO_VAULT health --verbose"

echo ""
echo "━━━ 6. BATCH OPERATIONS ━━━"
type_cmd "vaultic batch tag --filter 'GitHub' --add 'important'" \
         "$VAULTIC --vault $DEMO_VAULT batch tag --filter 'GitHub' --add 'important'"

type_cmd "vaultic list" \
         "$VAULTIC --vault $DEMO_VAULT list"

echo ""
echo "━━━ 7. VAULT STATUS ━━━"
type_cmd "vaultic status" \
         "$VAULTIC --vault $DEMO_VAULT status"

echo ""
echo "━━━ 8. LOCK VAULT ━━━"
type_cmd "vaultic lock" \
         "$VAULTIC --vault $DEMO_VAULT lock"

type_cmd "vaultic status" \
         "$VAULTIC --vault $DEMO_VAULT status"

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║           Demo Complete! 🎉                ║"
echo "╚════════════════════════════════════════════╝"
sleep 2
