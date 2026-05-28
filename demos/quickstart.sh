#!/usr/bin/env bash
# demos/quickstart.sh — CLI quick-start cast.
#
# Walks through init / unlock / add / list / get / search / lock against a
# throwaway vault under /tmp. Designed to be recorded with:
#   asciinema rec demos/quickstart.cast --command="bash demos/quickstart.sh"
#
# Re-runnable: removes /tmp/vaultic_demo before starting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULTIC="$SCRIPT_DIR/../target/release/vaultic"
DEMO_VAULT=/tmp/vaultic_demo
DEMO_PASS='demo-password-123!'

PROMPT='\033[1;32m$\033[0m'

# Show a clean command line, then run the version with the temp-vault flag.
say() {
  local display="$1"
  local run="$2"
  echo -e "\n${PROMPT} ${display}"
  sleep 0.7
  eval "$run"
  sleep 0.8
}

rm -rf "$DEMO_VAULT"

clear
echo "════════════════════════════════════════════"
echo "  vaultic — local-first password manager"
echo "════════════════════════════════════════════"
sleep 1.5

say "vaultic init --name 'Demo Vault' --password '${DEMO_PASS}'" \
    "$VAULTIC --vault $DEMO_VAULT init --name 'Demo Vault' --password '${DEMO_PASS}'"

say "vaultic unlock --password '${DEMO_PASS}'" \
    "$VAULTIC --vault $DEMO_VAULT unlock --password '${DEMO_PASS}'"

say "vaultic add 'GitHub' -u 'dev@example.com' -p 'gh-secret' --tags 'dev,code'" \
    "$VAULTIC --vault $DEMO_VAULT add 'GitHub' -u 'dev@example.com' -p 'gh-secret' --tags 'dev,code'"

say "vaultic add 'AWS Console' -u 'admin@company.com' --generate --tags 'cloud,work'" \
    "$VAULTIC --vault $DEMO_VAULT add 'AWS Console' -u 'admin@company.com' --generate --tags 'cloud,work'"

say "vaultic add 'Gmail' -u 'me@gmail.com' -p 'gm-secret' --tags 'personal'" \
    "$VAULTIC --vault $DEMO_VAULT add 'Gmail' -u 'me@gmail.com' -p 'gm-secret' --tags 'personal'"

say "vaultic list" \
    "$VAULTIC --vault $DEMO_VAULT list"

say "vaultic search 'git'" \
    "$VAULTIC --vault $DEMO_VAULT --quiet list --tags dev"

say "vaultic generate --length 24" \
    "$VAULTIC --vault $DEMO_VAULT generate --length 24"

say "vaultic status" \
    "$VAULTIC --vault $DEMO_VAULT status"

say "vaultic lock" \
    "$VAULTIC --vault $DEMO_VAULT lock"

echo ""
echo "─────────────────────────────────"
echo "  done. vault: $DEMO_VAULT"
echo "─────────────────────────────────"
sleep 1
