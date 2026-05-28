#!/usr/bin/env bash
# demos/tui.sh — TUI showcase. Seeds a richer vault than quickstart.sh
# (multiple types, tags, a favorite, a TOTP-bearing entry), unlocks it,
# and launches `vaultic tui` with the dracula theme.
#
# The TUI is interactive — keys you press get captured by the recording.
# Drive it however you like. A reasonable script:
#
#   - j / k or ↓ / ↑ to walk the list
#   - / then "git" then Enter to fuzzy-search
#   - Enter on an entry to open the detail view
#   - p to toggle password visibility
#   - y to copy
#   - Esc to back out
#   - q to quit
#
# Record with:
#   asciinema rec demos/tui.cast
#   ... interact with the TUI ...
#   exit            # ends the recording when the TUI returns
#
# Then:
#   asciinema upload demos/tui.cast
#
# Drop the resulting asciicast ID into the README in place of ZZZZZ.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULTIC="$SCRIPT_DIR/../target/release/vaultic"
DEMO_VAULT=/tmp/vaultic_demo_tui
DEMO_PASS='demo-password-123!'

if [ ! -x "$VAULTIC" ]; then
  echo "vaultic binary not found at $VAULTIC"
  echo "build first:  cargo build --release --bin vaultic"
  exit 1
fi

rm -rf "$DEMO_VAULT"

# Seed quietly — the recording should start with the TUI on screen,
# not a wall of "Added entry" lines.
{
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet init --name 'TUI Demo' --password "$DEMO_PASS"
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet unlock --password "$DEMO_PASS"
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'GitHub'      -u 'dev@example.com'   -p 'gh-secret'   --url 'https://github.com'    --tags 'dev,code'      --favorite
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'GitLab'      -u 'dev@example.com'   -p 'gl-secret'   --url 'https://gitlab.com'    --tags 'dev,code'
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'AWS Console' -u 'admin@company.com' --generate       --url 'https://aws.amazon.com' --tags 'cloud,work'
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'GCP'         -u 'admin@company.com' --generate       --url 'https://console.cloud.google.com' --tags 'cloud,work'
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'Gmail'       -u 'me@gmail.com'      -p 'gm-secret'   --tags 'personal'              --totp-secret 'JBSWY3DPEHPK3PXP'
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'Bank'        -u 'me'                -p 'bank-secret' --tags 'finance'
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'Netflix'     -u 'me@example.com'    -p 'nf-secret'   --tags 'personal,media'
} >/dev/null 2>&1

exec "$VAULTIC" --vault "$DEMO_VAULT" tui --theme dracula
