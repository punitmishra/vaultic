#!/usr/bin/env bash
# demos/daemon.sh — vaultic-agent + CLI bridge cast.
#
# Shows: agent starts, CLI unlock notifies the agent, CLI list/get route
# through the agent (no second decryption), agent locks on `vaultic lock`,
# graceful shutdown.
#
# Record with:
#   asciinema rec demos/daemon.cast --command="bash demos/daemon.sh"
#
# IMPORTANT: stop any user-level vaultic-agent before recording — the
# daemon binds the per-OS default socket and there's only one of those.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULTIC="$SCRIPT_DIR/../target/release/vaultic"
AGENT="$SCRIPT_DIR/../target/release/vaultic-agent"
DEMO_VAULT=/tmp/vaultic_demo_agent
DEMO_PASS='demo-password-123!'

PROMPT='\033[1;32m$\033[0m'

say() {
  local display="$1"
  local run="$2"
  echo -e "\n${PROMPT} ${display}"
  sleep 0.7
  eval "$run"
  sleep 0.8
}

# Refuse to clobber a real agent. `status` exits 0 even when the daemon
# isn't running (it just reports state), so check the output.
if "$AGENT" status 2>/dev/null | grep -q 'state:[[:space:]]*running'; then
  echo "An agent is already running on the default socket."
  echo "Stop it first:  vaultic-agent stop"
  exit 1
fi

rm -rf "$DEMO_VAULT"

# Seed the vault before the cast so we can focus on the agent flow.
# Redirected so seed output doesn't pollute the recording.
{
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet init --name 'Daemon Demo' --password "$DEMO_PASS"
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet unlock --password "$DEMO_PASS"
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'GitHub' -u 'dev@example.com' -p 'gh-secret' --tags 'dev'
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet add 'AWS' -u 'admin@company.com' -p 'aws-secret' --tags 'cloud'
  "$VAULTIC" --vault "$DEMO_VAULT" --quiet lock
} >/dev/null 2>&1

clear
echo "════════════════════════════════════════════"
echo "  vaultic-agent + CLI bridge"
echo "════════════════════════════════════════════"
sleep 1.5

say "# start the daemon in the background" \
    ":"

"$AGENT" start &
AGENT_PID=$!
trap 'kill $AGENT_PID 2>/dev/null || true' EXIT

# Wait for the socket to be ready.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  "$AGENT" status >/dev/null 2>&1 && break
  sleep 0.2
done

say "vaultic-agent status" \
    "$AGENT status"

say "vaultic unlock --password '${DEMO_PASS}'   # notifies the agent" \
    "$VAULTIC --vault $DEMO_VAULT unlock --password '${DEMO_PASS}'"

say "vaultic-agent status                       # daemon now holds the key" \
    "$AGENT status"

say "vaultic list                               # routes through the agent" \
    "$VAULTIC --vault $DEMO_VAULT list"

say "vaultic get 'GitHub'                       # also via the agent" \
    "$VAULTIC --vault $DEMO_VAULT get 'GitHub'"

say "vaultic lock                               # clears agent + session" \
    "$VAULTIC --vault $DEMO_VAULT lock"

say "vaultic-agent status                       # locked again" \
    "$AGENT status"

say "vaultic-agent stop                         # graceful shutdown" \
    "$AGENT stop"

# Make sure the background process is actually gone before the recording ends.
wait "$AGENT_PID" 2>/dev/null || true

echo ""
echo "─────────────────────────────────"
echo "  done."
echo "─────────────────────────────────"
sleep 1
