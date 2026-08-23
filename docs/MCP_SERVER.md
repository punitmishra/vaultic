# Vaultic MCP Server

The `vaultic-mcp` binary implements the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), allowing AI assistants like Claude Code to securely access credentials from your Vaultic vault without you having to paste secrets in chat.

## Architecture

```
┌─────────────┐     MCP/stdio      ┌─────────────┐    Unix socket    ┌──────────────┐
│ Claude Code │ ◄────────────────► │ vaultic-mcp │ ◄────────────────► │ vaultic-agent│
└─────────────┘                    └─────────────┘                    └──────────────┘
                                                                             │
                                                                             ▼
                                                                      ┌──────────────┐
                                                                      │ Encrypted    │
                                                                      │ Vault (sled) │
                                                                      └──────────────┘
```

## Security Model

1. **Pre-unlocked vault**: The vault must be unlocked via `vaultic unlock` before using the MCP server. No passwords are transmitted over the MCP protocol.

2. **User consent**: Secret-access tools (`get_password`, `get_credential`, `get_totp`) prompt the user on the **controlling terminal** (`/dev/tty`) before revealing credentials — never on stdin/stdout, which carry the MCP protocol. If `vaultic-mcp` has no controlling terminal (for example, it was launched by a GUI MCP host), it **fails closed**: the secret tool returns a "consent unavailable" error rather than leaking the credential. Run it from a terminal, or use `--no-consent` in a trusted, non-interactive environment. The AI can never access a secret without explicit approval.

3. **Local-only**: All credentials stay on your machine. The MCP server communicates with the local `vaultic-agent` daemon — nothing is sent to AI servers.

4. **Rate limiting**: Credential disclosures are rate-limited to 10 per minute to blunt enumeration. Only **consented disclosures** count — not-found lookups, malformed requests, and denials don't consume the budget.

## Setup

### Prerequisites

1. Install Vaultic (all binaries):
   ```bash
   cargo install --path .
   ```

2. Initialize and unlock your vault:
   ```bash
   vaultic init -n "My Vault"
   vaultic unlock
   ```

3. Start the agent daemon:
   ```bash
   vaultic-agent start &
   ```

### Claude Code Configuration

Add Vaultic to your Claude Code MCP servers configuration:

**For Claude Code CLI** (`~/.claude/settings.json`):
```json
{
  "mcpServers": {
    "vaultic": {
      "command": "vaultic-mcp"
    }
  }
}
```

**For Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):
```json
{
  "mcpServers": {
    "vaultic": {
      "command": "/path/to/vaultic-mcp"
    }
  }
}
```

### Verify Setup

After configuring, restart Claude Code. You can verify the connection by asking:

> "What's my vault status?"

Claude should be able to call the `vault_status` tool and report whether your vault is locked or unlocked.

## Available Tools

### No Consent Required

These tools don't reveal secrets and can be called without user approval:

| Tool | Description |
|------|-------------|
| `vault_status` | Check if vault is locked/unlocked, see entry count and session expiry |
| `list_entries` | List all entries with metadata (name, username, URL, tags) but no passwords |
| `search_entries` | Fuzzy search entries by name, username, URL, or tags |

### Requires User Consent

These tools reveal secrets and will prompt for approval:

| Tool | Description |
|------|-------------|
| `get_password` | Retrieve the password for an entry |
| `get_credential` | Get full credential (username + password + URL) |
| `get_totp` | Get the current TOTP code and time remaining |

When Claude calls one of these tools, you'll see a consent prompt on the
terminal where `vaultic-mcp` is running (its controlling terminal, `/dev/tty`):

```
┌─────────────────────────────────────────────────────────────┐
│  VAULTIC: AI Credential Access Request                      │
├─────────────────────────────────────────────────────────────┤
│  Action: get_password                                        │
│  Entry:  GitHub                                              │
└─────────────────────────────────────────────────────────────┘
Allow access? [y/N]: 
```

Type `y` to approve or `n` (or just press Enter) to deny.

> **No terminal?** Consent needs a controlling terminal because stdin/stdout
> are reserved for the MCP protocol. If you launch `vaultic-mcp` from a GUI
> MCP host (no TTY), secret tools fail closed with a "consent unavailable"
> error — unless the entry is pre-authorized in the consent-policy config
> (below). Otherwise launch it from a terminal or run it with `--no-consent`
> in a trusted environment. A protocol-native approval flow (MCP elicitation)
> is on the roadmap — see [`ROADMAP.md`](../ROADMAP.md).

### Pre-authorizing entries (consent policy)

For unattended or GUI-host use, you can pre-authorize specific entries so the
AI may read them without an interactive prompt. Create a TOML config at
`~/.config/vaultic/mcp.toml` (or pass `--config <path>`):

```toml
[consent]
# Entry names (case-insensitive, exact match) the AI may read without a prompt.
auto_approve_names = ["GitHub CI", "Deploy Bot"]
# Any entry carrying one of these tags is auto-approved.
auto_approve_tags = ["ai-ok", "automation"]
```

- With **no config** (the default), nothing is pre-authorized — every secret
  access prompts on the terminal, or fails closed without one.
- A matching entry is granted **without a prompt**, and the disclosure is
  logged to stderr (`auto-approved get_password for 'GitHub CI' ...`) so you
  can see what the AI accessed.
- Non-matching entries still prompt (or fail closed).
- `--no-consent` overrides everything and approves all access; don't combine
  it with untrusted clients.

**Security tradeoff:** auto-approve swaps the per-use prompt for standing
authorization. Only list entries you're comfortable an AI reading unattended —
tag the handful of CI/automation credentials you want exposed (e.g. `ai-ok`)
and leave everything else prompt-gated.

## Usage Examples

### Finding Credentials

Ask Claude to find credentials:

> "What credentials do I have for AWS?"

Claude will use `search_entries` to find matching entries.

### Logging In

Ask Claude to help you log in:

> "Help me log in to my GitHub account"

Claude will:
1. Use `search_entries` to find GitHub entries
2. Use `get_credential` to retrieve username/password (with your consent)
3. Help you complete the login

### Getting TOTP Codes

> "What's the current TOTP code for my AWS account?"

Claude will use `get_totp` to retrieve the current code and tell you how many seconds until it expires.

## Command-Line Options

```
vaultic-mcp [OPTIONS]

Options:
      --no-consent       Disable user consent prompts (WARNING: use only in trusted environments)
      --socket <PATH>    Custom socket path for vaultic-agent
      --config <PATH>    Consent-policy config (TOML); defaults to ~/.config/vaultic/mcp.toml if present
  -v, --verbose          Enable debug logging to stderr
  -h, --help             Print help
  -V, --version          Print version
```

### Disabling Consent (Advanced)

In fully trusted, non-interactive environments (e.g., automated testing), you can disable consent prompts:

```bash
vaultic-mcp --no-consent
```

**Warning**: This allows the AI to access any credential without asking. Only use this in secure, isolated environments.

## Troubleshooting

### "Vaultic agent is not running"

Start the daemon:
```bash
vaultic-agent start
```

### "Vault is locked"

Unlock your vault:
```bash
vaultic unlock
```

### "Rate limit exceeded"

Wait a minute before requesting more credentials. The limit is 10 requests per minute.

### Connection Issues

Check that the socket exists:
```bash
ls -la /run/user/$(id -u)/vaultic/agent.sock  # Linux
ls -la ~/Library/Caches/vaultic/agent.sock     # macOS
```

Use verbose mode for debugging:
```bash
vaultic-mcp --verbose
```

## Security Considerations

1. **Don't disable consent in interactive sessions**: The consent prompt is your protection against AI assistants accessing credentials you didn't intend to share.

2. **Review before approving**: When prompted for consent, verify the entry name matches what you expect.

3. **Lock when done**: Lock your vault when you're finished:
   ```bash
   vaultic lock
   ```

4. **Session timeout**: The agent has an inactivity timeout (default 15 minutes). After this period, the vault auto-locks.

5. **Audit trail**: Consider reviewing which credentials were accessed in a session.
