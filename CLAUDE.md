# CLAUDE.md - Development Continuation Plan

This document provides context for Claude to continue developing Vaultic.

## Project Overview

**Vaultic** is a lightweight, local-first password manager in Rust featuring:
- FIDO2/YubiKey hardware authentication
- End-to-end encryption (XChaCha20-Poly1305 + Argon2id)
- AI-powered password analysis (local Ollama/llama.cpp)
- Secure sharing with perfect forward secrecy
- Beautiful CLI with fuzzy search
- Interactive TUI mode (ratatui)

---

## Current Status: current tree post-v2.2.0 (MCP + sequoia 2.3 → v2.3.0)

### Checkpoint: 2026-08-22

> Released v2.2.0 shipped three binaries (CLI/TUI, daemon, GUI) + the
> CLI↔daemon bridge. `vaultic-mcp` (#43) and the sequoia 2.3 bump (#42)
> are merged but **unreleased**, landing in v2.3.0. Counts below reflect
> the current tree.

**Build Status**: COMPILING AND RUNNING (four binaries; `vaultic-mcp` unreleased → v2.3.0)
**Binaries**: `vaultic` (CLI/TUI), `vaultic-agent` (daemon), `vaultic-gui` (egui app), `vaultic-mcp` (MCP server)
**Tests**: 450 passing (lib + bin + integration + doc)
**Core Workflow**: FULLY FUNCTIONAL
**TUI**: FULLY IMPLEMENTED + 4 themes (default/dracula/solarized-dark/monochrome)
**GUI**: FULLY IMPLEMENTED — unlock + list + detail + live TOTP + 4 themes + keyboard nav
**Daemon**: FULLY IMPLEMENTED — Unix socket, peer-cred auth, 9 protocol methods, inactivity lock
**MCP**: FULLY IMPLEMENTED — Model Context Protocol server for AI tool integration
**Benchmarks**: `cargo bench --bench vault_ops` covers list/search/get/add/unlock against 10k entries
**Audit**: `cargo audit` is currently RED — 6 vulnerabilities + 11 warnings across ~702 deps (RUSTSEC-2025-0136/sequoia was cleared by the 2.3 bump #42). Open vulns: crossbeam-epoch, quick-xml ×2, quinn-proto, rmcp (DNS rebinding in the *Streamable HTTP* transport — `vaultic-mcp` uses stdio, likely unreachable), webbrowser. The `deps/rustsec-dep-bumps` branch clears 4 (crossbeam-epoch/quinn-proto/webbrowser + anyhow unsound); quick-xml ×2 + rmcp remain. `.github/workflows/audit.yml` runs but is `continue-on-error: true` (non-gating).
**CI/CD**: GitHub Actions configured; currently billing-locked (issue #8)
**Documentation**: CHANGELOG.md, slim ROADMAP.md, AGENT_PROTOCOL.md, MCP_SERVER.md, comprehensive CLAUDE.md
**GitHub**: https://github.com/punitmishra/vaultic
**Active issues**: #6 deps hardening (Phase B remains), #8 CI billing

```bash
# Verify everything works
cargo build --release        # Builds four binaries
cargo test --release         # 450 passing

# CLI
./target/release/vaultic --help

# Daemon
./target/release/vaultic-agent start    # Foreground; binds Unix socket
./target/release/vaultic-agent status   # Probe running daemon
./target/release/vaultic-agent stop     # Graceful shutdown

# GUI
./target/release/vaultic-gui                          # Default theme
./target/release/vaultic-gui --theme dracula          # Or any of 4 named themes
./target/release/vaultic-gui --socket /custom/path.sock

# MCP Server (for AI tool integration)
./target/release/vaultic-mcp              # Starts MCP server over stdio
./target/release/vaultic-mcp --verbose    # With debug logging
./target/release/vaultic-mcp --no-consent # Skip consent prompts (trusted env only)

# Verify everything works (CLI side)

# Key commands
./target/release/vaultic health            # Security audit
./target/release/vaultic health --verbose  # Detailed breakdown
./target/release/vaultic history           # Password history
./target/release/vaultic batch             # Batch operations
./target/release/vaultic credential        # Git credential helper
./target/release/vaultic migrate           # Migrate v1 vault to v2
./target/release/vaultic unlock-method     # Manage unlock methods
./target/release/vaultic identity show     # View/create identity
./target/release/vaultic share             # Share entries securely
./target/release/vaultic totp scan         # Scan TOTP QR codes
./target/release/vaultic totp show         # Show TOTP codes
```

---

## What's Implemented

### All Phases Complete

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Core CLI (init, unlock, lock, add, list, get, delete, edit, search) | ✅ Complete |
| 2 | TUI Mode (ratatui, vim keybindings, search, detail view, delete) | ✅ Complete |
| 3 | Import/Export (Bitwarden, LastPass, 1Password, JSON, CSV, Encrypted) | ✅ Complete |
| 4 | AI Analysis (Ollama) + HIBP Breach Checking | ✅ Complete |
| 5 | FIDO2/YubiKey Structure | ✅ Complete (needs hardware to test) |
| 6 | Shell Completions (bash/zsh/fish/powershell) | ✅ Complete |
| 7 | Password History (tracking, listing, restore) | ✅ Complete |
| 8 | Batch Operations (tag, delete, move, favorite) | ✅ Complete |
| 9 | Git Credential Helper (get, store, erase) | ✅ Complete |
| 10 | Integration Tests (44 comprehensive tests) | ✅ Complete |
| 11 | TOTP QR Code Scanning (PNG/JPEG, scan/show/watch) | ✅ Complete |
| - | Web Client (terminal-style demo) | ✅ Complete |
| - | Demo Recordings (asciinema) | ✅ Complete |

### v2.0 Multi-Method Unlock Progress

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Key Hierarchy (VaultKey, KEK, wrapping) | ✅ Complete |
| 2 | BIP39 Recovery Keys + QR Display | ✅ Complete |
| 3 | AI Auto-Tagging | ✅ Complete |
| 4 | Shell Integration (exec, shell-init) | ✅ Complete |
| 5 | Identity & Sharing (X25519 key exchange) | ✅ Complete |

### Module Status

| Module | Status | Lines | Description |
|--------|--------|-------|-------------|
| `cli` | COMPLETE | ~4800 | All CLI commands + sharing/identity/batch/history/credential/migrate/totp |
| `tui` | COMPLETE | ~650 | Full ratatui TUI with vim keys |
| `crypto` | COMPLETE | ~1200 | XChaCha20-Poly1305, Argon2id, key hierarchy |
| `crypto/keys` | NEW | ~430 | VaultKey, KEK, UnlockMethod, VaultKeyring |
| `crypto/kek` | NEW | ~230 | KEK derivation (password, recovery, hardware) |
| `crypto/wrap` | NEW | ~330 | Key wrapping/unwrapping with XChaCha20-Poly1305 |
| `storage` | COMPLETE | ~800 | Sled DB, encrypted CRUD, search, history, identity storage |
| `storage/keyring` | NEW | ~200 | Keyring persistence and version detection |
| `migration` | NEW | ~390 | V1 to V2 vault migration with backup/rollback |
| `session` | COMPLETE | ~250 | Compressed sessions, auto-expiry |
| `ai` | COMPLETE | ~600 | Ollama integration, HIBP checking |
| `models` | COMPLETE | ~250 | VaultEntry, SensitiveString, PasswordHistory |
| `totp` | COMPLETE | ~650 | RFC 6238 TOTP generation, QR code scanning (PNG/JPEG), otpauth URI |
| `gpg` | COMPLETE | ~350 | Sequoia OpenPGP integration |
| `sharing` | COMPLETE | ~400 | X25519 key exchange, identity management, QR codes |
| `fido2` | COMPLETE | ~300 | Structure ready (needs hardware) |
| `import` | COMPLETE | ~250 | Bitwarden, LastPass, 1Password |
| `export` | COMPLETE | ~200 | JSON, CSV, encrypted backup |
| `recovery` | COMPLETE | ~450 | BIP39 mnemonic, QR display, key wrapping |
| `mcp` | NEW | ~500 | Model Context Protocol server for AI tool integration |
| `tests` | COMPLETE | ~900 | 450 tests (unit, integration, doctests) |

---

## MCP Server Implementation Details

The MCP server (`src/mcp/`) enables AI assistants to access vault credentials securely.

### Architecture
```
Claude Code ──(MCP/stdio)──► vaultic-mcp ──(Unix socket)──► vaultic-agent ──► Vault
```

### Tools Exposed
| Tool | Consent | Description |
|------|---------|-------------|
| `vault_status` | No | Check lock state, entry count, session expiry |
| `list_entries` | No | List entries without secrets |
| `search_entries` | No | Fuzzy search by name/username/URL/tags |
| `get_password` | Yes | Retrieve password |
| `get_credential` | Yes | Get username + password + URL |
| `get_totp` | Yes | Get current TOTP code |

### Security Features
- User consent prompts on stderr for secret access
- Rate limiting (10 requests/minute)
- Vault must be pre-unlocked via CLI
- All credentials stay local

### Claude Code Configuration
```json
{
  "mcpServers": {
    "vaultic": {
      "command": "vaultic-mcp"
    }
  }
}
```

See `docs/MCP_SERVER.md` for full documentation.

---

## TUI Implementation Details

The TUI (`src/tui/mod.rs`) is fully implemented with ratatui:

### Features
- Entry list with search filtering
- Entry detail view with password show/hide
- Clipboard copy for passwords
- Delete with confirmation popup
- Vim-style navigation

### Key Bindings
| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `g` | Go to first entry |
| `G` | Go to last entry |
| `/` | Search mode |
| `Enter` | View entry details |
| `y` | Copy password to clipboard |
| `p` | Toggle password visibility |
| `d` | Delete entry |
| `r` | Refresh entries |
| `?` | Show help |
| `Esc` | Cancel / go back |
| `q` | Quit |

### Running the TUI
```bash
# Unlock vault first
vaultic unlock

# Launch TUI
vaultic tui

# Launch TUI with a different theme (default, dracula, solarized-dark, monochrome)
vaultic tui --theme dracula
```

---

## Commands Implementation Status

| Command | Status | Notes |
|---------|--------|-------|
| `init` | ✅ WORKING | Creates vault + KDF params |
| `unlock` | ✅ WORKING | Password + session creation |
| `lock` | ✅ WORKING | Secure session destruction |
| `status` | ✅ WORKING | Shows vault/session info |
| `add` | ✅ WORKING | Full entry creation with tags, favorites, custom fields, notes, TOTP |
| `list` | ✅ WORKING | Filters by tags, folder, favorites |
| `generate` | ✅ WORKING | Password gen with entropy |
| `get` | ✅ WORKING | Entry retrieval |
| `edit` | ✅ WORKING | Full entry editing with all fields |
| `delete` | ✅ WORKING | Entry deletion with confirmation |
| `search` | ✅ WORKING | Fuzzy search |
| `import` | ✅ WORKING | Bitwarden, LastPass, 1Password |
| `export` | ✅ WORKING | JSON, CSV, encrypted |
| `tui` | ✅ WORKING | Full terminal UI |
| `completions` | ✅ WORKING | bash, zsh, fish, powershell |
| `check` | ✅ WORKING | HIBP breach checking |
| `analyze` | ✅ WORKING | AI password analysis |
| `health` | ✅ WORKING | Security audit with health score |
| `history` | ✅ WORKING | Password history tracking and restore |
| `batch` | ✅ WORKING | Batch operations (tag, delete, move, favorite) |
| `credential` | ✅ WORKING | Git credential helper integration |
| `migrate` | ✅ WORKING | Migrate v1 vault to v2 with multi-method unlock |
| `unlock-method` | ✅ WORKING | List, add, remove unlock methods |
| `recovery` | ✅ WORKING | BIP39 recovery key (generate, verify, show, unlock) |
| `share` | ✅ WORKING | Share entries with X25519 key exchange |
| `identity` | ✅ WORKING | Identity management (show, add, list, remove, export) |
| `suggest` | ✅ WORKING | AI auto-tagging, analysis, breach checking |
| `exec` | ✅ WORKING | Run commands with vault secrets as env vars |
| `shell-init` | ✅ WORKING | Generate shell aliases (bash/zsh/fish/powershell) |
| `totp scan` | ✅ WORKING | Scan QR code images (PNG/JPEG) for TOTP secrets |
| `totp show` | ✅ WORKING | Show TOTP codes with countdown, copy, watch mode |

---

## Test Results (Latest)

```
cargo test: 450 tests passing
  - 204 lib tests (crypto, storage, models, migration, recovery, ai, totp, mcp)
  - 182 bin tests (CLI parsing, commands)
  - 59 integration tests (44 end-to-end + 15 agent protocol)
  - 5 doctests (code examples in documentation)

cargo build --release: Success
cargo clippy: No warnings
cargo fmt --check: Formatted

Local workflow test:
✓ init       - Vault created with KDF params
✓ unlock     - Session created (15 min expiry)
✓ add        - Entries with tags, custom fields, notes, TOTP (--totp-secret/--totp-uri)
✓ generate   - Strong password with entropy analysis
✓ list       - Formatted table with filters
✓ get        - Entry retrieval with clipboard
✓ edit       - Entry editing with all fields
✓ delete     - Entry deletion with confirmation
✓ search     - Fuzzy search with interactive selection
✓ status     - Shows vault and session info
✓ health     - Security audit with health score
✓ history    - Password history tracking and restore
✓ batch      - Batch operations (tag, delete, move)
✓ credential - Git credential helper (get/store/erase)
✓ recovery   - BIP39 key generation, QR display, unlock
✓ suggest    - AI auto-tagging, analysis, breach checking
✓ exec       - Run commands with vault secrets as env vars
✓ shell-init - Generate shell integration scripts
✓ identity   - Identity management (show/add/list/remove/export)
✓ share      - Secure entry sharing with X25519 key exchange
✓ totp scan  - QR code scanning from PNG/JPEG images
✓ totp show  - TOTP code display with countdown, copy, watch mode
✓ tui        - Full terminal UI with vim keys
✓ import     - Bitwarden, LastPass, 1Password
✓ export     - JSON, CSV, encrypted backup
✓ lock       - Session securely destroyed
✓ completions - bash/zsh/fish/powershell
```

---

## Key Files

### Core Implementation
```
src/
├── main.rs           # Entry point
├── lib.rs            # Module exports
├── cli/mod.rs        # All CLI commands (~1800 lines)
├── tui/mod.rs        # Full TUI implementation (~650 lines)
├── crypto/
│   ├── mod.rs        # Encryption, KDF, password gen
│   ├── keys.rs       # VaultKey, KEK, UnlockMethod, VaultKeyring
│   ├── kek.rs        # KEK derivation functions
│   └── wrap.rs       # Key wrapping/unwrapping
├── storage/
│   ├── mod.rs        # Sled DB operations
│   └── keyring.rs    # Keyring persistence
├── mcp/
│   ├── mod.rs        # MCP module root
│   ├── server.rs     # ServerHandler implementation
│   ├── tools.rs      # Tool definitions, consent, rate limiting
│   └── error.rs      # MCP-specific errors
├── migration/mod.rs  # V1 to V2 migration
├── session/mod.rs    # Session management
├── models/mod.rs     # Data structures
├── ai/mod.rs         # Ollama + HIBP integration
├── totp/mod.rs       # TOTP generation
├── gpg/mod.rs        # OpenPGP integration
├── sharing/mod.rs    # E2E sharing
├── fido2/mod.rs      # Hardware auth
├── import.rs         # Import parsers
└── export.rs         # Export writers
```

### Binaries
```
src/bin/
├── vaultic_agent.rs  # Daemon binary
├── vaultic_gui.rs    # GUI binary
└── vaultic_mcp.rs    # MCP server binary
```

### Additional Files
```
web/index.html        # Terminal-style web client
demos/*.cast          # Asciinema recordings
demos/*.sh            # Demo scripts
```

---

## Session Management

Fully implemented with:
- **DEFLATE compression** for lightweight session files
- **XChaCha20-Poly1305** encryption with machine-derived key
- **Auto-expiry** (default 15 minutes)
- **Activity refresh** on vault operations

### Session Flow
1. `unlock` → derives key → creates encrypted session
2. `add/list/get/tui` → loads session → performs operation
3. `lock` → securely destroys session file
4. Timeout → auto-expires, requires re-unlock

---

## Remaining Work (Nice to Have)

### Optional Features
1. **FIDO2 testing** - Requires YubiKey hardware for verification
2. **Browser extension** - Chrome/Firefox integration

### Polish (Low Priority)
1. Performance optimization for vaults with 10,000+ entries
2. Localization/i18n support
3. Custom themes for TUI

---

## Nix Development Environment

The project includes Nix flake configuration for reproducible builds with all dependencies.

### Quick Start with Nix

```bash
# Enter development shell (includes all deps for FIDO2 + GPG)
nix develop

# Or use minimal shell (no FIDO2/GPG deps)
nix develop .#minimal

# Build with Nix
nix build              # Full build with all features
nix build .#minimal    # Minimal build

# With direnv (auto-activates on cd)
direnv allow
```

### Without Nix (Manual Dependencies)

For building without optional features, no extra deps needed:
```bash
cargo build --release
```

For optional features:
- **GPG support**: `apt install nettle-dev libgmp-dev` (or equivalent)
- **FIDO2 support**: `apt install libudev-dev` (or equivalent)

```bash
# Build with optional features
cargo build --release --features gpg
cargo build --release --features fido2
cargo build --release --all-features
```

---

## Development Commands

```bash
# Build
cargo build                 # Debug build
cargo build --release       # Release build

# Test
cargo test                  # All tests (450 passing)
cargo test tui              # TUI tests only
cargo test storage          # Storage tests only

# Run
cargo run -- <command>      # Debug mode
./target/release/vaultic    # Release binary

# Debug
VAULTIC_DEBUG=1 cargo run -- <command>

# Lint
cargo clippy
cargo fmt
```

---

## Testing Checklist

Before any major changes:

```bash
# 1. Tests pass
cargo test

# 2. Build works
cargo build --release

# 3. Core flow works
rm -rf /tmp/test_vault
./target/release/vaultic --vault /tmp/test_vault init -n "Test" --password "test123!"
./target/release/vaultic --vault /tmp/test_vault unlock --password "test123!"
./target/release/vaultic --vault /tmp/test_vault add "Test" -u "user" -p "pass"
./target/release/vaultic --vault /tmp/test_vault list
./target/release/vaultic --vault /tmp/test_vault tui  # Test TUI
./target/release/vaultic --vault /tmp/test_vault lock
```

---

## Notes for Claude

1. **100% feature complete** - All core features implemented and tested
2. **450 tests passing** - Keep them green (204 lib + 182 bin + 59 integration + 5 doc)
3. **CI/CD fully configured** - GitHub Actions with matrix builds for all features
4. **TUI is fully working** - Tested and confirmed working by user
5. **Session system works** - Don't recreate it
6. **--password flag exists** - For non-interactive testing
7. **Import/Export working** - Bitwarden, LastPass, 1Password
8. **Web client exists** - Simple demo in web/index.html
9. **Shell completions work** - bash, zsh, fish, powershell
10. **Demo recordings exist** - `demos/*.cast` for asciinema playback
11. **Nix environment configured** - Use `nix develop` for full deps
12. **GitHub Actions configured** - CI/CD in `.github/workflows/`
13. **Claude Code hooks set up** - Commands in `.claude/commands/`
14. **Git credential helper** - Works with `git config credential.helper vaultic`
15. **Password history** - Automatic tracking with restore capability
16. **Batch operations** - Tag, delete, move, favorite multiple entries
17. **BIP39 Recovery Keys** - Full implementation with QR display and unlock
18. **AI Auto-Tagging** - Rule-based + Ollama-enhanced tag suggestions
19. **Shell Integration** - exec command + shell-init for bash/zsh/fish/powershell
20. **Identity Management** - Full X25519 keypair generation, export/import
21. **Secure Sharing** - Entry sharing with ephemeral key exchange
22. **TOTP QR Scanning** - Scan PNG/JPEG QR codes for otpauth URIs, `totp scan`/`totp show` commands
23. **TOTP on Add** - `--totp-secret` and `--totp-uri` flags on `add` command
24. **TOTP Display** - TOTP codes shown in `display_entry` with countdown bar
25. **MCP Server** - `vaultic-mcp` for AI tool integration (Claude Code, etc.)

### MCP Notes
- MCP server communicates with vaultic-agent over Unix socket
- User consent prompts on stderr for secret-access tools
- Rate limited to 10 credential requests per minute
- Configure in Claude Code with `{"mcpServers": {"vaultic": {"command": "vaultic-mcp"}}}`
- See `docs/MCP_SERVER.md` for full documentation

### TUI Notes
- TUI requires unlocked vault (loads session + master key)
- Uses `VaultStorage::unlock(&master_key)` to decrypt entries
- Clipboard copy uses the `arboard` crate
- Password visibility toggle in detail view
- Delete has confirmation popup

### Architecture Notes
- Session stores vault_path + master_key (encrypted)
- Storage needs `unlock()` call before reading entries
- SensitiveString uses `.expose()` to access inner value
- All entries encrypted with XChaCha20-Poly1305
- FIDO2 and GPG are optional features (require system deps)
