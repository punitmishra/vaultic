# CLAUDE.md - Development Continuation Plan

This document provides context for Claude to continue developing Vaultic.

## Project Overview

**Vaultic** is a lightweight, local-first password manager in Rust featuring:
- FIDO2/YubiKey hardware authentication
- End-to-end encryption (XChaCha20-Poly1305 + Argon2id)
- AI-powered password analysis (local Ollama/llama.cpp)
- Secure sharing with perfect forward secrecy
- Beautiful CLI with fuzzy search

---

## Current Status: ~85% Complete

### Checkpoint: 2024-12-28

**Build Status**: COMPILING AND RUNNING
**Tests**: 38 passing
**Core Workflow**: FULLY FUNCTIONAL

```bash
# Verify everything works
cargo build --release        # Build optimized binary
cargo test                   # Run all tests (38 pass)
./target/release/vaultic --help  # Show all commands
```

---

## What's Working (Tested End-to-End)

### Core Vault Operations
```bash
# Initialize a new vault
vaultic init --name "My Vault" --password "your-secure-password"

# Unlock vault (creates 15-minute session)
vaultic unlock --password "your-secure-password"

# Add entries
vaultic add "GitHub" -u "user@example.com" -p "secret" --tags "dev,work"
vaultic add "AWS" -u "admin" --generate --url "https://aws.amazon.com"

# List entries
vaultic list
vaultic list --tags "work"

# Check status
vaultic status

# Lock when done
vaultic lock
```

### Password Generation
```bash
vaultic generate                    # 20-char secure password
vaultic generate --length 32        # Custom length
vaultic generate --no-symbols       # Alphanumeric only
```

---

## Module Status

| Module | Status | Description |
|--------|--------|-------------|
| `crypto` | COMPLETE | XChaCha20-Poly1305, Argon2id, password analysis |
| `storage` | COMPLETE | Sled DB, encrypted CRUD, search, filters |
| `session` | COMPLETE | Compressed session files, auto-expiry |
| `cli` | COMPLETE | All command handlers wired up |
| `models` | COMPLETE | VaultEntry, SensitiveString, filters |
| `totp` | COMPLETE | RFC 6238 TOTP generation |
| `gpg` | COMPLETE | Sequoia OpenPGP integration |
| `sharing` | COMPLETE | X25519 key exchange, QR codes |
| `ai` | COMPLETE | Ollama integration, rule-based analysis |
| `fido2` | STUBBED | Needs hardware for testing |
| `tui` | STUBBED | Needs ratatui implementation |

---

## Session Management (Implemented)

Session management is now fully implemented with:

- **Compressed storage**: DEFLATE compression for lightweight session files
- **Encrypted at rest**: XChaCha20-Poly1305 with machine-derived key
- **Auto-expiry**: Configurable timeout (default 15 minutes)
- **Activity refresh**: Session extends on vault operations

### How It Works

```
~/.vaultic/
├── .session              # Encrypted session file (compressed)
├── kdf_params.json       # Salt + KDF parameters (unencrypted)
└── [vault db files]      # Sled database (encrypted)
```

### Session Flow
1. `unlock` → derives key from password → creates encrypted session
2. `add/list/get` → loads session → refreshes timeout → performs operation
3. `lock` → securely destroys session file
4. Timeout → session auto-expires, requires re-unlock

---

## Commands Implementation Status

| Command | Status | Notes |
|---------|--------|-------|
| `init` | WORKING | Creates vault + KDF params |
| `unlock` | WORKING | Password + session creation |
| `lock` | WORKING | Secure session destruction |
| `status` | WORKING | Shows vault/session info |
| `add` | WORKING | Full entry creation with tags |
| `list` | WORKING | Filters by tags, folder, etc. |
| `generate` | WORKING | Strong password generation |
| `get` | PARTIAL | Needs clipboard integration |
| `edit` | STUB | Needs implementation |
| `delete` | STUB | Needs implementation |
| `search` | STUB | Needs fuzzy search UI |
| `share` | STUB | Needs identity management |
| `suggest` | STUB | Needs AI connection |
| `import` | STUB | Needs format parsers |
| `export` | STUB | Needs format writers |
| `tui` | STUB | Needs ratatui UI |

---

## Next Priority Tasks

### Phase 1: Complete Core Commands (1-2 days)
1. **`get` command** - Copy password to clipboard, show entry details
2. **`delete` command** - Remove entries with confirmation
3. **`edit` command** - Interactive entry modification
4. **`search` command** - Fuzzy search with selection

### Phase 2: TUI Mode (2-3 days)
1. Add ratatui + crossterm dependencies
2. Implement main event loop
3. Build views: list, detail, search, edit
4. Add vim-style keybindings (j/k, /, etc.)

### Phase 3: Import/Export (1-2 days)
1. Bitwarden JSON import
2. LastPass CSV import
3. 1Password CSV import
4. Encrypted backup format

### Phase 4: Polish (1-2 days)
1. AI suggestions integration
2. Breach checking (HIBP)
3. Better error messages
4. Shell completions

### Phase 5: FIDO2 (When Hardware Available)
1. Update ctap-hid-fido2 API
2. Test with YubiKey
3. HMAC-Secret key derivation

---

## Key Architecture Decisions

### Why DEFLATE Compression for Sessions?
- Sessions contain ~200 bytes of JSON
- DEFLATE reduces to ~100 bytes
- Minimal CPU overhead
- Keeps the app lightweight as requested

### Why File-Based Sessions (Not Keychain)?
- Cross-platform compatibility
- No external dependencies
- User can see/delete session file
- Encrypted with machine-derived key (still secure)

### Why Sled Database?
- Embedded (no separate process)
- ACID compliant
- Crash-safe
- Pure Rust (no FFI)

---

## Development Commands

```bash
# Build
cargo build                 # Debug build
cargo build --release       # Release build

# Test
cargo test                  # All tests
cargo test session          # Session module only
cargo test storage          # Storage module only

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

## File Structure

```
src/
├── main.rs              # Entry point
├── lib.rs               # Module exports
├── models/mod.rs        # Data structures
├── crypto/mod.rs        # Encryption, KDF, password gen
├── storage/mod.rs       # Sled DB operations
├── session/mod.rs       # Session management (NEW)
├── fido2/mod.rs         # Hardware auth (stubbed)
├── ai/mod.rs            # Ollama integration
├── cli/mod.rs           # Commands + run_command()
├── sharing/mod.rs       # E2E sharing
├── gpg/mod.rs           # OpenPGP operations
├── totp/mod.rs          # TOTP generation
└── tui/mod.rs           # Terminal UI (stubbed)
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULTIC_HOME` | `~/.vaultic` | Vault directory |
| `VAULTIC_PASSWORD` | - | Password for non-interactive mode |
| `VAULTIC_DEBUG` | - | Enable debug logging |

---

## Testing Checklist

Before any major changes, verify:

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
./target/release/vaultic --vault /tmp/test_vault lock
```

---

## Notes for Claude

1. **Session is implemented** - Don't recreate it
2. **KDF params saved separately** - Required for unlock to work
3. **--password flag exists** - For non-interactive testing
4. **38 tests passing** - Keep them green
5. **Compression is important** - User wants lightweight app
