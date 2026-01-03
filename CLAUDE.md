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

## Current Status: ~99% Complete

### Checkpoint: 2026-01-03

**Build Status**: COMPILING AND RUNNING
**Tests**: 72 passing
**Core Workflow**: FULLY FUNCTIONAL
**TUI**: FULLY IMPLEMENTED
**CI/CD**: GitHub Actions configured
**GitHub**: https://github.com/punitmishra/vaultic

```bash
# Verify everything works
cargo build --release        # Build optimized binary
cargo test                   # Run all tests (72 pass)
./target/release/vaultic --help  # Show all commands

# New commands
./target/release/vaultic health            # Security audit
./target/release/vaultic health --verbose  # Detailed breakdown
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
| - | Web Client (terminal-style demo) | ✅ Complete |

### Module Status

| Module | Status | Lines | Description |
|--------|--------|-------|-------------|
| `cli` | COMPLETE | ~1300 | All CLI commands |
| `tui` | COMPLETE | ~650 | Full ratatui TUI with vim keys |
| `crypto` | COMPLETE | ~600 | XChaCha20-Poly1305, Argon2id, password gen |
| `storage` | COMPLETE | ~650 | Sled DB, encrypted CRUD, search |
| `session` | COMPLETE | ~250 | Compressed sessions, auto-expiry |
| `ai` | COMPLETE | ~600 | Ollama integration, HIBP checking |
| `models` | COMPLETE | ~200 | VaultEntry, SensitiveString |
| `totp` | COMPLETE | ~150 | RFC 6238 TOTP generation |
| `gpg` | COMPLETE | ~350 | Sequoia OpenPGP integration |
| `sharing` | COMPLETE | ~200 | X25519 key exchange, QR codes |
| `fido2` | COMPLETE | ~300 | Structure ready (needs hardware) |
| `import` | COMPLETE | ~250 | Bitwarden, LastPass, 1Password |
| `export` | COMPLETE | ~200 | JSON, CSV, encrypted backup |

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
```

---

## Commands Implementation Status

| Command | Status | Notes |
|---------|--------|-------|
| `init` | ✅ WORKING | Creates vault + KDF params |
| `unlock` | ✅ WORKING | Password + session creation |
| `lock` | ✅ WORKING | Secure session destruction |
| `status` | ✅ WORKING | Shows vault/session info |
| `add` | ✅ WORKING | Full entry creation with tags, favorites, custom fields, notes |
| `list` | ✅ WORKING | Filters by tags, folder, favorites |
| `generate` | ✅ WORKING | Password gen with entropy |
| `get` | ✅ WORKING | Entry retrieval |
| `edit` | ⚠️ PARTIAL | Basic implementation |
| `delete` | ⚠️ PARTIAL | Basic implementation |
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
| `share` | ⚠️ STUB | Identity management needed |
| `suggest` | ⚠️ STUB | AI suggestions needed |

---

## Test Results (Latest)

```
cargo test: 47 tests passing
cargo build --release: Success

Local workflow test:
✓ init       - Vault created
✓ unlock     - Session created (15 min)
✓ add        - Entries added with tags, custom fields, notes
✓ generate   - Strong password with entropy
✓ list       - Formatted table output
✓ status     - Shows vault info
✓ health     - Security audit report
✓ history    - Password history and restore
✓ batch      - Batch operations on entries
✓ credential - Git credential helper
✓ tui        - Full terminal UI working
✓ lock       - Session destroyed
✓ completions - bash/zsh/fish working
```

---

## Key Files

### Core Implementation
```
src/
├── main.rs           # Entry point
├── lib.rs            # Module exports
├── cli/mod.rs        # All CLI commands (~1300 lines)
├── tui/mod.rs        # Full TUI implementation (~650 lines)
├── crypto/mod.rs     # Encryption, KDF, password gen
├── storage/mod.rs    # Sled DB operations
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

### Not Critical
1. **`share` command** - Full identity management
2. **`suggest` command** - AI-powered suggestions
3. **FIDO2 testing** - Requires YubiKey hardware
4. **More tests** - Integration tests

### Polish
1. Fix compiler warnings (mostly missing docs)
2. Add docstrings to public APIs
3. Performance optimization for large vaults

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
cargo test                  # All tests (42 passing)
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

1. **99% complete** - Only polish and optional features remain
2. **72 tests passing** - Keep them green
3. **TUI is fully working** - Tested and confirmed working by user
4. **Session system works** - Don't recreate it
5. **--password flag exists** - For non-interactive testing
6. **Import/Export working** - Bitwarden, LastPass, 1Password
7. **Web client exists** - Simple demo in web/index.html
8. **Shell completions work** - bash, zsh, fish, powershell
9. **README is comprehensive** - Includes TUI mockup and full keybindings
10. **Nix environment configured** - Use `nix develop` for full deps
11. **GitHub Actions configured** - CI/CD in `.github/workflows/`
12. **Claude Code hooks set up** - Commands in `.claude/commands/`

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
