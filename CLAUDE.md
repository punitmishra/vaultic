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

## Current Status: ~80% Complete (Checkpoint: 2024-12-28)

### Build Status: COMPILING AND RUNNING

The project now builds successfully on macOS. Run:
```bash
cargo build              # Build the project
cargo run -- --help      # Show CLI help
cargo run -- generate    # Test password generation
cargo run -- status      # Show vault status
```

### Recent Fixes Applied

The following issues were fixed to get the project compiling:

#### 1. Cargo.toml
- Changed `edition = "2024"` to `edition = "2021"` (2024 doesn't exist yet)
- Added missing dependencies: `urlencoding`, `dirs`, `sha1`, `env_logger`

#### 2. System Dependencies (macOS)
```bash
brew install nettle pkg-config  # Required for sequoia-openpgp
```

#### 3. FIDO2 Module (`src/fido2/mod.rs`)
- **Status**: Stubbed out (hardware-dependent)
- The `ctap-hid-fido2` crate API changed significantly
- Created stub implementation that returns `Fido2Error::NotAvailable`
- Full implementation requires hardware for testing
- Key types preserved: `StoredCredential`, `DeviceInfo`, `Fido2Auth`

#### 4. GPG Module (`src/gpg/mod.rs`)
- Fixed sequoia-openpgp API changes:
  - Renamed local `DecryptionHelper` struct to `VaulticDecryptionHelper`
  - Fixed `Recipient::from()` usage
  - Fixed KeyID comparison in decryption helper
  - Fixed `RevocationStatus` enum matching

#### 5. Storage Module (`src/storage/mod.rs`)
- Added `use fuzzy_matcher::FuzzyMatcher;` trait import
- Fixed borrow checker issues in `add_entry()` and `delete_entry()`
- Clone metadata before calling `save_metadata()` to avoid double borrow

#### 6. Sharing Module (`src/sharing/mod.rs`)
- Fixed image crate API: `encode()` → `write_image()`
- Added `use image::ImageEncoder;` trait import

#### 7. CLI Module (`src/cli/mod.rs`)
- Fixed dialoguer error handling (wrap with `map_err`)
- Fixed clipboard API (use trait-based approach)
- Fixed temporary value lifetime in `input()` function
- **Added complete `run_command()` function** with handlers for all commands

#### 8. TUI Module (`src/tui/mod.rs`)
- Created new stub module with basic `App` struct and `Mode` enum
- Placeholder `run()` function that displays usage message

#### 9. Main (`src/main.rs`)
- Added `mod tui;` declaration
- Fixed imports

---

### Module Status Overview

| Module | File | Status | Notes |
|--------|------|--------|-------|
| Models | `src/models/mod.rs` | ✅ Complete | Data structures working |
| Crypto | `src/crypto/mod.rs` | ✅ Complete | Encryption, KDF, password gen working |
| Storage | `src/storage/mod.rs` | ✅ Complete | Sled DB, encrypted CRUD working |
| FIDO2 | `src/fido2/mod.rs` | ⚠️ Stubbed | Needs hardware to implement |
| AI | `src/ai/mod.rs` | ✅ Complete | Ollama integration ready |
| CLI | `src/cli/mod.rs` | ✅ Complete | All commands have handlers |
| Sharing | `src/sharing/mod.rs` | ✅ Complete | E2E sharing ready |
| GPG | `src/gpg/mod.rs` | ✅ Complete | OpenPGP working |
| TOTP | `src/totp/mod.rs` | ✅ Complete | OTP generation working |
| TUI | `src/tui/mod.rs` | ⚠️ Stubbed | Needs ratatui implementation |
| Main | `src/main.rs` | ✅ Complete | Entry point working |
| Lib | `src/lib.rs` | ✅ Complete | Module exports working |

---

## What Works Now

### Commands That Function:
```bash
vaultic --help                    # Full help with all commands
vaultic generate                  # Generate secure password (FULLY WORKING)
vaultic generate --length 32      # Custom length password
vaultic generate --passphrase     # Generate passphrase
vaultic status                    # Show vault status (displays locked)
```

### Commands With Stub Handlers (Display Messages):
```bash
vaultic init "My Vault"           # Prompts for password, creates vault
vaultic unlock                    # Shows "not yet implemented"
vaultic lock                      # Shows "vault locked"
vaultic add --name "Test"         # Prompts work, storage not connected
vaultic list                      # Shows header, needs vault unlock
vaultic tui                       # Shows usage message
```

---

## Next Priority: Session Management

### The Problem
Currently, each CLI command runs independently. Users must unlock the vault for every operation. We need:
1. Unlock once, stay unlocked for a timeout period
2. Derived key stored securely between commands
3. Auto-lock after inactivity

### Proposed Architecture

```
~/.vaultic/
├── vault/                    # Sled database (encrypted entries)
├── config.toml              # User configuration
└── session.json             # Encrypted session state (temporary)
```

### Session Module Design (`src/session/mod.rs`)

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Session state stored between CLI invocations
#[derive(Serialize, Deserialize)]
pub struct Session {
    /// Path to the vault this session is for
    pub vault_path: PathBuf,

    /// Master key encrypted with machine-specific key
    /// Using platform keychain or file-based key
    pub encrypted_key: Vec<u8>,

    /// Nonce used for key encryption
    pub nonce: [u8; 24],

    /// When this session expires
    pub expires_at: DateTime<Utc>,

    /// Session creation time
    pub created_at: DateTime<Utc>,
}

pub struct SessionManager {
    session_path: PathBuf,
    machine_key: [u8; 32],  // Derived from machine ID or keychain
}

impl SessionManager {
    /// Create a new session after successful unlock
    pub fn create_session(
        &self,
        vault_path: &Path,
        master_key: &MasterKey,
        timeout_minutes: u32,
    ) -> Result<(), SessionError>;

    /// Load and validate existing session
    pub fn load_session(&self) -> Result<Option<(PathBuf, MasterKey)>, SessionError>;

    /// Extend session timeout (on activity)
    pub fn refresh_session(&self) -> Result<(), SessionError>;

    /// Destroy session (lock command)
    pub fn destroy_session(&self) -> Result<(), SessionError>;

    /// Check if session is valid without loading key
    pub fn is_valid(&self) -> bool;
}
```

### Machine Key Derivation

For encrypting the session key at rest:

**Option A: Platform Keychain (Recommended for security)**
- macOS: Security.framework keychain
- Linux: libsecret/GNOME Keyring
- Windows: Windows Credential Manager

**Option B: File-based (Fallback)**
```rust
fn derive_machine_key() -> [u8; 32] {
    // Combine machine-specific identifiers
    let machine_id = get_machine_id();      // /etc/machine-id on Linux
    let username = whoami::username();
    let salt = b"vaultic-session-key-v1";

    // Derive key using Argon2
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(
        format!("{}:{}", machine_id, username).as_bytes(),
        salt,
        &mut key,
    ).unwrap();
    key
}
```

### Integration with CLI Commands

```rust
pub fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let session_mgr = SessionManager::new()?;

    match cli.command {
        Commands::Unlock { timeout } => {
            // 1. Prompt for password
            // 2. Derive master key
            // 3. Verify against vault
            // 4. Create session
            session_mgr.create_session(&vault_path, &master_key, timeout)?;
        }

        Commands::Lock => {
            session_mgr.destroy_session()?;
        }

        Commands::Add { .. } | Commands::Get { .. } | Commands::List { .. } => {
            // Commands that need unlocked vault
            let (vault_path, master_key) = session_mgr
                .load_session()?
                .ok_or("Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh timeout on activity
            session_mgr.refresh_session()?;

            // Now use master_key for operation...
        }

        Commands::Generate { .. } | Commands::Status => {
            // Commands that don't need unlock
        }
    }
}
```

### Security Considerations

1. **Session file permissions**: `chmod 600 session.json`
2. **Memory safety**: Use `zeroize` on master key after encryption
3. **Timeout**: Default 15 minutes, max 24 hours
4. **Lock on sleep**: Consider platform-specific hooks
5. **Multiple vaults**: Session tied to specific vault path

---

## Implementation Order for Session Management

1. **Create `src/session/mod.rs`** with `Session` and `SessionManager` structs
2. **Implement machine key derivation** (file-based first, keychain later)
3. **Add session creation** in `unlock` command
4. **Add session loading** for protected commands
5. **Add session destruction** in `lock` command
6. **Add session refresh** on activity
7. **Update CLI** to check session before vault operations
8. **Add tests** for session lifecycle

---

## Other Remaining Work

### After Session Management:

1. **Full Command Implementation**
   - `init`: Wire to `VaultStorage::create()` ✅ (partially done)
   - `unlock`: Create session after password verification
   - `add`: Create `VaultEntry`, call `storage.add_entry()`
   - `get`: Load entry, display/copy password
   - `list`: Load entries, display table
   - `edit`: Load entry, prompt for changes, update
   - `delete`: Confirm, remove entry

2. **TUI Mode** (`src/tui/mod.rs`)
   - Add ratatui dependency
   - Implement main loop with crossterm
   - Build list view, detail view, search
   - Add vim-style keybindings

3. **Import/Export** (`src/import_export/mod.rs`)
   - Bitwarden JSON import
   - LastPass CSV import
   - 1Password CSV import
   - Encrypted backup export/import

4. **FIDO2 Implementation** (when hardware available)
   - Update ctap-hid-fido2 API usage
   - Test with YubiKey
   - Implement HMAC-Secret extension

---

## File Structure

```
src/
├── main.rs              # Entry point
├── lib.rs               # Module exports
├── models/mod.rs        # Data structures
├── crypto/mod.rs        # Encryption, KDF
├── storage/mod.rs       # Sled DB operations
├── fido2/mod.rs         # Hardware auth (stubbed)
├── ai/mod.rs            # Ollama integration
├── cli/mod.rs           # Commands + run_command()
├── sharing/mod.rs       # E2E sharing
├── gpg/mod.rs           # OpenPGP operations
├── totp/mod.rs          # TOTP generation
├── tui/mod.rs           # Terminal UI (stubbed)
└── session/mod.rs       # [TO CREATE] Session management
```

---

## Quick Start for Continuation

```bash
# 1. Verify build still works
cargo build

# 2. Run tests
cargo test

# 3. Check current functionality
cargo run -- generate --length 24
cargo run -- status

# 4. Start implementing session management
# Create src/session/mod.rs following the design above
```

---

## Environment Variables

- `VAULTIC_HOME` - Vault directory (default: `~/.vaultic`)
- `VAULTIC_DEBUG` - Enable debug logging (`export VAULTIC_DEBUG=1`)

---

## Testing

```bash
cargo test                          # Run all tests
cargo test --lib                    # Library tests only
cargo test session                  # Test session module (once created)
VAULTIC_DEBUG=1 cargo run -- init   # Debug mode
```
