# Vaultic v2.0 Architecture Design

## Overview

This document outlines the architecture for Vaultic's next major features:
- Enhanced encryption with recovery keys
- Backup and sync system
- Polished TUI experience
- Additional security features

---

## 1. Key Management Architecture

### Current State (v1.0)

```
┌─────────────────────────────────────────────────────────────┐
│  Master Password                                             │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐     ┌──────────────┐                       │
│  │  Argon2id   │────▶│  Master Key  │                       │
│  │  (64MB/3i)  │     │  (256-bit)   │                       │
│  └─────────────┘     └──────┬───────┘                       │
│                             │                                │
│                             ▼                                │
│                    ┌────────────────┐                       │
│                    │ XChaCha20-Poly │                       │
│                    │  (per entry)   │                       │
│                    └────────────────┘                       │
│                                                              │
│  ⚠️  Single point of failure: lose password = lose data     │
└─────────────────────────────────────────────────────────────┘
```

### Proposed State (v2.0)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        KEY HIERARCHY                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │Master Password│  │Recovery Key  │  │ YubiKey/FIDO │              │
│  │  (Argon2id)  │  │  (BIP39 24w) │  │   (HMAC)     │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
│         │                 │                 │                        │
│         ▼                 ▼                 ▼                        │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │              Key Encryption Keys (KEKs)                  │        │
│  │                                                          │        │
│  │  KEK_password = Argon2id(password, salt)                │        │
│  │  KEK_recovery = HKDF(bip39_seed, "vaultic-recovery")    │        │
│  │  KEK_hardware = HKDF(yubikey_hmac, "vaultic-hw")        │        │
│  └─────────────────────────┬───────────────────────────────┘        │
│                            │                                         │
│                            ▼                                         │
│                   ┌─────────────────┐                               │
│                   │   Vault Key     │  Random 256-bit               │
│                   │   (VK)          │  Generated once at init       │
│                   └────────┬────────┘                               │
│                            │                                         │
│         ┌──────────────────┼──────────────────┐                     │
│         ▼                  ▼                  ▼                     │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐               │
│  │ VK_enc_pass │   │ VK_enc_recv │   │ VK_enc_hw   │               │
│  │ (encrypted) │   │ (encrypted) │   │ (encrypted) │               │
│  └─────────────┘   └─────────────┘   └─────────────┘               │
│                            │                                         │
│                            ▼                                         │
│                   ┌─────────────────┐                               │
│                   │  Entry Data     │                               │
│                   │ XChaCha20-Poly  │                               │
│                   └─────────────────┘                               │
│                                                                      │
│  ✅ Any KEK can unlock the Vault Key independently                  │
│  ✅ Adding/removing unlock methods doesn't re-encrypt data          │
│  ✅ Hardware key optional but recommended                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Storage Format

```rust
// New structure in vault metadata
struct VaultKeys {
    // The vault key, encrypted by each KEK
    vault_key_encrypted: Vec<EncryptedVaultKey>,

    // Key derivation parameters
    kdf_params: KdfParams,
}

struct EncryptedVaultKey {
    // Which method encrypted this
    method: UnlockMethod,

    // The encrypted vault key
    ciphertext: Vec<u8>,

    // Nonce used for encryption
    nonce: [u8; 24],

    // For password: Argon2 salt
    // For recovery: key fingerprint
    // For hardware: credential ID
    method_data: Vec<u8>,

    // When this unlock method was added
    created_at: DateTime<Utc>,
}

enum UnlockMethod {
    Password,
    RecoveryKey,
    YubiKey { slot: u8 },
    Passkey { credential_id: Vec<u8> },
}
```

---

## 2. Recovery Key System

### BIP39 Mnemonic Generation

```
┌─────────────────────────────────────────────────────────────┐
│                   RECOVERY KEY FLOW                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  GENERATION (at vault init or later):                       │
│                                                              │
│  1. Generate 256 bits of entropy (CSPRNG)                   │
│  2. Convert to BIP39 mnemonic (24 words)                    │
│  3. Derive seed using BIP39 (with empty passphrase)         │
│  4. Derive KEK: HKDF-SHA256(seed, salt, "vaultic-recovery") │
│  5. Encrypt vault key with KEK                              │
│  6. Store encrypted vault key + key fingerprint             │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Your Recovery Key (write this down!):              │    │
│  │                                                      │    │
│  │  abandon ability able about above absent absorb     │    │
│  │  abstract absurd abuse access accident account      │    │
│  │  accuse achieve acid acoustic acquire across act    │    │
│  │                                                      │    │
│  │  ⚠️  Anyone with these words can access your vault  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  RECOVERY (when password is lost):                          │
│                                                              │
│  1. User enters 24 words                                    │
│  2. Derive seed → KEK                                       │
│  3. Decrypt vault key                                       │
│  4. Optionally: set new password                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Recovery Key Commands

```bash
# Generate recovery key during init
vaultic init --name "My Vault" --with-recovery

# Add recovery key to existing vault
vaultic recovery generate
# Displays 24 words, asks user to confirm they wrote them down

# Verify recovery key works
vaultic recovery verify
# User enters words, confirms they can decrypt

# Recover vault with recovery key
vaultic recover
# Prompts for 24 words, then sets new password

# Revoke recovery key (requires current password)
vaultic recovery revoke
```

---

## 3. Backup System

### Backup Types

```
┌─────────────────────────────────────────────────────────────┐
│                     BACKUP ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  TYPE 1: Full Encrypted Backup                              │
│  ─────────────────────────────                              │
│  • Single file containing entire vault                      │
│  • Encrypted with vault key (inherits all unlock methods)   │
│  • Portable - can restore to any machine                    │
│                                                              │
│  vaultic backup create ~/backups/vault-2026-01-04.vaultic  │
│  vaultic backup restore ~/backups/vault-2026-01-04.vaultic │
│                                                              │
│  ┌─────────────────────────────────────────┐                │
│  │  backup.vaultic                          │                │
│  │  ├── metadata.json (encrypted)          │                │
│  │  │   └── vault_keys (all KEKs)          │                │
│  │  ├── entries.db (encrypted)             │                │
│  │  └── checksum.sha256                    │                │
│  └─────────────────────────────────────────┘                │
│                                                              │
│  TYPE 2: Automatic Local Backups                            │
│  ────────────────────────────────                           │
│  • Automatic backup on significant changes                  │
│  • Configurable retention (default: 7 days, max 10)         │
│  • Stored in ~/.vaultic/backups/                           │
│                                                              │
│  ~/.vaultic/backups/                                        │
│  ├── 2026-01-04T10-30-00.vaultic                           │
│  ├── 2026-01-03T15-45-00.vaultic                           │
│  └── 2026-01-02T09-00-00.vaultic                           │
│                                                              │
│  TYPE 3: Cloud Sync (Optional)                              │
│  ─────────────────────────────                              │
│  • E2E encrypted before upload                              │
│  • Supports: Local path, S3, Dropbox, WebDAV               │
│  • Conflict resolution with vector clocks                   │
│                                                              │
│  vaultic sync configure s3://my-bucket/vaultic             │
│  vaultic sync push                                          │
│  vaultic sync pull                                          │
│  vaultic sync status                                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Backup File Format

```rust
struct VaulticBackup {
    // Format version
    version: u32,

    // When backup was created
    created_at: DateTime<Utc>,

    // Vault metadata (name, created, etc.)
    metadata: EncryptedBlob,

    // All encrypted vault keys (password, recovery, hardware)
    vault_keys: Vec<EncryptedVaultKey>,

    // All entries, encrypted with vault key
    entries: EncryptedBlob,

    // Password history
    history: EncryptedBlob,

    // Integrity check
    checksum: [u8; 32],
}

// File format: MessagePack for efficiency, or CBOR
// Extension: .vaultic
// Magic bytes: 0x56 0x4C 0x54 0x43 ("VLTC")
```

---

## 4. TUI Architecture

### Enhanced TUI Design

```
┌─ Vaultic ─────────────────────────────────────────────────────────┐
│                                                                    │
│  ╭─ Status ──────────────────────────────────────────────────────╮│
│  │ 🔓 Unlocked  │  ⏱️ 12:34 remaining  │  📊 Health: 92/100      ││
│  ╰───────────────────────────────────────────────────────────────╯│
│                                                                    │
│  ╭─ Entries (24) ────────────────────────────────────────────────╮│
│  │                                                                ││
│  │  🔍 Search: github_                                           ││
│  │  ─────────────────────────────────────────────────────────────││
│  │                                                                ││
│  │  ▸ 🌐 GitHub           dev@example.com        [dev, work]    ││
│  │    🌐 GitHub Work      admin@company.com      [work]         ││
│  │    🌐 GitLab           user@gitlab.com        [dev]          ││
│  │                                                                ││
│  │  ─────────────────────────────────────────────────────────────││
│  │  Showing 3 of 24 entries                                      ││
│  │                                                                ││
│  ╰───────────────────────────────────────────────────────────────╯│
│                                                                    │
│  ╭─ Quick Actions ───────────────────────────────────────────────╮│
│  │  [a] Add  [e] Edit  [d] Delete  [g] Generate  [h] Health     ││
│  ╰───────────────────────────────────────────────────────────────╯│
│                                                                    │
│  j/k:nav  /:search  Enter:view  y:copy  Tab:panels  ?:help  q:quit│
└────────────────────────────────────────────────────────────────────┘
```

### Detail View

```
┌─ Vaultic ─────────────────────────────────────────────────────────┐
│                                                                    │
│  ╭─ Entry: GitHub ───────────────────────────────────────────────╮│
│  │                                                                ││
│  │  Username:   dev@example.com                          [y] copy││
│  │  Password:   ●●●●●●●●●●●●●●●●                    [p] show/hide││
│  │  URL:        https://github.com                       [o] open││
│  │  TOTP:       483 291                    ████░░ 18s    [t] copy││
│  │                                                                ││
│  │  ─────────────────────────────────────────────────────────────││
│  │                                                                ││
│  │  Tags:       dev, work, important                             ││
│  │  Folder:     Development                                      ││
│  │  Created:    2026-01-01 10:30:00                              ││
│  │  Modified:   2026-01-04 15:45:00                              ││
│  │  Strength:   ████████░░ Very Strong (127 bits)               ││
│  │                                                                ││
│  │  ─────────────────────────────────────────────────────────────││
│  │                                                                ││
│  │  Notes:                                                       ││
│  │  Personal account for open source projects.                   ││
│  │                                                                ││
│  ╰───────────────────────────────────────────────────────────────╯│
│                                                                    │
│  [e] Edit  [d] Delete  [h] History  [Esc] Back                    │
└────────────────────────────────────────────────────────────────────┘
```

### TUI Components

```rust
// Modular TUI architecture
mod tui {
    mod app;           // Main application state
    mod views {
        mod list;      // Entry list view
        mod detail;    // Entry detail view
        mod edit;      // Edit form
        mod search;    // Search interface
        mod health;    // Health dashboard
        mod settings;  // Settings panel
        mod backup;    // Backup management
    }
    mod widgets {
        mod entry_row;     // Single entry display
        mod password;      // Password field with show/hide
        mod totp;          // TOTP with countdown
        mod strength_bar;  // Password strength indicator
        mod status_bar;    // Top status bar
        mod help;          // Help overlay
    }
    mod input;         // Keyboard handling
    mod theme;         // Color schemes
}
```

---

## 5. Implementation Phases

### Phase 1: Key Hierarchy (Foundation)
- [ ] Implement VaultKey generation (separate from password-derived key)
- [ ] Implement KEK wrapping/unwrapping
- [ ] Migrate existing vaults to new format
- [ ] Add `vaultic migrate` command

### Phase 2: Recovery Keys
- [ ] Add BIP39 dependency (bip39 crate)
- [ ] Implement recovery key generation
- [ ] Implement recovery key verification
- [ ] Implement vault recovery flow
- [ ] Add `vaultic recovery` subcommand

### Phase 3: Backup System
- [ ] Design backup file format
- [ ] Implement full backup creation
- [ ] Implement backup restoration
- [ ] Add automatic local backups
- [ ] Add `vaultic backup` subcommand

### Phase 4: TUI Enhancement
- [ ] Refactor TUI into modular components
- [ ] Add status bar with session timer
- [ ] Add health score display
- [ ] Add TOTP display with countdown
- [ ] Add inline editing
- [ ] Add theming support

### Phase 5: Sync (Optional)
- [ ] Design sync protocol
- [ ] Implement local folder sync
- [ ] Add S3 backend
- [ ] Add conflict resolution
- [ ] Add `vaultic sync` subcommand

---

## 6. Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Password brute force | Argon2id with 64MB+ memory |
| Recovery key theft | User responsibility to secure |
| Backup file theft | Encrypted with vault key |
| Memory disclosure | Zeroize all sensitive data |
| Side-channel attacks | Constant-time operations |
| Malicious sync server | E2E encryption, server sees only ciphertext |

### Cryptographic Choices

| Component | Algorithm | Rationale |
|-----------|-----------|-----------|
| KDF | Argon2id | Memory-hard, GPU/ASIC resistant |
| Encryption | XChaCha20-Poly1305 | Misuse-resistant, fast |
| Key wrapping | AES-256-GCM-SIV | Deterministic for KEK |
| Recovery seed | BIP39 | Standard, well-tested |
| Key expansion | HKDF-SHA256 | Standard, proven |
| Integrity | HMAC-SHA256 | Fast, secure |

---

## 7. Questions to Decide

1. **Backup format**: MessagePack vs CBOR vs custom binary?
2. **Sync protocol**: Custom vs rclone backend vs cloud SDK?
3. **TUI framework**: Keep ratatui or consider alternatives?
4. **Migration**: Automatic or manual for existing vaults?
5. **Recovery key**: 12 words (128-bit) or 24 words (256-bit)?

---

## Appendix: File Formats

### Vault Directory Structure (v2)

```
~/.vaultic/
├── vault.json              # Vault metadata (encrypted)
├── keys/
│   ├── password.key        # Vault key encrypted by password KEK
│   ├── recovery.key        # Vault key encrypted by recovery KEK
│   └── hardware-*.key      # Vault key encrypted by hardware KEK
├── db/                     # Sled database (entries)
├── backups/                # Automatic local backups
│   ├── 2026-01-04.vaultic
│   └── ...
├── .session                # Current session (temporary)
└── config.toml             # User preferences
```

### Config File

```toml
# ~/.vaultic/config.toml

[session]
timeout_minutes = 15
auto_lock_on_idle = true

[backup]
enabled = true
retention_days = 7
max_backups = 10

[sync]
enabled = false
backend = "local"  # local, s3, dropbox, webdav
path = "/path/to/sync/folder"

[tui]
theme = "dark"  # dark, light, nord, dracula
show_passwords = false
vim_mode = true
```
