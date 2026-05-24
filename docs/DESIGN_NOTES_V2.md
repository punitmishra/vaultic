# Vaultic v2.0 Architecture Design

## Overview

This document outlines the architecture for Vaultic's next major features:
- Enhanced encryption with recovery keys + QR backup
- Incremental backup and sync system
- AI-powered tagging (lightweight local model or rule-based)
- Developer shell integrations
- GPG storage and hardware key setup
- Polished TUI experience

---

## Design Decisions (Confirmed)

| Feature | Decision |
|---------|----------|
| Recovery Key | BIP39 24-word mnemonic + QR code for shell display |
| Backup (Local) | Incremental with rotation |
| Backup (Cloud) | Incremental chunks, E2E encrypted |
| AI Tagging | Gemini 1B in-memory (small footprint) OR rule-based fallback |
| Hardware Key | Seamless YubiKey/FIDO2 setup |
| Shell Integration | Full dev-friendly commands, env injection, aliases |

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
struct VaultKeys {
    vault_key_encrypted: Vec<EncryptedVaultKey>,
    kdf_params: KdfParams,
}

struct EncryptedVaultKey {
    method: UnlockMethod,
    ciphertext: Vec<u8>,
    nonce: [u8; 24],
    method_data: Vec<u8>,  // salt, fingerprint, or credential ID
    created_at: DateTime<Utc>,
}

enum UnlockMethod {
    Password,
    RecoveryKey,
    YubiKey { slot: u8 },
    Passkey { credential_id: Vec<u8> },
    GpgKey { key_id: String },
}
```

---

## 2. Recovery Key System

### BIP39 + QR Code Display

```
┌─────────────────────────────────────────────────────────────────────┐
│                   RECOVERY KEY SYSTEM                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  GENERATION:                                                         │
│  ───────────                                                         │
│  1. Generate 256 bits entropy (CSPRNG)                              │
│  2. Convert to BIP39 mnemonic (24 words)                            │
│  3. Display in terminal + generate QR code                          │
│  4. Derive KEK: HKDF-SHA256(seed, salt, "vaultic-recovery")        │
│  5. Encrypt vault key with KEK                                      │
│                                                                      │
│  TERMINAL OUTPUT:                                                    │
│  ────────────────                                                    │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                                                              │    │
│  │  ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄     ┃  Recovery Key:              │    │
│  │  █ ▄▄▄ █ ▀█ ▄▀█ █ ▄▄▄ █     ┃                              │    │
│  │  █ ███ █ ▀▀█▄▄█ █ ███ █     ┃  1. abandon   13. account    │    │
│  │  █▄▄▄▄▄█ ▄▀▄▀▄▀ █▄▄▄▄▄█     ┃  2. ability   14. accuse     │    │
│  │  ▄▄▄▄▄ ▄▄▄▀▀▄▀█ ▄ ▄ ▄▄▄     ┃  3. able      15. achieve    │    │
│  │  █ ▄▄▄ █ ▀█▀▄▄█ █▄▀▄ ▀▀     ┃  4. about     16. acid       │    │
│  │  █ ███ █ █ █ ▀▀ █ █ ▀█▄     ┃  5. above     17. acoustic   │    │
│  │  █▄▄▄▄▄█ █▀▄▀▄█ █▀▀▀█▄█     ┃  6. absent    18. acquire    │    │
│  │                              ┃  7. absorb    19. across     │    │
│  │  Scan QR or copy words       ┃  8. abstract  20. act        │    │
│  │  Store safely offline!       ┃  9. absurd    21. action     │    │
│  │                              ┃  10. abuse    22. actor      │    │
│  │                              ┃  11. access   23. actress    │    │
│  │                              ┃  12. accident 24. adapt      │    │
│  │                                                              │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ⚠️  Anyone with these words OR this QR code can access your vault  │
│                                                                      │
│  EXPORT OPTIONS:                                                     │
│  ───────────────                                                     │
│  vaultic recovery show --qr          # Display QR in terminal       │
│  vaultic recovery show --words       # Display words only           │
│  vaultic recovery export --pdf       # Generate printable PDF       │
│  vaultic recovery export --png       # Save QR as image             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Recovery Commands

```bash
# Generate recovery key during init
vaultic init --name "My Vault" --with-recovery

# Add recovery key to existing vault
vaultic recovery generate
vaultic recovery generate --qr    # Show QR code in terminal

# Display existing recovery key (requires unlock)
vaultic recovery show
vaultic recovery show --qr        # QR code
vaultic recovery show --words     # Words only

# Export recovery key
vaultic recovery export recovery.pdf   # Printable backup sheet
vaultic recovery export recovery.png   # QR code image

# Verify recovery key works
vaultic recovery verify

# Recover vault (forgot password)
vaultic recover
vaultic recover --scan             # Scan QR code from camera

# Revoke recovery key
vaultic recovery revoke
```

---

## 3. Backup System (Incremental + Chunked)

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                   INCREMENTAL BACKUP SYSTEM                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  LOCAL BACKUPS (Automatic)                                          │
│  ─────────────────────────                                          │
│                                                                      │
│  ~/.vaultic/backups/                                                │
│  ├── manifest.json              # Backup index                      │
│  ├── full/                                                          │
│  │   └── 2026-01-01T00-00-00/  # Weekly full backup                │
│  │       ├── metadata.enc                                           │
│  │       ├── entries.enc                                            │
│  │       └── checksum.sha256                                        │
│  └── incremental/                                                   │
│      ├── 2026-01-02T10-30-00.delta                                 │
│      ├── 2026-01-03T15-45-00.delta                                 │
│      └── 2026-01-04T09-00-00.delta                                 │
│                                                                      │
│  DELTA FORMAT:                                                       │
│  ─────────────                                                       │
│  {                                                                   │
│    "base": "2026-01-01T00-00-00",                                   │
│    "sequence": 3,                                                   │
│    "added": ["entry-uuid-1", "entry-uuid-2"],                       │
│    "modified": ["entry-uuid-3"],                                    │
│    "deleted": ["entry-uuid-4"],                                     │
│    "data": { ... encrypted entry data ... }                         │
│  }                                                                   │
│                                                                      │
│  CLOUD SYNC (Chunked + Incremental)                                 │
│  ──────────────────────────────────                                 │
│                                                                      │
│  s3://bucket/vaultic/                                               │
│  ├── manifest.enc               # Encrypted manifest                │
│  ├── chunks/                    # Content-addressed chunks          │
│  │   ├── a1b2c3d4.enc          # 64KB encrypted chunks             │
│  │   ├── e5f6g7h8.enc                                              │
│  │   └── ...                                                        │
│  └── snapshots/                                                     │
│      ├── 2026-01-01.snapshot   # Weekly snapshots                  │
│      └── latest.snapshot       # Current state                      │
│                                                                      │
│  CHUNKING STRATEGY:                                                  │
│  ──────────────────                                                  │
│  • Content-defined chunking (FastCDC algorithm)                     │
│  • Average chunk size: 64KB                                         │
│  • Deduplication via content hashing                                │
│  • Each chunk encrypted independently                               │
│  • Only changed chunks uploaded                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Backup Commands

```bash
# Local backups (automatic by default)
vaultic backup status              # Show backup status
vaultic backup list                # List all backups
vaultic backup create              # Force immediate backup
vaultic backup restore 2026-01-03  # Restore to date

# Cloud sync
vaultic sync init s3://bucket/vaultic
vaultic sync init /mnt/external/vaultic
vaultic sync init dropbox://Apps/vaultic

vaultic sync push                  # Upload changes
vaultic sync pull                  # Download changes
vaultic sync status                # Show sync status
vaultic sync history               # Show sync log

# Configuration
vaultic config backup.auto true
vaultic config backup.retention_days 30
vaultic config backup.full_interval_days 7
vaultic config sync.auto true
vaultic config sync.interval_minutes 30
```

### Backup File Format

```rust
struct BackupManifest {
    version: u32,
    vault_id: Uuid,
    created_at: DateTime<Utc>,

    // Full backups
    full_backups: Vec<FullBackupRef>,

    // Incremental deltas
    deltas: Vec<DeltaRef>,

    // For cloud: chunk references
    chunks: HashMap<ChunkId, ChunkMetadata>,
}

struct DeltaBackup {
    base_backup: String,
    sequence: u32,
    timestamp: DateTime<Utc>,

    added: Vec<Uuid>,
    modified: Vec<Uuid>,
    deleted: Vec<Uuid>,

    // Encrypted entry data for added/modified
    data: EncryptedBlob,
}

struct Chunk {
    id: ChunkId,           // SHA256 of content
    size: u32,
    encrypted_data: Vec<u8>,
}
```

---

## 4. AI-Powered Tagging System

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                   SMART TAGGING SYSTEM                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TWO MODES:                                                          │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  MODE 1: Local AI (Gemini Nano / TinyLlama)                 │    │
│  │  ──────────────────────────────────────────                 │    │
│  │  • Runs entirely in-memory                                   │    │
│  │  • ~500MB model footprint                                    │    │
│  │  • No network required                                       │    │
│  │  • Features:                                                 │    │
│  │    - Auto-tag suggestions based on URL/name                 │    │
│  │    - Smart note summarization                               │    │
│  │    - Password strength explanations                         │    │
│  │    - Similar entry detection                                │    │
│  │                                                              │    │
│  │  vaultic config ai.enabled true                             │    │
│  │  vaultic config ai.model gemini-nano                        │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  MODE 2: Rule-Based Fallback                                │    │
│  │  ───────────────────────────                                │    │
│  │  • Zero additional memory                                    │    │
│  │  • Pattern matching on URLs and names                       │    │
│  │  • Built-in category rules:                                 │    │
│  │                                                              │    │
│  │    github.com, gitlab.com     → [dev, code, git]           │    │
│  │    aws.amazon.com, cloud.*    → [cloud, infra]             │    │
│  │    *bank*, *finance*          → [finance, sensitive]       │    │
│  │    mail.*, *email*            → [email, communication]     │    │
│  │    social: twitter, facebook  → [social, personal]         │    │
│  │                                                              │    │
│  │  vaultic config ai.enabled false                            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  TAG COMMANDS:                                                       │
│  ─────────────                                                       │
│  vaultic tag suggest GitHub          # Get tag suggestions          │
│  vaultic tag auto                    # Auto-tag all entries         │
│  vaultic tag search "cloud infra"    # Find by tags                 │
│  vaultic tag list                    # List all tags with counts    │
│  vaultic tag rename old-tag new-tag  # Rename across entries        │
│  vaultic tag delete unused-tag       # Remove tag from all          │
│                                                                      │
│  SMART NOTES:                                                        │
│  ────────────                                                        │
│  vaultic note add GitHub "API token for CI/CD"                      │
│  vaultic note search "API"           # Search notes                 │
│  vaultic note summarize              # AI summary of all notes      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Rule-Based Tag Engine

```rust
struct TagRule {
    name: String,
    patterns: Vec<Pattern>,
    suggested_tags: Vec<String>,
}

enum Pattern {
    Domain(String),           // "github.com"
    DomainSuffix(String),     // ".edu"
    NameContains(String),     // "*bank*"
    UrlContains(String),      // "cloud"
    Category(Category),       // Built-in category
}

enum Category {
    Development,    // github, gitlab, bitbucket, stackoverflow
    Cloud,          // aws, gcp, azure, digitalocean
    Finance,        // banks, trading, crypto
    Social,         // twitter, facebook, linkedin
    Email,          // gmail, outlook, protonmail
    Shopping,       // amazon, ebay, stores
    Entertainment,  // netflix, spotify, gaming
    Work,           // slack, jira, confluence
}

// Built-in rules
const DEFAULT_RULES: &[TagRule] = &[
    TagRule {
        name: "development",
        patterns: vec![
            Pattern::Domain("github.com"),
            Pattern::Domain("gitlab.com"),
            Pattern::Domain("bitbucket.org"),
            Pattern::NameContains("api"),
            Pattern::NameContains("dev"),
        ],
        suggested_tags: vec!["dev", "code"],
    },
    // ... more rules
];
```

---

## 5. Developer Shell Integration

### Shell Commands & Aliases

```
┌─────────────────────────────────────────────────────────────────────┐
│                   DEVELOPER SHELL INTEGRATION                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ENVIRONMENT INJECTION                                               │
│  ─────────────────────                                               │
│                                                                      │
│  # Run command with secrets as env vars                             │
│  vaultic exec "AWS Production" -- aws s3 ls                         │
│                                                                      │
│  # Injects: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY               │
│  # Based on entry's custom fields                                   │
│                                                                      │
│  # Run shell with multiple secrets                                  │
│  vaultic exec --entries "AWS,GitHub" -- bash                        │
│                                                                      │
│  # Template-based injection                                         │
│  vaultic exec "Database" --template "PGPASSWORD={{password}}" -- psql│
│                                                                      │
│  ───────────────────────────────────────────────────────────────────│
│                                                                      │
│  GIT CREDENTIAL HELPER (Enhanced)                                   │
│  ─────────────────────────────────                                  │
│                                                                      │
│  git config --global credential.helper vaultic                      │
│                                                                      │
│  # Auto-matches by URL, supports multiple accounts per host         │
│  # Prompts for selection if multiple matches                        │
│                                                                      │
│  ───────────────────────────────────────────────────────────────────│
│                                                                      │
│  SSH KEY MANAGEMENT                                                  │
│  ───────────────────                                                 │
│                                                                      │
│  # Store SSH key in vault                                           │
│  vaultic ssh add ~/.ssh/id_ed25519 --name "Personal SSH"           │
│                                                                      │
│  # Add to ssh-agent                                                 │
│  vaultic ssh agent add "Personal SSH"                               │
│                                                                      │
│  # List loaded keys                                                 │
│  vaultic ssh agent list                                             │
│                                                                      │
│  # SSH wrapper (loads key automatically)                            │
│  vaultic ssh connect server.example.com                             │
│                                                                      │
│  ───────────────────────────────────────────────────────────────────│
│                                                                      │
│  SHELL ALIASES & FUNCTIONS                                          │
│  ──────────────────────────                                         │
│                                                                      │
│  # Generate shell integration script                                │
│  vaultic shell-init bash >> ~/.bashrc                               │
│  vaultic shell-init zsh >> ~/.zshrc                                 │
│  vaultic shell-init fish >> ~/.config/fish/config.fish             │
│                                                                      │
│  # Provides:                                                        │
│  vg "name"         # vaultic get (copy password)                   │
│  va "name"         # vaultic add (interactive)                     │
│  vs "query"        # vaultic search                                │
│  vt               # vaultic tui                                    │
│  vexec "name" cmd  # vaultic exec                                  │
│                                                                      │
│  # Fuzzy finder integration (fzf)                                  │
│  vf               # Interactive fuzzy search + copy                │
│  vfe              # Fuzzy search + exec                            │
│                                                                      │
│  ───────────────────────────────────────────────────────────────────│
│                                                                      │
│  MULTIPLE WEBSITE TAGGING                                           │
│  ─────────────────────────                                          │
│                                                                      │
│  # Entry with multiple URLs                                         │
│  vaultic add "Google Account" \                                     │
│    --url "https://google.com" \                                     │
│    --url "https://gmail.com" \                                      │
│    --url "https://drive.google.com" \                               │
│    --url "https://youtube.com"                                      │
│                                                                      │
│  # All URLs trigger credential fill                                │
│  # Browser extension matches any URL                                │
│                                                                      │
│  ───────────────────────────────────────────────────────────────────│
│                                                                      │
│  DIRENV INTEGRATION                                                  │
│  ──────────────────                                                  │
│                                                                      │
│  # .envrc in project directory                                     │
│  eval "$(vaultic exec "Project Secrets" --export)"                 │
│                                                                      │
│  # Automatically loads secrets when entering directory             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Entry Model Extension

```rust
struct VaultEntry {
    // ... existing fields ...

    // Multiple URLs for same credential
    urls: Vec<String>,

    // Custom fields for env injection
    custom_fields: HashMap<String, SensitiveString>,

    // Field mapping for exec
    env_mapping: Option<EnvMapping>,
}

struct EnvMapping {
    // Map entry fields to env var names
    mappings: HashMap<String, String>,
    // e.g., "password" -> "AWS_SECRET_ACCESS_KEY"
}
```

---

## 6. GPG Storage & Hardware Key Integration

### GPG Integration

```
┌─────────────────────────────────────────────────────────────────────┐
│                   GPG STORAGE INTEGRATION                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  GPG KEY AS UNLOCK METHOD                                           │
│  ────────────────────────                                           │
│                                                                      │
│  # Add GPG key as unlock method                                     │
│  vaultic unlock-method add gpg --key-id ABCD1234                   │
│                                                                      │
│  # Unlock with GPG key (uses gpg-agent)                            │
│  vaultic unlock --gpg                                               │
│                                                                      │
│  # Flow:                                                            │
│  1. Vault key encrypted with GPG public key                        │
│  2. On unlock, GPG decrypts vault key                              │
│  3. Works with hardware GPG (YubiKey OpenPGP)                      │
│                                                                      │
│  ───────────────────────────────────────────────────────────────────│
│                                                                      │
│  GPG-ENCRYPTED EXPORT                                               │
│  ────────────────────                                               │
│                                                                      │
│  # Export encrypted to recipient                                    │
│  vaultic export --gpg recipient@example.com backup.gpg             │
│                                                                      │
│  # Export encrypted to own key                                     │
│  vaultic export --gpg-self backup.gpg                              │
│                                                                      │
│  # Import GPG-encrypted backup                                     │
│  vaultic import backup.gpg --format gpg                            │
│                                                                      │
│  ───────────────────────────────────────────────────────────────────│
│                                                                      │
│  PASS COMPATIBILITY                                                  │
│  ──────────────────                                                  │
│                                                                      │
│  # Import from pass (GPG-encrypted password store)                 │
│  vaultic import ~/.password-store --format pass                    │
│                                                                      │
│  # Export to pass format                                           │
│  vaultic export ./password-store --format pass                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Seamless Hardware Key Setup

```
┌─────────────────────────────────────────────────────────────────────┐
│                   HARDWARE KEY SETUP WIZARD                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  vaultic setup hardware                                             │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                                                              │    │
│  │  🔑 Hardware Key Setup                                       │    │
│  │  ─────────────────────                                       │    │
│  │                                                              │    │
│  │  Detected devices:                                          │    │
│  │                                                              │    │
│  │    [1] YubiKey 5 NFC (Serial: 12345678)                    │    │
│  │        ├─ FIDO2: ✅ Available                               │    │
│  │        ├─ OpenPGP: ✅ Available                             │    │
│  │        └─ HMAC-SHA1: ✅ Slot 2 available                    │    │
│  │                                                              │    │
│  │    [2] YubiKey 5C (Serial: 87654321)                       │    │
│  │        ├─ FIDO2: ✅ Available                               │    │
│  │        └─ OpenPGP: ❌ Not configured                        │    │
│  │                                                              │    │
│  │  Select device [1]:                                         │    │
│  │                                                              │    │
│  │  ─────────────────────────────────────────────────────────  │    │
│  │                                                              │    │
│  │  Select authentication method:                              │    │
│  │                                                              │    │
│  │    [1] FIDO2/WebAuthn (recommended)                        │    │
│  │        Touch to authenticate, most secure                   │    │
│  │                                                              │    │
│  │    [2] HMAC-SHA1 Challenge-Response                        │    │
│  │        Touch to unlock, works offline                       │    │
│  │                                                              │    │
│  │    [3] OpenPGP Decryption                                  │    │
│  │        Uses existing GPG key on device                      │    │
│  │                                                              │    │
│  │  Select method [1]:                                         │    │
│  │                                                              │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  After setup:                                                        │
│                                                                      │
│  vaultic unlock                  # Auto-detects hardware key        │
│  vaultic unlock --touch          # Require hardware key             │
│  vaultic unlock --password       # Force password only              │
│                                                                      │
│  Hardware key provides:                                             │
│  • Phishing-resistant authentication                                │
│  • Touch requirement prevents malware                               │
│  • Key never leaves hardware                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. Enhanced TUI

### Main View with Status

```
┌─ Vaultic ─────────────────────────────────────────────────────────────┐
│                                                                        │
│  ╭─ Status ──────────────────────────────────────────────────────────╮│
│  │ 🔓 Unlocked │ ⏱️ 12:34 │ 🔑 YubiKey │ 📊 92/100 │ 🔄 Synced 5m ago ││
│  ╰───────────────────────────────────────────────────────────────────╯│
│                                                                        │
│  ╭─ Entries (24) ──────────────────────────────────────────────────╮  │
│  │                                                                  │  │
│  │  🔍 Search: _                                      [Tags ▼]     │  │
│  │  ───────────────────────────────────────────────────────────────│  │
│  │                                                                  │  │
│  │  ▸ 🌐 GitHub           dev@example.com     ●●●●●  [dev, work]  │  │
│  │    🌐 GitHub Work      admin@company.com   ●●●●●  [work]       │  │
│  │    ☁️  AWS Console      admin               ●●●●●  [cloud]      │  │
│  │    🔐 GPG Master Key   -                   -      [security]   │  │
│  │    💰 Bank Login       user1234            ●●●●●  [finance]    │  │
│  │                                                                  │  │
│  │  ───────────────────────────────────────────────────────────────│  │
│  │  5 of 24 │ Health: ████████░░ 92% │ Last backup: 2h ago        │  │
│  ╰─────────────────────────────────────────────────────────────────╯  │
│                                                                        │
│  ╭─ Quick Actions ─────────────────────────────────────────────────╮  │
│  │ [a]dd [e]dit [d]elete [g]enerate [s]ync [b]ackup [h]ealth [?]  │  │
│  ╰─────────────────────────────────────────────────────────────────╯  │
│                                                                        │
│  j/k:nav  /:search  Enter:view  y:copy  Tab:switch  ?:help  q:quit   │
└────────────────────────────────────────────────────────────────────────┘
```

### Detail View with TOTP

```
┌─ Vaultic ─────────────────────────────────────────────────────────────┐
│                                                                        │
│  ╭─ Entry: GitHub ─────────────────────────────────────────────────╮  │
│  │                                                                  │  │
│  │  Username:   dev@example.com                        [y] copy    │  │
│  │  Password:   ●●●●●●●●●●●●●●●●               [p] show [c] copy   │  │
│  │  URLs:       https://github.com              [o] open [1-3]     │  │
│  │              https://gist.github.com                            │  │
│  │              https://github.dev                                 │  │
│  │  TOTP:       483 291                   ████████░░ 18s  [t] copy │  │
│  │                                                                  │  │
│  │  ─────────────────────────────────────────────────────────────  │  │
│  │                                                                  │  │
│  │  Tags:       dev, work, code, git                               │  │
│  │  Folder:     Development                                        │  │
│  │  Strength:   ████████░░ Very Strong (127 bits)                 │  │
│  │  Created:    2026-01-01 10:30:00                                │  │
│  │  Modified:   2026-01-04 15:45:00                                │  │
│  │                                                                  │  │
│  │  ─────────────────────────────────────────────────────────────  │  │
│  │                                                                  │  │
│  │  Notes:                                                         │  │
│  │  Personal account for open source projects.                     │  │
│  │  SSH key: ~/.ssh/github_ed25519                                 │  │
│  │                                                                  │  │
│  │  AI Tags: #development #version-control #open-source            │  │
│  │                                                                  │  │
│  ╰─────────────────────────────────────────────────────────────────╯  │
│                                                                        │
│  [e]dit [d]elete [h]istory [x]exec [Esc] back                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Implementation Phases

### Phase 1: Key Hierarchy (Foundation) ⬅️ START HERE
- [ ] Implement VaultKey generation
- [ ] Implement KEK wrapping/unwrapping
- [ ] Add key storage format
- [ ] Migrate existing vaults
- [ ] Add `vaultic migrate` command

### Phase 2: Recovery Keys + QR
- [ ] Add BIP39 crate dependency
- [ ] Implement recovery key generation
- [ ] Add QR code terminal display (qrcode crate)
- [ ] Implement PDF/PNG export
- [ ] Add `vaultic recovery` subcommand
- [ ] Implement vault recovery flow

### Phase 3: Hardware Key (Seamless)
- [ ] Implement YubiKey detection
- [ ] Add FIDO2/WebAuthn support
- [ ] Add HMAC-SHA1 challenge-response
- [ ] Implement setup wizard
- [ ] Add `vaultic setup hardware` command

### Phase 4: Incremental Backups
- [ ] Implement delta backup format
- [ ] Add automatic local backups
- [ ] Implement backup rotation
- [ ] Add chunked cloud sync
- [ ] Add `vaultic backup` and `vaultic sync` commands

### Phase 5: GPG Integration
- [ ] Add GPG unlock method
- [ ] Implement GPG-encrypted export
- [ ] Add pass compatibility
- [ ] Integrate with gpg-agent

### Phase 6: AI Tagging
- [ ] Implement rule-based tagger
- [ ] Add tag suggestion engine
- [ ] Optional: Integrate small local model
- [ ] Add `vaultic tag` subcommand

### Phase 7: Shell Integration
- [ ] Implement `vaultic exec` with env injection
- [ ] Add SSH key management
- [ ] Generate shell aliases
- [ ] Add fzf integration
- [ ] Implement direnv support

### Phase 8: TUI Polish
- [ ] Add status bar with all indicators
- [ ] Add TOTP countdown animation
- [ ] Add inline editing
- [ ] Add multiple URL display
- [ ] Add theming support

---

## 9. File Format Summary

### Vault Directory (v2)

```
~/.vaultic/
├── vault.json                # Vault metadata
├── keys/
│   ├── password.key          # VK encrypted by password KEK
│   ├── recovery.key          # VK encrypted by recovery KEK
│   ├── yubikey-*.key         # VK encrypted by hardware KEK
│   └── gpg-*.key             # VK encrypted by GPG key
├── db/                       # Sled database (entries)
├── backups/
│   ├── manifest.json
│   ├── full/
│   └── incremental/
├── sync/
│   ├── manifest.json
│   └── chunks/
├── .session                  # Encrypted session
└── config.toml               # User preferences
```

### Config File

```toml
[session]
timeout_minutes = 15
auto_lock_on_idle = true
hardware_key_required = false

[backup]
enabled = true
retention_days = 30
full_interval_days = 7

[sync]
enabled = false
backend = "s3"
endpoint = "s3://bucket/vaultic"
auto_sync = true
interval_minutes = 30

[ai]
enabled = true
model = "rule-based"  # or "gemini-nano", "tinyllama"

[tui]
theme = "dark"
show_passwords = false
vim_mode = true

[shell]
aliases = true
fzf_integration = true
```
