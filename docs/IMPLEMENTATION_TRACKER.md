# Vaultic v2.0 Implementation Tracker

## Status Overview

| Phase | Feature | Status | Priority | Dependencies |
|-------|---------|--------|----------|--------------|
| 1 | Key Hierarchy | 🔵 Planned | Critical | None (foundation) |
| 2 | Recovery Keys + QR | 🔵 Planned | High | Phase 1 |
| 3 | Hardware Key Setup | 🔵 Planned | High | Phase 1 |
| 4 | Incremental Backups | 🔵 Planned | Medium | Phase 1 |
| 5 | GPG Integration | 🔵 Planned | Medium | Phase 1 |
| 6 | AI Tagging | 🔵 Planned | Medium | None |
| 7 | Shell Integration | 🔵 Planned | High | None |
| 8 | TUI Polish | 🔵 Planned | Low | All above |

**Legend:** ⬜ Not Started | 🔵 Planned | 🟡 In Progress | 🟢 Complete | 🔴 Blocked

---

## Phase 1: Key Hierarchy (Foundation)

### Overview
Implement multi-method unlock system with VaultKey wrapped by multiple KEKs.

### New Files to Create

```
src/crypto/
├── keys.rs          # VaultKey, KeyEncryptionKey, EncryptedVaultKey
├── kek.rs           # KEK derivation (Argon2id, HKDF)
└── wrap.rs          # Key wrapping/unwrapping with XChaCha20-Poly1305

src/storage/
└── keyring.rs       # Keyring persistence and management

src/migration/
└── mod.rs           # V1 to V2 vault migration
```

### Core Data Structures

```rust
// src/crypto/keys.rs

use zeroize::{Zeroize, ZeroizeOnDrop};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Master vault key - generated once, never changes
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Generate new random vault key
    pub fn generate() -> Self;

    /// Create from raw bytes (recovery/migration)
    pub fn from_bytes(bytes: [u8; 32]) -> Self;

    /// Get bytes for encryption operations
    pub fn expose(&self) -> &[u8; 32];
}

/// Key Encryption Key - derives from unlock method
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey([u8; 32]);

impl KeyEncryptionKey {
    /// Derive from password using Argon2id
    pub fn from_password(password: &str, salt: &[u8], params: &KdfParams) -> Self;

    /// Derive from BIP39 seed using HKDF
    pub fn from_recovery_seed(seed: &[u8], salt: &[u8]) -> Self;

    /// Derive from hardware key HMAC
    pub fn from_hardware_response(response: &[u8], salt: &[u8]) -> Self;

    /// Wrap a vault key
    pub fn wrap(&self, vault_key: &VaultKey) -> Result<EncryptedVaultKey>;

    /// Unwrap a vault key
    pub fn unwrap(&self, encrypted: &EncryptedVaultKey) -> Result<VaultKey>;
}

/// Supported unlock methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnlockMethod {
    Password,
    RecoveryKey,
    YubiKey { slot: u8 },
    Passkey { credential_id: Vec<u8> },
    GpgKey { key_id: String },
}

/// Method-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MethodData {
    Password { salt: [u8; 32], params: KdfParams },
    Recovery { salt: [u8; 32], created_at: DateTime<Utc> },
    YubiKey { serial: u32, slot: u8, challenge: [u8; 32] },
    Passkey { credential_id: Vec<u8>, public_key: Vec<u8> },
    Gpg { key_id: String, fingerprint: String },
}

/// Encrypted vault key with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVaultKey {
    pub id: Uuid,
    pub method: UnlockMethod,
    pub ciphertext: Vec<u8>,    // 32 bytes VK + 16 bytes tag
    pub nonce: [u8; 24],
    pub method_data: MethodData,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub label: Option<String>,  // User-friendly name
}

/// Collection of all unlock methods for a vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyring {
    pub vault_id: Uuid,
    pub version: u32,           // Format version (2 for new system)
    pub keys: Vec<EncryptedVaultKey>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl VaultKeyring {
    /// Add a new unlock method
    pub fn add_key(&mut self, encrypted: EncryptedVaultKey);

    /// Remove an unlock method by ID
    pub fn remove_key(&mut self, id: &Uuid) -> Result<()>;

    /// Find encrypted key for a method
    pub fn find_by_method(&self, method: &UnlockMethod) -> Option<&EncryptedVaultKey>;

    /// Check if password method exists
    pub fn has_password(&self) -> bool;

    /// Check if recovery method exists
    pub fn has_recovery(&self) -> bool;
}
```

### CLI Commands

```bash
# New unlock method management
vaultic unlock-method list           # List all unlock methods
vaultic unlock-method add password   # Add password (prompts)
vaultic unlock-method add recovery   # Generate recovery key
vaultic unlock-method add yubikey    # Setup YubiKey
vaultic unlock-method add gpg        # Add GPG key
vaultic unlock-method remove <id>    # Remove method
vaultic unlock-method rename <id> "name"

# Enhanced unlock
vaultic unlock                       # Auto-detect best method
vaultic unlock --password            # Force password
vaultic unlock --recovery            # Use recovery key
vaultic unlock --touch               # Require hardware key
vaultic unlock --gpg                 # Use GPG key

# Migration
vaultic migrate                      # Upgrade v1 vault to v2
vaultic migrate --dry-run            # Preview migration
```

### Migration Strategy

```rust
// src/migration/mod.rs

pub struct MigrationV1ToV2 {
    vault_path: PathBuf,
}

impl MigrationV1ToV2 {
    /// Check if vault needs migration
    pub fn needs_migration(&self) -> Result<bool>;

    /// Perform migration
    pub fn migrate(&self, password: &str) -> Result<MigrationReport> {
        // 1. Read existing kdf_params.json
        // 2. Derive old master key from password
        // 3. Generate new VaultKey (random)
        // 4. Re-encrypt all entries with VaultKey
        // 5. Create EncryptedVaultKey for password
        // 6. Write new keyring.json
        // 7. Backup old format
        // 8. Return report with entry count
    }

    /// Rollback migration
    pub fn rollback(&self) -> Result<()>;
}

pub struct MigrationReport {
    pub entries_migrated: usize,
    pub old_format_backed_up: PathBuf,
    pub new_keyring_created: bool,
}
```

### Storage Format

```
~/.vaultic/
├── keyring.json              # NEW: VaultKeyring serialized
├── keys/                     # NEW: Per-method encrypted keys
│   ├── password.key
│   ├── recovery.key
│   └── yubikey-12345.key
├── db/                       # Unchanged: Sled database
├── kdf_params.json           # DEPRECATED: Kept for migration
└── .session                  # Unchanged
```

### Test Cases

```rust
#[test]
fn test_vault_key_generation() {
    let vk = VaultKey::generate();
    assert_eq!(vk.expose().len(), 32);
}

#[test]
fn test_kek_wrap_unwrap() {
    let vk = VaultKey::generate();
    let kek = KeyEncryptionKey::from_password("test", &salt, &params);
    let encrypted = kek.wrap(&vk).unwrap();
    let unwrapped = kek.unwrap(&encrypted).unwrap();
    assert_eq!(vk.expose(), unwrapped.expose());
}

#[test]
fn test_multiple_unlock_methods() {
    let mut keyring = VaultKeyring::new();
    let vk = VaultKey::generate();

    // Add password method
    let kek_pass = KeyEncryptionKey::from_password("pass", &salt, &params);
    keyring.add_key(kek_pass.wrap(&vk).unwrap());

    // Add recovery method
    let kek_recv = KeyEncryptionKey::from_recovery_seed(&seed, &salt);
    keyring.add_key(kek_recv.wrap(&vk).unwrap());

    assert!(keyring.has_password());
    assert!(keyring.has_recovery());
}

#[test]
fn test_migration_v1_to_v2() {
    let migrator = MigrationV1ToV2::new(&vault_path);
    let report = migrator.migrate("password").unwrap();
    assert!(report.entries_migrated > 0);
}
```

---

## Phase 2: Recovery Keys + QR

### Overview
BIP39 24-word mnemonic with terminal QR display and PDF export.

### New Files to Create

```
src/recovery/
├── mod.rs           # RecoveryManager, public API
├── mnemonic.rs      # BIP39 wrapper with Zeroize
├── kek.rs           # HKDF-based KEK derivation
├── qr.rs            # Terminal QR + PNG generation
└── export.rs        # PDF export with printpdf
```

### Dependencies to Add

```toml
# Cargo.toml
[dependencies]
bip39 = "2.0"
qrcode = "0.14"
image = { version = "0.25", default-features = false, features = ["png"] }
printpdf = { version = "0.7", optional = true }

[features]
pdf-export = ["printpdf"]
```

### Core Data Structures

```rust
// src/recovery/mod.rs

use bip39::{Mnemonic, Language};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Manages recovery key generation, display, and verification
pub struct RecoveryManager {
    vault_path: PathBuf,
}

impl RecoveryManager {
    /// Generate new recovery key (24 words)
    pub fn generate(&self) -> Result<RecoveryKeyBundle>;

    /// Show existing recovery key (requires unlock)
    pub fn show(&self, master_key: &VaultKey) -> Result<RecoveryKeyBundle>;

    /// Verify recovery key works
    pub fn verify(&self, words: &str) -> Result<bool>;

    /// Recover vault with mnemonic
    pub fn recover(&self, words: &str, new_password: &str) -> Result<()>;

    /// Revoke recovery key
    pub fn revoke(&self, master_key: &VaultKey) -> Result<()>;
}

/// Bundle containing recovery key in multiple formats
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKeyBundle {
    mnemonic: Mnemonic,
    #[zeroize(skip)]
    qr_data: Option<Vec<u8>>,
}

impl RecoveryKeyBundle {
    /// Get words as numbered list
    pub fn words_formatted(&self) -> String;

    /// Get words as single string
    pub fn words_raw(&self) -> &str;

    /// Render QR code to terminal
    pub fn display_qr_terminal(&self);

    /// Export QR code as PNG
    pub fn export_qr_png(&self, path: &Path) -> Result<()>;

    /// Export as printable PDF
    #[cfg(feature = "pdf-export")]
    pub fn export_pdf(&self, path: &Path, vault_name: &str) -> Result<()>;
}

/// Metadata stored with recovery key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKeyMetadata {
    pub created_at: DateTime<Utc>,
    pub last_verified: Option<DateTime<Utc>>,
    pub fingerprint: String,  // First 4 words hash for identification
}
```

### CLI Commands

```bash
# Generate recovery key
vaultic recovery generate              # Show words + QR
vaultic recovery generate --words-only # Words only
vaultic recovery generate --qr-only    # QR only

# Show existing recovery key (requires unlock)
vaultic recovery show                  # Show words + QR
vaultic recovery show --words          # Words only
vaultic recovery show --qr             # QR only

# Export
vaultic recovery export recovery.pdf   # PDF for printing
vaultic recovery export recovery.png   # QR code image

# Verify
vaultic recovery verify                # Interactive verify

# Recover vault (forgot password)
vaultic recover                        # Interactive
vaultic recover --words "word1 word2..." --new-password "newpass"

# Revoke
vaultic recovery revoke                # Remove recovery key
```

### Terminal QR Display

```rust
// src/recovery/qr.rs

use qrcode::{QrCode, render::unicode};

pub fn render_qr_terminal(data: &str) -> String {
    let code = QrCode::new(data.as_bytes()).unwrap();
    code.render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build()
}

pub fn display_recovery_screen(bundle: &RecoveryKeyBundle, vault_name: &str) {
    println!("╭─ Recovery Key for \"{}\" ─────────────────────────────╮", vault_name);
    println!("│                                                       │");

    // Show QR on left, words on right
    let qr_lines = render_qr_terminal(&bundle.words_raw());
    let words: Vec<_> = bundle.words_raw().split_whitespace().collect();

    // Print side by side...
    println!("│                                                       │");
    println!("│  ⚠️  Store these safely - they unlock your vault!     │");
    println!("╰───────────────────────────────────────────────────────╯");
}
```

### Test Cases

```rust
#[test]
fn test_recovery_key_generation() {
    let rm = RecoveryManager::new(&vault_path);
    let bundle = rm.generate().unwrap();
    assert_eq!(bundle.words_raw().split_whitespace().count(), 24);
}

#[test]
fn test_recovery_key_derive_kek() {
    let mnemonic = Mnemonic::parse("abandon abandon ...").unwrap();
    let seed = mnemonic.to_seed("");
    let kek = KeyEncryptionKey::from_recovery_seed(&seed, &salt);
    // Verify KEK can wrap/unwrap
}

#[test]
fn test_vault_recovery_flow() {
    // 1. Create vault with password
    // 2. Generate recovery key
    // 3. Lock vault
    // 4. Recover with mnemonic + new password
    // 5. Verify entries still accessible
}

#[test]
fn test_qr_generation() {
    let bundle = RecoveryKeyBundle::generate();
    let qr_png = bundle.export_qr_png(Path::new("/tmp/test.png"));
    assert!(qr_png.is_ok());
}
```

---

## Phase 6: AI Tagging

### Overview
Rule-based pattern matching for automatic tag suggestions with optional local AI model.

### New Files to Create

```
src/tagging/
├── mod.rs           # TagManager, public API
├── pattern.rs       # Pattern enum and matching
├── category.rs      # Built-in categories and rules
├── matcher.rs       # Pattern matching engine
└── suggest.rs       # Suggestion generation
```

### Core Data Structures

```rust
// src/tagging/pattern.rs

/// Pattern types for matching entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Pattern {
    /// Exact domain match
    Domain(String),
    /// Domain suffix (.edu, .gov)
    DomainSuffix(String),
    /// URL contains substring
    UrlContains(String),
    /// Name contains substring (case-insensitive)
    NameContains(String),
    /// Built-in category
    Category(Category),
    /// All patterns must match
    All(Vec<Pattern>),
    /// Any pattern must match
    Any(Vec<Pattern>),
    /// Negate pattern
    Not(Box<Pattern>),
}

impl Pattern {
    /// Test if pattern matches entry
    pub fn matches(&self, entry: &VaultEntry) -> bool;
}

// src/tagging/category.rs

/// Built-in categories with predefined patterns
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Category {
    Development,
    Cloud,
    Finance,
    Social,
    Email,
    Shopping,
    Entertainment,
    Work,
    Gaming,
    Education,
    Government,
    Healthcare,
    Security,
    Communication,
    News,
}

impl Category {
    /// Get patterns for this category
    pub fn patterns(&self) -> Vec<Pattern> {
        match self {
            Category::Development => vec![
                Pattern::Domain("github.com".into()),
                Pattern::Domain("gitlab.com".into()),
                Pattern::Domain("bitbucket.org".into()),
                Pattern::Domain("stackoverflow.com".into()),
                Pattern::UrlContains("api".into()),
                Pattern::NameContains("dev".into()),
            ],
            Category::Cloud => vec![
                Pattern::Domain("aws.amazon.com".into()),
                Pattern::Domain("console.cloud.google.com".into()),
                Pattern::Domain("portal.azure.com".into()),
                Pattern::Domain("digitalocean.com".into()),
                Pattern::NameContains("cloud".into()),
            ],
            // ... more categories
        }
    }

    /// Get suggested tags for this category
    pub fn suggested_tags(&self) -> Vec<&'static str> {
        match self {
            Category::Development => vec!["dev", "code", "programming"],
            Category::Cloud => vec!["cloud", "infrastructure", "devops"],
            Category::Finance => vec!["finance", "banking", "money"],
            // ...
        }
    }
}

// src/tagging/mod.rs

/// Tag rule with patterns and suggested tags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRule {
    pub name: String,
    pub patterns: Vec<Pattern>,
    pub suggested_tags: Vec<String>,
    pub priority: i32,
    pub enabled: bool,
}

/// Manages tag suggestions and auto-tagging
pub struct TagManager {
    rules: Vec<TagRule>,
    custom_rules: Vec<TagRule>,
}

impl TagManager {
    /// Load default rules + custom rules
    pub fn new() -> Self;

    /// Get tag suggestions for an entry
    pub fn suggest(&self, entry: &VaultEntry) -> Vec<TagSuggestion>;

    /// Auto-tag all entries
    pub fn auto_tag_all(&self, storage: &mut VaultStorage) -> Result<AutoTagReport>;

    /// Add custom rule
    pub fn add_rule(&mut self, rule: TagRule);

    /// Search entries by tags
    pub fn search_by_tags(&self, storage: &VaultStorage, tags: &[&str]) -> Vec<VaultEntry>;
}

#[derive(Debug, Clone)]
pub struct TagSuggestion {
    pub tag: String,
    pub confidence: f32,  // 0.0 - 1.0
    pub reason: String,   // "Matched pattern: github.com"
}

pub struct AutoTagReport {
    pub entries_processed: usize,
    pub tags_added: usize,
    pub entries_modified: Vec<String>,
}
```

### Built-in Rules

```rust
// src/tagging/category.rs

pub fn default_rules() -> Vec<TagRule> {
    vec![
        TagRule {
            name: "development".into(),
            patterns: vec![
                Pattern::Category(Category::Development),
            ],
            suggested_tags: vec!["dev", "code"],
            priority: 10,
            enabled: true,
        },
        TagRule {
            name: "cloud-services".into(),
            patterns: vec![
                Pattern::Category(Category::Cloud),
            ],
            suggested_tags: vec!["cloud", "infra"],
            priority: 10,
            enabled: true,
        },
        TagRule {
            name: "financial".into(),
            patterns: vec![
                Pattern::Category(Category::Finance),
                Pattern::NameContains("bank".into()),
                Pattern::NameContains("credit".into()),
                Pattern::NameContains("invest".into()),
            ],
            suggested_tags: vec!["finance", "sensitive"],
            priority: 20,  // Higher priority for sensitive
            enabled: true,
        },
        // ... 15+ more rules
    ]
}
```

### CLI Commands

```bash
# Tag suggestions
vaultic tag suggest "GitHub"           # Suggest tags for entry
vaultic tag suggest "GitHub" --apply   # Apply suggested tags
vaultic tag suggest --all              # Suggest for all entries

# Auto-tagging
vaultic tag auto                       # Auto-tag all entries
vaultic tag auto --dry-run             # Preview without applying
vaultic tag auto --force               # Override existing tags

# Search
vaultic tag search "dev,cloud"         # AND search
vaultic tag search "dev|cloud"         # OR search
vaultic tag search "dev -personal"     # Exclude tag

# Management
vaultic tag list                       # List all tags with counts
vaultic tag rename old-tag new-tag     # Rename across entries
vaultic tag delete unused-tag          # Remove from all entries
vaultic tag merge tag1 tag2 target     # Merge tags

# Rules
vaultic tag rules                      # List all rules
vaultic tag rules add --name "custom" --pattern "*.internal.com" --tags "work,internal"
vaultic tag rules disable "rule-name"
```

### Test Cases

```rust
#[test]
fn test_domain_pattern() {
    let pattern = Pattern::Domain("github.com".into());
    let entry = VaultEntry { url: Some("https://github.com/user".into()), ..Default::default() };
    assert!(pattern.matches(&entry));
}

#[test]
fn test_category_matching() {
    let entry = VaultEntry {
        name: "AWS Console".into(),
        url: Some("https://console.aws.amazon.com".into()),
        ..Default::default()
    };
    assert!(Category::Cloud.matches(&entry));
}

#[test]
fn test_tag_suggestions() {
    let manager = TagManager::new();
    let entry = VaultEntry {
        name: "GitHub".into(),
        url: Some("https://github.com".into()),
        ..Default::default()
    };
    let suggestions = manager.suggest(&entry);
    assert!(suggestions.iter().any(|s| s.tag == "dev"));
}

#[test]
fn test_auto_tag_all() {
    let manager = TagManager::new();
    let report = manager.auto_tag_all(&mut storage).unwrap();
    assert!(report.tags_added > 0);
}
```

---

## Phase 7: Shell Integration

### Overview
Developer-friendly shell commands with environment injection, SSH management, and fzf integration.

### New Files to Create

```
src/shell/
├── mod.rs           # Module root and exports
├── exec.rs          # EnvInjector, ExecRunner
├── ssh.rs           # SshKeyManager, SshAgent integration
├── aliases.rs       # Shell alias generation
└── direnv.rs        # Direnv support

src/models/mod.rs    # Extended with urls, env_mapping, ssh_key_data
```

### Model Extensions

```rust
// src/models/mod.rs - additions

/// Extended VaultEntry with multi-URL and env support
pub struct VaultEntry {
    // ... existing fields ...

    /// Multiple URLs for same credential
    pub urls: Vec<String>,

    /// Environment variable mapping for exec
    pub env_mapping: Option<EnvMapping>,

    /// SSH key data (if this entry is an SSH key)
    pub ssh_key_data: Option<SshKeyData>,
}

/// Maps entry fields to environment variables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvMapping {
    /// Map field name to env var name
    /// e.g., "password" -> "AWS_SECRET_ACCESS_KEY"
    pub mappings: HashMap<String, String>,
}

/// SSH key stored in vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyData {
    pub key_type: SshKeyType,
    pub private_key: SensitiveString,  // Encrypted
    pub public_key: String,
    pub fingerprint: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SshKeyType {
    Ed25519,
    Rsa,
    Ecdsa,
}
```

### Core Components

```rust
// src/shell/exec.rs

use std::process::Command;
use std::collections::HashMap;

/// Injects vault entries as environment variables
pub struct EnvInjector {
    storage: VaultStorage,
}

impl EnvInjector {
    /// Get env vars for entry
    pub fn get_env(&self, entry_name: &str) -> Result<HashMap<String, String>>;

    /// Get env vars with template
    pub fn get_env_templated(&self, entry_name: &str, template: &str) -> Result<HashMap<String, String>>;

    /// Export format for shell
    pub fn export_string(&self, entry_name: &str) -> Result<String>;
}

/// Runs commands with injected environment
pub struct ExecRunner {
    injector: EnvInjector,
}

impl ExecRunner {
    /// Run command with single entry's env
    pub fn run(&self, entry_name: &str, command: &[&str]) -> Result<ExitStatus>;

    /// Run with multiple entries
    pub fn run_multi(&self, entry_names: &[&str], command: &[&str]) -> Result<ExitStatus>;

    /// Run with template
    pub fn run_templated(&self, entry_name: &str, template: &str, command: &[&str]) -> Result<ExitStatus>;
}

// src/shell/ssh.rs

use std::process::Command;

/// Manages SSH keys in vault
pub struct SshKeyManager {
    storage: VaultStorage,
}

impl SshKeyManager {
    /// Import SSH key into vault
    pub fn add(&self, key_path: &Path, name: &str, passphrase: Option<&str>) -> Result<()>;

    /// Export SSH key to file
    pub fn export(&self, name: &str, path: &Path) -> Result<()>;

    /// List SSH keys in vault
    pub fn list(&self) -> Result<Vec<SshKeyInfo>>;

    /// Get public key
    pub fn get_public_key(&self, name: &str) -> Result<String>;
}

/// Integrates with ssh-agent
pub struct SshAgent {
    socket_path: Option<PathBuf>,
}

impl SshAgent {
    /// Add key to running ssh-agent
    pub fn add_key(&self, key_data: &SshKeyData, lifetime: Option<Duration>) -> Result<()>;

    /// Remove key from agent
    pub fn remove_key(&self, fingerprint: &str) -> Result<()>;

    /// List keys in agent
    pub fn list_keys(&self) -> Result<Vec<String>>;
}

// src/shell/aliases.rs

/// Generates shell aliases and functions
pub struct AliasGenerator;

impl AliasGenerator {
    /// Generate for bash
    pub fn bash(with_fzf: bool) -> String;

    /// Generate for zsh
    pub fn zsh(with_fzf: bool) -> String;

    /// Generate for fish
    pub fn fish(with_fzf: bool) -> String;
}
```

### Generated Aliases

```bash
# Generated by: vaultic shell-init bash

# Basic aliases
alias vg='vaultic get'
alias va='vaultic add'
alias vs='vaultic search'
alias vt='vaultic tui'
alias vl='vaultic list'

# Exec wrapper
vexec() {
    vaultic exec "$1" -- "${@:2}"
}

# FZF integration
if command -v fzf &> /dev/null; then
    vf() {
        local entry
        entry=$(vaultic list --json | jq -r '.[].name' | fzf --preview 'vaultic get {} --show-info')
        [ -n "$entry" ] && vaultic get "$entry" --copy
    }

    vfe() {
        local entry
        entry=$(vaultic list --json | jq -r '.[].name' | fzf)
        [ -n "$entry" ] && vaultic exec "$entry" -- "${@:1}"
    }
fi
```

### CLI Commands

```bash
# Environment injection
vaultic exec "AWS" -- aws s3 ls
vaultic exec "AWS,GitHub" -- bash              # Multiple entries
vaultic exec "DB" --template "DATABASE_URL=postgres://{{username}}:{{password}}@{{url}}/db" -- psql
vaultic exec "API" --export                     # Print export statements

# SSH management
vaultic ssh add ~/.ssh/id_ed25519 --name "GitHub SSH"
vaultic ssh add ~/.ssh/work_rsa --name "Work SSH" --passphrase
vaultic ssh list
vaultic ssh get "GitHub SSH" --public           # Print public key
vaultic ssh export "GitHub SSH" /tmp/key        # Export private key
vaultic ssh agent add "GitHub SSH"              # Add to ssh-agent
vaultic ssh agent add "GitHub SSH" --lifetime 1h
vaultic ssh agent list
vaultic ssh agent remove "GitHub SSH"
vaultic ssh connect "GitHub SSH" git@github.com # Wrapper for ssh

# Shell integration
vaultic shell-init bash >> ~/.bashrc
vaultic shell-init bash --fzf >> ~/.bashrc      # With fzf integration
vaultic shell-init zsh >> ~/.zshrc
vaultic shell-init fish >> ~/.config/fish/config.fish

# Direnv
vaultic direnv "Project Secrets"                # Generate .envrc content
```

### Test Cases

```rust
#[test]
fn test_env_injection() {
    let entry = VaultEntry {
        name: "AWS".into(),
        username: Some("AKIA...".into()),
        password: SensitiveString::new("secret"),
        custom_fields: vec![
            ("access_key_id".into(), SensitiveString::new("AKIA...")),
            ("secret_access_key".into(), SensitiveString::new("secret")),
        ].into_iter().collect(),
        env_mapping: Some(EnvMapping {
            mappings: vec![
                ("access_key_id".into(), "AWS_ACCESS_KEY_ID".into()),
                ("secret_access_key".into(), "AWS_SECRET_ACCESS_KEY".into()),
            ].into_iter().collect(),
        }),
        ..Default::default()
    };

    let injector = EnvInjector::new(&storage);
    let env = injector.get_env("AWS").unwrap();
    assert_eq!(env.get("AWS_ACCESS_KEY_ID"), Some(&"AKIA...".into()));
}

#[test]
fn test_ssh_key_import() {
    let manager = SshKeyManager::new(&storage);
    manager.add(Path::new("~/.ssh/id_ed25519"), "Test Key", None).unwrap();

    let keys = manager.list().unwrap();
    assert!(keys.iter().any(|k| k.name == "Test Key"));
}

#[test]
fn test_exec_command() {
    let runner = ExecRunner::new(&storage);
    let status = runner.run("Test", &["echo", "hello"]).unwrap();
    assert!(status.success());
}

#[test]
fn test_alias_generation() {
    let bash = AliasGenerator::bash(true);
    assert!(bash.contains("alias vg="));
    assert!(bash.contains("fzf"));
}
```

---

## Consolidated Task List

### Immediate (Phase 1 - Foundation)
- [ ] Create `src/crypto/keys.rs` with VaultKey, KEK structs
- [ ] Create `src/crypto/kek.rs` with derivation functions
- [ ] Create `src/crypto/wrap.rs` with wrapping/unwrapping
- [ ] Create `src/storage/keyring.rs` for persistence
- [ ] Create `src/migration/mod.rs` for v1 → v2
- [ ] Add `unlock-method` subcommand to CLI
- [ ] Update `unlock` command for multi-method
- [ ] Write migration tests
- [ ] Update storage format documentation

### Next (Phases 2, 6, 7 - Can Parallelize)
**Recovery Keys:**
- [ ] Add bip39, qrcode dependencies
- [ ] Create `src/recovery/` module
- [ ] Implement mnemonic generation
- [ ] Implement QR terminal display
- [ ] Add `recovery` subcommand
- [ ] Write recovery flow tests

**AI Tagging:**
- [ ] Create `src/tagging/` module
- [ ] Implement Pattern enum and matching
- [ ] Implement Category enum with patterns
- [ ] Implement TagManager
- [ ] Add `tag` subcommand
- [ ] Write pattern matching tests

**Shell Integration:**
- [ ] Create `src/shell/` module
- [ ] Implement EnvInjector
- [ ] Implement SshKeyManager
- [ ] Implement AliasGenerator
- [ ] Extend VaultEntry with urls, env_mapping
- [ ] Add `exec`, `ssh`, `shell-init` commands
- [ ] Write integration tests

---

## Context Preservation Notes

This tracker consolidates outputs from 4 parallel planning agents:
1. **Phase 1 Agent** - Key hierarchy architecture
2. **Phase 2 Agent** - Recovery keys + BIP39 + QR
3. **Phase 6 Agent** - AI tagging with rule engine
4. **Phase 7 Agent** - Shell integration + SSH + env

All implementation plans are complete and ready for execution. Phase 1 (Key Hierarchy) should be implemented first as it's the foundation for phases 2-5.

### TOTP QR Code Scanning (Completed 2026-02-08)

**New Feature:** Full TOTP QR code scanning support added.

**Files Modified:**
- `Cargo.toml` - Added `rqrr = "0.9"`, `jpeg` feature on `image` crate
- `src/totp/mod.rs` - Added `scan_qr_image()`, accessor methods, `QrCodeError`
- `src/cli/mod.rs` - Added `totp scan`/`totp show` subcommands, `--totp-secret`/`--totp-uri` flags on `add`, TOTP display in entry view
- `tests/integration_tests.rs` - 3 new TOTP integration tests

**New Commands:**
```bash
vaultic totp scan <image.png>              # Scan QR code, create/attach entry
vaultic totp scan <image.png> --entry X    # Attach to existing entry
vaultic totp scan <image.png> --dry-run    # Decode without saving
vaultic totp show <query>                  # Show TOTP code with countdown
vaultic totp show <query> --watch          # Live countdown
vaultic totp show <query> --copy           # Copy to clipboard
vaultic add "X" --totp-secret "BASE32"     # Add with TOTP secret
vaultic add "X" --totp-uri "otpauth://..." # Add with otpauth URI
```

**Test Results:** 291 tests passing (122 bin + 120 lib + 44 integration + 5 doc)

---

**Last Updated:** 2026-02-08
**Session Branch:** `main`
