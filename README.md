# 🔐 Vaultic

A lightweight, security-focused password manager written in Rust with hardware authentication, end-to-end encryption, and AI-powered management.

```
╔═══════════════════════════════════════════════════════════════╗
║  ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗██╗ ██████╗          ║
║  ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██║██╔════╝          ║
║  ██║   ██║███████║██║   ██║██║     ██║   ██║██║               ║
║  ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██║██║               ║
║   ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ██║╚██████╗          ║
║    ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝          ║
║                                                               ║
║  Local-first • Hardware Auth • AI-Powered • Zero Trust        ║
╚═══════════════════════════════════════════════════════════════╝
```

## ✨ Features

### 🔒 Security First
- **FIDO2/YubiKey Authentication** - Passwordless unlock with hardware keys
- **XChaCha20-Poly1305** - Military-grade authenticated encryption
- **Argon2id KDF** - Memory-hard key derivation (64MB-256MB)
- **Zero Memory Leaks** - Sensitive data auto-zeroed on drop
- **Local-Only** - No cloud, no servers, no third-party access

### 🤖 AI-Powered Management
- **Password Analysis** - Strength scoring, entropy calculation
- **Breach Detection** - Have I Been Pwned integration (k-anonymity)
- **Smart Suggestions** - Rotation reminders, organization tips
- **Local AI** - Ollama/llama.cpp support (your data never leaves)

### 🔗 Secure Sharing
- **End-to-End Encrypted** - X25519 key exchange
- **Perfect Forward Secrecy** - Ephemeral keys per share
- **One-Time Shares** - Self-destructing passwords
- **QR Code Support** - Easy mobile sharing

### 📟 Beautiful CLI
- **Fuzzy Search** - Find entries instantly
- **Interactive TUI** - Full terminal interface
- **Rich Output** - Colors, tables, progress indicators
- **Clipboard Integration** - Auto-clear after 30 seconds

## 🚀 Quick Start

```bash
# Build from source
cargo build --release

# Initialize a new vault
vaultic init

# Or with YubiKey
vaultic init --fido2

# Add your first password
vaultic add

# List all entries
vaultic list

# Search entries
vaultic search github

# Generate a secure password
vaultic generate --length 32 --copy

# Check for security issues
vaultic suggest --analyze
```

## 📖 Usage

### Vault Management

```bash
# Create vault with high-security KDF (256MB memory)
vaultic init --high-security

# Unlock vault (starts session)
vaultic unlock

# Lock vault
vaultic lock

# Check vault status
vaultic status
```

### Password Operations

```bash
# Add entry interactively
vaultic add

# Add with flags
vaultic add --name "GitHub" --username "user@email.com" --url "https://github.com"

# Get password (copies to clipboard)
vaultic get github --copy

# Show password in terminal
vaultic get github --show

# Generate QR code for sharing
vaultic get github --qr

# Edit entry
vaultic edit github

# Delete entry
vaultic delete github
```

### Search & Organization

```bash
# Fuzzy search
vaultic search git

# List by folder
vaultic list --folder work

# List favorites
vaultic list --favorites

# List weak passwords
vaultic list --weak

# List needing rotation
vaultic list --needs-rotation

# Filter by tags
vaultic list --tags "social,important"
```

### Password Generation

```bash
# Generate random password
vaultic generate

# Custom length
vaultic generate --length 24

# Passphrase (EFF wordlist)
vaultic generate --passphrase --words 6

# No ambiguous characters
vaultic generate --no-ambiguous

# Copy to clipboard
vaultic generate --copy
```

### Secure Sharing

```bash
# Share with another Vaultic user
vaultic share github --to alice@example.com

# One-time share (deleted after access)
vaultic share github --one-time

# Expiring share
vaultic share github --expires 24h

# Export your identity for sharing
vaultic identity export

# Add trusted identity
vaultic identity add --file alice.identity
```

### AI Suggestions

```bash
# Run full analysis
vaultic suggest --analyze

# Check for breached passwords
vaultic suggest --check-breaches

# Apply a suggestion
vaultic suggest apply <suggestion-id>
```

### Import/Export

```bash
# Export encrypted backup
vaultic export backup.vaultic

# Export to JSON (decrypted)
vaultic export passwords.json --format json

# Import from Bitwarden
vaultic import bitwarden_export.json --format bitwarden

# Import from 1Password
vaultic import 1password_export.csv --format 1password
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Commands│ │   TUI   │ │ Tables  │ │Progress │           │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
└───────┼──────────┼──────────┼──────────┼───────────────────┘
        │          │          │          │
┌───────┴──────────┴──────────┴──────────┴───────────────────┐
│                     Core Services                           │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Storage │ │ Crypto  │ │ Sharing │ │   AI    │           │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
└───────┼──────────┼──────────┼──────────┼───────────────────┘
        │          │          │          │
┌───────┴──────────┴──────────┴──────────┴───────────────────┐
│                   Authentication                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                       │
│  │  FIDO2  │ │ Argon2  │ │   GPG   │                       │
│  │ YubiKey │ │   KDF   │ │  Keys   │                       │
│  └─────────┘ └─────────┘ └─────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Security Model

### Encryption Stack
1. **Master Key Derivation**
   - Password → Argon2id (64/256MB memory) → 32-byte key
   - FIDO2 → HMAC-Secret extension → HKDF → 32-byte key

2. **Data Encryption**
   - HKDF derives separate encryption + authentication keys
   - XChaCha20-Poly1305 AEAD (256-bit key, 192-bit nonce)
   - Nonce prepended to ciphertext

3. **Sharing**
   - X25519 ephemeral key exchange
   - HKDF for shared secret derivation
   - Ed25519 signatures for authenticity

### Memory Safety
- All secrets wrapped in `SensitiveString` (auto-zeroed)
- No sensitive data in debug output
- Clipboard auto-cleared after timeout

### Storage
- Sled embedded database (ACID, crash-safe)
- All data encrypted at rest
- Audit logging for all operations

## 🛠️ Building

### Prerequisites
- Rust 1.70+ (for workspace features)
- pkg-config
- OpenSSL development libraries
- udev (Linux, for FIDO2)

### Linux
```bash
# Ubuntu/Debian
sudo apt install pkg-config libssl-dev libudev-dev

# Fedora
sudo dnf install pkg-config openssl-devel systemd-devel

# Build
cargo build --release
```

### macOS
```bash
brew install pkg-config openssl

cargo build --release
```

### Windows
```powershell
# Requires Visual Studio Build Tools
cargo build --release
```

## 📁 Configuration

Default vault location: `~/.vaultic/`

```bash
# Set custom location
export VAULTIC_HOME=/path/to/vault

# Enable debug logging
export VAULTIC_DEBUG=1
```

### Config Options
```bash
vaultic config set ai.backend ollama
vaultic config set ai.model llama3.2:3b
vaultic config set clipboard.timeout 60
vaultic config set password.rotation_days 90
```

## 🤝 Contributing

Contributions welcome! Please read the contributing guidelines first.

### Development
```bash
# Run tests
cargo test

# Run with debug logging
VAULTIC_DEBUG=1 cargo run -- <command>

# Format code
cargo fmt

# Lint
cargo clippy
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) - Cryptographic primitives
- [Sequoia PGP](https://sequoia-pgp.org/) - OpenPGP implementation
- [Have I Been Pwned](https://haveibeenpwned.com/) - Breach checking API
- [EFF Wordlist](https://www.eff.org/dice) - Passphrase generation

---

**⚠️ Security Notice**: This is a security-sensitive application. Please review the code before using it with real credentials. Report vulnerabilities responsibly.
