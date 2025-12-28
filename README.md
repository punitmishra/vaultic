# Vaultic

A lightweight, security-focused password manager written in Rust with hardware authentication, end-to-end encryption, and AI-powered management.

```
 ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗██╗ ██████╗
 ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██║██╔════╝
 ██║   ██║███████║██║   ██║██║     ██║   ██║██║
 ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██║██║
  ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ██║╚██████╗
   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝

 Local-first | Hardware Auth | AI-Powered | Zero Trust
```

## Demo

### Quick Start (Full Workflow)

[![asciicast](https://asciinema.org/a/placeholder-quickstart.svg)](https://asciinema.org/a/placeholder-quickstart)

```bash
# Initialize vault
vaultic init --name "My Vault" --password "secure-password"

# Unlock (creates 15-min session)
vaultic unlock --password "secure-password"

# Add entries
vaultic add "GitHub" -u "user@example.com" -p "secret" --tags "dev"
vaultic add "AWS" -u "admin" --generate --url "https://aws.amazon.com"

# List entries
vaultic list

# Check status
vaultic status

# Lock when done
vaultic lock
```

### Password Generation

[![asciicast](https://asciinema.org/a/placeholder-generate.svg)](https://asciinema.org/a/placeholder-generate)

```bash
# Default 20-char password with entropy analysis
vaultic generate

# Custom length
vaultic generate --length 32

# Alphanumeric only
vaultic generate --no-symbols

# PIN-style
vaultic generate --length 6 --no-uppercase --no-lowercase --no-symbols
```

**View demos locally:**
```bash
# Install asciinema
brew install asciinema  # macOS
apt install asciinema   # Linux

# Play recordings
asciinema play demos/quickstart.cast
asciinema play demos/generate.cast
```

---

## Features

### Security
- **XChaCha20-Poly1305** - Authenticated encryption with 256-bit keys
- **Argon2id KDF** - Memory-hard key derivation (64MB default)
- **Compressed Sessions** - DEFLATE-compressed, encrypted session files
- **Zero Memory Leaks** - Sensitive data auto-zeroed with `zeroize`
- **Local-Only** - No cloud, no servers, your data stays with you

### Implemented
| Feature | Status |
|---------|--------|
| Vault init/unlock/lock | Working |
| Session management | Working |
| Add/List entries | Working |
| Password generation | Working |
| Tag/folder filtering | Working |
| TOTP/2FA support | Working |
| GPG key integration | Working |
| X25519 key exchange | Working |
| QR code generation | Working |
| AI analysis (Ollama) | Ready |

### Coming Soon
| Feature | Status |
|---------|--------|
| Interactive TUI | Planned |
| Import (Bitwarden/1Password) | Planned |
| Export formats | Planned |
| FIDO2/YubiKey | Needs hardware |
| Breach checking (HIBP) | Planned |

---

## Installation

### From Source (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/vaultic.git
cd vaultic

# Build release binary
cargo build --release

# Install to PATH (optional)
cp target/release/vaultic /usr/local/bin/

# Verify installation
vaultic --version
```

### Prerequisites

**macOS:**
```bash
brew install nettle pkg-config
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install pkg-config libssl-dev libudev-dev libnettle-dev
```

---

## Usage

### Vault Management

```bash
# Create a new vault
vaultic init --name "Personal"

# Create with high-security KDF (256MB memory)
vaultic init --name "Work" --high-security

# Unlock vault (default: 15 minute session)
vaultic unlock

# Unlock with custom timeout
vaultic unlock --timeout 60

# Check status
vaultic status

# Lock vault
vaultic lock
```

### Password Entries

```bash
# Add entry interactively
vaultic add "Service Name"

# Add with all options
vaultic add "GitHub" \
  --username "user@example.com" \
  --password "your-password" \
  --url "https://github.com" \
  --tags "dev,work" \
  --folder "Development"

# Add with generated password
vaultic add "New Service" -u "user" --generate --length 24

# List all entries
vaultic list

# Filter by tags
vaultic list --tags "work"

# Filter by folder
vaultic list --folder "Development"
```

### Password Generation

```bash
# Generate secure password (20 chars)
vaultic generate

# Custom length
vaultic generate --length 32

# Without symbols
vaultic generate --no-symbols

# Without uppercase
vaultic generate --no-uppercase

# Digits only (PIN)
vaultic generate --length 6 --no-uppercase --no-lowercase --no-symbols
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Commands│ │  Tables │ │Progress │ │  Colors │           │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
└───────┼──────────┼──────────┼──────────┼───────────────────┘
        │          │          │          │
┌───────┴──────────┴──────────┴──────────┴───────────────────┐
│                     Core Services                           │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Session │ │ Storage │ │ Crypto  │ │   AI    │           │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
└───────┼──────────┼──────────┼──────────┼───────────────────┘
        │          │          │          │
┌───────┴──────────┴──────────┴──────────┴───────────────────┐
│                   Data Layer                                │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                       │
│  │  Sled   │ │  Files  │ │  KDF    │                       │
│  │   DB    │ │(session)│ │ params  │                       │
│  └─────────┘ └─────────┘ └─────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### File Structure

```
~/.vaultic/
├── db                  # Sled database (encrypted entries)
├── conf                # Sled configuration
├── blobs/              # Sled blob storage
├── kdf_params.json     # Salt + KDF parameters
└── .session            # Encrypted session (temporary)
```

---

## Security Model

### Encryption Stack

1. **Key Derivation**: Password → Argon2id (64MB memory, 3 iterations) → 32-byte master key
2. **Key Expansion**: Master key → HKDF → encryption key + auth key
3. **Data Encryption**: XChaCha20-Poly1305 with random nonces
4. **Session Storage**: DEFLATE compression → XChaCha20-Poly1305 → file

### Session Security

- Sessions encrypted with machine-specific key
- Machine key = SHA256(username + hostname + machine-id)
- Auto-expires after configurable timeout
- Securely overwritten on lock

---

## Development

```bash
# Run tests
cargo test

# Build debug
cargo build

# Build release
cargo build --release

# Run with debug logging
VAULTIC_DEBUG=1 cargo run -- <command>

# Format code
cargo fmt

# Lint
cargo clippy
```

### Project Structure

```
src/
├── main.rs         # Entry point
├── lib.rs          # Module exports
├── cli/mod.rs      # Command handlers
├── crypto/mod.rs   # Encryption, KDF
├── storage/mod.rs  # Database operations
├── session/mod.rs  # Session management
├── models/mod.rs   # Data structures
├── ai/mod.rs       # Ollama integration
├── totp/mod.rs     # 2FA support
├── gpg/mod.rs      # OpenPGP integration
├── sharing/mod.rs  # E2E sharing
├── fido2/mod.rs    # Hardware auth (stub)
└── tui/mod.rs      # Terminal UI (stub)
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULTIC_HOME` | `~/.vaultic` | Vault directory |
| `VAULTIC_PASSWORD` | - | Password for scripts/CI |
| `VAULTIC_DEBUG` | - | Enable debug logging |

---

## Roadmap

### v0.1.0 (Current)
- [x] Core encryption (XChaCha20-Poly1305)
- [x] Argon2id key derivation
- [x] Sled database storage
- [x] Session management
- [x] Basic CLI commands
- [x] Password generation

### v0.2.0 (Next)
- [ ] Get/Edit/Delete commands
- [ ] Interactive search
- [ ] Clipboard integration
- [ ] Shell completions

### v0.3.0
- [ ] TUI mode (ratatui)
- [ ] Import/Export
- [ ] AI suggestions

### v0.4.0
- [ ] FIDO2/YubiKey support
- [ ] Breach checking
- [ ] Sharing features

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Run tests (`cargo test`)
4. Submit a pull request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) - Cryptographic primitives
- [Sequoia PGP](https://sequoia-pgp.org/) - OpenPGP implementation
- [Sled](https://sled.rs/) - Embedded database

---

**Security Notice**: This is a security-sensitive application. Review the code before using with real credentials. Report vulnerabilities responsibly.
