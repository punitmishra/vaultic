# Vaultic

A lightweight, security-focused password manager written in Rust with hardware authentication, end-to-end encryption, and AI-powered management.

```
 ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗██╗ ██████╗
 ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██║██╔════╝
 ██║   ██║███████║██║   ██║██║     ██║   ██║██║
 ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██║██║
  ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ██║╚██████╗
   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝ ╚═════╝

 Local-first | Hardware Auth | AI-Powered | Zero Trust
```

## Features

### Security
- **XChaCha20-Poly1305** - Authenticated encryption with 256-bit keys
- **Argon2id KDF** - Memory-hard key derivation (64MB default)
- **Compressed Sessions** - DEFLATE-compressed, encrypted session files
- **Zero Memory Leaks** - Sensitive data auto-zeroed with `zeroize`
- **Local-Only** - No cloud, no servers, your data stays with you

### What's Working

| Feature | Status |
|---------|--------|
| Vault init/unlock/lock | ✅ Working |
| Session management (15-min auto-expiry) | ✅ Working |
| Add/List/Get entries | ✅ Working |
| Password generation with entropy analysis | ✅ Working |
| Tag/folder filtering | ✅ Working |
| Import (Bitwarden, LastPass, 1Password) | ✅ Working |
| Export (JSON, CSV, Encrypted) | ✅ Working |
| Interactive TUI mode (ratatui) | ✅ Working |
| Shell completions (bash/zsh/fish) | ✅ Working |
| AI analysis (Ollama integration) | ✅ Working |
| HIBP breach checking | ✅ Working |
| TOTP/2FA support | ✅ Working |
| GPG key integration | ✅ Working |
| X25519 key exchange | ✅ Working |
| QR code generation | ✅ Working |
| Simple web client | ✅ Working |
| FIDO2/YubiKey | 🔧 Structure ready (needs hardware) |

---

## Quick Start

```bash
# Initialize vault
vaultic init --name "My Vault"

# Unlock (creates 15-min session)
vaultic unlock

# Add entries
vaultic add "GitHub" -u "user@example.com" -p "secret" --tags "dev"
vaultic add "AWS" -u "admin" --generate --url "https://aws.amazon.com"

# List entries
vaultic list

# Generate password
vaultic generate --length 24

# Check status
vaultic status

# Lock when done
vaultic lock
```

---

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/punitmishra/vaultic.git
cd vaultic

# Build release binary
cargo build --release

# Install to PATH (optional)
cp target/release/vaultic /usr/local/bin/

# Verify installation
vaultic --version
```

### Shell Completions

```bash
# Bash
vaultic completions bash > ~/.local/share/bash-completion/completions/vaultic

# Zsh
vaultic completions zsh > ~/.zfunc/_vaultic

# Fish
vaultic completions fish > ~/.config/fish/completions/vaultic.fish
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

# Digits only (PIN)
vaultic generate --length 6 --no-uppercase --no-lowercase --no-symbols
```

### Import/Export

```bash
# Import from Bitwarden
vaultic import bitwarden_export.json --format bitwarden

# Import from LastPass
vaultic import lastpass_export.csv --format lastpass

# Import from 1Password
vaultic import 1password_export.csv --format onepassword

# Export to JSON (plaintext - handle carefully!)
vaultic export backup.json --format json

# Export encrypted backup
vaultic export backup.vaultic --format encrypted
```

### Interactive TUI

Launch a full-screen terminal interface for managing your passwords:

```bash
# Make sure vault is unlocked first
vaultic unlock

# Launch terminal UI
vaultic tui
```

```
┌──────────────────────────────────────────────────────────────┐
│  Vaultic - Password Manager                                  │
├──────────────────────────────────────────────────────────────┤
│ Entries (3)                                                  │
│                                                              │
│ ▶ AWS Console  admin@company.com  [cloud, work]             │
│   GitHub       dev@example.com    [dev, code]               │
│   Gmail        user@gmail.com     [personal]                │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ j/k:nav  /:search  Enter:view  y:copy  d:delete  ?:help     │
└──────────────────────────────────────────────────────────────┘
```

**TUI Features:**
- Entry list with fuzzy search
- Detail view with password show/hide
- Copy password to clipboard
- Delete with confirmation
- Vim-style navigation

**Keybindings:**

| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `g` | Go to first entry |
| `G` | Go to last entry |
| `/` | Search entries |
| `Enter` | View entry details |
| `y` | Copy password to clipboard |
| `p` | Toggle password visibility (in detail view) |
| `d` | Delete entry (with confirmation) |
| `r` | Refresh entries |
| `?` | Show help screen |
| `Esc` | Cancel / go back |
| `q` | Quit |

---

## Demo

**Play demo recordings locally:**
```bash
# Install asciinema
brew install asciinema  # macOS
apt install asciinema   # Linux

# Play recordings
asciinema play demos/quickstart.cast
asciinema play demos/generate.cast
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
├── fido2/mod.rs    # Hardware auth
├── tui/mod.rs      # Terminal UI
├── import.rs       # Import formats
└── export.rs       # Export formats
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULTIC_HOME` | `~/.vaultic` | Vault directory |
| `VAULTIC_PASSWORD` | - | Password for scripts/CI |
| `VAULTIC_DEBUG` | - | Enable debug logging |

---

## Test Results (2025-12-28)

```
cargo test: 42 tests passing
cargo build --release: Success

Local workflow test:
✓ init        - Vault created
✓ unlock      - Session created (15 min)
✓ add         - Entries added with tags
✓ generate    - 127.8 bits entropy (Very Strong)
✓ list        - Formatted table output
✓ status      - Shows vault info
✓ tui         - Full terminal UI working
✓ lock        - Session destroyed
✓ completions - bash/zsh/fish working
```

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
- [ratatui](https://ratatui.rs/) - Terminal UI framework

---

**Security Notice**: This is a security-sensitive application. Review the code before using with real credentials. Report vulnerabilities responsibly.
