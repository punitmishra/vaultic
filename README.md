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
- **Multi-Method Unlock** - Password, BIP39 recovery keys, or hardware keys
- **X25519 Key Exchange** - Secure sharing with perfect forward secrecy
- **Compressed Sessions** - DEFLATE-compressed, encrypted session files
- **Zero Memory Leaks** - Sensitive data auto-zeroed with `zeroize`
- **Local-Only** - No cloud, no servers, your data stays with you

### What's Working

| Feature | Status |
|---------|--------|
| Vault init/unlock/lock | ✅ Working |
| Multi-method unlock (password, recovery key) | ✅ Working |
| BIP39 recovery keys with QR display | ✅ Working |
| Session management (15-min auto-expiry) | ✅ Working |
| Add/List/Get/Edit/Delete/Search entries | ✅ Working |
| Password generation with entropy analysis | ✅ Working |
| Tag/folder filtering | ✅ Working |
| Import (Bitwarden, LastPass, 1Password) | ✅ Working |
| Export (JSON, CSV, Encrypted) | ✅ Working |
| Interactive TUI mode (ratatui) | ✅ Working |
| Shell completions (bash/zsh/fish/powershell) | ✅ Working |
| Shell integration (exec, shell-init) | ✅ Working |
| AI analysis (Ollama integration) | ✅ Working |
| AI auto-tagging | ✅ Working |
| HIBP breach checking | ✅ Working |
| TOTP/2FA support | ✅ Working |
| TOTP QR code scanning (PNG/JPEG) | ✅ Working |
| Identity management & secure sharing | ✅ Working |
| X25519 key exchange | ✅ Working |
| QR code generation & scanning | ✅ Working |
| Simple web client | ✅ Working |
| Password history (tracking + restore) | ✅ Working |
| Batch operations (tag, delete, move) | ✅ Working |
| Git credential helper | ✅ Working |
| Health audit with scoring | ✅ Working |
| FIDO2/YubiKey | 🔧 Structure ready (needs hardware) |

---

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap punitmishra/vaultic
brew install vaultic
```

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

### Direct Download

Download pre-built binaries from the [releases page](https://github.com/punitmishra/vaultic/releases):
- macOS (Intel): `vaultic-macos-x86_64.tar.gz`
- macOS (Apple Silicon): `vaultic-macos-aarch64.tar.gz`
- Linux (x86_64): `vaultic-linux-x86_64.tar.gz`
- Linux (ARM64): `vaultic-linux-aarch64.tar.gz`
- Linux (musl): `vaultic-linux-x86_64-musl.tar.gz`

### Shell Completions

```bash
# Bash
vaultic completions bash > ~/.local/share/bash-completion/completions/vaultic

# Zsh
vaultic completions zsh > ~/.zfunc/_vaultic

# Fish
vaultic completions fish > ~/.config/fish/completions/vaultic.fish
```

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

# Search entries
vaultic search "git"

# Generate password
vaultic generate --length 24

# Check vault health
vaultic health

# Lock when done
vaultic lock
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

### Multi-Method Unlock (v2.0)

```bash
# Migrate existing vault to v2 format
vaultic migrate

# Generate BIP39 recovery key
vaultic recovery generate --qr

# Unlock with recovery phrase
vaultic recovery unlock

# List configured unlock methods
vaultic unlock-method list
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

# Get entry details
vaultic get "GitHub"

# Edit an entry
vaultic edit "GitHub"

# Delete an entry
vaultic delete "GitHub"

# Search entries
vaultic search "git"

# List all entries
vaultic list

# Filter by tags
vaultic list --tags "work"
```

### Identity & Sharing

```bash
# View/create your identity
vaultic identity show

# Export your identity (share with others)
vaultic identity export

# Add someone's identity
vaultic identity add "Alice" "<exported_identity_string>"

# List trusted identities
vaultic identity list

# Share an entry securely
vaultic share "GitHub" --to "Alice"

# Share with expiration (24 hours)
vaultic share "AWS" --to "Bob" --expires 24 --one-time
```

### Shell Integration

```bash
# Run command with vault secrets as environment variables
vaultic exec "AWS" -- aws s3 ls

# Generate shell aliases
eval "$(vaultic shell-init bash)"
eval "$(vaultic shell-init zsh)"
vaultic shell-init fish | source

# Use convenient aliases (after shell-init)
vg GitHub          # Get entry
vcp GitHub         # Copy password
vrun GitHub aws    # Run with secrets
```

### AI Features

```bash
# Get AI-powered tag suggestions
vaultic suggest --auto-tag

# Apply suggested tags
vaultic suggest --auto-tag --apply

# Analyze password strength
vaultic suggest --analyze

# Check for breaches
vaultic suggest --check-breaches
```

### TOTP / Two-Factor Authentication

```bash
# Scan a QR code image to add TOTP
vaultic totp scan ~/Downloads/github-2fa-qr.png

# Scan and attach to existing entry
vaultic totp scan ~/Downloads/qr.png --entry "GitHub"

# Scan and preview without saving
vaultic totp scan ~/Downloads/qr.png --dry-run

# Add entry with TOTP secret directly
vaultic add "GitHub" -u "user@example.com" --totp-secret "JBSWY3DPEHPK3PXP"

# Add entry with otpauth:// URI
vaultic add "GitHub" --totp-uri "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

# Show current TOTP code
vaultic totp show "GitHub"

# Watch TOTP code with live countdown
vaultic totp show "GitHub" --watch

# Copy TOTP code to clipboard
vaultic totp show "GitHub" --copy
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

### Security Health Check

```bash
# Run security audit
vaultic health

# Verbose output with recommendations
vaultic health --verbose
```

### Password History

```bash
# View password history for an entry
vaultic history GitHub

# Restore a previous password
vaultic history GitHub --restore 2
```

### Batch Operations

```bash
# Add tags to multiple entries
vaultic batch tag --add "work" GitHub AWS GitLab

# Move entries to a folder
vaultic batch move --folder "Cloud" AWS GCP Azure

# Delete multiple entries (with confirmation)
vaultic batch delete OldService1 OldService2
```

### Git Credential Helper

```bash
# Configure git to use vaultic
git config --global credential.helper vaultic

# Or for a specific repository
git config credential.helper vaultic

# Vaultic will now provide credentials for git operations
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
| `p` | Toggle password visibility |
| `d` | Delete entry (with confirmation) |
| `r` | Refresh entries |
| `?` | Show help screen |
| `Esc` | Cancel / go back |
| `q` | Quit |

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
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │  Sled   │ │  Files  │ │  KDF    │ │ Keyring │           │
│  │   DB    │ │(session)│ │ params  │ │  (v2)   │           │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### File Structure

```
~/.vaultic/
├── db                  # Sled database (encrypted entries)
├── conf                # Sled configuration
├── blobs/              # Sled blob storage
├── kdf_params.json     # Salt + KDF parameters
├── keyring.json        # v2: Encrypted unlock method keys
└── .session            # Encrypted session (temporary)
```

---

## Security Model

### Encryption Stack

1. **Key Derivation**: Password → Argon2id (64MB memory, 3 iterations) → 32-byte master key
2. **Key Expansion**: Master key → HKDF → encryption key + auth key
3. **Data Encryption**: XChaCha20-Poly1305 with random nonces
4. **Session Storage**: DEFLATE compression → XChaCha20-Poly1305 → file
5. **Sharing**: X25519 ephemeral key exchange → XChaCha20-Poly1305

### Multi-Method Unlock (v2)

- **VaultKey**: Random 256-bit key that encrypts all vault data
- **KEK (Key Encryption Key)**: Derived from unlock method (password, recovery key, hardware key)
- **Wrapped Keys**: VaultKey encrypted with each KEK, stored in keyring.json
- **Recovery Keys**: BIP39 24-word mnemonic for emergency recovery

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

---

## Test Results (v2.0.0)

```
cargo test: 291 tests passing
  - 122 bin tests (CLI commands and parsing)
  - 120 lib tests (crypto, storage, models, migration, recovery, ai, totp)
  - 44 integration tests (end-to-end workflows)
  - 5 doctests (code examples)

cargo build --release: Success
cargo clippy: No warnings
cargo fmt --check: Formatted

All features tested and working:
✓ init, unlock, lock, status
✓ add, list, get, edit, delete, search
✓ generate, health, history
✓ totp (scan QR codes, show codes, watch)
✓ identity (show, export, add, list, remove)
✓ share (with expiration, one-time)
✓ recovery (generate, verify, unlock)
✓ exec, shell-init
✓ suggest (auto-tag, analyze, check-breaches)
✓ batch, credential
✓ tui, import, export, completions
```

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Run tests (`cargo test`)
4. Format code (`cargo fmt`)
5. Submit a pull request

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
