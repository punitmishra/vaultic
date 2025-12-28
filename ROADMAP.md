# Vaultic Development Roadmap

## Current State (v0.1.0)

**Status**: Core functionality complete, ~85% of planned features implemented.

### What's Working
- Vault initialization with encrypted storage
- Password-based authentication with Argon2id
- Session management (compressed, encrypted, auto-expiry)
- Add/List password entries
- Password generation with entropy analysis
- Tag and folder filtering

### What's Stubbed
- FIDO2/YubiKey (needs hardware)
- TUI mode (needs ratatui implementation)

---

## Phase 1: Complete Core Commands

**Priority**: HIGH
**Effort**: 1-2 days

### 1.1 Get Command
Retrieve and display entry details with clipboard support.

```bash
vaultic get github              # Fuzzy search, show details
vaultic get github --copy       # Copy password to clipboard
vaultic get github --show       # Show password in terminal
vaultic get github --field url  # Get specific field
vaultic get github --qr         # Display as QR code
```

**Implementation Tasks:**
- [ ] Fuzzy search implementation
- [ ] Entry selection when multiple matches
- [ ] Clipboard integration with auto-clear
- [ ] QR code display in terminal
- [ ] Field-specific retrieval

### 1.2 Delete Command
Remove entries with confirmation.

```bash
vaultic delete github           # Confirm then delete
vaultic delete github --force   # Skip confirmation
```

**Implementation Tasks:**
- [ ] Entry lookup by name/ID
- [ ] Confirmation prompt
- [ ] Audit log entry
- [ ] Force flag for scripts

### 1.3 Edit Command
Modify existing entries.

```bash
vaultic edit github                    # Interactive edit
vaultic edit github --username "new"   # Update specific field
vaultic edit github --regenerate       # Generate new password
```

**Implementation Tasks:**
- [ ] Load existing entry
- [ ] Interactive field editing
- [ ] Field-specific updates via flags
- [ ] Password regeneration option
- [ ] Update timestamp tracking

### 1.4 Search Command
Interactive fuzzy search with selection.

```bash
vaultic search              # Interactive mode
vaultic search git          # Pre-filtered search
```

**Implementation Tasks:**
- [ ] Fuzzy matching with scores
- [ ] Interactive selection UI
- [ ] Real-time filtering
- [ ] Action menu (copy, show, edit, delete)

---

## Phase 2: Terminal User Interface (TUI)

**Priority**: MEDIUM
**Effort**: 2-3 days

### 2.1 Core TUI Framework

Add dependencies:
```toml
[dependencies]
ratatui = "0.28"
crossterm = "0.28"
```

**Views to Implement:**
1. **List View** - All entries in a scrollable list
2. **Detail View** - Full entry information
3. **Search View** - Real-time fuzzy search
4. **Edit View** - Form-based entry editing
5. **Status Bar** - Session info, vault status

### 2.2 Keybindings

```
Navigation:
  j/↓     Move down
  k/↑     Move up
  g       Go to top
  G       Go to bottom
  Enter   Select/Open

Actions:
  a       Add new entry
  e       Edit selected
  d       Delete selected
  c       Copy password
  s       Show password
  /       Search
  ?       Help

General:
  q       Quit
  Esc     Back/Cancel
  Tab     Next field
```

### 2.3 Implementation Tasks

- [ ] Set up ratatui app structure
- [ ] Implement event loop with crossterm
- [ ] Build list view with highlighting
- [ ] Build detail view with field display
- [ ] Implement search with live filtering
- [ ] Add vim-style navigation
- [ ] Password visibility toggle
- [ ] Clipboard integration
- [ ] Help overlay

---

## Phase 3: Import/Export

**Priority**: MEDIUM
**Effort**: 1-2 days

### 3.1 Export Formats

```bash
vaultic export backup.vaultic              # Encrypted backup
vaultic export passwords.json --format json # Plain JSON
vaultic export passwords.csv --format csv   # CSV format
```

**Implementation Tasks:**
- [ ] Encrypted backup format (native)
- [ ] JSON export (decrypted)
- [ ] CSV export
- [ ] Selective export (by folder/tag)

### 3.2 Import Formats

```bash
vaultic import backup.vaultic --format encrypted
vaultic import export.json --format bitwarden
vaultic import export.csv --format lastpass
vaultic import export.csv --format 1password
```

**Format Specifications:**

**Bitwarden JSON:**
```json
{
  "items": [
    {
      "type": 1,
      "name": "GitHub",
      "login": {
        "username": "user@example.com",
        "password": "secret",
        "uris": [{"uri": "https://github.com"}]
      }
    }
  ]
}
```

**LastPass CSV:**
```csv
url,username,password,name,grouping,fav
https://github.com,user@example.com,secret,GitHub,Development,0
```

**1Password CSV:**
```csv
Title,Username,Password,URL,Notes
GitHub,user@example.com,secret,https://github.com,
```

**Implementation Tasks:**
- [ ] Bitwarden JSON parser
- [ ] LastPass CSV parser
- [ ] 1Password CSV parser
- [ ] Conflict resolution (merge/skip/overwrite)
- [ ] Dry-run mode
- [ ] Import progress display

---

## Phase 4: AI & Security Enhancements

**Priority**: MEDIUM
**Effort**: 1-2 days

### 4.1 AI Suggestions

Connect to local Ollama for password analysis.

```bash
vaultic suggest                    # Show all suggestions
vaultic suggest --analyze          # Run full analysis
vaultic suggest apply <id>         # Apply a suggestion
```

**Suggestion Types:**
- Weak password warnings
- Duplicate password detection
- Old password rotation reminders
- Organization suggestions (tags/folders)

**Implementation Tasks:**
- [ ] Connect to Ollama API
- [ ] Rule-based fallback analysis
- [ ] Suggestion storage and tracking
- [ ] Apply suggestion workflow

### 4.2 Breach Checking (HIBP)

```bash
vaultic suggest --check-breaches   # Check all passwords
vaultic check <entry>              # Check specific entry
```

**Implementation Tasks:**
- [ ] HIBP k-anonymity API integration
- [ ] SHA-1 prefix lookup
- [ ] Breach count display
- [ ] Batch checking with rate limiting

---

## Phase 5: FIDO2/YubiKey Support

**Priority**: LOW (requires hardware)
**Effort**: 2-3 days

### 5.1 Hardware Authentication

```bash
vaultic init --fido2               # Initialize with YubiKey
vaultic unlock                     # Touch to unlock
vaultic add-key                    # Register additional key
```

**Implementation Tasks:**
- [ ] Update ctap-hid-fido2 to latest API
- [ ] Device discovery and selection
- [ ] HMAC-Secret extension for key derivation
- [ ] Credential storage
- [ ] Multi-key support
- [ ] Recovery key generation

### 5.2 Key Management

```bash
vaultic keys list                  # List registered keys
vaultic keys add                   # Register new key
vaultic keys remove <id>           # Remove key
vaultic keys rename <id> "Name"    # Rename key
```

---

## Phase 6: Polish & Distribution

**Priority**: LOW
**Effort**: 1-2 days

### 6.1 Shell Completions

```bash
# Generate completions
vaultic completions bash > /etc/bash_completion.d/vaultic
vaultic completions zsh > ~/.zfunc/_vaultic
vaultic completions fish > ~/.config/fish/completions/vaultic.fish
```

**Implementation Tasks:**
- [ ] Add clap completions feature
- [ ] Generate scripts for bash/zsh/fish
- [ ] Installation instructions

### 6.2 Error Handling

- [ ] Improve error messages
- [ ] Add suggestions for common errors
- [ ] Color-coded severity levels
- [ ] Debug mode with stack traces

### 6.3 Distribution

- [ ] GitHub releases with binaries
- [ ] Homebrew formula
- [ ] AUR package
- [ ] Docker image
- [ ] Cargo publish

---

## Technical Debt & Improvements

### Code Quality
- [ ] Add more unit tests (target: 80% coverage)
- [ ] Integration tests for CLI commands
- [ ] Benchmark encryption/KDF performance
- [ ] Documentation for public APIs

### Security Audit
- [ ] Review memory handling
- [ ] Audit clipboard clearing
- [ ] Verify session file permissions
- [ ] Test timing attack resistance

### Performance
- [ ] Lazy loading for large vaults
- [ ] Index optimization for search
- [ ] Parallel entry processing
- [ ] Compression tuning

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | 2024-12-28 | Initial release, core functionality |
| 0.2.0 | TBD | Get/Edit/Delete, Search |
| 0.3.0 | TBD | TUI mode |
| 0.4.0 | TBD | Import/Export |
| 0.5.0 | TBD | FIDO2 support |
| 1.0.0 | TBD | Stable release |

---

## Contributing

Pick an item from any phase and submit a PR! Please:
1. Check existing issues/PRs first
2. Create an issue to discuss major changes
3. Follow Rust style guidelines
4. Add tests for new features
5. Update documentation

---

## Resources

- [Rust Crypto Libraries](https://github.com/RustCrypto)
- [Ratatui TUI Framework](https://ratatui.rs/)
- [FIDO2 Specification](https://fidoalliance.org/specs/)
- [HIBP API](https://haveibeenpwned.com/API/v3)
- [Argon2 RFC](https://datatracker.ietf.org/doc/html/rfc9106)
