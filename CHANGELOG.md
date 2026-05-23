# Changelog

All notable changes to Vaultic are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

See [open issues](https://github.com/punitmishra/vaultic/issues) for what's
in flight, especially the `cargo audit` follow-ups in
[#6](https://github.com/punitmishra/vaultic/issues/6) and the beyond-CLI
direction discussion in [#9](https://github.com/punitmishra/vaultic/issues/9).

## [2.0.1] - 2026-05-23

### Added
- TUI themes: `--theme {default,dracula,solarized-dark,monochrome}` on
  `vaultic tui`. Default theme preserves the original look exactly.
- `benches/vault_ops.rs` — criterion benchmarks for `list_entries`,
  `search_entries` (4 query shapes), `get_entry`, `add_entry`, and
  `unlock` against a deterministic 10k-entry vault.

### Changed
- `VaultStorage::list_entries` is ~22% faster on 10k-entry vaults via
  `Vec::with_capacity(tree.len())` and `sort_by_cached_key`. All search
  paths inherit ~19-20% of that win since they call `list_entries`
  internally. No change to on-disk format or sort order.
- `[profile.bench]` in `Cargo.toml` overrides the size-tuned release
  profile so benchmark numbers reflect realistic optimization.

### Fixed
- `cargo clippy --release --all-features` is warning-clean: cleaned up
  `match_like_matches_macro` in `src/gpg/mod.rs` and a needless borrow
  in `src/fido2/mod.rs`.

### Removed
- Unused `proptest` from `[dev-dependencies]`. No tests reference it.

### Internal
- Test count: **303** (122 bin + 126 lib + 44 integration + 5 doc + 6 new theme tests).

## [2.0.0] - 2026-02-08

### Added
- **Multi-method unlock**: password, BIP39 recovery key, or hardware key.
- **BIP39 recovery keys** with QR code display and verify/unlock flows.
- **Identity management & secure sharing** using X25519 key exchange.
- **AI auto-tagging** for vault entries (rule-based + Ollama-enhanced).
- **Shell integration**: `exec` (run a command with vault secrets as env
  vars) and `shell-init` (bash/zsh/fish/powershell).
- **TOTP QR scanning**: `vaultic totp scan` reads PNG/JPEG QR codes
  containing `otpauth://` URIs.
- Full CLI surface: `get`, `edit`, `delete`, `search`, `health`,
  `history`, `batch`, `credential` (git credential helper).
- Vault format **v1 → v2 migration** with backup + rollback.

### Test Results
- 264 tests passing at release.

## [0.1.0] - 2025-12-29

Initial release. Core functionality: vault init/unlock/lock, encrypted
storage with XChaCha20-Poly1305 + Argon2id, password generation, basic
add/list/get commands, session management.

[Unreleased]: https://github.com/punitmishra/vaultic/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/punitmishra/vaultic/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/punitmishra/vaultic/compare/v0.1.0...v2.0.0
[0.1.0]: https://github.com/punitmishra/vaultic/releases/tag/v0.1.0
