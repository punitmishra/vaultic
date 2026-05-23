# Changelog

All notable changes to Vaultic are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

See [open issues](https://github.com/punitmishra/vaultic/issues) for what's
in flight, especially the `bincode 1 → 2` migration in
[#6](https://github.com/punitmishra/vaultic/issues/6) Phase B and the
beyond-CLI direction discussion in
[#9](https://github.com/punitmishra/vaultic/issues/9).

## [2.0.2] - 2026-05-23

Phase A of the dependency-hardening pass tracked in
[#6](https://github.com/punitmishra/vaultic/issues/6). `cargo audit`
went from 8 vulnerabilities + 8 unmaintained warnings to **1 + 4**.

### Security
- Bumped `reqwest 0.12 → 0.13`, which (combined with `cargo update`)
  cleared 7 advisories: `bytes` integer overflow
  ([RUSTSEC-2026-0007](https://rustsec.org/advisories/RUSTSEC-2026-0007)),
  `quinn-proto` DoS
  ([RUSTSEC-2026-0037](https://rustsec.org/advisories/RUSTSEC-2026-0037)),
  four `rustls-webpki` issues
  ([RUSTSEC-2026-0049](https://rustsec.org/advisories/RUSTSEC-2026-0049),
  [-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098),
  [-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099),
  [-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104)), and `time`
  DoS via stack exhaustion
  ([RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009)).
- Bumped `ratatui 0.29 → 0.30` and `rqrr 0.9 → 0.10`, clearing the
  `lru 0.12.x` `IterMut` Stacked-Borrows unsoundness
  ([RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002)).
- The `rand` advisory
  ([RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097))
  also cleared as a side effect — `cargo update` brought rand to 0.8.6
  / 0.9.4, both beyond the affected version range.

### Changed
- reqwest 0.13's `rustls-tls` feature was renamed to `rustls`. New
  default crypto provider is `aws-lc-rs` (replaced `ring`); platform
  trust store is now used via `rustls-platform-verifier`.
- ratatui 0.30 made `Backend::Error` a generic associated type instead
  of `std::io::Error`. Internal: `run_app` now adds a
  `where B::Error: Display` bound and converts via `map_err →
  TuiError::Terminal`. No behavioural change for users.

### Known
- Phase A1 (`rand 0.8 → 0.9` direct bump) is **blocked upstream** until
  the RustCrypto stable releases (`chacha20poly1305 0.11`,
  `ed25519-dalek 3.0`, `x25519-dalek 3.0`) ship. They are currently RC
  / pre-release only. The advisory does not bite our actual usage
  (we don't ship a custom panic logger). Tracked in #6.

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

[Unreleased]: https://github.com/punitmishra/vaultic/compare/v2.0.2...HEAD
[2.0.2]: https://github.com/punitmishra/vaultic/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/punitmishra/vaultic/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/punitmishra/vaultic/compare/v0.1.0...v2.0.0
[0.1.0]: https://github.com/punitmishra/vaultic/releases/tag/v0.1.0
