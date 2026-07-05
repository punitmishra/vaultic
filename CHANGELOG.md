# Changelog

All notable changes to Vaultic are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — MCP server (`vaultic-mcp`) ([#43](https://github.com/punitmishra/vaultic/pull/43))

A fourth binary: an [MCP](https://modelcontextprotocol.io/) server that
lets AI clients (Claude Code, etc.) read vault credentials without the
user pasting secrets into chat.

- Bridges MCP (JSON-RPC over stdio) to `vaultic-agent`'s Unix socket, so
  the vault must be unlocked via `vaultic unlock` first — no password
  ever crosses MCP.
- Six tools. Read-only (`vault_status`, `list_entries`,
  `search_entries`) need no consent; secret-returning tools
  (`get_password`, `get_credential`, `get_totp`) prompt for explicit
  y/N consent on stderr and are rate-limited to 10 requests/minute.
- All credentials stay local; nothing is sent to AI servers.
- `--no-consent` (trusted-env only), `--socket <path>`, and `--verbose`
  flags. New module `src/mcp/` (server, tools, error) and binary
  `src/bin/vaultic_mcp.rs`. Documented in
  [`docs/MCP_SERVER.md`](docs/MCP_SERVER.md).

### Changed

- **`sequoia-openpgp` 1.21 → 2.3**
  ([#42](https://github.com/punitmishra/vaultic/pull/42)) clears
  RUSTSEC-2025-0136. The `gpg` feature is still off by default; this
  removes the advisory for users who opt in.

See [open issues](https://github.com/punitmishra/vaultic/issues) for what's
still in flight. Notable next-up: cut **v2.3.0** and publish to crates.io
(see [`ROADMAP.md`](ROADMAP.md) § Release chores), then `bincode 1 → 2` in
[#6](https://github.com/punitmishra/vaultic/issues/6) Phase B and the
mlock follow-through in [#24](https://github.com/punitmishra/vaultic/issues/24).

## [2.2.0] - 2026-05-28

The CLI and the daemon now share unlock state. When `vaultic-agent` is
running, `vaultic` routes through it; when it isn't, the CLI behaves
exactly as before. This release also adds the OSS-foundation docs
(`SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `VIBE_CODING.md`)
that close [#21](https://github.com/punitmishra/vaultic/issues/21) and
the broader repo-hygiene work.

### Added — CLI ↔ daemon bridge ([#21](https://github.com/punitmishra/vaultic/issues/21))

When `vaultic-agent` is running and unlocked for the active vault, the
CLI now routes through it instead of opening sled directly. This is what
lets a CLI user work against a vault that the GUI (or any other client)
is the one holding open.

- **v1 — session sync** ([#29](https://github.com/punitmishra/vaultic/pull/29)):
  `vaultic unlock` writes the CLI session **and** notifies a running
  agent (best-effort; if the agent isn't running, the CLI behaves as
  before). `vaultic lock` clears both. `vaultic status` shows agent
  state alongside vault/session and prefers the agent's entry count
  when unlocked for the same vault.
- **v2 — read routing** ([#30](https://github.com/punitmishra/vaultic/pull/30)):
  `vaultic get` and `vaultic totp show` (including `--watch`) try the
  agent first and fall back to the local-session path on a clean miss.
  The `--watch` loop reconnects per tick and exits cleanly if the agent
  stops being routable.
- **v3 — list + search routing** ([#31](https://github.com/punitmishra/vaultic/pull/31)):
  `vaultic list` and `vaultic search` go through the agent's new
  `Method::ListFiltered { filter: SearchFilter }`. The full
  `SearchFilter` (folder, tags, favorites-only, needs-rotation,
  weak-passwords, limit, offset) is honored over the wire — `list
  --weak` and `list --needs-rotation` produce the same set whether they
  ran locally or through the daemon.

### Changed

- **Agent caches the master key only** (introduced with #29). The
  daemon no longer holds a long-lived sled handle — each request opens
  storage, performs the operation, and drops the handle. This is what
  lets the CLI, TUI, GUI, and agent all share the same vault directory
  without tripping sled's exclusive process lock.
- **`EntrySummary` extended** with `entry_type`, `password_strength`,
  and `last_accessed`, so the CLI's Type / Strength / Last Used columns
  render identically through the agent or locally. The new fields are
  pinned by a `json_shape_*` test for forward-compat.
- **`SearchFilter` is now `Serialize` + `Deserialize`** (every field is
  `#[serde(default)]` so older clients keep working).

### Internal

- New `src/cli/agent_bridge.rs` (~840 lines): three-state
  `Option<Result<...>>` helpers — `None` means "agent isn't routable,
  fall back to local sled"; `Some(Ok)` means success; `Some(Err)` means
  surface this error to the user. Each helper has a `_at`
  `pub(crate)` variant so tests can drive a real daemon on a temp
  socket without touching the global socket path.
- Test count: **359 → 435** (+76 across the three sessions). 16 new
  end-to-end tests boot a real daemon on a temp socket and exercise
  the full request path.

### Documentation

- `docs/AGENT_PROTOCOL.md` updated for `Method::ListFiltered`.
- `ROADMAP.md` refreshed for the v2.2.0+ planning surface
  ([#28](https://github.com/punitmishra/vaultic/pull/28)).
- README refresh for the three-binary layout, the CLI/daemon bridge,
  and three asciinema casts on the front page
  ([#34](https://github.com/punitmishra/vaultic/pull/34)).
- New repo-hygiene docs: `SECURITY.md`, `CONTRIBUTING.md` (DCO sign-off
  required), `GOVERNANCE.md`, `VIBE_CODING.md` (honest report on AI-assisted
  development), and `.github/` issue + PR templates
  ([#32](https://github.com/punitmishra/vaultic/pull/32)).
- CI workflows match the documented test matrix; release tarballs now
  contain all three binaries on native targets; weekly `cargo audit`
  ([#33](https://github.com/punitmishra/vaultic/pull/33)).
- `FUNDING.yml` enables the GitHub Sponsors button
  ([#35](https://github.com/punitmishra/vaultic/pull/35)).

## [2.1.0] - 2026-05-23

Vaultic now ships **three binaries** instead of one. Closes the
beyond-CLI arc tracked in [#9](https://github.com/punitmishra/vaultic/issues/9).

### Added — `vaultic-agent` (new binary)

Long-running Unix-socket daemon that holds an unlocked vault key in
memory and serves clients (the new GUI today; CLI/browser-extension
later). Same model as `ssh-agent` / `gpg-agent`.

- **Wire protocol**: 4-byte LE length-prefixed JSON, 1 MiB cap.
  Documented in [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md).
- **Methods**: `ping`, `status`, `unlock`, `lock`, `list_summary`,
  `get_entry`, `get_totp`, `search`, `shutdown`. Each returns a typed
  `result` or a stable `error` code.
- **Auth**: peer-credential check on accept (`SO_PEERCRED` on Linux,
  `getpeereid()` on macOS). Same UID only.
- **Lifecycle**: `vaultic-agent start` (foreground) /
  `vaultic-agent stop` / `vaultic-agent status`. Stale sockets from
  crashed daemons are detected (`ECONNREFUSED`) and recreated. SIGINT
  triggers graceful shutdown that unlinks the socket.
- **Inactivity timeout**: 15 minutes (mirrors the CLI session
  timeout). Auto-locks and emits a `SessionExpired` event to all
  connected clients.

### Added — `vaultic-gui` (new binary)

eframe / egui desktop app. Connects to `vaultic-agent`. Single
window, no background process of its own.

- **Unlock flow**: vault path + password input. Argon2id KDF runs
  **locally in the GUI**; the daemon never sees the raw password
  (Option B from the protocol's threat model). Wrong-password
  attempts surface as inline form errors (`bad_key`) — they don't
  blank the screen.
- **Entry list**: scrollable, with type-ahead fuzzy search
  (150 ms debounce). Entries with TOTP secrets carry a small "TOTP"
  tag in the accent color.
- **Detail pane**: name, username, password (masked + reveal toggle),
  URL, tags, folder, notes. Copy buttons for username and password.
- **Live TOTP**: when a TOTP entry is selected, the GUI polls
  `Method::GetTotp` every second. Displays the 6-digit code at 18 pt,
  a "{n}s left" label, and a progress bar for the current 30 s
  window. Copy button puts the code on the clipboard.
- **Clipboard auto-clear**: every Copy schedules a 30-second timer.
  On expiry the worker overwrites the clipboard with empty string
  **only if** it still contains the value we copied — so the user's
  later clipboard contents aren't trampled.
- **Themes**: four built-in themes shared by name with the TUI:
  `default`, `dracula`, `solarized-dark`, `monochrome`. Theme picker
  in the header; `--theme <name>` on the CLI; hot-swappable.
- **Keyboard nav**: `j` / `k` / arrow keys move selection (wraps),
  `/` focuses the search box, `Esc` clears the search. Behaves only
  when no text field has focus.

### Added — reusable `AgentClient` library

`src/agent/client.rs` ships a thin async wrapper over the agent's
Unix socket with one typed method per protocol method. Reusable by
the GUI today; available for any future client (CLI-via-agent,
browser-extension host, integration tests).

`src/agent/keys.rs` exposes `derive_for_unlock(vault_path, password)`
— the canonical client-side KDF helper. Returns a `DerivedKeyHex`
wrapped in `Zeroize` with no `Debug` impl (printing it would leak
the key).

### Added — TUI/GUI parity

The `Theme` struct lives in both `src/tui/theme.rs` (ratatui) and
`src/gui/theme.rs` (egui). Different style systems, but the four
named palettes are tuned to coherent looks across CLI and GUI.

### Internal

- New `src/bin/vaultic_agent.rs` and `src/bin/vaultic_gui.rs`
  binaries declared in `Cargo.toml`.
- New `eframe = 0.33` dependency (default features stripped to
  `default_fonts/glow/wayland/x11`).
- Test count: **303 → 359** (+56 over the v2.0.x line):
  - 5 protocol unit tests (framing roundtrip, JSON shape lock-down,
    error code stability)
  - 6 path resolution tests
  - 13 state.rs / server.rs / client.rs unit tests
  - 15 daemon integration tests through real Unix sockets
  - 3 KDF helper tests
  - 5 GUI theme tests
  - 9 misc

### Sequenced PRs

- [#14](https://github.com/punitmishra/vaultic/pull/14) Session 1: protocol + skeleton
- [#15](https://github.com/punitmishra/vaultic/pull/15) Session 2: daemon MVP
- [#16](https://github.com/punitmishra/vaultic/pull/16) Session 3: GUI shell
- [#17](https://github.com/punitmishra/vaultic/pull/17) Session 4: functional GUI (unlock + list + detail)
- [#18](https://github.com/punitmishra/vaultic/pull/18) Session 5: TOTP + theme + keyboard nav + clipboard auto-clear

### Known limitations

- The CLI's `vaultic unlock` (session-file model) and the daemon
  (in-memory key model) are **not bridged**. Unlocking via CLI
  doesn't make the GUI see "unlocked". Bridging is a separate
  workstream.
- Daemon is **Unix only**: Linux + macOS. Windows is deferred
  (named-pipe transport, peer-cred equivalent).
- No daemonization or `launchd` / `systemd` integration; users
  start the agent manually.
- The master key in the daemon's address space is **not mlock'd**
  (could swap to disk under memory pressure). Possible follow-up.

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

[Unreleased]: https://github.com/punitmishra/vaultic/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/punitmishra/vaultic/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/punitmishra/vaultic/compare/v2.0.2...v2.1.0
[2.0.2]: https://github.com/punitmishra/vaultic/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/punitmishra/vaultic/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/punitmishra/vaultic/compare/v0.1.0...v2.0.0
[0.1.0]: https://github.com/punitmishra/vaultic/releases/tag/v0.1.0
