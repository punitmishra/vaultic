# Vaultic Architecture

This is a contributor-oriented overview of how Vaultic is laid out as
of v2.2.0. It complements:

- [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md) — wire format and threat
  model for the daemon ↔ client conversation
- [`DESIGN_NOTES_V2.md`](DESIGN_NOTES_V2.md) — historical design notes
  from the v2.0 cycle, preserved for context
- [`../CHANGELOG.md`](../CHANGELOG.md) — what shipped when
- [`../ROADMAP.md`](../ROADMAP.md) — what's next

## At a glance

Vaultic is one Rust crate that produces four binaries plus a
reusable library surface. Everything reads and writes the same
on-disk vault format.

```
┌──────────────────────────────────────────────────────────────────┐
│                          Four binaries                           │
│                                                                  │
│   vaultic        vaultic-gui      vaultic-mcp     vaultic-agent  │
│   (CLI + TUI)    (eframe/egui)    (MCP server)    (UDS daemon)   │
│        ┆              │                │                │        │
│        ┆ opportunistic└── peer-cred ───┼── JSON/UDS ────►│        │
│        ┆   (GUI + MCP are pure agent clients; the CLI    │        │
│        ▼    routes through the agent when available)     ▼        │
│   ┌──────────────────────────────────────────────────────┐       │
│   │                    vaultic library                    │       │
│   │                                                       │       │
│   │   crypto    storage    models    agent    gui  tui   │       │
│   │   sharing   recovery   migration totp     ai   mcp   │       │
│   └──────────────────────────────────────────────────────┘       │
│                                │                                 │
│                                ▼                                 │
│   ┌──────────────────────────────────────────────────────┐       │
│   │                   On-disk vault                       │       │
│   │   sled DB (encrypted entries)                         │       │
│   │   kdf_params.json (Argon2id parameters, salt)         │       │
│   │   keyring.json (v2 multi-method unlock)               │       │
│   │   session/ (CLI session files, encrypted)             │       │
│   └──────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
```

## The four binaries

### `vaultic` (CLI + TUI)

The original surface, and a **hybrid** client. It is primarily
self-contained: with no daemon running it opens the vault directly
using session files (`session/` under the vault directory). When
`vaultic-agent` IS running and unlocked for the same vault, the CLI
opportunistically routes reads (`get`/`list`/`search`/`totp show`)
through it and notifies it on unlock/lock — best-effort, and it falls
back to the local-sled path on a clean miss (shipped in 2.2.0; see
`src/cli/agent_bridge.rs`). The agent is an accelerator, not a
requirement.

- Entry point: `src/main.rs` → `src/cli/mod.rs`
- Subcommands defined as `clap` enum variants in `cli::Commands`
- TUI lives in `src/tui/mod.rs`; launched via `vaultic tui`

### `vaultic-agent` (Unix-socket daemon)

A long-running process that holds an unlocked vault key in memory
and serves clients over a Unix-domain socket. Like `ssh-agent` /
`gpg-agent`.

- Entry point: `src/bin/vaultic_agent.rs`
- Server: `src/agent/server.rs` (bind, peer-cred check, accept loop,
  per-connection task)
- State machine: `src/agent/state.rs` (locked / unlocked, master
  key holder, inactivity timer)
- Wire format: `src/agent/protocol.rs` (4-byte LE length + JSON;
  same framing as Chrome native messaging)
- Socket path resolution: `src/agent/paths.rs`
  (`$XDG_RUNTIME_DIR/vaultic/agent.sock` on Linux,
  `~/Library/Caches/vaultic/agent.sock` on macOS)

The full protocol is documented in [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md).

### `vaultic-gui` (egui desktop app)

An eframe app that talks to `vaultic-agent`. Doesn't open the vault
directly; everything goes through the daemon's typed protocol.

- Entry point: `src/bin/vaultic_gui.rs`
- App + state machine: `src/gui/mod.rs`
- Drawing routines: `src/gui/screens.rs`
- Tokio worker bridging egui ↔ agent: `src/gui/worker.rs`
- Theme system: `src/gui/theme.rs` (mirrors `src/tui/theme.rs` by
  name; different style data)

### `vaultic-mcp` (MCP server)

A [Model Context Protocol](https://modelcontextprotocol.io/) server
that exposes the vault to AI clients (Claude Code, etc.) over stdio.
Like the GUI, it's an agent client — it never opens the vault
directly; every operation goes through the daemon's typed protocol.

- Entry point: `src/bin/vaultic_mcp.rs`
- Server + tool dispatch: `src/mcp/server.rs` (implements `rmcp`'s
  `ServerHandler`; maps each MCP tool call to an `AgentClient` call)
- Tool params, consent handler, rate limiter: `src/mcp/tools.rs`
- MCP-specific errors (AI-friendly messages): `src/mcp/error.rs`

Six tools: `vault_status`, `list_entries`, `search_entries` (no
consent) and `get_password`, `get_credential`, `get_totp` (explicit
stderr consent + 10/min rate limit). The vault must be unlocked via
`vaultic unlock` first; the MCP server does not take a password. Full
detail in [`../docs/MCP_SERVER.md`](MCP_SERVER.md).

## Reusable library surface

Anything in `src/lib.rs` is `pub` and available to other crates.
The pieces a downstream consumer is most likely to use:

| Module | What |
|---|---|
| `crypto` | XChaCha20-Poly1305 cipher, Argon2id KDF, X25519 + Ed25519 keys |
| `storage` | Encrypted sled-backed vault storage (open, create, unlock, CRUD) |
| `models` | `VaultEntry`, `KdfParams`, `SearchFilter`, `SensitiveString` |
| `agent::client` | `AgentClient` — async typed wrapper around the agent's socket |
| `agent::keys` | `derive_for_unlock(vault_path, password)` — canonical client-side KDF |
| `agent::protocol` | `Frame`, `Method`, `Response`, `ErrorCode`, framing helpers |
| `recovery` | BIP39 mnemonic generation, encoding, QR display |
| `sharing` | Identity types, X25519 key exchange |
| `totp` | TOTP generation + base32 + URI parsing + QR scan |

## How the agent and GUI compose

When the user clicks **Unlock** in `vaultic-gui`:

1. GUI thread collects vault path + password.
2. Worker thread calls `agent::keys::derive_for_unlock(path, password)`.
   This reads `kdf_params.json` and runs Argon2id locally. Returns
   a `DerivedKeyHex` (zeroized on drop, no `Debug` impl).
3. Worker uses `AgentClient::unlock(path, derived_key_hex)` to send
   `Method::Unlock` over the socket.
4. Daemon decodes the hex, calls `MasterKey::from_bytes`, then
   `VaultStorage::unlock`. On success it stores the key + storage
   handle in `AgentState`.
5. GUI receives `Event::UnlockResult(Ok(()))`, switches to the
   split-pane view, and queues `Method::ListSummary` to populate
   the entry list.

**The user's password never leaves the GUI process.** Only the
32-byte derived key crosses the socket. See the threat model in
[`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md) for the rationale.

## On-disk format

```
<vault_path>/
├── db/                  sled-backed database (encrypted entries)
├── kdf_params.json      Argon2id params + salt (unencrypted —
│                        contains no secrets, just parameters)
├── keyring.json         v2 multi-method unlock — encrypted
│                        wrappings of the vault key
└── session/             CLI session files (encrypted with a
                         machine-derived key, 15-min auto-expiry)
```

Entries are stored under sled tree `entries`, keyed by the entry's
UUID. Each value is `bincode::serialize(VaultEntry)` encrypted
under the master key with XChaCha20-Poly1305.

`session/` is **only used by the CLI**. The daemon keeps its
unlocked state purely in memory.

## Threading model in `vaultic-gui`

egui is immediate-mode and runs on the main thread. The agent
client is async tokio. We bridge them with two `mpsc` channels and
a worker task:

```
   ┌─ egui main thread ────────────┐         ┌─ tokio worker thread ─────┐
   │ VaulticGui (eframe::App)       │         │ Holds AgentClient         │
   │  - drains Event channel        │◄────────┤  - reconnects on drop     │
   │  - draws UI                    │         │  - dispatches Commands    │
   │  - sends Command on click      ├────────►│  - polls Status every 5s  │
   └────────────────────────────────┘   mpsc  └───────────────────────────┘
```

The worker calls `egui::Context::request_repaint()` after every
event so the UI doesn't have to poll. Both channels are
`std::sync::mpsc` since egui is sync; a `spawn_blocking` adapter
in the worker pumps them into tokio mpsc.

## Testing layout

| File | What it covers |
|---|---|
| `src/{module}/mod.rs` `#[cfg(test)]` | Unit tests for that module |
| `tests/integration_tests.rs` | Storage, models, end-to-end vault workflows |
| `tests/agent_integration.rs` | Spins up `vaultic-agent` on a temp socket against a fixture vault and exercises every protocol method through real Unix-socket frames |
| `benches/vault_ops.rs` | Criterion benchmarks for list / search / get / add / unlock against a 10k-entry vault |

`cargo test --release` runs everything except benches. Total: 439
tests as of v2.2.0.

## Known seams (for future contributors)

- **Daemon is Unix-only.** Windows would need a named-pipe transport
  and a different peer-cred mechanism. `vaultic-mcp` inherits this —
  it's a client of the Unix-socket daemon.
- **GPG support is feature-gated.** `--features gpg` pulls in
  `sequoia-openpgp 2.x` (bumped from 1.x in #42, clearing
  RUSTSEC-2025-0136). Off by default.
- **No daemonization or service-manager integration.** Users start
  `vaultic-agent` themselves; launchd / systemd integration is on
  the roadmap ([#22](https://github.com/punitmishra/vaultic/issues/22))
  and would also make `vaultic-mcp` reliably available to AI clients.
- **Master key is not mlock'd.** Could swap to disk under memory
  pressure. Possible follow-up.
- **No audit log.** The daemon doesn't record which entries were
  accessed; that's a deliberate choice but a different threat model
  might want it.
