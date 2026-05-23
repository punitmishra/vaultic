# Vaultic Agent Protocol

This document specifies the wire protocol between `vaultic-agent` (the
daemon) and its clients. The agent holds an unlocked vault key in memory and
exposes that capability to local clients — initially the upcoming `vaultic-gui`
binary, eventually browser extensions and other tools.

> Status: **draft, v1**. Session 1 of the work tracked in
> [issue #9](https://github.com/punitmishra/vaultic/issues/9) ships the
> protocol types and the binary entry. The socket listener and method
> handlers ship in Session 2.

## Architecture

```
                   ┌─────────────────────┐
                   │ vaultic-agent       │
                   │   (daemon)          │
                   │                     │
                   │ - holds master key  │
                   │ - listens on        │
                   │   $sock             │
                   │ - timed lock        │
                   └─────────┬───────────┘
                             │ Unix socket, length-prefixed JSON
                             │ peer-cred auth (same UID only)
            ┌────────────────┼─────────────────┐
            ▼                ▼                 ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
    │ vaultic-gui  │ │ vaultic CLI  │ │ browser-ext      │
    │ (egui app)   │ │ (future)     │ │ (future)         │
    └──────────────┘ └──────────────┘ └──────────────────┘
```

All clients link the `vaultic` library for KDF and protocol types.

## Transport

- **Unix-domain stream socket** (`SOCK_STREAM`).
- One process can hold multiple concurrent connections; each is independent.
- The socket file lives at:
  - Linux: `$XDG_RUNTIME_DIR/vaultic/agent.sock` (falls back to
    `$XDG_CACHE_HOME/vaultic/agent.sock` if `$XDG_RUNTIME_DIR` is unset)
  - macOS: `~/Library/Caches/vaultic/agent.sock`
  - Windows: not supported in v1 (named pipes are a follow-up).
- The parent directory is created with mode `0700`. The socket itself with
  mode `0600`.

## Framing

Each frame is:

```
[ 4 bytes little-endian length N ][ N bytes UTF-8 JSON body ]
```

- Maximum frame size: **1 MiB** (`MAX_FRAME_BYTES`). Oversize → connection
  closed.
- Body must be valid UTF-8 and valid JSON. Invalid → connection closed.
- A clean read of zero bytes at the start of a new frame means the peer has
  disconnected gracefully. A read that returns zero **mid-frame** is an
  error.

This matches the Chrome native messaging framing on purpose: a future browser
extension can use the same wire format with a different transport.

## Message types

Three top-level frame kinds:

```json
{ "type": "request",  "id": "<uuid>", "method": "...", "params": {...} }
{ "type": "response", "id": "<uuid>", "result": ... }
{ "type": "response", "id": "<uuid>", "error":  { "code": "...", "message": "..." } }
{ "type": "event",    "kind": "...", "data": {...} }
```

Clients SHOULD generate a fresh UUID per request. The daemon echoes the
request's `id` in the matching response, allowing pipelined in-flight
requests on a single connection.

### Methods

| Method | Params | Result | Notes |
|---|---|---|---|
| `ping` | — | `{ "agent_version": "x.y.z", "protocol_version": 1 }` | Liveness + version handshake. No vault state required. |
| `status` | — | `{ "unlocked": bool, "vault_path": str?, "entry_count": uint?, "expires_at": rfc3339? }` | Current agent state. Always succeeds. |
| `unlock` | `{ "vault_path": str, "derived_key_hex": str (64 chars) }` | `{ "unlocked": true }` | See **Authentication**. |
| `lock` | — | `{ "locked": true }` | Idempotent. |
| `list_summary` | — | `[ EntrySummary ]` | Requires unlocked. Sorted by name (case-insensitive). |
| `get_entry` | `{ "id": uuid }` | full entry incl. password/notes | Requires unlocked. |
| `get_totp` | `{ "id": uuid }` | `{ "code": str, "period_remaining_seconds": uint, "period_total_seconds": uint }` | Requires unlocked. Errors with `not_found` if entry has no `totp_secret`. |
| `search` | `{ "query": str }` | `[ EntrySummary ]` | Requires unlocked. Fuzzy match on name/username/url/tags. |

Schemas for `EntrySummary` and the various views are defined in the canonical
Rust types in `src/agent/protocol.rs`. Their JSON representations are pinned
by tests (`json_shape_*`) so they cannot drift silently.

### Stable error codes

| Code | Meaning |
|---|---|
| `vault_locked` | The method requires an unlocked vault. |
| `not_found` | The requested entry id (or TOTP secret) doesn't exist. |
| `bad_key` | The derived key did not unwrap the vault metadata. Either wrong password or a corrupt vault. |
| `vault_io` | Filesystem / sled / decryption error reading the vault. |
| `ipc` | Wire-format problem: bad framing, invalid JSON, oversized frame. |
| `not_implemented` | This method or feature is not implemented in this daemon version. |
| `protocol_mismatch` | Client and daemon disagree on protocol version. |

New codes will be **added** rather than repurposed.

### Events (daemon → client, unsolicited)

| Kind | Data | When |
|---|---|---|
| `session_expired` | — | Daemon auto-locked because of inactivity. Clients should refresh `status`. |
| `shutdown` | — | Daemon is shutting down (SIGINT / `vaultic-agent stop`). Clients should disconnect. |

## Authentication

### Why peer-cred, no tokens

The socket lives in a per-user directory with mode 0700; only the same user's
processes can `connect()`. On accept, the daemon checks the peer credentials
(`SO_PEERCRED` on Linux, `getpeereid()` on macOS) and **rejects connections
from any UID other than the daemon's own**. There are no shared secrets,
auth tokens, or session cookies; the kernel is the source of truth.

This is the same model SSH and GPG agents use.

### Why the client does the KDF

The `unlock` method takes `derived_key_hex` (32 bytes hex-encoded), **not** a
password. The client is responsible for:

1. Reading `<vault_path>/kdf_params.json`.
2. Running `vaultic::crypto::KeyDeriver::derive_from_password(password,
   &kdf_params)` to produce a `MasterKey`.
3. Hex-encoding `MasterKey::as_bytes()` and sending it over the wire.
4. Zeroizing both the password and the encoded key in client memory after
   send.

The daemon then:

1. Decodes the hex string into a 32-byte buffer.
2. Calls `MasterKey::from_bytes()` and tries to unwrap vault metadata.
3. Returns `bad_key` on failure or stores the master key on success.
4. Zeroes the hex-encoded buffer immediately.

**Why this split:** the user's actual password never crosses a process
boundary. Only the derived key — sufficient to decrypt the vault, but not
sufficient to attack other vaults a user might have with the same password —
is exchanged. The daemon process is therefore not in the password-exposure
path; its compromise leaks only this vault's key, which it would need to
hold anyway.

(Compare ssh-agent, which holds private keys but never the passphrases that
unlock them. The model here is the same shape.)

### Threat model

In scope:
- Other-UID attackers on the same host: blocked at the kernel by socket
  permissions and peer-cred check.
- Malicious code in other applications running as the same user: out of
  scope. Such code can read process memory, ptrace, etc. — there is no
  meaningful defense within the OS process boundary, so we don't try to
  build one.
- Network attackers: out of scope. The agent is local-only; it does not
  open any TCP/UDP port and does not speak any network protocol.
- Malformed frames / oversized frames: rejected by the framing layer
  with bounded resource use.

Out of scope (deferred to follow-up work):
- Anti-forensics. The agent's process memory is not specially mlock'd; the
  master key may swap to disk under memory pressure. Possible follow-up:
  `mlock(MCL_FUTURE)` and a small dedicated allocator for secret bytes.
- Auditable access logs. The daemon does not log which entries were
  accessed; doing so requires careful thought about where the log lives.

## Lifecycle (v1)

The user starts and stops the daemon explicitly:

```
$ vaultic-agent start    # binds the socket, runs in foreground
$ vaultic-agent stop     # signals running daemon to shut down
$ vaultic-agent status   # prints socket path + version + state
```

There's no integration with `launchd` or `systemd` in v1. That's a follow-up.

The daemon auto-locks after **15 minutes** of inactivity (configurable in a
later session — same default as the existing CLI session timeout).

## Compatibility

`PROTOCOL_VERSION = 1` will be carried in `ping` responses. Clients that get
a different version back **must** disconnect and surface
`protocol_mismatch`. Backwards-incompatible changes to message schemas bump
this number; additive changes (new methods, new fields with default values)
do not.

## See also

- `src/agent/protocol.rs` — canonical Rust types and JSON shape tests
- `src/agent/paths.rs` — socket path resolution
- `src/bin/vaultic_agent.rs` — binary entry point
- Issue [#9](https://github.com/punitmishra/vaultic/issues/9) — work
  tracking + multi-session arc
