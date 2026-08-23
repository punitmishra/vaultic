# Security Policy

Vaultic stores secrets. Security issues take priority over feature work, and
we'd rather hear about a problem than not.

## Reporting a vulnerability

**Please don't open a public GitHub issue for security problems.**

Use GitHub's private vulnerability reporting:
[https://github.com/punitmishra/vaultic/security/advisories/new](https://github.com/punitmishra/vaultic/security/advisories/new)

If that's blocked or not working for you, email the maintainer at the address
listed on [the GitHub profile](https://github.com/punitmishra). Include:

- A description of the issue and where it lives (file/line, command, daemon
  method, etc.).
- A reproduction or proof of concept if you have one.
- The version (`vaultic --version` / `vaultic-agent --version`) and OS.
- Whether you'd like credit in the advisory and under what name.

You should get an acknowledgement within **72 hours**. We'll work on a fix in
a private branch, request a CVE if the issue warrants one, and coordinate
disclosure with you. We don't have a bug bounty program — this is an
unfunded OSS project — but we will credit reporters in the advisory and
changelog unless you'd rather stay anonymous.

## Supported versions

Only the latest **2.x** release line gets security fixes. Pre-2.0 versions
are unsupported.

| Version | Supported |
|---------|-----------|
| 2.2.x   | ✅ Yes    |
| 2.1.x   | ⚠️ Critical fixes only |
| < 2.1   | ❌ No     |

## Threat model (in scope)

Vaultic is a **local-first** password manager. The vault is a directory of
files on disk. The daemon (`vaultic-agent`) holds an unlocked master key in
memory and exposes it to local clients over a per-user Unix socket.

What we defend against:

- **Disk theft / cold-boot of the vault directory.** The vault is encrypted
  at rest with XChaCha20-Poly1305. The master key is derived from the user's
  password with Argon2id (default 64 MB cost) using per-vault parameters in
  `kdf_params.json`. Without the password, BIP39 recovery key, or hardware
  key, the vault is opaque.
- **Other-UID attackers on the same host.** The agent's socket lives under a
  per-user `0700` directory and the socket itself is `0600`. On every
  accept the daemon checks peer credentials (`SO_PEERCRED` on Linux,
  `getpeereid()` on macOS) and rejects connections from any UID other than
  its own. There are no auth tokens — the kernel is the source of truth.
- **Network attackers.** Vaultic does not open any TCP/UDP port. The daemon
  is local-only.
- **Password exposure across processes.** The daemon never receives the
  user's password. Clients (CLI, GUI) run Argon2id **locally** and send only
  the 32-byte derived key. See `docs/AGENT_PROTOCOL.md` § Authentication for
  the rationale.
- **AI clients over-reaching (`vaultic-mcp`).** The MCP server never unlocks
  the vault itself — it requires a vault already unlocked via `vaultic
  unlock`, and it inherits the agent's same-UID socket protection. Every
  secret-returning tool (`get_password`, `get_credential`, `get_totp`)
  prompts for explicit consent on stderr and is rate-limited (10/min), so a
  connected AI can't silently enumerate credentials. Secrets are returned to
  the local MCP client only; the server sends nothing to remote AI services.
  See [`docs/MCP_SERVER.md`](docs/MCP_SERVER.md) for the full tool list and
  consent model.
- **Malformed wire frames.** Frames are length-prefixed and capped at 1 MiB.
  Oversized or invalid frames close the connection without resource use.
- **Memory hygiene at rest.** Sensitive in-memory values
  (`SensitiveString`, `MasterKey`, `DerivedKeyHex`) implement `Zeroize` and
  are wiped on drop. `DerivedKeyHex` deliberately has no `Debug` impl —
  printing it would leak the key.

## Out of scope

These aren't bugs we'll treat as security issues — they're known limits of
the threat model:

- **Same-UID malicious code.** Code running as your user can read your
  process memory, ptrace, snoop your X server, etc. There's no meaningful
  defense at the OS-process boundary, so we don't pretend to build one.
- **Anti-forensics / mlock.** The daemon's master key is not currently
  `mlock`'d; under memory pressure it may swap to disk. A dedicated
  secret-bytes allocator with `MCL_FUTURE` is on the roadmap (tracked in
  [#24](https://github.com/punitmishra/vaultic/issues/24)) but not shipped.
- **Auditable access logs.** The daemon does not log which entries were
  accessed. Adding this requires careful thought about where logs live and
  who can read them.
- **Compromised dependencies.** We track `cargo audit` in CI and update
  promptly, but a malicious supply-chain compromise is out of scope for
  what an unfunded OSS project can prevent. Build from source if you need
  to verify.

## Known unfixed issues

- **Windows** is not supported (no named-pipe transport, no peer-cred
  equivalent yet). Don't run the daemon on Windows expecting the same
  guarantees.
- **Master key is not `mlock`'d.** Under memory pressure the daemon's key
  region may swap to disk. Tracked in
  [#24](https://github.com/punitmishra/vaultic/issues/24).

> The `sequoia-openpgp 1.x` advisory (RUSTSEC-2025-0136) that used to be
> listed here was cleared by the 2.3 bump in
> [#42](https://github.com/punitmishra/vaultic/pull/42). The `gpg` feature
> remains off by default.

## Cryptography

Vaultic uses standard primitives, not novel ones:

| Use | Algorithm |
|-----|-----------|
| Authenticated encryption (vault, sessions) | XChaCha20-Poly1305 |
| Password KDF | Argon2id (RFC 9106) |
| Recovery keys | BIP39 mnemonic → seed → master key |
| Identity / sharing | X25519 ECDH + XChaCha20-Poly1305 (sealed-box) |
| TOTP | RFC 6238 (HMAC-SHA1) |

If you spot a cryptographic misuse — wrong nonce reuse, missing
authentication tag, forged AAD, etc. — please report it via the channel
above. Cryptographic correctness is taken seriously even when it doesn't
look exploitable to a casual reader.

## See also

- [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md) — wire protocol + full
  threat model for the daemon
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — component layout
- [`docs/DESIGN_NOTES_V2.md`](docs/DESIGN_NOTES_V2.md) — multi-method unlock
  and key hierarchy
