# Vaultic Threat Model

This document formalizes what Vaultic defends against, what it does not,
and — importantly — *how* each defense is actually implemented in the
code as of v2.2.0. It is the long-form companion to the shorter
"Threat model" section in [`../SECURITY.md`](../SECURITY.md).

It complements:

- [`../SECURITY.md`](../SECURITY.md) — reporting process + in-scope summary
- [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md) — daemon wire protocol + its own
  threat model
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component layout and on-disk format
- [`DESIGN_NOTES_V2.md`](DESIGN_NOTES_V2.md) — multi-method unlock + key
  hierarchy rationale

Ground rule for this document: **every claimed defense maps to a real
mechanism in the source.** Where something is aspirational or a known gap,
it is called out as such with an issue link, not dressed up as a
mitigation.

Tracked as [issue #26](https://github.com/punitmishra/vaultic/issues/26).

---

## 1. Assets

These are the things worth protecting, roughly in order of blast radius if
compromised.

| Asset | Where it lives | Protection at rest |
|---|---|---|
| **Master key / VaultKey** | Derived in memory from a password (Argon2id), or unwrapped from `keyring.json`. Held live by the daemon (`AgentState`) or in a CLI session file. | Never written in plaintext. Wrapped under a KEK with XChaCha20-Poly1305 (`crypto/wrap.rs`). In memory it is `Zeroize`/`ZeroizeOnDrop` (`crypto/mod.rs` `MasterKey`, `crypto/keys.rs` `VaultKey`). |
| **Vault entries** (passwords, usernames, URLs, notes, custom fields) | sled DB under `<vault>/db/`. | Each value is `bincode::serialize(VaultEntry)` then XChaCha20-Poly1305 with a random 24-byte nonce prepended (`storage/mod.rs`). Opaque without the master key. |
| **Session material** | `<vault>/session/` (CLI only). | Encrypted with a *machine-derived* key (SHA-256 of user + hostname + machine-id), DEFLATE-compressed, 15-min auto-expiry (`session/mod.rs`). See the caveat in §3.3 — this key is not password-derived. |
| **Identity / sharing keys** (X25519 + Ed25519) | sled DB (`UserIdentity`), encrypted like entries. | Wrapped under the master key. Sharing uses ephemeral X25519 ECDH → sealed-box (`sharing/mod.rs`, `crypto/mod.rs`). |
| **TOTP secrets** | A field on `VaultEntry`; encrypted with the entry. | Same at-rest protection as any entry field. Never displayed except through `get_totp` / `totp show`. |
| **KDF parameters + salt** | `<vault>/kdf_params.json` (plaintext). | *Not* a secret — parameters and salt only. Documented as such in `ARCHITECTURE.md`. Its integrity matters (weakened params would weaken key derivation) but its confidentiality does not. |

---

## 2. Trust boundaries

Vaultic crosses these boundaries. Each is a place where an adversary might
sit.

1. **Disk (at rest).** The vault directory (`db/`, `keyring.json`,
   `session/`, `kdf_params.json`). Crosses the boundary any time the
   process reads or writes it, and is fully exposed if the disk/backup is
   stolen.
2. **Process memory / swap.** Live keys held by `vaultic-agent` or a CLI
   process. Crosses into swap if the OS pages the region out.
3. **Unix domain socket.** `vaultic-agent`'s `$XDG_RUNTIME_DIR/vaultic/agent.sock`
   (Linux) or `~/Library/Caches/vaultic/agent.sock` (macOS). Every GUI /
   MCP / future browser-ext request crosses it.
4. **MCP stdio.** `vaultic-mcp` speaks MCP over stdin/stdout to an AI client
   (e.g. Claude Code), and relays to the daemon over the socket above.
5. **Network.** Three *optional, opt-in* egress paths:
   - HIBP breach check → `https://api.pwnedpasswords.com` (`ai/mod.rs`).
   - Ollama / llama.cpp → `http://localhost:11434` by default (`ai/mod.rs`).
   - Sharing → payloads the user transports out-of-band (file/QR); Vaultic
     itself opens no inbound port.

The daemon **does not open any TCP/UDP port** — the only local IPC surface
is the Unix socket.

---

## 3. Adversary classes

For each adversary: what Vaultic defends against and the mechanism, then
what it explicitly does not.

### 3.1 Attacker with disk access at rest (stolen laptop, backup, cold disk)

**Defends against: reading vault contents without a credential.**

- Entries are XChaCha20-Poly1305-encrypted under the master key
  (`storage/mod.rs`); ciphertext carries a random 24-byte nonce
  (`crypto/mod.rs::encrypt`). No key on disk decrypts them directly.
- The master key is only reachable via an unlock method, each wrapping the
  VaultKey under a KEK (`crypto/keys.rs`, `crypto/wrap.rs`):
  - **Password** → Argon2id (RFC 9106, `Argon2id`, `V0x13`) with per-vault
    memory/time/parallelism + salt from `kdf_params.json`
    (`crypto/kek.rs::derive_from_password`). Default cost 64 MiB.
  - **BIP39 recovery** → HKDF-SHA256 over the 64-byte seed
    (`crypto/kek.rs::derive_from_recovery_seed`).
  - **Hardware (FIDO2 HMAC)** → HKDF-SHA256 over the HMAC response
    (`crypto/kek.rs::derive_from_hardware_response`). *Structure only —
    see §5 / issue #25.*
- `kdf_params.json` holds no secret, so leaking it does not help beyond
  revealing the (deliberately expensive) KDF cost.

**Does NOT defend against:**

- **Brute-force of a weak password.** Argon2id raises the cost per guess but
  a low-entropy password is still guessable offline once the disk is stolen.
  Vault strength is bounded by password strength.
- **An active/unexpired CLI session on the stolen disk.** The session file
  in `session/` stores the master key encrypted under a *machine-derived*
  key (§3.3), not the password. An attacker who images the whole machine
  can recompute that key. Mitigation is the 15-minute auto-expiry and
  `vaultic lock`, not cryptographic secrecy of the session file. Prefer
  locking before the machine leaves your control.
- **Tampering/rollback of ciphertext.** AEAD detects modification of a given
  record, but there is no vault-wide integrity/version MAC preventing an
  attacker from reverting `db/` to an earlier encrypted snapshot.

### 3.2 Local unprivileged process (another program running as *you*)

**Defends against: a *different-UID* user reaching the daemon.**

- The socket lives in a `0700` per-user directory; the socket file is
  `0600` (`agent/paths.rs`, `AGENT_PROTOCOL.md`).
- On every `accept`, the daemon checks peer credentials via tokio's
  `peer_cred()` (`SO_PEERCRED` on Linux, `getpeereid()` on macOS) and
  rejects any UID other than its own — `is_authorized_peer` in
  `agent/server.rs` compares `cred.uid()` against `getuid()`. There are no
  auth tokens; the kernel is the source of truth.
- Malformed or oversized frames (> 1 MiB) close the connection with bounded
  work (`agent/protocol.rs`, `agent/server.rs`).

**Does NOT defend against:**

- **Same-UID code.** This is the hard boundary. Any process running as your
  user can `connect()` to the socket and pass the peer-cred check, can
  `ptrace`/read the daemon's or CLI's memory, and can read `session/`. There
  is no meaningful in-OS defense at the process boundary, and Vaultic does
  not pretend to build one (stated in `SECURITY.md` and `AGENT_PROTOCOL.md`).
  The daemon's inactivity auto-lock (15 min) reduces the *window*, not the
  boundary.

### 3.3 Memory scraping / swap (anti-forensics)

**Defends against: casual key remanence in live process memory.**

- `MasterKey`, `VaultKey`, `SensitiveString`, `DerivedKeyHex`, and the
  session key implement `Zeroize`/`ZeroizeOnDrop` and are wiped on drop
  (`crypto/mod.rs`, `crypto/keys.rs`, `agent/keys.rs`, `session/mod.rs`).
- `DerivedKeyHex` deliberately has **no `Debug` impl** so it cannot be
  accidentally logged (`agent/keys.rs`).
- The password never crosses the socket: clients run Argon2id locally and
  send only the 32-byte derived key, hex-encoded, which the daemon zeroes
  immediately after decoding (`agent/keys.rs`, `AGENT_PROTOCOL.md`
  § Authentication). Daemon compromise leaks *this* vault's key, not the
  password (so other vaults using the same password are unaffected).

**Does NOT defend against:**

- **Swap / hibernation leakage.** The daemon's master-key region is **not
  `mlock`'d** and may be paged to disk under memory pressure. This is a
  known gap, tracked in
  [issue #24](https://github.com/punitmishra/vaultic/issues/24) (a dedicated
  secret-bytes allocator with `MCL_FUTURE`). Not shipped.
- **Live memory inspection** by same-UID code or root (see §3.2 / §5).
- **Note on the session machine-key:** the CLI session key is derived only
  from machine-stable, locally readable inputs (username, hostname,
  `/etc/machine-id` or the macOS `IOPlatformUUID`). It is a
  binding-to-this-machine convenience, **not** a secret barrier against an
  attacker who has the machine.

### 3.4 Malicious or buggy MCP client (AI assistant over stdio)

**Defends against: an AI silently exfiltrating secrets.**

- **Consent gate.** Secret-returning tools (`get_password`, `get_credential`,
  `get_totp`) prompt the user on **stderr** and require an explicit `y`
  before returning anything (`mcp/tools.rs::ConsentHandler`,
  `mcp/server.rs`). Non-secret tools (`vault_status`, `list_entries`,
  `search_entries`) return metadata only — no passwords.
- **Rate limiting.** Secret access is capped at **10 requests / 60 s**
  (`mcp/tools.rs::RateLimiter`, default via `RateLimiter::default`), bounding
  enumeration/brute pull-down of the whole vault.
- **Pre-unlock required + local only.** The MCP server holds no key; it
  relays to `vaultic-agent` over the local socket, and the vault must
  already be unlocked out-of-band. Nothing is sent to AI servers
  (`MCP_SERVER.md`).

**Does NOT defend against:**

- **`--no-consent` mode.** Running `vaultic-mcp --no-consent` disables the
  prompt entirely (`ConsentHandler::new(false)`); any tool call then returns
  secrets without asking. This is documented as trusted-environment-only and
  is a deliberate footgun, not a defended state.
- **A user who approves a bad request.** Consent is only as good as the human
  reading the prompt; the prompt shows the action + entry name, but the AI
  chooses which entry to request. Social-engineering the *user* is out of
  scope.
- **A compromised AI client tricking the user via chat.** Vaultic controls
  the credential boundary, not what the assistant says around it.

### 3.5 Network attacker (MITM on HIBP / breach / sharing)

**Defends against: passive network disclosure of what you looked up.**

- **HIBP uses k-anonymity over HTTPS.** Only the **first 5 hex chars** of the
  SHA-1 of the password are sent to `https://api.pwnedpasswords.com/range/…`;
  the match is finished locally against the returned suffix list
  (`ai/mod.rs::check_password_breach`). The full password/hash never leaves
  the machine, and the transport is TLS.
- **No inbound surface.** The daemon opens no network port, so there is no
  remote attack surface to MITM into the vault.
- **Sharing is sealed to the recipient.** Share payloads use ephemeral
  X25519 ECDH + XChaCha20-Poly1305 (`sharing/mod.rs`, `crypto/mod.rs`), so a
  carrier who relays the payload cannot read it without the recipient's
  private key.

**Does NOT defend against:**

- **A malicious/rogue Ollama endpoint.** The AI backend defaults to
  `http://localhost:11434` over plain HTTP (`ai/mod.rs`). If a user points it
  at a remote host, entry *metadata* included in analysis prompts is exposed
  to that host, and plain HTTP offers no confidentiality. Keep the model
  local.
- **Traffic-analysis of HIBP usage.** The 5-char prefix leaks a small
  anonymity-set signal (by design of the HIBP protocol) and the *fact* that a
  check occurred.
- **Out-of-band delivery of shares.** Vaultic seals the payload but does not
  transport it; whoever carries the file/QR is trusted not to tamper with
  delivery (the seal still protects confidentiality/integrity of contents).

### 3.6 Shoulder-surfing / clipboard

**Defends against: leaving secrets on screen or clipboard indefinitely.**

- **Masked by default.** TUI/CLI hide passwords until explicitly revealed
  (`p` toggles visibility in the TUI, `tui/mod.rs`).
- **Clipboard auto-clear (best-effort).** `copy_to_clipboard(text, secs)`
  spawns a background thread that, after the delay, clears the clipboard
  **only if the contents are still the copied value** (`cli/mod.rs`),
  avoiding clobbering something the user copied since.

**Does NOT defend against:**

- **A camera / observer** reading a revealed password.
- **Clipboard managers / other apps** that snapshot the clipboard during the
  window before auto-clear.
- **Short-lived-process clipboard clear.** The auto-clear runs in a spawned
  thread; if the invoking `vaultic` process exits before the delay elapses,
  the thread dies with it and the clipboard is **not** cleared. The clear is
  reliable only while a long-lived process (e.g. the TUI) stays alive. Some
  copy paths use the plain `copy_to_clipboard_internal` helper, which never
  schedules a clear at all. Treat clipboard clearing as best-effort, not a
  guarantee.

---

## 4. Explicit non-goals

Vaultic does **not** attempt to defend against any of these, and treats
reports about them as design limits rather than vulnerabilities:

- **A compromised OS or root.** Root/kernel-level attackers, malicious
  kernel modules, or a hostile OS can read any process's memory and any
  file. Nothing at the application layer meaningfully resists this.
- **Malicious hardware / firmware.** Evil-maid firmware implants, malicious
  USB, DMA attacks, and compromised secure-elements are out of scope.
- **Keyloggers.** A keylogger captures the master password as it is typed;
  Vaultic cannot defend the input path.
- **Same-UID malicious code.** Covered in §3.2 — this is the OS process
  boundary, and Vaultic does not build a sandbox within your own UID.
- **Cloud sync / server-side compromise.** Vaultic is local-first by design;
  there is no Vaultic server, no default cloud sync, and therefore no
  server-side trust to defend (stated as a planning principle in `ROADMAP.md`).
- **Supply-chain compromise of dependencies.** Tracked with `cargo audit` in
  CI and patched promptly, but a malicious upstream is beyond what an
  unfunded OSS project can prevent. Build from source to verify.

---

## 5. Known gaps

Honest list of things that are weaker than they could be, with tracking
issues.

| Gap | Impact | Status |
|---|---|---|
| **Master key not `mlock`'d** | Under memory pressure the daemon's/CLI's key region may swap to disk, surviving as plaintext in swap. | [#24](https://github.com/punitmishra/vaultic/issues/24) — dedicated secret allocator + `MCL_FUTURE`. Not shipped. |
| **`bincode 1.x` (unmaintained)** | Every encrypted entry is `bincode`-serialized before encryption; the direct dep is unmaintained. Not a live exploit (input is always our own decrypted, authenticated data) but a maintenance/robustness risk. | [#6](https://github.com/punitmishra/vaultic/issues/6) — `bincode 1 → 2`, needs a vault-format migration design. |
| **FIDO2 / hardware unlock is structure-only** | The hardware-KEK derivation path exists (`crypto/kek.rs`) but has not been exercised against real hardware; do not rely on it as a live unlock method yet. | [#25](https://github.com/punitmishra/vaultic/issues/25) — hardware test pass. |
| **`sequoia-openpgp 1.x` advisory (feature-gated)** | Only compiled with `--features gpg`, off by default. Open RUSTSEC advisory on the 1.x line. | Tracked in `SECURITY.md`; bump to 2.x is an API migration. |
| **No audit log of secret access** | The daemon does not record which entries were read, so post-incident "what did the AI/attacker touch?" cannot be answered from Vaultic itself. | Deliberate (log placement/readability needs design); noted in `AGENT_PROTOCOL.md`. |
| **No vault-wide rollback/integrity protection** | Per-record AEAD detects tampering of a record but not reversion of `db/` to an old encrypted state. | Not yet tracked; noted here (§3.1). |
| **Windows unsupported** | No named-pipe transport, no peer-cred equivalent. Do not expect the §3.2 guarantees on Windows. | Noted in `SECURITY.md` / `ARCHITECTURE.md`. |

---

## See also

- [`../SECURITY.md`](../SECURITY.md) — reporting + supported versions
- [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md) — daemon protocol + auth rationale
- [`MCP_SERVER.md`](MCP_SERVER.md) — MCP consent + rate-limit details
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component + on-disk layout
