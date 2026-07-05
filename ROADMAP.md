# Vaultic Roadmap

This file is a high-level pointer to where the project is going. For
**what's already shipped**, see [`CHANGELOG.md`](CHANGELOG.md). For
**day-to-day tracking**, see [GitHub issues](https://github.com/punitmishra/vaultic/issues).

## Current state

The current tree ships **four binaries**: the original CLI/TUI
(`vaultic`), a long-running Unix-socket daemon (`vaultic-agent`),
an egui desktop app (`vaultic-gui`), and an MCP server for AI
clients (`vaultic-mcp`). The released v2.2.0 shipped the first three;
`vaultic-mcp` is merged but unreleased, landing in v2.3.0. All four
share the underlying library, with the daemon serving the GUI, CLI,
and MCP server over a typed JSON-over-Unix-socket protocol (see
[`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md) and
[`docs/MCP_SERVER.md`](docs/MCP_SERVER.md)).

A ~10k-entry vault performs at ~16 ms list / ~20 ms search
(reproduce with `cargo bench --bench vault_ops`). The
`sequoia-openpgp` advisory (RUSTSEC-2025-0136) was cleared by the
2.3 bump in [#42](https://github.com/punitmishra/vaultic/pull/42);
remaining `cargo audit` output is unmaintained-transitive warnings.

## Active tracks

### Headline for v2.3 — launch + crates.io

`vaultic-mcp` (merged, [#43](https://github.com/punitmishra/vaultic/pull/43))
and the sequoia bump close the last two blockers for a public launch.
The next release is about getting Vaultic installable and discoverable:
publish to crates.io so `cargo install vaultic` works, cut real
release binaries, and run the launch. See **Release chores** below.

### Make the daemon invisible — remaining half

The CLI↔daemon bridge shipped in 2.2.0 ([#21](https://github.com/punitmishra/vaultic/issues/21)).
What remains is auto-starting the agent so users never think about it:

| Track | Issue | Summary |
|---|---|---|
| launchd / systemd integration for `vaultic-agent` | [#22](https://github.com/punitmishra/vaultic/issues/22) | Now that the CLI uses the daemon transparently, auto-starting it at login means the user never has to think about the daemon. Also makes `vaultic-mcp` reliably available to AI clients. |

### Tech debt / security hardening

| Track | Issue | Summary |
|---|---|---|
| Dependency hardening — Phase B (`bincode 1 → 2`) | [#6](https://github.com/punitmishra/vaultic/issues/6) | The remaining unmaintained-direct-dep. Touches every encrypted vault entry; needs a vault format migration design. |
| Mlock the unlocked master key | [#24](https://github.com/punitmishra/vaultic/issues/24) | Prevent the daemon's master-key region from swapping to disk under memory pressure. |
| Threat model document | [#26](https://github.com/punitmishra/vaultic/issues/26) | Formalize what we defend against, what we don't, and why. |

### MCP hardening & next steps

A correctness pass on `vaultic-mcp` (landing in v2.3.0) fixed five real
bugs: consent read from the protocol-owned stdin (now reads `/dev/tty` and
fails closed without one), locked-vault errors were mislabeled (now surface
`VaultLocked` with the "run `vaultic unlock`" hint), the rate limiter
charged for denials/not-founds (now counts only consented disclosures),
malformed tool args silently defaulted (now rejected), and a redundant
`list_summary` round-trip per secret fetch (now removed).

**Shipped since:** a consent-policy config (`~/.config/vaultic/mcp.toml` /
`--config`) with `auto_approve_names` + `auto_approve_tags`, so specific
entries can be pre-authorized without an interactive prompt — the pragmatic
path to using `vaultic-mcp` from a no-TTY GUI host. Auto-approved
disclosures are logged to stderr; empty config = unchanged behavior.

What's next:

| Track | Summary |
|---|---|
| Protocol-native consent (MCP elicitation) | The nicer answer to non-TTY hosts than the config allowlist: send an approval request back to the MCP client so it renders the prompt. **Blocked on an rmcp upgrade** — the pinned `rmcp 0.1.5` has no elicitation/server-request API; moving to `rmcp` 1.x is a real API migration (the server surface changed substantially). Track as its own workstream. |
| Audit log of MCP accesses | Persist which entries were disclosed to which client and when (today auto-approvals log to stderr only), so a user can review AI credential access. Ties into the daemon's (currently absent) access log — design where the log lives and who can read it. |
| Richer consent policy | Extend the config beyond auto-approve: per-tool allowlists (which tools a client may call), folder scoping, and glob/deny rules, so access can be shaped rather than all-or-`--no-consent`. |
| Write tools behind stronger gating | `add`/`edit`/`generate` exposed to AI clients would be powerful but higher-risk; only behind explicit config + per-call consent, never in `--no-consent`. |

### Feature completions

| Track | Issue | Summary |
|---|---|---|
| GUI add / edit / delete forms | [#23](https://github.com/punitmishra/vaultic/issues/23) | Closes the read-only caveat. Adds three protocol methods (additive). |
| FIDO2 / YubiKey hardware test pass | [#25](https://github.com/punitmishra/vaultic/issues/25) | Code structure exists; needs ~1-2 hours with real hardware to flip the stubs. |

### Beyond CLI/GUI — separate workstream

| Track | Issue | Summary |
|---|---|---|
| Browser extension over native messaging host | [#27](https://github.com/punitmishra/vaultic/issues/27) | The wire format is already browser-ext-friendly; add a tiny relay shim + Chrome MV3 extension. Pairs with #22 so the agent is reliably available. |

### Infrastructure

| Track | Issue | Summary |
|---|---|---|
| GitHub Actions billing lock | [#8](https://github.com/punitmishra/vaultic/issues/8) | CI/release pipelines blocked until resolved. Tags exist but artifacts can't auto-build. |

## Release chores (v2.3 / launch)

Getting-it-shipped work, tracked here until it has issues of its own.
Roughly in the order it needs doing:

| Chore | Status | Notes |
|---|---|---|
| Cut v2.3.0 | ☐ Todo | Bump `Cargo.toml` + `CITATION.cff` to 2.3.0, move `[Unreleased]` CHANGELOG entries (MCP #43, sequoia #42) under a dated `[2.3.0]`, tag `v2.3.0`. |
| Threat-model story ready | ☐ Todo | The launch sequence leads with crypto-honesty + threat model. `SECURITY.md` already carries an in-scope/out-of-scope model linked from the README; formalize/expand it per [#26](https://github.com/punitmishra/vaultic/issues/26) so the front-page story holds up to r/crypto / HN scrutiny before posting. |
| Publish to crates.io | ☐ Todo | `cargo publish` so the README's `cargo install vaultic` works (currently only `--git` installs). Verify `Cargo.toml` metadata (`description`, `keywords`, `categories`, `readme`, `license`) and that `cargo package` is clean. |
| Release binaries for macOS / Linux / Windows | ☐ Todo | Blocked on the CI billing lock ([#8](https://github.com/punitmishra/vaultic/issues/8)). All four binaries per target; the Direct Download table in the README already lists the expected artifact names. Windows is CLI-only until the daemon gets a named-pipe transport. |
| Refresh Homebrew formula | ☐ Todo | Point `Formula/` at the new tag + checksums once release artifacts exist. |
| `cargo audit` gate green | ☐ Todo | Confirm the tree is advisory-free (sequoia already cleared) or that every remaining warning is an unmaintained-transitive with a documented rationale. |
| Record an MCP demo cast | ☐ Todo | The three existing asciinema casts cover CLI / daemon / TUI; add one for `vaultic-mcp` driving a credential fetch from an AI client. |
| Launch sequence | ☐ Todo | Show HN + r/rust + r/privacy + r/selfhosted + lobste.rs, angled per community. Lead with the crypto-honesty + threat-model story. |

## Recently closed

| Track | Issue | Closed in |
|---|---|---|
| MCP server for AI tool integration | [#43](https://github.com/punitmishra/vaultic/pull/43) | Unreleased (→ v2.3.0) — `vaultic-mcp` |
| `sequoia-openpgp` 1.x advisory (RUSTSEC-2025-0136) | [#42](https://github.com/punitmishra/vaultic/pull/42) | Unreleased (→ v2.3.0) — bumped to 2.3 |
| Bridge CLI session model and daemon in-memory state | [#21](https://github.com/punitmishra/vaultic/issues/21) | v2.2.0 — PRs #29/#30/#31 |
| Release pipeline + Homebrew formula bug | [#7](https://github.com/punitmishra/vaultic/issues/7) | v2.0.1 |
| Beyond CLI: GUI / daemon / browser ext | [#9](https://github.com/punitmishra/vaultic/issues/9) | v2.1.0 — five-PR arc (#14–#18) |

## Planning principles

- **Local-first stays local-first.** No cloud sync as a default mode.
- **Crypto core is small and audited.** Argon2id + XChaCha20-Poly1305 +
  X25519 — we don't roll our own primitives.
- **CLI is the source of truth.** GUIs / browser exts / agents are
  thin clients of the same library, not parallel implementations.
- **Migrations matter.** Every on-disk format change ships with a
  migration path (and a backup).
