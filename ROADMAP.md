# Vaultic Roadmap

This file is a high-level pointer to where the project is going. For
**what's already shipped**, see [`CHANGELOG.md`](CHANGELOG.md). For
**day-to-day tracking**, see [GitHub issues](https://github.com/punitmishra/vaultic/issues).

## Current state

Vaultic 2.1.0 ships **three binaries**: the original CLI/TUI
(`vaultic`), a long-running Unix-socket daemon (`vaultic-agent`),
and an egui desktop app (`vaultic-gui`). All three share the
underlying library, with the daemon serving the GUI over a typed
JSON-over-Unix-socket protocol (see
[`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md)).

A ~10k-entry vault performs at ~16 ms list / ~20 ms search. `cargo
audit` reports 1 vulnerability (`sequoia-openpgp`, only built with
`--features gpg`) and 4 unmaintained warnings (mostly transitive).

## Active tracks

### Headline for v2.2 — make the daemon invisible

The biggest UX gap right now is that the agent and the CLI feel
like two separate tools. Closing it is two paired issues:

| Track | Issue | Summary |
|---|---|---|
| Bridge CLI session model and daemon in-memory state | [#21](https://github.com/punitmishra/vaultic/issues/21) | When the daemon is running, route CLI commands through it. Drop back to session files when not. Single best UX upgrade. |
| launchd / systemd integration for `vaultic-agent` | [#22](https://github.com/punitmishra/vaultic/issues/22) | Pairs with #21. Once the CLI uses the daemon transparently, auto-starting it at login means the user never has to think about the daemon. |

### Tech debt / security hardening

| Track | Issue | Summary |
|---|---|---|
| Dependency hardening — Phase B (`bincode 1 → 2`) | [#6](https://github.com/punitmishra/vaultic/issues/6) | The remaining unmaintained-direct-dep. Touches every encrypted vault entry; needs a vault format migration design. |
| Mlock the unlocked master key | [#24](https://github.com/punitmishra/vaultic/issues/24) | Prevent the daemon's master-key region from swapping to disk under memory pressure. |
| Threat model document | [#26](https://github.com/punitmishra/vaultic/issues/26) | Formalize what we defend against, what we don't, and why. |

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

## Recently closed

| Track | Issue | Closed in |
|---|---|---|
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
