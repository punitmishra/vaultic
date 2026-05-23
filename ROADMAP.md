# Vaultic Roadmap

This file is a high-level pointer to where the project is going. For
**what's already shipped**, see [`CHANGELOG.md`](CHANGELOG.md). For
**day-to-day tracking**, see [GitHub issues](https://github.com/punitmishra/vaultic/issues).

## Current state

Vaultic 2.0.x is feature-complete for the original CLI/TUI vision:
multi-method unlock, BIP39 recovery, secure sharing, TUI mode with
themes, TOTP scan/show, shell integration, import/export, and a
~10k-entry vault performs at ~16ms list / ~20ms search.

## Active tracks

| Track | Issue | Summary |
|---|---|---|
| Dependency hardening (security advisories, `bincode 1 → 2`) | [#6](https://github.com/punitmishra/vaultic/issues/6) | Working through 8 vulns + 8 unmaintained warnings from `cargo audit`. Phase A (rand/reqwest/ratatui bumps) is the next concrete PR. |
| Release pipeline + Homebrew formula bug | [#7](https://github.com/punitmishra/vaultic/issues/7) | Closes with v2.0.1 ship. |
| GitHub Actions billing lock | [#8](https://github.com/punitmishra/vaultic/issues/8) | Tracker. CI/release pipelines blocked until resolved. |
| Beyond CLI: GUI / daemon / browser ext | [#9](https://github.com/punitmishra/vaultic/issues/9) | Discussion issue. Headline target is a native GUI, with `vaultic-agent` (Unix-socket daemon) underneath as the architectural multiplier. |

## Planning principles

- **Local-first stays local-first.** No cloud sync as a default mode.
- **Crypto core is small and audited.** Argon2id + XChaCha20-Poly1305 +
  X25519 — we don't roll our own primitives.
- **CLI is the source of truth.** GUIs / browser exts / agents are
  thin clients of the same library, not parallel implementations.
- **Migrations matter.** Every on-disk format change ships with a
  migration path (and a backup).
