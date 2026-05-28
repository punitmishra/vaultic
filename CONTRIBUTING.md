# Contributing to Vaultic

Thanks for thinking about contributing. Vaultic is a small, local-first
password manager with a deliberately tight scope, but real outside
contribution makes it better.

This file is the practical guide: how the codebase is set up, what tests
need to pass, the legal sign-off on commits, and what kinds of changes are
likely to land vs. likely to bounce.

## Before you open a PR

For anything beyond a typo or a small bug fix, **open an issue first**. The
project has a single maintainer and a [ROADMAP](ROADMAP.md); a quick chat in
an issue saves you from writing a 500-line PR that turns out to be the
wrong shape. We're friendly about it — just describe what you'd like to
change and we'll align on scope.

Good things to send without asking:

- Bug fixes with a regression test.
- Documentation fixes, typos, broken links.
- Performance improvements with a benchmark to back them up.
- Filling in a CLI flag the docs claim exists but doesn't.

Things that should start as an issue first:

- New commands, new flags, new vault-format fields.
- New dependencies (we keep the tree small on purpose).
- Refactors that touch more than ~3 modules.
- Anything that changes the on-disk vault format or the agent wire protocol.
- Anything cryptographic (even "small" changes).

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by:` line. This is the [Developer
Certificate of Origin 1.1](https://developercertificate.org/) — the same
sign-off the Linux kernel and most upstream projects use. You're certifying
that you have the right to submit the change, not that you've assigned
copyright to anyone.

Sign your commits with `-s`:

```bash
git commit -s -m "your message"
```

The line looks like:

```
Signed-off-by: Your Name <you@example.com>
```

The name and email must match your `git config` user. Anonymous /
pseudonymous contributions are fine as long as you sign off under the
identity you're using.

If you forget on a single commit:

```bash
git commit --amend --signoff
```

For a series, rebase with `git rebase -i --signoff <base>`.

PRs without sign-off will be flagged in review and need to be amended
before merge. There is no CLA — DCO is the entire bar.

## Development setup

### Prerequisites

- Rust **1.74+** (we test on stable). Install via [rustup](https://rustup.rs/).
- A POSIX environment. Linux and macOS are fully supported. Windows builds
  the CLI but not the daemon.

### Optional system dependencies

Most of the codebase builds with no system deps. Two feature flags pull in
extras:

- `--features gpg` — needs `nettle` and `gmp` (`apt install nettle-dev libgmp-dev` on Debian/Ubuntu, `brew install nettle gmp` on macOS).
- `--features fido2` — needs `libudev` on Linux (`apt install libudev-dev`).

For a fully reproducible env, the project ships a Nix flake:

```bash
nix develop          # full deps including FIDO2 + GPG
nix develop .#minimal  # no optional deps
```

### Build, test, lint

```bash
# Build
cargo build                           # debug
cargo build --release                 # release (slower; use for hands-on testing)

# Test
cargo test                            # all tests, default features
cargo test --release                  # release-mode tests (closer to CI)
cargo test --all-features             # include GPG + FIDO2

# Lint — must be clean before merge
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# Audit
cargo audit
```

The CI matrix runs the same commands on Linux + macOS, with and without
`--all-features`. Local `cargo test --release` catches most things; the
matrix catches the rest.

### Running the binaries

```bash
# CLI / TUI
cargo run -- --help
cargo run -- init -n "test" --password "test123!"
cargo run -- tui

# Daemon (foreground; bind a Unix socket)
cargo run --bin vaultic-agent -- start

# GUI (talks to the daemon)
cargo run --bin vaultic-gui
```

### Debugging

```bash
VAULTIC_DEBUG=1 cargo run -- <command>
RUST_LOG=vaultic=debug cargo run --bin vaultic-agent -- start
```

## Testing expectations

- **Unit tests** live next to the code in `#[cfg(test)] mod tests`.
- **Integration tests** live in `tests/`. They drive the public API of a
  binary or library surface end-to-end.
- **Doctests** are encouraged on public-facing types/functions.
- **Property tests** are welcome where they add real coverage; don't add
  them just to add them.

If you fix a bug, add a regression test. If you add a feature with a public
surface (a CLI flag, a daemon method, a new EntrySummary field), pin its
shape with a test so future refactors can't drift it silently. The
`json_shape_*` tests in `src/agent/protocol.rs` are the model.

The full suite runs in well under a minute on a developer laptop. Please
run it before pushing — pre-merge feedback rounds are slow when CI catches
things `cargo test` would have.

## Code style

- `cargo fmt` is enforced. No exceptions.
- `cargo clippy --all-targets --all-features -- -D warnings` must be
  warning-clean.
- We avoid `unsafe` outside of the small, audited spots that already use
  it (mostly `getuid()` interop). New `unsafe` needs a justification in
  the PR.
- Comments explain **why**, not what. The code already says what it does.
- `tracing` for structured logging; `eprintln!` is fine for short-lived
  CLI scripts but not for library code.
- Error types are `thiserror` enums with stable variants. We don't use
  `anyhow` in library code.
- New dependencies need a one-line justification in the PR. We're trying
  to keep the tree under control.

## Commit style

- Short, present-tense subject line (≤72 chars).
- Optional body explaining the **why** if it isn't obvious from the diff.
- Reference issues (`Closes #123`, `Refs #45`) where relevant.
- One logical change per commit. If you're doing a refactor + a feature,
  split them.
- `Signed-off-by:` line, as above.

Mixed-feeling commits like `wip` or `fix stuff` get squashed at merge time
or asked to be cleaned up before review.

## Cryptography & security

If your PR touches anything in `src/crypto/`, `src/agent/`, the vault
format, or the recovery flow:

- Open an issue first. We'd rather discuss the shape than discover it in
  review.
- Cite the primitive and parameters you're using. We use standard
  algorithms with conservative parameters; surprises don't land.
- Add tests that exercise the threat-model boundary, not just the happy
  path (wrong key, wrong nonce, replayed frame, etc.).

If you've found a vulnerability, **don't open a public PR for it**. See
[SECURITY.md](SECURITY.md) for private reporting.

## Code review

The maintainer reviews every PR. Review usually happens within a few days.
Larger or cryptographic changes take longer; you may be asked to split a
PR into smaller ones, add tests, or align with prior design notes in
`docs/`.

Pushing back on review feedback is fine — make your case. But if a
discussion stalls, the maintainer's call is final. Vaultic is a
benevolent-dictator-with-trusted-reviewers project; see
[GOVERNANCE.md](GOVERNANCE.md) for the model.

## Code of conduct

Be decent. Reports of abuse go to the maintainer via the email on the
GitHub profile and are handled privately.

## License

By contributing, you agree your work is licensed under the project's
[MIT License](LICENSE). The DCO sign-off is the documentation of that
agreement.

## See also

- [`README.md`](README.md) — what Vaultic is and how to use it
- [`ROADMAP.md`](ROADMAP.md) — what's next, what's in flight
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — component layout
- [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md) — daemon wire protocol
- [`SECURITY.md`](SECURITY.md) — vuln reporting + threat model
- [`GOVERNANCE.md`](GOVERNANCE.md) — how decisions get made
