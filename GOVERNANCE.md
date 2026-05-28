# Governance

Vaultic is a small, single-maintainer project. This document describes how
decisions get made, who makes them, and how that can change over time. It
exists so contributors know what to expect — not to add ceremony.

## Model

Vaultic uses a **benevolent-dictator-with-trusted-reviewers** model. There is
one maintainer who has final say on everything that lands in `main`. Trusted
reviewers may be invited over time to share the review load; their reviews
carry real weight, but the maintainer retains the tie-breaking vote.

This is the same model the Linux kernel and many small-to-mid OSS projects
use. It's chosen here for the same reason: it scales down well. A single
person can keep the project coherent without standing committees, RFC
processes, or vote-counting.

## Roles

### Maintainer

- One person. Currently [@punitmishra](https://github.com/punitmishra).
- Final call on architecture, scope, releases, and merges.
- Owns the release cadence and the [ROADMAP](ROADMAP.md).
- Holds the keys: GitHub admin, crates.io, Homebrew tap, signing keys.
- Responsible for security disclosures (see [SECURITY.md](SECURITY.md)).

### Trusted reviewers

- Invited by the maintainer based on a track record of good reviews and
  good judgement on the project.
- Can `Approve` PRs and their approval counts toward merge readiness.
- Cannot self-merge their own PRs — those still need a second review.
- Don't have admin or release rights.

There are currently no trusted reviewers. The role exists for when the
project needs it.

### Contributors

- Anyone who opens a PR or issue. No formal status, no application.
- See [CONTRIBUTING.md](CONTRIBUTING.md) for the practical guide.

## How decisions get made

**Most things: lazy consensus.** Open an issue or PR. If nobody objects within
a reasonable window (a few days for small things, longer for bigger ones)
and a reviewer approves, it lands.

**Disagreements: discuss in the open.** Push back on review feedback if you
think it's wrong. Make the case in the PR or issue thread, not in DMs. If a
discussion stalls, the maintainer's call is final — but the goal is to avoid
needing that fallback.

**Larger or cross-cutting changes:** start with a short design note in
`docs/` (the existing files in there are the model — `DESIGN_NOTES_V2.md`,
`AGENT_PROTOCOL.md`). Get rough alignment before writing the code. This
isn't an RFC process; it's "write down what you're proposing so we can talk
about the right thing."

**Cryptography and security:** these don't go through normal lazy consensus.
Anything in `src/crypto/`, `src/agent/`, the vault format, or the recovery
flow needs explicit maintainer sign-off, regardless of how clean the diff
looks. See [CONTRIBUTING.md § Cryptography & security](CONTRIBUTING.md#cryptography--security).

## Releases

- The maintainer cuts releases. Tags are signed.
- Versioning is semver: `MAJOR.MINOR.PATCH`.
- See [CHANGELOG.md](CHANGELOG.md) for what's in each release. Entries are
  added as work lands, not at release time.
- Security fixes for the supported version line ship as patch releases. See
  [SECURITY.md § Supported versions](SECURITY.md#supported-versions).

## Becoming a trusted reviewer

There's no application form. The path is:

1. Send several thoughtful PRs and reviews.
2. Show good judgement about scope, security, and what the project *is*.
3. The maintainer invites you.

If you're interested but you're not sure your contribution shape matches
that, ask in an issue. The honest answer might be "not yet" or "not really
this kind of project for that role" — neither is a no on contributing.

## Changing this model

If the project outgrows the single-maintainer shape, this document gets
rewritten. That decision is the maintainer's to make, in consultation with
trusted reviewers if any exist at the time. Likely triggers:

- The maintainer can no longer respond on a useful timeline.
- The project picks up enough trusted reviewers that a more formal model
  (e.g., maintainers-by-area, or a small steering group) makes sense.
- The project moves to a foundation or umbrella org.

If the maintainer becomes unavailable for an extended period without
arrangements, trusted reviewers may collectively appoint an interim
maintainer to keep the project alive. This has not happened and is not
expected; it's documented so the path exists.

## Code of conduct

Be decent. Reports of abuse go to the maintainer via the email on the
GitHub profile. The maintainer handles them privately.

We don't ship a separate Contributor Covenant document because the project
is small enough that "be decent, talk to the maintainer if there's a
problem" is the whole policy. If the project grows to a size where that
stops being enough, we'll adopt one.

## See also

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to send a PR, DCO, dev setup
- [SECURITY.md](SECURITY.md) — vulnerability reporting, threat model
- [ROADMAP.md](ROADMAP.md) — what's planned, what's in flight
- [CHANGELOG.md](CHANGELOG.md) — what's shipped
