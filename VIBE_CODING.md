# Vibe coding: how Vaultic actually got built

> Vaultic is built with heavy AI assistance. This is the honest story of
> what that looked like — what worked, what didn't, and where I had to
> override it. It's also the part of the project most people don't put in
> a README.

I'm a single maintainer. Vaultic is ~25k lines of Rust, three binaries, a
custom Unix-socket protocol, a TUI, a GUI, a vault format, encrypted
sharing, and 435 tests. I wrote a meaningful fraction of those lines
myself. Most of the rest came out of long sessions with Claude Code,
where I described the shape I wanted and the assistant produced the code,
the tests, the doc, or all three.

I want to be clear about what that means before anyone trusts the binary.

## The good parts

Most of what worked was unglamorous.

- **Boilerplate that has to be exactly right.** Length-prefixed JSON
  framing, the `EntrySummary` struct with its `json_shape_*` lock-down
  tests, the four named theme palettes shared between ratatui and egui,
  the table renderer that has to produce identical output whether the
  data came from sled or from the daemon. This kind of code is tedious
  to type and unforgiving of small mistakes. Getting it right by saying
  "make me a parser for this and pin its shape with a test" is genuinely
  one of the things AI tooling is good at.

- **End-to-end tests through the agent.** The 16 daemon integration
  tests in `agent_bridge.rs` boot a real `vaultic-agent` against a temp
  socket. Writing the harness once was hard; bolting another scenario
  onto it is now trivial. I'd have shipped fewer of these tests by
  hand.

- **Refactors with the test suite as ground truth.** The "agent caches
  only the master key, opens sled on demand per request" change in
  [#21 v1](https://github.com/punitmishra/vaultic/pull/29) touched
  state, server, three call paths, and the lifecycle assumptions of
  every method. Done by hand it's an afternoon of paranoia. Done with
  the suite as the contract, it was a few cycles of "make this
  refactor, run the tests, fix what broke."

- **Docs.** Every file in `docs/`, this CHANGELOG, the agent protocol
  spec, the architecture doc — most of those started as a session
  prompt of "write this, in this tone, covering these points," and got
  iterated. Plain prose is one of the things models are reliably good
  at when you give them the source material.

## The bad parts

The interesting failures, not the boring ones.

- **Sled's process-wide lock.** The first cut of the daemon held an
  open `VaultStorage` for the lifetime of the unlock. It worked. It
  also meant that anyone running the CLI or TUI against the same vault
  while the agent was unlocked would see "could not acquire lock"
  errors, because sled enforces an exclusive lock at the OS level on
  the database directory. Neither I nor the assistant caught this in
  review; it surfaced when I actually ran `vaultic list` after the GUI
  had unlocked the vault. The fix
  ([#21 v1](https://github.com/punitmishra/vaultic/pull/29)) was to
  cache only the master key and open + drop sled per request. Lesson:
  AI is good at *what the code does*; it's worse at *what the OS does
  underneath the code*, especially around shared state, file locks,
  signals, and process boundaries. Test the integration, not just the
  unit.

- **Premature abstractions.** Default behavior, when asked to add a
  feature, is to build a small framework around it. Three traits
  where one function would do, an enum with two variants and a
  `Box<dyn Strategy>` where a match arm would do, a config struct
  where two arguments would do. I caught most of these in review and
  cut them back. The repo would be 10-15% larger, materially harder to
  read, and not measurably more flexible if I hadn't.

- **Confident-sounding wrong code.** Models are good at producing code
  that compiles, type-checks, and reads like it knows what it's doing
  while being subtly wrong about a primitive. Not a hypothetical: I
  had to push back on at least one suggested KDF parameter, one
  suggested approach to nonce handling, and a "let's hash the
  password before sending it to the daemon" idea that would have
  defeated the point of doing the KDF client-side. Code review is
  not optional. Especially in `src/crypto/` and `src/agent/`, every
  line goes through human eyes.

- **Velocity drift.** Without push-back, sessions tend toward "fan out
  and ship." A bug fix grows a refactor; a refactor grows a doc
  update; a doc update grows a roadmap edit. By the time you're
  reviewing the diff there are five things in it and you can no
  longer revert the bad one cleanly. The countermeasure was just
  saying "no — one logical change per PR" repeatedly, until that
  became the default.

## Where I overrode it

A short list of decisions where the assistant's first answer wasn't the
shipped one:

- **No CLA, just DCO.** The first draft of CONTRIBUTING.md proposed a
  CLA. The Linux-kernel-style sign-off is a lower bar for contributors
  and the same legal cover.
- **Same-UID peer-credential check, no auth tokens.** The early
  protocol sketches kept reaching for capability tokens and bearer
  schemes. The kernel already knows who's on the other end of the
  socket; building anything on top of that just adds attack surface.
- **`DerivedKeyHex` has no `Debug` impl.** A handful of "let me add
  some logging" suggestions would have printed the master-key
  equivalent. Removed; the type-system enforces it now.
- **Argon2id runs in the client, not the daemon.** Every variant of
  "send the password to the daemon, the daemon runs the KDF" got
  rejected. The client does the KDF; the daemon receives 32 bytes of
  derived key. This is documented in `docs/AGENT_PROTOCOL.md`.
- **No mlock, *yet*.** Pressed for a quick-win mlock around the master
  key. Said no — a half-built mlock that doesn't cover the KDF
  buffers, the wrap/unwrap intermediates, and the per-request decrypt
  buffers is security theatre. Tracked in
  [#24](https://github.com/punitmishra/vaultic/issues/24) for when
  it's done properly.

## What this means for the project's safety story

Vaultic stores secrets. AI assistance does not relax the threat model.
The threat model is in [SECURITY.md](SECURITY.md) and the protocol's
[threat-model section](docs/AGENT_PROTOCOL.md). Code touching
cryptography, the agent, the vault format, or the recovery flow gets
reviewed by a human before it lands — that human is currently me, and I
am the same human regardless of who typed the first draft.

If you find a bug, the cause won't be "an AI wrote it." It'll be a bug
that a human committed to the repo. Report it via the
[private channel](SECURITY.md#reporting-a-vulnerability), the same as
any other.

## Why I'm publishing this

Two reasons.

The first is honesty. "Vibe coding" is everywhere now and there's a real
question about whether you can trust software built that way,
especially security software. The honest answer is "it depends on the
review discipline of the human who shipped it." I wanted to lay out what
that discipline actually looks like for this project, instead of either
pretending I wrote every line by hand or pretending the model is
infallible.

The second is that I think there's a useful pattern in here for other
small OSS maintainers thinking about doing the same. AI assistance is
extremely good at helping one person ship in the shape that used to need
three. It is not good at letting one person ship in the shape that used
to need three *while not bothering to read the code.* The first version
saves your nights and weekends. The second one ships a bug.

— [@punitmishra](https://github.com/punitmishra)
