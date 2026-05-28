<!--
Thanks for sending a PR. A few things to confirm before review:

- For anything beyond a typo / small bug fix, there should be an issue
  describing the change. If there isn't, link a brief description here
  and we'll align on shape before deep review.
- Every commit needs a Signed-off-by line (DCO). If you forgot:
    git commit --amend --signoff       # for one commit
    git rebase -i --signoff <base>     # for a series
  See CONTRIBUTING.md for details.
- Cryptographic / agent / vault-format / recovery-flow changes should
  start as an issue. See CONTRIBUTING.md § Cryptography & security.
-->

## Summary

<!--
What this PR does, in 1-3 sentences. Focus on the *why*.
-->

## Related issue

<!-- Closes #123, Refs #45, etc. -->

## Changes

<!--
Bullet list of the meaningful changes. Skip the trivial ones.
-->

-

## Testing

<!--
What you ran, what you saw. New tests added? Manual verification? If
the change is user-facing (CLI flag, daemon method, GUI behavior),
include the commands or steps you ran.
-->

```
cargo test --release
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## Checklist

- [ ] Every commit has a `Signed-off-by:` line (DCO)
- [ ] `cargo test` (or `cargo test --all-features` if relevant) passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` is clean
- [ ] `cargo fmt --all -- --check` is clean
- [ ] Docs / CHANGELOG updated if user-visible
- [ ] New dependencies (if any) have a one-line justification below

<!-- New deps justification: -->
