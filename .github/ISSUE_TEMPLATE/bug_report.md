---
name: Bug report
about: Something is broken or not behaving as documented
title: ''
labels: bug
assignees: ''
---

<!--
Before filing: if this is a security issue (could expose secrets, bypass
unlock, leak the master key, etc.) please use private reporting instead:
https://github.com/punitmishra/vaultic/security/advisories/new
-->

## What happened

<!-- A clear, minimal description of the bug. -->

## What you expected

<!-- What you thought would happen instead. -->

## Reproduction

<!--
Exact steps. Include the commands you ran. If it depends on vault state,
say so. A failing test is the gold standard.
-->

```
$ vaultic ...
```

## Environment

- Vaultic version: <!-- `vaultic --version`, `vaultic-agent --version` -->
- OS + version: <!-- e.g. macOS 14.5, Ubuntu 24.04 -->
- Install method: <!-- cargo install, brew, nix, source build -->
- Features enabled: <!-- default, --features gpg, --features fido2, --all-features -->

## Logs

<!--
If relevant, run with debug logging and paste the output. Trim to what's
relevant — don't paste megabytes.

  VAULTIC_DEBUG=1 vaultic <command>
  RUST_LOG=vaultic=debug vaultic-agent start
-->

```
```

## Anything else

<!-- Links to related issues, screenshots, hunches, etc. -->
