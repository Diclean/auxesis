# Security policy

## Reporting a vulnerability

Report suspected security issues **privately**. Do not open a public issue or
pull request for them.

- Once this repository is mirrored on GitHub, use **Security → Report a
  vulnerability** to open a private advisory.
- Until then, send the report directly to the maintainer, not to a chat, a log
  or an issue tracker.

Include the crate, the commit, a reproduction and what you expected. A proof of
concept helps. If you think a credential was committed, say so and treat it as
compromised until it is rotated.

## Builders cannot close defects; only breakers do

A fix is not done when its author says it is. A defect is closed only by a
breaker: someone who attacked the build, reproduced the failure, and kept the
reproduction as a permanent test in the repository. The author of a fix may not
close the defect it fixes.

## Scope

This policy covers the six crates in this repository and the `qa/` harness:

- `kernel-core`: configuration, `admit()` and `Grant`, `SafeText`, budgets, STOP;
- `kernel-privacy`: detectors, tokens, the vault, the contacts index;
- `kernel-broker`: rules, taint, scrubbing, the audit event types;
- `kernel-net`: the one HTTP client factory, SSRF checks, DNS pinning;
- `kernel-mcp`: the MCP client, sandbox profiles, tool identity pinning;
- `gliner2` (`gliner2-rs`): the local span model, weights loading, byte offsets;
- `qa/privacy-eval`: the evaluation corpus (the prompt-injection corpus that
  the tests read is not part of this repository).

The daemon, the CLI and the macOS app live in another repository and are out of
scope here. Report their issues there.

Especially in scope:

- sandbox or approval escapes (a tool acting without the owner's consent);
- secret exposure (keys, tokens, personal paths) in logs, the store or the repo;
- privacy leaks: a value that reaches a cloud payload in Private mode;
- egress outside the allow-list in `docs/egress.md`, including SSRF and DNS
  rebinding;
- prompt-injection paths that make untrusted content act as instructions.

## Supported versions

Only `main` is supported. There are no releases yet, so tags and older commits
receive no security fixes.

## What to expect

This is an early project maintained by one person. Reports are read as soon as
possible. High-severity issues are fixed as fast as reasonably possible, but
there is no response-time promise and no bug bounty.
