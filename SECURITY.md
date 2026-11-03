# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's security
advisories for this repository:

1. Go to the **Security** tab of the GitHub repository.
2. Click **Report a vulnerability**.
3. Describe the issue, and include a proof of concept if you can.

There is no security email address on purpose: a private advisory keeps the
report, the discussion and the fix in one place with the maintainer.

If you think a credential may have been committed, say so in the report
rather than opening a public issue — and treat that credential as compromised
until it is rotated.

## Supported versions

Only the `main` branch is supported. There are no releases yet: tags and
older commits receive no security fixes.

## What to expect

This is an early, owner-first project maintained by one person. Reports are
read as soon as possible, usually within a week, and high-severity issues are
fixed as fast as we reasonably can — but there is no response-time promise and
no bug bounty. Honest answers are more important than fast ones.

## Scope notes

Auxesis runs shell commands, fetches web pages and holds model API keys, so
the following are especially in scope:

- sandbox or approval escapes (a tool acting without the user's consent);
- secret exposure (keys, tokens, personal paths) in logs, the store or the
  repo;
- prompt-injection paths that make an agent treat untrusted content as
  instructions;
- local API exposure beyond `127.0.0.1`.
