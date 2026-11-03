# Contributing

**Contributions are accepted.** The project is licensed under the PolyForm
Noncommercial License 1.0.0 (see [`LICENSE`](./LICENSE)); a patch you send is
accepted under the same licence. By sending a contribution you grant the
copyright holder the right to license that contribution commercially as well,
on the same terms it can license the rest of the project; see
[`COMMERCIAL.md`](./COMMERCIAL.md) for what counts as commercial use. Issues
and security reports are welcome — for vulnerabilities use
[`SECURITY.md`](./SECURITY.md), not a public issue.

## Build and test

Everything runs on macOS with the toolchain pinned in
[`rust-toolchain.toml`](./rust-toolchain.toml); `rustup` installs that exact
version for you. `scripts/gate-fast.sh` also needs Python 3.11 or later for its
gitleaks-config check (`python3 -c 'import tomllib'`); the `python3` that ships
with macOS is older.

```sh
cargo build --workspace --locked   # the daemon, the CLI and the privacy kernel
cargo test -p <crate>              # one crate at a time, e.g. -p aux-engine
```

The workspace lives in `crates/`; the privacy kernel is in `kernel/` and is
used as an in-tree path dependency, so nothing is fetched from elsewhere.
The macOS app is a separate Swift package under `apps/auxesis-mac`.

Tests that start the daemon must run in a sandbox: a throwaway home
directory, a throwaway state directory and an ephemeral port, so a test never
touches your real `~/.auxesis` and never talks to a daemon that is already
running. The environment is always exactly:

```sh
env -i PATH="$PATH" HOME=<tmp dir> AUXESIS_HOME=<tmp dir>/.auxesis \
  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
  AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0
```

`PATH`, `CARGO_HOME` and `RUSTUP_HOME` keep the installed toolchain and the
crate cache. Without them `rustup` downloads the pinned toolchain into the
throwaway home and `cargo` re-fetches every dependency.

which you can write as:

```sh
sandbox="$(mktemp -d)"
trap 'rm -rf "$sandbox"' EXIT
env -i PATH="$PATH" HOME="$sandbox" \
  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
  AUXESIS_HOME="$sandbox/.auxesis" AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0 \
  cargo test -p auxd
```

Before a push, run the gates from the repository root:

```sh
scripts/gate-fast.sh      # format, clippy on the crates you touched, egress, secrets
scripts/check-egress.sh   # every outbound client is documented in docs/egress.md
scripts/swift-gate.sh     # the macOS app: swift build + swift test
```

`scripts/check-egress.sh` fails when a new outbound HTTP client appears
without a line in [`docs/egress.md`](docs/egress.md). `scripts/swift-gate.sh`
needs macOS and the Xcode Command Line Tools.

The gates call `cargo` directly, so no extra build wrapper is needed. The
first `scripts/gate-fast.sh` run takes a few minutes while clippy builds the
workspace.

## Proposing a change

Small changes are easier to review than large ones. Open an issue first for
anything big — a design, a new dependency or a new egress path — so the
direction is agreed before the code is written.

Keep one change per branch, and make it easy to check:

- The description says what changed and why, in a sentence or two.
- The diff is one topic. Unrelated reformatting belongs in its own change.
- A bug fix comes with the test that would have caught it.
- New behaviour comes with the test that pins it down.

CI runs on every pull request, on GitHub-hosted machines
(`.github/workflows/ci.yml`). The `lint` job checks the formatting and the
egress contract. The `check` job runs clippy and the whole test suite on
macOS, in the sandbox. The `swift` job builds and tests the Swift app on
macOS.

## The gates in CI

Once per clone, install the versioned hooks:

```sh
scripts/install-hooks.sh    # points core.hooksPath at .githooks/
```

The pre-commit hook runs the secret and personal-data scan over the whole
tree. Before a push, run the same checks by hand:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -j 2
scripts/check-no-secrets.sh      # secrets and personal data, whole tree
```

`lint` also runs a blocking `cargo deny` step (licences, advisories, bans,
sources); a violation fails the job. The `No secrets tracked` step also
self-tests the scanner against a planted secret in a throwaway temp tree.

## House rules

- Never commit secrets, keys or personal data. The scanners are strict; if a
  hit is a synthetic fixture, justify it in
  `scripts/secret-scan-allowlist.txt` — never weaken the pattern.
- Never touch the real macOS Keychain, the real `~/.auxesis`, or a real home
  directory from a test; use `AUXESIS_HOME` and throwaway temp dirs.
- Keep documents and fixtures free of machine-specific paths: use `~`,
  `<home>`, `<tmp>`, `$HOME`, `${TMPDIR:-/tmp}`.
- Evidence beats opinion: put the command, the output and the version in the
  pull request description.

## Publishing checklist

A pull request runs the workflow as the pull request wrote it, so no check in
the workflow files can stop an outside contributor from rewriting them. These
repository settings are the defence, and they are hard rules for the public
repository:

- It is a NEW repository with no self-hosted runner, at repository and at
  organisation level. Never register a machine of your own on it.
- Settings → Actions → General: "Require approval for all outside
  collaborators" for fork pull request workflows.
- Settings → Actions → General: the default `GITHUB_TOKEN` is read-only.
- No repository or organisation secrets.
