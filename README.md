# Auxesis

**A personal assistant on one Mac. Cloud models think; private values stay local.**

Auxesis runs all the time on one Mac. You ask Aux, the chief agent, for
something; it answers or hands the work to Mail, Calendar, Clients or Documents.
You choose the model provider and key. Before text reaches that provider, the
privacy kernel replaces the values it recognises with tokens.

## What it does

You can talk to Aux in the app, in `aux chat`, or by text message. These are the
kinds of things you can ask:

- **Mail** — "What needs a reply today?" "Summarise this thread." Read, search,
  open a thread, fetch attachments, and send mail after your approval.
- **Calendar** — "When am I free on Thursday?" "Invite this client on Tuesday."
  Read your calendar, propose slots, create events after approval, and send the
  invitation as a calendar file.
- **Clients** — "What did I last do with this client?" "Log this call." A client
  card with a timeline of mail and meetings, notes, search, import and merge.
- **Documents** — "Find the receipts from March and export them." Collect mailed
  receipts, read them with the personal data hidden, link them to a client, and
  export a spreadsheet with the original files.
- **The day** — "What did I miss?" A morning brief and a short record of what
  happened while you were away, in the app.

### What it does not do

- It does not run on Linux or Windows. It is one person on one Apple Silicon
  Mac: no account system, no hosted service, no telemetry, no team mode, no sync
  between Macs.
- It does not ship a model. You bring a provider you already pay for, with your
  own key. Without one, Aux cannot answer.
- It does not have a notarised `.dmg` or a tagged release yet. Build from source.
- It does not guarantee that nothing leaves. Names and company names go as
  written, detection has gaps, and the measured recall is below the 99.5 % bar.
  Do not send text you would not want a provider to see.

## How privacy works

The kernel sits in front of every model call. It is Rust code in this repository,
not a prompt instruction.

```text
 you ──▶ privacy kernel ──tokens──▶ cloud model
            │                            │
       real values                  answer with tokens
            │                            │
            └──────── restore ◀──────────┘
                     on this Mac
```

- It replaces IBANs, payment cards, national IDs, health details, secrets,
  e-mail addresses and phone numbers with tokens before any cloud call. The real
  values come back on this Mac: in the answer you read, and when an approved
  action runs.
- Names and company names are **not** hidden. This is deliberate, since
  2026-10-19: an assistant that cannot say who a mail is from or which client a
  meeting is with is hard to use, and the values that can unlock an account or
  move money stay masked.
- **Every action that sends a message or changes something outside Auxesis needs
  your approval.** Mail, invitations, calendar events and shell commands open a
  card first; nothing leaves or changes until you say yes. A stricter mode can
  ask for reads too.
- Private mode is the default. Open mode sends e-mail addresses and phone numbers
  as written and still masks the other classes. The mode is resolved per turn
  from the global, agent and conversation settings; the most restrictive wins,
  and a setting that cannot be read is treated as Private.

Other guards: the shell runs under a macOS sandbox (no network unless you allow
it, writes limited to the workspace); text fetched from the web is handled as
untrusted data; every agent has daily caps on tokens, spend and connector calls;
`aux stop` pauses all work at the next step. Every outbound HTTP client is listed
in [`docs/egress.md`](docs/egress.md), and a gate fails the build if a new one
appears without a line there.

The kernel is also a separate Rust project:
[`Diclean/auxesis-privacy-kernel`](https://github.com/Diclean/auxesis-privacy-kernel).
Its crates are vendored in this repository under `kernel/`.

## Measured, not promised

Recall is measured on a private held-out set: 250 invented values in 184 carrier
texts, in French, English, Afrikaans, Hungarian, Slovenian and Chinese. The set
is not in this repository, so fixes cannot be tuned to it. A value counts as
hidden only when no six-character run of it is readable in the output; a partial
mask is a miss.

| Class | n | Private | Open |
| --- | ---: | ---: | ---: |
| IBAN | 40 | 100.00 % | 100.00 % |
| card | 35 | 100.00 % | 100.00 % |
| ID | 70 | 95.71 % | 94.29 % |
| secret | 45 | 93.33 % | 93.33 % |
| health | 60 | 81.67 % | 81.67 % |
| **all** | **250** | **93.20 %** | **92.80 %** |

ID covers national identity numbers and passports. The run is from 2026-11-01,
with Standard detection only; the optional local model (Deep) was not measured in
this run. The 99.5 % bar is **not met**: 93.20 % in Private, 92.80 % in Open.
This is measured recall on our held-out set, not a guarantee. The per-class
detail and the previous run are in
[`RECALL.md`](kernel/qa/privacy-eval/RECALL.md).

## Install

Build from source. There is no notarised `.dmg` and no published release yet.
[`docs/INSTALL.md`](docs/INSTALL.md) is the long guide; the French copy is
[`docs/INSTALL.fr.md`](docs/INSTALL.fr.md).

You need macOS 14 (Sonoma) or later on Apple Silicon, Rust 1.99.0 (pinned in
`rust-toolchain.toml`; install it with [rustup](https://rustup.rs)), Swift 6.2 or
later, and the Xcode Command Line Tools.

```sh
git clone https://github.com/Diclean/auxesis.git
cd auxesis
cargo metadata --locked --format-version 1 >/dev/null   # check the lockfile
cargo build --workspace --locked
apps/auxesis-mac/scripts/make-app.sh                   # build/Auxesis.app
```

The first build takes a few minutes. The app bundle is
`apps/auxesis-mac/build/Auxesis.app`; it is signed ad-hoc, so macOS may ask you
to confirm the first time you open it.

### First run

```sh
scripts/run-dev.sh --sandbox   # throwaway home; Cmd-Q stops everything
scripts/run-dev.sh             # your real ~/.auxesis
cargo run -p aux-cli -- doctor
cargo run -p aux-cli -- install   # optional: keep auxd running at login
```

Start with `--sandbox`: it reads nothing of yours and deletes the temporary
directory when you stop.

### Choose a model provider

Auxesis never ships a model and never shares your key. Write
`~/.auxesis/providers.toml`:

```toml
[[provider]]
id       = "my-provider"                       # your own id, [a-z0-9-]
kind     = "openai"                            # openai | anthropic | ollama | acp
base_url = "https://api.example.com/v1"        # https, or http on loopback only
key      = "env:AUX_KEY_MY_PROVIDER"
models   = ["my-model"]

[brain]
default = "my-provider/my-model"               # <provider>/<model>
```

Then store the key:

```sh
cargo run -p aux-cli -- secret set my-provider   # paste the key, press Return
cargo run -p aux-cli -- secret check my-provider
```

The key is read from standard input, never from the command line, and written to
`~/.auxesis/.env` with mode `0600`. `secret check` says whether it exists and
never prints it. Every field and the other provider kinds are in
[`docs/providers.md`](docs/providers.md).

### Where files live

- `~/.auxesis/` — `config.toml`, `providers.toml`, the encrypted `store.db`,
  `logs/`, and `.env` if you keep keys there. Set `AUXESIS_HOME` to move it.
- `~/Library/LaunchAgents/dev.auxesis.auxd.plist` — the login agent, if installed.
- `apps/auxesis-mac/build/Auxesis.app` — the app you built.

The macOS Keychain is default-deny: nothing writes to it, and reads happen only
if you set `AUXESIS_ALLOW_KEYCHAIN=1`.

## Architecture

| Piece | What it is |
| --- | --- |
| `auxd` | The local daemon. Runs the agents and the scheduler, owns the store, and serves a loopback API. It keeps working while the app is closed. |
| `aux` | The control CLI: chat, doctor, install, secrets, brief, mail, CRM, documents, skills, MCP and extensions. |
| `apps/auxesis-mac` | The native SwiftUI app: Today, Waiting for you, Since you left, approvals, and settings. |
| `kernel/` | The privacy kernel crates: `admit` and `Grant`, detectors, tokenisation, the encrypted vault and the egress client. |
| Connectors | `aux-mail` (IMAP/SMTP), the EventKit bridge in the app, `aux-google` (feature-gated), `aux-imessage`, and MCP. |

Where to read more: [`docs/phase1.md`](docs/phase1.md) for the behaviour
contract, [`docs/providers.md`](docs/providers.md) for providers and brains,
[`docs/egress.md`](docs/egress.md) for every outbound HTTP client,
[`kernel/README.md`](kernel/README.md) for the kernel, and
[`docs/README.md`](docs/README.md) for the documentation index.

## Development

You need the same toolchain as for install, plus Python 3.11 or later for
`scripts/gate-fast.sh`.

```sh
scripts/gate-fast.sh        # fmt, clippy, egress, secrets, docs checks
cargo test --workspace      # Rust tests
scripts/hero-smoke.sh       # end-to-end, sandbox only
scripts/swift-gate.sh       # swift build and swift test for the app
```

The end-to-end smoke test starts a real `auxd` in a throwaway home and runs one
chat turn, the morning brief, a client card, an invitation and a receipt. Tests
that start the daemon must never touch your real `~/.auxesis`; the exact sandbox
environment is in [`CONTRIBUTING.md`](CONTRIBUTING.md).

Pull requests follow four rules:

1. **Acceptance test first.** New behaviour and bug fixes start with a test that
   fails before the change and passes after it.
2. **Keep it small.** One topic per pull request; smaller diffs are reviewed
   faster.
3. **Approval-path changes get a security review.** If a change can alter what
   leaves the Mac or what runs without a yes — approvals, egress, secrets, auth,
   extensions/MCP, or the kernel — say so and wait for the review.
4. **Tell the reviewer how to check it.** The pull request template asks for a
   plain summary, the steps to reproduce, and the technical details.

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before your first pull request.

## Status and roadmap

Version 0.1.0 is unreleased. The current milestone is **M6, extensions**: browse a
short list of MCP servers and skills in the app, see what each one can read,
write and contact before installing, install with one approval, and ask again
when permissions grow. The target is that every MCP call goes through the
privacy kernel like a built-in tool, and that a server is pinned to a version and
checksum. One milestone runs at a time, with an acceptance test for each.
Recent changes are in [`CHANGELOG.md`](CHANGELOG.md).

## Security

Please report vulnerabilities privately through GitHub's security advisories, as
described in [`SECURITY.md`](SECURITY.md). Do not open a public issue for a
security report. Only `main` is supported, and there are no releases yet.

## Licence

**PolyForm Noncommercial 1.0.0.** Free for noncommercial use. Any commercial
use needs a paid licence from the copyright holder — see
[`COMMERCIAL.md`](COMMERCIAL.md). The full text is in [`LICENSE`](LICENSE);
third-party components keep their own licences, see [`NOTICE`](NOTICE) and
[`THIRD-PARTY-LICENSES.txt`](THIRD-PARTY-LICENSES.txt).
