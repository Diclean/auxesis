# Egress inventory

Every outbound HTTP client in production code, and the policy it applies.
`scripts/check-egress.sh` fails when a `reqwest` client is constructed in a file
that is not in the [allowlist](#allowed-constructors) below, so a new egress
point cannot ship without being documented here first.

"Configured" means the base URL comes from user config (a provider, MCP server or
connector entry); the constructor pins the origin and refuses plaintext `http`
to a non-loopback host. "Fixed" means a compile-time constant. "Arbitrary" means
the caller supplies the URL and a separate policy (SSRF) vets it.

## Clients

| Construction | Hosts | Redirects | Timeouts | Proxy |
| --- | --- | --- | --- | --- |
| `crates/aux-google/src/lib.rs:318` | `oauth2.googleapis.com` / `accounts.google.com`, validated | `none` | connect 10s / total 30s | default |
| `crates/aux-google/src/lib.rs:670` | `oauth2.googleapis.com`, validated | `none` | connect 10s / total 30s | default |
| `crates/aux-google/src/tools.rs:151` | `gmail.googleapis.com`, `www.googleapis.com`, fixed | `none` | total 30s / **no connect timeout** | default |
| `crates/aux-providers/src/openai_compat.rs:148` | configured OpenAI-compatible endpoint, https/loopback | **default (follows up to 10)** | connect 120s / total 120s | **environment proxy** |
| `crates/aux-providers/src/openai_compat.rs:153` | configured OpenAI-compatible endpoint, https/loopback | **default (follows up to 10)** | connect 120s / idle-read 120s | **environment proxy** |
| `crates/aux-providers/src/anthropic.rs:80` | configured Anthropic endpoint, https/loopback | **default (follows up to 10)** | connect 120s / total 120s | **environment proxy** |
| `crates/aux-runtime/src/net.rs` (`pinned_client`, kernel-net `build_client`) | the simple fetch and the extension artefact URL: `resolve_checked` public-only, client pinned to the one validated address | `none` (kernel) | fetch: `FETCH_TIMEOUT`; download: total 60s | none (`.no_proxy()`, kernel) |
| `crates/aux-runtime/src/net.rs:50` | `127.0.0.1` wiremock test server, pinned by hand (kernel `build_client` refuses loopback); `#[cfg(any(test, feature = "testing"))]` only | `none` | connect `CONNECT_TIMEOUT` | none (`.no_proxy()`) |
| `crates/aux-runtime/src/extensions/oauth.rs` (kernel `resolve_checked` + `build_client` via `crates/aux-runtime/src/net.rs::pinned_client`) | the catalog entry's `[oauth].token_url`: `https` and public only, DNS-pinned to the one validated address (the extension token exchange; no relay) | `none` (kernel) | one token request bounded by total 30s | none (`.no_proxy()`, kernel) |
| `crates/aux-cli/src/brief.rs` (`call_daemon_with_body`) | the local `auxd` API on `127.0.0.1` only (the brief, docs, notification, and skill owner routes; sandbox-aware endpoint, `AUXESIS_API_PORT=0` = no call) | `none` | total 30s | none (`.no_proxy()`) |
| `crates/aux-cli/src/chat/daemon.rs` (`connect`) | the local `auxd` API on a literal loopback IP only (`127.0.0.1` or `::1`, never `localhost`; `/v1/health`, `/v1/threads/<agent>/messages`, `/v1/approvals`; sandbox-aware endpoint, `AUXESIS_API_PORT=0` = no call) | `none` | connect 2s / request 5s (health, approvals) / turn 6h backstop (the daemon's deadlines end it first); a daemon that answers but refuses the token fails closed, never falls back | none (`.no_proxy()`) |
| `crates/aux-runtime/src/executor.rs:1889` | `127.0.0.1` wiremock test server, loopback; `#[cfg(test)]` only | reqwest default | reqwest defaults | default |

## Findings

- **No redirect policy (3 clients).** `openai_compat.rs:148`,
  `openai_compat.rs:153` and `anthropic.rs:80` never call `.redirect(...)`, so
  `reqwest` follows up to 10 redirects to any host. Every other client refuses
  redirects. The provider base URL is user-configurable, so a redirect can move a
  keyed request off the configured origin.
- **Environment proxy on the provider and Google clients.**
  `openai_compat.rs`, the two `aux-google/src/lib.rs` clients and
  `aux-google/src/tools.rs` do not call `.no_proxy()`, so `HTTP(S)_PROXY`
  applies. The MCP and fetch clients opt out.
- **`aux-google/src/tools.rs:151` has no connect timeout.** It bounds the total
  request at 30s but leaves the TCP connect unbounded.
- Google redirect behaviour is covered by tests (see
  [Redirect checks](#redirect-checks)).

## Redirect checks

- `crates/aux-google/src/tools.rs` — `redirects_are_not_followed` covers the
  Gmail/Calendar API client.
- `crates/aux-google/src/tests.rs` —
  `oauth_clients_do_not_follow_redirects_off_google_hosts` covers the two OAuth
  clients built in `lib.rs`.

## Raw sockets

Mail speaks IMAP and SMTP directly, so `aux-mail` dials its own TCP sockets
instead of going through `reqwest`. `scripts/check-egress.sh` applies the same
per-constructor rule to a `TcpStream::connect` in production code that it
applies to a `reqwest` client: the enclosing `file::function` must be listed in
the raw-sockets allowlist below.

Owner-account tools: in Private, the tools in `OWNER_ACCOUNT_TOOLS` (`aux-engine` `engine/tools.rs`) get real values, so a `mail_search` sends the searched name in IMAP `UID SEARCH` to the owner's own mail server, which already holds that mail; every other tool (MCP, web, any new tool) keeps the tokens.

| Construction | Hosts | Timeout | TLS |
| --- | --- | --- | --- |
| `crates/aux-mail/src/dial.rs::Dialer::connect` | the configured IMAP/SMTP endpoints (`host`/`port` from account config, or a provider preset) | TCP connect **and** the TLS handshake are bounded by `connect_timeout` (default 8s, `limits.rs`); the greeting/CAPABILITY/STARTTLS exchange is bounded by the same budget and the whole login by `call_timeout` | `tokio-rustls` with the explicitly selected `ring` provider and `webpki-roots`; there is no insecure/ignore-certificate mode |
| `crates/aux-mail/src/smtp.rs::connect_tcp` | the account's configured SMTP submission endpoint (`host`/`port`, never user text) | `TcpStream::connect` bounded by `connect_timeout`; the whole exchange by `call_timeout`; one attempt, never retried | implicit TLS or a mandatory STARTTLS upgrade through the same `Dialer` handshake; a `plain` account is refused before the socket unless it carries no credential |
| `crates/aux-cli/src/doctor.rs::check_service` | the local `auxd` API port on `127.0.0.1` (`service_addr`, sandbox-aware) | `SERVICE_PROBE_TIMEOUT` as `connect_timeout` | none (loopback liveness probe, no payload) |
| `crates/auxd/src/api/providers.rs::probe_base_url` | the configured provider base URL's already-validated public address | `REACHABILITY_TIMEOUT` as `connect_timeout` | none (plain reachability probe before the provider client is built) |

## App updater (Swift, URLSession)

The macOS app's update check is Swift `URLSession`, not `reqwest`, so
`scripts/check-egress.sh` does not scan it. It is documented here for the
inventory. `apps/auxesis-mac/Sources/AuxesisKit/Updater.swift` holds the flow:

| Construction | Hosts | What is sent | When | Off switch |
| --- | --- | --- | --- | --- |
| `apps/auxesis-mac/Sources/AuxesisKit/Updater.swift` (`checkForUpdates`, `fetchSmall`, `streamDownload`; feed at `Updater.swift:104`) | `updates.auxesis.app` for `release.json` and its `.sig`, then the `dmgURL` named by the signed manifest; every URL must be `https`, and a redirect is followed only while it stays `https` | one plain `GET` per file with `User-Agent: Auxesis/<app version>`; no cookie, token, account id or personal data (the host still sees the IP address) | the `Check for Updates…` menu command on demand; at app launch at most once per 24 h, only when `Check for Updates Automatically` is on (default off, `AuxesisMacApp.swift:38`) | leave the automatic toggle off and do not run the menu command; no other code path calls the updater |

The pinned key in the tree is still the placeholder (`Updater.swift:109`), so
every manifest is refused until the production key ships — fail closed.

## Process egress (AppleScript, Messages)

The Messages gateway (`crates/aux-imessage`) does not speak HTTP or dial a
socket. Its outbound leg is the local Messages app, driven by `osascript`:

| Construction | Hosts | Redirects | Timeouts | Proxy |
| --- | --- | --- | --- | --- |
| `crates/aux-imessage/src/sender.rs::AppleScriptSender::send_text` | none (local `/usr/bin/osascript`; no shell, no network) | n/a | 20 s child wait, then kill | none |

The message text, the recipient and the pinned chat GUID are passed as `on run
argv` arguments, never interpolated into either script, so the text cannot
become AppleScript. The sender tries `send … to chat id <guid>` first and, on a
non-zero exit, falls back to `send … to participant <handle> of (1st account
whose service type = iMessage)`; both scripts take the text through `argv`. It
refuses an empty message, the agent's own handle, and any recipient that is not
a pinned owner handle before `osascript` runs, and it never retries a send. The
program is the absolute `/usr/bin/osascript`, never resolved through `PATH`, and
it is verified root-owned and not group- or world-writable before every spawn;
the child runs with a cleared environment. `scripts/check-egress.sh` gates only
`reqwest` clients and raw TCP sockets, so this process egress is documented here
for the inventory rather than allowlisted.

**Kernel path: C5.** Outbound iMessage text is admitted on `PathId::C5`
(`crates/auxd/src/gateway/imessage.rs::EGRESS_PATH`). The registry labels C5
`Telegram out`; its policy is the outbound-channel one: `NotCovered`,
`Disabled` in Private, `Allow` in Open, which is exactly the policy a
dedicated iMessage row would carry. `PathId` lives in the pinned kernel crate
and is `#[non_exhaustive]`, so the daemon cannot add a row of its own;
binding to C5 widens nothing, and a new row with the same policy would be a
rename, not a fix. C11 is not that row: it is the `Covered` row for the fixed
Private-mode notice the gateway may send (`PRIVATE_NOTICE`,
`PRIVATE_FAILURE_NOTICE` or `BRIEF_NOTICE`). Private therefore holds every
model-derived iMessage send, and Open allows it, exactly as a dedicated row
would.

## Process egress (shell)

`crates/aux-runtime/src/tools/shell.rs` runs the model's command line inside a
Seatbelt sandbox. With the owner's `[shell] network = true` the profile allows
**all** sockets (any host and port, loopback included), so a command the model
writes can leave the Mac without a `reqwest` client or a raw socket in this
tree. The command's output is untrusted and the tool is admitted on
`PathId::B5`, but the command's own sockets are not gated by `admit()`: the
sandbox is the boundary.

| Construction | Hosts | Redirects | Timeouts | Proxy |
| --- | --- | --- | --- | --- |
| `crates/aux-runtime/src/tools/shell.rs::ShellTool::run` | any host and port, while `[shell] network = true` (Seatbelt `(allow network*)`) | n/a (the command decides) | the command's timeout, capped at `MAX_SHELL_TIMEOUT_SECS` | n/a (the command's environment) |

Policy: every shell call with `network = true` needs a fresh owner card. The
tool reports `ExecutionMode::Networked`, so a stored `allow` rule (and a
persisted "always allow") never skips the card, and `allow_always` is refused
for the ask. Private mode forces `network = false` whatever the config says, so
the socket is never open there; `network = false` keeps the existing allow-rule
behaviour.

## Allowed constructors

Constructor-level allowlist read by `scripts/check-egress.sh`. Each entry is
`file::function`: the Rust function that holds the `Client::builder(` or
`Client::new(` call. A second client added to an allowlisted file is flagged
until its function is listed too. Add the entry and a row above before merging
a new client.

<!-- egress-allowlist:start -->
crates/aux-google/src/lib.rs::build_with_key
crates/aux-google/src/lib.rs::http_client
crates/aux-google/src/tools.rs::build
crates/aux-runtime/src/executor.rs::google_wiremock_receives_real_values_only_after_approval
crates/aux-providers/src/openai_compat.rs::with_key_and_timeout
crates/aux-providers/src/anthropic.rs::with_key_and_timeout
crates/aux-runtime/src/net.rs::loopback_client
crates/aux-cli/src/brief.rs::call_daemon_with_body
crates/aux-cli/src/chat/daemon.rs::connect
<!-- egress-allowlist:end -->

<!-- egress-raw-sockets:start -->
crates/aux-mail/src/dial.rs::connect
crates/aux-mail/src/smtp.rs::connect_tcp
crates/aux-cli/src/doctor.rs::check_service
crates/auxd/src/api/providers.rs::probe_base_url
<!-- egress-raw-sockets:end -->

## Test-only seams

`aux-mail`'s `Dialer::with_client_config` (the pinned-certificate seam the
offline TLS fake needs) is compiled only with the `test-support` cargo feature.
Only `crates/aux-mail/Cargo.toml`'s `[dev-dependencies]` self-reference enables
it; `scripts/check-egress.sh` fails if any other `Cargo.toml` names the feature,
and the default library build therefore contains no certificate-override path.

The extension OAuth flow reuses the loopback seam in
`crates/aux-runtime/src/net.rs`. `extensions/oauth.rs::oauth_endpoints` accepts
an `http` loopback `token_url` only when called with `allow_loopback`, and the
`auxd` route passes `loopback_endpoints_allowed()`, which is true only under
`cfg(test)` or `aux-runtime`'s `testing` feature (a `[dev-dependencies]` edge).
A production build refuses a plaintext endpoint.
