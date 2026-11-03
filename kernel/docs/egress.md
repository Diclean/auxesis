# Egress inventory

Every outbound HTTP client constructed in production code of this repository,
and the policy it applies. `scripts/check-egress.sh` fails when a `reqwest`
client is built in a function that is not in the allowlist below, so a new
egress point cannot ship without being documented here first.

The check is static and offline. It greps `crates/**/src/**` for `Client::builder(`,
`Client::new(` and `build_client(` — the kernel's SSRF-pinned factory — then names
the enclosing `fn`, so a second client, or a second caller of the pinned factory,
added to an allowlisted file is still flagged.

## Clients

| Function | Constructor | Hosts | Redirects | Timeouts | Proxy | Why |
| --- | --- | --- | --- | --- | --- | --- |
| `crates/kernel-mcp/src/http.rs::new` | `reqwest::Client::builder` (line 185) | configured MCP endpoint, https or loopback only; no DNS guard | `none` | connect 5 s / 30 s per request | `no_proxy` | Unchecked constructor, used by tests and as the first step of `new_checked`, which replaces this client before any request |
| `crates/kernel-mcp/src/http.rs::new_checked` | `reqwest::Client::builder` (line 235) | configured MCP endpoint, SSRF-checked: https to a public host, DNS pinned to the one checked address | `none` | connect 5 s / 30 s per request | `no_proxy` | The production MCP HTTP path (`runtime.rs`); the pinned address cannot be rebound between check and connect |
| `crates/kernel-net/src/ssrf.rs::build_client` | `reqwest::Client::builder` (line 188) | caller's host, DNS pinned to the address `resolve_checked` validated | `none` | connect 10 s (`CONNECT_TIMEOUT`); the caller owns the total budget | `no_proxy` | Public API: returns a `PinnedClient` whose `get`/`request` refuse any URL host but the pinned one. `resolve_checked` and `AddressPolicy` are public beside it, so a caller can refuse a private or loopback answer before building. |
| `crates/kernel-mcp/src/runtime.rs::build_client` | no reqwest constructor | MCP endpoint | — | — | — | The MCP transport factory; its reqwest clients are `http.rs::new` and `http.rs::new_checked` above. Matched only by the `build_client(` name in the check. |
| `crates/kernel-mcp/src/runtime.rs::discover_server` | calls `runtime.rs::build_client` | — | — | — | — | Caller of the MCP transport factory. Matched only by the `build_client(` name in the check. |

`kernel-net` exports the SSRF-pinned factory as public API (`build_client`,
`resolve_checked`, `AddressPolicy`): the app's L1 fetch runtime calls
`resolve_checked` to validate the host and every DNS answer, then `build_client`
to pin the connection to the one validated address. A private or loopback
answer is refused before any client is built.

Three `ssrf.rs` unit tests call `build_client` to check host matching. They
build request builders only and send nothing.

Clients for providers, Google, Zoho, Telegram, voice, WhatsApp and the CLI are
not in this repository. They stay in the app repository and are allowlisted there
when it consumes the kernel.

## Allowed constructors

One `file::function` per line. The script matches each line exactly.

<!-- egress-allowlist:start -->
crates/kernel-mcp/src/http.rs::new
crates/kernel-mcp/src/http.rs::new_checked
crates/kernel-mcp/src/runtime.rs::build_client
crates/kernel-mcp/src/runtime.rs::discover_server
crates/kernel-net/src/ssrf.rs::build_client
crates/kernel-net/src/ssrf.rs::a_bracketed_ipv6_host_must_match_its_pinned_address
crates/kernel-net/src/ssrf.rs::a_pinned_host_compares_after_normalisation
crates/kernel-net/src/ssrf.rs::a_pinned_ipv6_literal_is_allowed_with_its_brackets
<!-- egress-allowlist:end -->
