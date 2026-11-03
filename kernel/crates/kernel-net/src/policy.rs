//! Deterministic web egress policy (slice W1).
//!
//! A web `GET` is **egress**, not a harmless local read: the URL path/query
//! and the DNS lookup both leave the machine before anything is refused. This
//! module holds the one deterministic policy every fetch funnels through:
//!
//! - [`WebGate::check`] refuses a URL *shape* before any socket, and
//!   [`WebGate::decide`] adds the mode/private-data rule on top. The gate is
//!   the control; a judge (W2) is only ever advisory. On a sensitive turn
//!   (taint or private owner data) **every** fetch asks
//!   ([`AskReason::SensitiveTurn`]): any silent request is itself a covert
//!   channel, because the origin — or anyone who can observe it — sees
//!   *whether* the agent asked, and the model can condition that request on a
//!   private bit. There is no bare-root exception left, no seen-origin
//!   exception, and an allowlist never exempts a host on a sensitive turn. A
//!   non-sensitive turn keeps the mode and allowlist rules, where the
//!   already-seen set still decides `ask_once_per_site` and `smart`.
//! - [`WebBudget`] is checked before an approval card and reserved at **connect
//!   time** (every hop, the first included), so a refused or unapproved fetch
//!   never consumes a slot. [`FetchEgress`] shares one budget, the turn's
//!   ask-rule facts and the approved origins with the fetcher, so every
//!   redirect hop re-enters the rule and the counters too.
//! - [`WebFetchEvent`] is the single `web.fetch` audit row per attempt. It
//!   records the **host**, a SHA-256 of the query and — for a refused
//!   redirect hop — a SHA-256 of the URL, never the query or URL text: those
//!   are themselves the outbound data the policy exists to protect.
//!
//! Deny always wins: `deny_domains` beats `allow_domains`, a remembered
//! approval, and every mode. An unknown or missing state fails closed.
//!
//! Friction, stated plainly (maintainer decision, security-review round 4): after any web
//! read or private read in a conversation, every further fetch asks. That is
//! deliberate — a silent egress while the turn is sensitive is a channel.

use kernel_core::WebConfig;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The per-turn conversation facts the ask rule depends on.
///
/// The engine fills this in; it never comes from the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EgressContext {
    /// The conversation holds untrusted content (WS-C taint).
    pub tainted: bool,
    /// The turn read mail/calendar/memory/notes: private owner data.
    pub carries_private_data: bool,
    /// This exact origin — `(scheme, host, effective port)` — was fetched
    /// before in this conversation and a response was actually received. Only
    /// the non-sensitive mode rules read it (`ask_once_per_site`, `smart`); a
    /// sensitive turn never does. An allowlist never counts as seen on its
    /// own.
    pub seen_origin: bool,
}

/// Why a fetch must ask before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskReason {
    /// A sensitive turn (taint or private owner data). Every fetch asks:
    /// there is no exception, not the bare root of an already-seen origin,
    /// not an allowlisted host, and not a re-fetch of a URL that already ran.
    SensitiveTurn,
    /// `[web] mode = "always_ask"`.
    ModeAlwaysAsk,
    /// `ask_once_per_site` with no remembered approval (W6 lands later).
    ModeAskOncePerSite,
    /// `smart` with no judge available (W5 lands later); fail closed.
    SmartJudgeUnavailable,
}

impl AskReason {
    /// Stable lowercase label for the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            AskReason::SensitiveTurn => "sensitive_turn",
            AskReason::ModeAlwaysAsk => "mode_always_ask",
            AskReason::ModeAskOncePerSite => "mode_ask_once_per_site",
            AskReason::SmartJudgeUnavailable => "smart_judge_unavailable",
        }
    }
}

/// Why the deterministic gate refused a URL. It is a refusal, never a silent
/// fallback, and it opens no socket and performs no DNS lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Not an absolute `http`/`https` URL.
    NotHttp,
    /// `https_only = true` and the URL is plain `http`.
    HttpsOnly,
    /// A redirect downgraded an HTTPS fetch to plain HTTP.
    HttpsDowngrade,
    /// The port is not in `port_allowlist`.
    PortNotAllowed,
    /// The whole URL is over `max_url_bytes` (refused, never truncated).
    UrlTooLong,
    /// The query string is over `max_query_bytes`.
    QueryTooLong,
    /// The host is a bare IP literal, not a name.
    IpLiteral,
    /// The host is an obfuscated numeric spelling (`2130706433`, `0x7f.1`).
    ObfuscatedHost,
    /// The host carries a punycode/IDN label (`xn--…`).
    PunycodeHost,
    /// The host matched `deny_domains`. Deny wins in every mode.
    DeniedDomain,
    /// The per-turn fetch budget is exhausted.
    BudgetTurn,
    /// The per-day fetch budget is exhausted.
    BudgetDay,
    /// The per-host-per-minute fetch budget is exhausted.
    BudgetHost,
    /// The connection targets an origin the call was not approved for: not a
    /// declared host and not the URL argument's origin. Refused before DNS.
    OriginNotApproved,
}

impl DenyReason {
    /// Stable lowercase label for the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::NotHttp => "not_http",
            DenyReason::HttpsOnly => "https_only",
            DenyReason::HttpsDowngrade => "https_downgrade",
            DenyReason::PortNotAllowed => "port_not_allowed",
            DenyReason::UrlTooLong => "url_too_long",
            DenyReason::QueryTooLong => "query_too_long",
            DenyReason::IpLiteral => "ip_literal",
            DenyReason::ObfuscatedHost => "obfuscated_host",
            DenyReason::PunycodeHost => "punycode_host",
            DenyReason::DeniedDomain => "denied_domain",
            DenyReason::BudgetTurn => "budget_turn",
            DenyReason::BudgetDay => "budget_day",
            DenyReason::BudgetHost => "budget_host",
            DenyReason::OriginNotApproved => "origin_not_approved",
        }
    }
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the policy says about one URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    /// The gate passed and no rule requires a card.
    Allow,
    /// The gate passed but a card is required first.
    Ask(AskReason),
    /// The gate refused the URL outright.
    Deny(DenyReason),
}

impl EgressDecision {
    /// True for [`EgressDecision::Allow`].
    pub fn is_allow(self) -> bool {
        matches!(self, EgressDecision::Allow)
    }

    /// Stable label for the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            EgressDecision::Allow => "allow",
            EgressDecision::Ask(_) => "ask",
            EgressDecision::Deny(_) => "deny",
        }
    }

    /// The reason label, when there is one.
    pub fn reason_label(self) -> Option<&'static str> {
        match self {
            EgressDecision::Allow => None,
            EgressDecision::Ask(reason) => Some(reason.as_str()),
            EgressDecision::Deny(reason) => Some(reason.as_str()),
        }
    }
}

/// A URL that passed the deterministic shape checks.
#[derive(Debug, Clone)]
pub struct CheckedUrl {
    /// The parsed URL.
    pub url: reqwest::Url,
    /// The bare host (brackets stripped for IPv6 literals), lowercased.
    pub host: String,
}

impl CheckedUrl {
    /// The seen-origin key: `scheme://host:effective-port`. The non-sensitive
    /// mode rules key on origins, not hosts, so `http://h/p` and `https://h/p`
    /// are different origins, as are port 80 and port 443.
    pub fn origin_key(&self) -> String {
        url_origin_key(&self.url)
    }
}

/// The seen-origin key of `url`: `scheme://host:effective-port`, host bare and
/// lowercased. Used for the conversation's already-seen set and for redirect
/// destinations, so both sides key on the same tuple.
pub(crate) fn url_origin_key(url: &reqwest::Url) -> String {
    let host = bare_host(url).unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{}://{host}:{port}", url.scheme())
}

/// The origin key of `url` (see [`url_origin_key`]), or `None` when it does
/// not parse.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .map(|parsed| url_origin_key(&parsed))
}

/// True when `pattern` covers `host` (case-insensitive).
///
/// A bare `example.com` matches the domain and every subdomain;
/// `*.example.com` and `.example.com` mean the same. There is no implicit
/// suffix at the TLD boundary here (that is `ask_once_per_site`, W6): a
/// `deny_domains` entry is matched literally as written, so no entry is ever
/// widened by the PSL.
pub fn domain_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    let suffix = pattern
        .strip_prefix("*.")
        .or_else(|| pattern.strip_prefix('.'))
        .unwrap_or(pattern.as_str());
    if suffix.is_empty() {
        return false;
    }
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// The deterministic egress gate, built from `[web]`.
#[derive(Debug, Clone)]
pub struct WebGate {
    config: WebConfig,
    /// Tests only: allow loopback IP literals and arbitrary ports so a
    /// `wiremock` server is reachable. Production is always `false`.
    #[cfg(any(test, feature = "testing"))]
    permissive: bool,
}

impl WebGate {
    /// Build a gate from the `[web]` section.
    pub fn new(config: WebConfig) -> Self {
        Self {
            config,
            #[cfg(any(test, feature = "testing"))]
            permissive: false,
        }
    }

    /// Tests only: the shape checks for ports/IP literals are relaxed so a
    /// loopback `wiremock` server can be reached. `deny_domains` and the URL
    /// caps still apply.
    #[cfg(any(test, feature = "testing"))]
    pub fn permissive_for_tests(config: WebConfig) -> Self {
        Self {
            config,
            permissive: true,
        }
    }

    /// The `[web]` settings this gate enforces.
    pub fn config(&self) -> &WebConfig {
        &self.config
    }

    /// The configured mode label.
    pub fn mode_label(&self) -> &'static str {
        self.config.mode.as_str()
    }

    fn bypasses_shape(&self) -> bool {
        #[cfg(any(test, feature = "testing"))]
        {
            self.permissive
        }
        #[cfg(not(any(test, feature = "testing")))]
        {
            false
        }
    }

    /// Checks that need no DNS lookup: scheme, `https_only`, the URL/query
    /// caps and `deny_domains`. Safe to run **before** a lookup, so a
    /// deny-listed or over-long URL resolves nothing.
    pub fn check_before_resolve(&self, url: &reqwest::Url) -> Result<(), DenyReason> {
        match url.scheme() {
            "http" | "https" => {}
            _ => return Err(DenyReason::NotHttp),
        }
        if self.config.https_only && url.scheme() == "http" {
            return Err(DenyReason::HttpsOnly);
        }
        if url.as_str().len() > self.config.max_url_bytes {
            return Err(DenyReason::UrlTooLong);
        }
        if let Some(query) = url.query() {
            if query.len() > self.config.max_query_bytes {
                return Err(DenyReason::QueryTooLong);
            }
        }
        let host = bare_host(url).ok_or(DenyReason::NotHttp)?;
        if self
            .config
            .deny_domains
            .iter()
            .any(|pattern| domain_matches(pattern, &host))
        {
            return Err(DenyReason::DeniedDomain);
        }
        Ok(())
    }

    /// Checks that need only the URL, not DNS or a connection: port allowlist
    /// and URL-shape refusals (IP literals, obfuscated numeric spellings,
    /// punycode/IDN labels). Despite the historical name, this is safe to run
    /// before resolution.
    pub fn check_after_resolve(&self, url: &reqwest::Url) -> Result<(), DenyReason> {
        let port = url.port_or_known_default().ok_or(DenyReason::NotHttp)?;
        if !self.bypasses_shape() && !self.config.port_allowed(port) {
            return Err(DenyReason::PortNotAllowed);
        }
        let host = bare_host(url).ok_or(DenyReason::NotHttp)?;
        self.check_host_shape(&host)
    }

    /// The host-shape refusals alone (also usable by a caller that already
    /// resolved the URL).
    pub fn check_host_shape(&self, host: &str) -> Result<(), DenyReason> {
        if self.bypasses_shape() {
            return Ok(());
        }
        if host.is_empty() {
            return Err(DenyReason::NotHttp);
        }
        let lowered = host.to_ascii_lowercase();
        if lowered.parse::<IpAddr>().is_ok() {
            // A bare public IP literal is still an egress address the owner
            // never typed. Private/reserved literals are handled by the SSRF
            // guard; the gate refuses the shape itself.
            return Err(DenyReason::IpLiteral);
        }
        if is_obfuscated_numeric_host(&lowered) {
            return Err(DenyReason::ObfuscatedHost);
        }
        if lowered.split('.').any(|label| label.starts_with("xn--")) {
            return Err(DenyReason::PunycodeHost);
        }
        Ok(())
    }

    /// The full deterministic check: parse, pre-resolve, post-resolve.
    pub fn check(&self, input: &str) -> Result<CheckedUrl, DenyReason> {
        if input.len() > self.config.max_url_bytes {
            return Err(DenyReason::UrlTooLong);
        }
        let url = reqwest::Url::parse(input).map_err(|_| DenyReason::NotHttp)?;
        self.check_before_resolve(&url)?;
        self.check_after_resolve(&url)?;
        let host = bare_host(&url).ok_or(DenyReason::NotHttp)?;
        Ok(CheckedUrl { url, host })
    }

    /// Best-effort host of `input`, for an audit row on a refused URL. `None`
    /// when the input does not parse.
    pub fn host_of(&self, input: &str) -> Option<String> {
        reqwest::Url::parse(input)
            .ok()
            .and_then(|url| bare_host(&url))
    }

    /// The mode/private-data rule, on top of [`WebGate::check`].
    ///
    /// The order is the contract: a denied URL is never asked about, and a
    /// judge (W2) is only ever consulted for an origin that passed and was not
    /// already seen.
    pub fn decide(&self, input: &str, ctx: &EgressContext) -> EgressDecision {
        match self.check(input) {
            Ok(checked) => self.decide_checked(&checked, ctx),
            Err(reason) => EgressDecision::Deny(reason),
        }
    }

    /// [`WebGate::decide`] for a URL that already passed [`WebGate::check`],
    /// so a caller that needs the host does not parse and shape-check twice.
    ///
    /// The order is the contract: on a sensitive turn **every** fetch asks,
    /// and that rule is never bypassed by `allow_domains` (an allowlist
    /// exempts a host from the *mode*, never from the sensitive-turn card).
    /// The already-seen origin is read only by the non-sensitive mode rules.
    pub fn decide_checked(&self, checked: &CheckedUrl, ctx: &EgressContext) -> EgressDecision {
        // Any silent request is a channel: on a sensitive turn every fetch
        // asks, before the allowlist and before the mode rules.
        if ctx.tainted || ctx.carries_private_data {
            return EgressDecision::Ask(AskReason::SensitiveTurn);
        }
        if self
            .config
            .allow_domains
            .iter()
            .any(|pattern| domain_matches(pattern, checked.host.as_str()))
        {
            return EgressDecision::Allow;
        }
        match self.config.mode {
            kernel_core::WebMode::OpenRead => EgressDecision::Allow,
            kernel_core::WebMode::AlwaysAsk => EgressDecision::Ask(AskReason::ModeAlwaysAsk),
            kernel_core::WebMode::AskOncePerSite => {
                if ctx.seen_origin {
                    EgressDecision::Allow
                } else {
                    EgressDecision::Ask(AskReason::ModeAskOncePerSite)
                }
            }
            kernel_core::WebMode::Smart => {
                if ctx.seen_origin {
                    EgressDecision::Allow
                } else {
                    EgressDecision::Ask(AskReason::SmartJudgeUnavailable)
                }
            }
        }
    }

    /// True when the fetch's response `Content-Type` may be rendered.
    pub fn content_type_allowed(&self, content_type: &str) -> bool {
        self.config.content_type_allowed(content_type)
    }

    /// SHA-256 (lowercase hex) of the query string, or `None` when the URL
    /// has no query. The query text itself is never logged.
    pub fn query_sha256(&self, url: &reqwest::Url) -> Option<String> {
        url.query().map(|query| sha256_hex(query.as_bytes()))
    }

    /// SHA-256 (lowercase hex) of text a declared-host tool sends off the
    /// machine (for example a place name). Only the hash is ever audited.
    pub fn text_sha256(&self, text: &str) -> String {
        sha256_hex(text.as_bytes())
    }
}

impl Default for WebGate {
    fn default() -> Self {
        Self::new(WebConfig::default())
    }
}

/// Host (or `None`) of `url`, brackets stripped for IPv6 literals.
pub(crate) fn bare_host(url: &reqwest::Url) -> Option<String> {
    url.host_str().map(|host| {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    })
}

/// True for a numeric spelling that is *not* a valid IP literal but is an
/// attempt to smuggle one (`2130706433`, `0177.0.0.1`, `127.1`, `0x7f.1`).
fn is_obfuscated_numeric_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if host.starts_with("0x") || host.split('.').any(|label| label.starts_with("0x")) {
        return true;
    }
    host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.contains('.')
}

/// Lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Which counter refused a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    /// Per-turn cap.
    Turn,
    /// Per-day cap.
    Day,
    /// Per-host rolling-minute cap.
    Host,
}

impl BudgetKind {
    /// The [`DenyReason`] this counter maps to.
    pub fn deny_reason(self) -> DenyReason {
        match self {
            BudgetKind::Turn => DenyReason::BudgetTurn,
            BudgetKind::Day => DenyReason::BudgetDay,
            BudgetKind::Host => DenyReason::BudgetHost,
        }
    }
}

/// In-memory fetch counters. `reserve` is called **before** the connect, so a
/// fetch that is over budget never opens a socket. W1 keeps this in memory
/// (per conversation); a persistent day ledger is slice W4.
#[derive(Debug, Default)]
pub struct WebBudget {
    turn: u32,
    day: u32,
    day_key: String,
    per_host: BTreeMap<String, VecDeque<Instant>>,
}

impl WebBudget {
    /// A fresh budget with every counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the per-turn counter. Called once at the start of each turn.
    pub fn start_turn(&mut self) {
        self.turn = 0;
    }

    /// Point the per-day counter at `key` (a local-day string). A different
    /// key resets the day counter.
    pub fn set_day(&mut self, key: &str) {
        if self.day_key != key {
            self.day_key = key.to_string();
            self.day = 0;
        }
    }

    /// The per-turn count so far (tests and diagnostics).
    pub fn turn_count(&self) -> u32 {
        self.turn
    }

    /// Reserve one fetch for `host`, or return the counter that refused it.
    pub fn reserve(
        &mut self,
        host: &str,
        now: Instant,
        config: &WebConfig,
    ) -> Result<(), BudgetKind> {
        if self.turn >= config.fetches_per_turn {
            return Err(BudgetKind::Turn);
        }
        if self.day >= config.fetches_per_day {
            return Err(BudgetKind::Day);
        }
        let window = Duration::from_secs(60);
        let recent = self.per_host.entry(host.to_string()).or_default();
        while let Some(front) = recent.front() {
            if now.saturating_duration_since(*front) >= window {
                recent.pop_front();
            } else {
                break;
            }
        }
        if recent.len() as u32 >= config.per_host_per_minute {
            return Err(BudgetKind::Host);
        }
        self.turn += 1;
        self.day += 1;
        recent.push_back(now);
        Ok(())
    }

    /// The per-day count so far (tests and diagnostics).
    pub fn day_count(&self) -> u32 {
        self.day
    }

    /// Whether one fetch for each of `hosts` would fit every counter, without
    /// reserving anything. The engine asks this before it shows an approval
    /// card; the fetcher reserves each destination when it connects, so a
    /// refused or unapproved call never consumes a slot.
    pub fn check(
        &self,
        hosts: &[&str],
        now: Instant,
        config: &WebConfig,
    ) -> Result<(), BudgetKind> {
        let needed = hosts.len() as u32;
        if self.turn + needed > config.fetches_per_turn {
            return Err(BudgetKind::Turn);
        }
        if self.day + needed > config.fetches_per_day {
            return Err(BudgetKind::Day);
        }
        let window = Duration::from_secs(60);
        let mut wanted: BTreeMap<&str, u32> = BTreeMap::new();
        for host in hosts {
            *wanted.entry(*host).or_default() += 1;
        }
        for (host, count) in wanted {
            let recent = self.per_host.get(host).map_or(0, |recent| {
                recent
                    .iter()
                    .filter(|reserved| now.saturating_duration_since(**reserved) < window)
                    .count() as u32
            });
            if recent + count > config.per_host_per_minute {
                return Err(BudgetKind::Host);
            }
        }
        Ok(())
    }
}

/// One redirect hop the fetcher refused because it needed its own approval.
///
/// The engine reads these back from [`FetchEgress`] after the tool ran and
/// writes one `web.fetch` row per refusal. It carries the hop host and a
/// SHA-256 of the refused URL — never the URL or query text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedRedirectHop {
    /// Host of the refused hop.
    pub host: String,
    /// SHA-256 (lowercase hex) of the refused hop URL.
    pub url_sha256: String,
}

/// The per-fetch egress authority the engine shares with the fetcher.
///
/// A redirect leaves the decided URL behind, and every hop is re-checked —
/// but not every hop re-runs the full decision:
///
/// - **Every hop** re-enters the deterministic shape gate
///   ([`WebGate::check_before_resolve`] + [`WebGate::check_after_resolve`]:
///   URL shape, deny domains, allowed port, HTTPS-downgrade refusal) before any
///   DNS lookup. Its origin must be one of [`FetchEgress::approved_origins`],
///   and its destination host is reserved from the shared per-turn/day/host
///   counters right before its connect.
/// - **A hop that leaves the origin's host** is never followed silently: its
///   destination origin re-runs [`WebGate::decide_checked`] under these facts,
///   and when that does not allow it the hop is refused with its own card
///   ([`crate::FetchError::RedirectNeedsApproval`]), so the card issued for the
///   original URL can never authorize another origin.
/// - **A same-host hop that changes port** re-runs [`WebGate::decide_checked`]
///   when the turn is sensitive (taint or private data), and can be refused.
/// - **A same-host, same-port hop** does **not** re-enter
///   [`WebGate::decide_checked`]: the card for that origin already covered it.
///   Only the shape gate and the budget reservation above apply.
///
/// Tools that run without the engine (tests, search-side fetchers) pass no
/// [`FetchEgress`]: hops then decide with [`EgressContext::default`], clean and
/// unseen, so every mode stricter than `open_read` refuses a cross-origin hop —
/// fail closed.
#[derive(Debug, Clone)]
pub struct FetchEgress {
    /// The turn's sensitive-turn facts: taint and private owner data. The
    /// `seen_origin` fact of [`EgressContext`] is recomputed per hop by
    /// [`FetchEgress::redirect_context`].
    pub context: EgressContext,
    /// Origins (`scheme://host:port`) already fetched in this conversation. A
    /// hop lands on one of them (or stays on the origin the card covered)
    /// without a new card; any other origin is unseen.
    pub seen_origins: Arc<BTreeSet<String>>,
    /// The origins (`scheme://host:port`) this call was approved for: the
    /// declared hosts plus the origin of the URL argument. The fetcher refuses
    /// a connection to any other origin, the first hop included, before DNS.
    pub approved_origins: Arc<BTreeSet<String>>,
    /// The shared fetch counters, reserved right before every hop connects.
    pub budget: Arc<Mutex<WebBudget>>,
    /// Redirect hops refused for approval during this fetch, for the engine's
    /// `web.fetch` audit row. Empty when the caller does not audit.
    pub refused_hops: Arc<Mutex<Vec<RefusedRedirectHop>>>,
    /// Set once any request in this fetch received an HTTP response. The
    /// engine reads it back to decide whether the origin may be recorded as
    /// seen: a DNS/TLS/connect/timeout failure leaves it false, so an origin
    /// is never marked seen by a fetch that reached no server.
    pub received_response: Arc<Mutex<bool>>,
    /// The origins that actually answered during this call, with the HTTP
    /// status and body bytes of each. An origin appears only after a server
    /// responded, so the engine can attribute bytes and status per target.
    pub received_origins: Arc<Mutex<BTreeMap<String, OriginReceipt>>>,
}

/// What one origin sent back during a call: the status of its last response
/// and the response body bytes read from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OriginReceipt {
    /// HTTP status of the last response from this origin.
    pub http_status: u16,
    /// Response body bytes read from this origin, after the body caps.
    pub bytes: usize,
}

impl FetchEgress {
    /// Whether the call was approved for the origin of `url`.
    pub fn approves(&self, url: &reqwest::Url) -> bool {
        self.approved_origins.contains(&url_origin_key(url))
    }

    /// Record one response from `url` (any status): the origin is now a
    /// server that answered, and `http_status` is its status.
    pub fn note_origin_response(&self, url: &str, http_status: u16) {
        self.note_received_response();
        if let Some(origin) = origin_of(url) {
            self.with_origins(|origins| {
                origins.entry(origin).or_default().http_status = http_status
            });
        }
    }

    /// Add `bytes` of response body read from `url`'s origin.
    pub fn note_origin_bytes(&self, url: &str, bytes: usize) {
        if let Some(origin) = origin_of(url) {
            self.with_origins(|origins| origins.entry(origin).or_default().bytes += bytes);
        }
    }

    /// What `origin` answered during this call, or `None` when it never did.
    pub fn origin_receipt(&self, origin: &str) -> Option<OriginReceipt> {
        match self.received_origins.lock() {
            Ok(origins) => origins.get(origin).copied(),
            Err(poisoned) => poisoned.into_inner().get(origin).copied(),
        }
    }

    fn with_origins<R>(&self, f: impl FnOnce(&mut BTreeMap<String, OriginReceipt>) -> R) -> R {
        match self.received_origins.lock() {
            Ok(mut origins) => f(&mut origins),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    /// Record that a request received an HTTP response (any status). Only then
    /// may the origin be remembered as seen.
    pub fn note_received_response(&self) {
        match self.received_response.lock() {
            Ok(mut reached) => *reached = true,
            Err(poisoned) => *poisoned.into_inner() = true,
        }
    }

    /// True once a request in this fetch received an HTTP response. False for
    /// a fetch that failed before any server answered (DNS, connect, TLS,
    /// timeout).
    pub fn received_response(&self) -> bool {
        match self.received_response.lock() {
            Ok(reached) => *reached,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Record one redirect hop refused for approval, for the engine's audit
    /// row. Stores the host and a SHA-256 of the URL, never the URL text. A
    /// URL that does not parse still gets a row, with an empty host.
    pub fn note_refused_hop(&self, url: &str) {
        let entry = RefusedRedirectHop {
            host: reqwest::Url::parse(url)
                .ok()
                .and_then(|parsed| bare_host(&parsed))
                .unwrap_or_default(),
            url_sha256: sha256_hex(url.as_bytes()),
        };
        match self.refused_hops.lock() {
            Ok(mut hops) => hops.push(entry),
            Err(poisoned) => poisoned.into_inner().push(entry),
        }
    }

    /// Take the redirect hops refused for approval so far.
    pub fn take_refused_hops(&self) -> Vec<RefusedRedirectHop> {
        match self.refused_hops.lock() {
            Ok(mut hops) => std::mem::take(&mut *hops),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        }
    }
}

/// One `web.fetch` audit row: host + hashes, never the query/URL text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebFetchEvent {
    /// Host that was (or would have been) reached.
    pub host: String,
    /// SHA-256 of the query string, when the URL had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_sha256: Option<String>,
    /// SHA-256 of the full URL. Set only on a refused-redirect-hop row, which
    /// names the hop host so the owner can see where a redirect tried to go.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_sha256: Option<String>,
    /// Bytes of rendered text returned (0 when nothing was fetched).
    pub bytes: usize,
    /// Outcome status (`ok`, `http_status`, `refused`, `asked`, `denied`,
    /// `budget_denied`, `redirect_refused`, `error`).
    pub status: String,
    /// Effective `[web] mode`.
    pub mode: String,
    /// Gate decision (`allow` / `ask` / `deny`) and its reason.
    pub outcome: String,
    /// True when the conversation carried untrusted content.
    pub tainted: bool,
    /// True when the turn had read private owner data.
    pub carries_private_data: bool,
}

impl WebFetchEvent {
    /// Serialize the row for `store.log_event("web.fetch", …)`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::{WebConfig, WebMode};

    fn web_gate(config: WebConfig) -> WebGate {
        WebGate::new(config)
    }

    #[test]
    fn domain_matching_is_suffix_scoped() {
        assert!(domain_matches("docs.rs", "docs.rs"));
        assert!(domain_matches("docs.rs", "a.docs.rs"));
        assert!(domain_matches("*.ads.example", "ads.example"));
        assert!(domain_matches("*.ads.example", "x.ads.example"));
        assert!(domain_matches(".example.com", "example.com"));
        assert!(!domain_matches("example.com", "notexample.com"));
        assert!(!domain_matches("example.com", "example.com.evil"));
        assert!(!domain_matches("", "example.com"));
        assert!(domain_matches("DOCS.RS", "docs.rs"));
    }

    #[test]
    fn deny_wins_over_allow_in_every_mode() {
        for mode in [
            WebMode::OpenRead,
            WebMode::Smart,
            WebMode::AskOncePerSite,
            WebMode::AlwaysAsk,
        ] {
            let gate = web_gate(WebConfig {
                mode,
                allow_domains: vec!["*.example.com".to_string()],
                deny_domains: vec!["ads.example.com".to_string()],
                ..WebConfig::default()
            });
            let ctx = EgressContext {
                seen_origin: true,
                ..EgressContext::default()
            };
            assert_eq!(
                gate.decide("https://ads.example.com/pixel", &ctx),
                EgressDecision::Deny(DenyReason::DeniedDomain),
                "{mode}"
            );
            // A non-denied sibling is still allowlisted without a card.
            assert_eq!(
                gate.decide("https://docs.example.com/page", &ctx),
                EgressDecision::Allow,
                "{mode}"
            );
        }
    }

    #[test]
    fn gate_refuses_url_shapes_before_any_network() {
        let default = web_gate(WebConfig::default());
        assert_eq!(
            default.check("ftp://example.com/x").unwrap_err(),
            DenyReason::NotHttp
        );
        assert_eq!(
            default.check("file:///etc/passwd").unwrap_err(),
            DenyReason::NotHttp
        );
        assert_eq!(
            web_gate(WebConfig {
                https_only: true,
                ..WebConfig::default()
            })
            .check("http://example.com/")
            .unwrap_err(),
            DenyReason::HttpsOnly
        );
        assert_eq!(
            default.check("https://example.com:8080/").unwrap_err(),
            DenyReason::PortNotAllowed
        );
        assert!(default.check("https://example.com/").is_ok());
        assert!(default.check("http://example.com/").is_ok());
    }

    #[test]
    fn gate_refuses_ip_and_obfuscated_hosts() {
        let default = web_gate(WebConfig::default());
        // A bare IP literal is refused outright.
        for url in ["https://8.8.8.8/", "https://[2606:4700::1111]/"] {
            assert_eq!(
                default.check(url).unwrap_err(),
                DenyReason::IpLiteral,
                "{url}"
            );
        }
        // Numeric smuggling spellings are refused whatever their exact
        // classification: Rust's IPv4 parser already accepts several of them
        // (single integer, `0x`-prefixed, short forms), the rest are caught as
        // obfuscated hosts. `256.1.1.1` is out of range, so it is not an
        // address and the shape check is what refuses it.
        for url in [
            "https://2130706433/",
            "https://0177.0.0.1/",
            "https://127.1/",
            "https://0x7f.1/",
        ] {
            assert!(default.check(url).is_err(), "{url} must be refused");
        }
        assert_eq!(
            default.check_host_shape("1.2.3.999").unwrap_err(),
            DenyReason::ObfuscatedHost
        );
        assert_eq!(
            default.check_host_shape("xn--g00gle-9db.com").unwrap_err(),
            DenyReason::PunycodeHost
        );
    }

    #[test]
    fn url_and_query_caps_refuse_never_truncate() {
        let url_gate = web_gate(WebConfig {
            max_url_bytes: 32,
            ..WebConfig::default()
        });
        assert_eq!(
            url_gate
                .check("https://example.com/aaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap_err(),
            DenyReason::UrlTooLong
        );
        let query_gate = web_gate(WebConfig {
            max_url_bytes: 256,
            max_query_bytes: 8,
            ..WebConfig::default()
        });
        assert_eq!(
            query_gate
                .check("https://example.com/?q=0123456789")
                .unwrap_err(),
            DenyReason::QueryTooLong
        );
    }

    fn sensitive_seen() -> EgressContext {
        EgressContext {
            tainted: true,
            seen_origin: true,
            ..EgressContext::default()
        }
    }

    #[test]
    fn the_origin_key_is_the_scheme_host_and_effective_port_tuple() {
        // R3: the old seen-URL identity was host+path+query and dropped the
        // scheme and the port, so a clean fetch of `http://h/p` made
        // `https://h/p` an "exact re-fetch". The key is the full tuple now.
        assert_eq!(
            url_origin_key(&reqwest::Url::parse("http://h/p").unwrap()),
            "http://h:80"
        );
        assert_eq!(
            url_origin_key(&reqwest::Url::parse("https://h/p").unwrap()),
            "https://h:443"
        );
        assert_eq!(
            url_origin_key(&reqwest::Url::parse("http://h:8080/p").unwrap()),
            "http://h:8080"
        );
        assert_ne!(
            url_origin_key(&reqwest::Url::parse("http://h/p").unwrap()),
            url_origin_key(&reqwest::Url::parse("https://h/p").unwrap()),
            "scheme is part of the origin"
        );
        assert_ne!(
            url_origin_key(&reqwest::Url::parse("https://h:80/p").unwrap()),
            url_origin_key(&reqwest::Url::parse("https://h:443/p").unwrap()),
            "port 80 and port 443 are different origins"
        );
        assert_ne!(
            url_origin_key(&reqwest::Url::parse("https://h/p").unwrap()),
            url_origin_key(&reqwest::Url::parse("https://h:8443/p").unwrap()),
            "effective port is part of the origin"
        );
    }

    /// The sensitive-turn facts for `input` as if the conversation had seen
    /// `seen_urls` (any URL on those origins). This models the engine's
    /// origin-keyed set at the policy level.
    fn ctx_seen_from(seen_urls: &[&str], input: &str, tainted: bool) -> EgressContext {
        let key = url_origin_key(&reqwest::Url::parse(input).unwrap());
        EgressContext {
            tainted,
            seen_origin: seen_urls
                .iter()
                .any(|url| url_origin_key(&reqwest::Url::parse(url).unwrap()) == key),
            ..EgressContext::default()
        }
    }

    #[test]
    fn a_sensitive_turn_asks_for_every_fetch_of_a_seen_origin() {
        // R4: the bare-root exception is gone. Any silent request is a channel
        // (the origin observes whether the agent asked), so a seen origin buys
        // nothing on a sensitive turn: its bare root asks like everything else.
        let gate = web_gate(WebConfig {
            port_allowlist: vec![80, 443, 8443],
            ..WebConfig::default()
        });
        let seen = |input: &str| ctx_seen_from(&["https://h/page"], input, true);
        for url in [
            "https://h/",
            "http://h/",
            "https://h:8443/",
            "https://h/next",
            "https://h/?q=1",
            "https://h",
        ] {
            assert_eq!(
                gate.decide(url, &seen(url)),
                EgressDecision::Ask(AskReason::SensitiveTurn),
                "{url}"
            );
        }
        // A never-seen origin asks at the root too.
        assert_eq!(
            gate.decide(
                "https://other/",
                &EgressContext {
                    tainted: true,
                    ..EgressContext::default()
                }
            ),
            EgressDecision::Ask(AskReason::SensitiveTurn)
        );
    }

    #[test]
    fn a_non_sensitive_turn_keeps_the_seen_origin_and_allowlist_rules() {
        // The redesign must not touch a clean turn: the modes and the
        // allowlist still decide, and a seen origin stays silent in
        // `open_read`/`ask_once_per_site`.
        let gate = web_gate(WebConfig {
            mode: WebMode::AskOncePerSite,
            ..WebConfig::default()
        });
        let seen = EgressContext {
            seen_origin: true,
            ..EgressContext::default()
        };
        assert_eq!(
            gate.decide("https://h/", &seen),
            EgressDecision::Allow,
            "a seen origin is still silent on a clean ask_once_per_site turn"
        );
        assert_eq!(
            gate.decide("https://h/deep/path?q=1", &seen),
            EgressDecision::Allow,
            "a clean turn has no path/query rule"
        );
        assert_eq!(
            gate.decide("https://new.example/", &EgressContext::default()),
            EgressDecision::Ask(AskReason::ModeAskOncePerSite)
        );
        let allowlisted = web_gate(WebConfig {
            mode: WebMode::AlwaysAsk,
            allow_domains: vec!["docs.rs".to_string()],
            ..WebConfig::default()
        });
        assert_eq!(
            allowlisted.decide("https://docs.rs/tokio", &EgressContext::default()),
            EgressDecision::Allow,
            "an allowlisted host is silent when the turn is not sensitive"
        );
    }

    #[test]
    fn a_sensitive_turn_asks_to_refetch_a_seen_non_root_url() {
        // There is no exact-URL exception left: the URL that already ran is
        // model-composed egress the second time on a sensitive turn.
        let gate = web_gate(WebConfig::default());
        assert_eq!(
            gate.decide("https://h/page", &sensitive_seen()),
            EgressDecision::Ask(AskReason::SensitiveTurn)
        );
    }

    #[test]
    fn a_path_carried_secret_on_a_seen_host_asks_while_sensitive() {
        // P3-1 (re-rated P2): a secret in the URL *path* must never leave on a
        // sensitive turn, whatever the host history.
        let gate = web_gate(WebConfig::default());
        let secret = "https://seen.example/log/GRID-CONTRACT-2026-AMOUNT-44000-EUROS";
        for sensitive in [
            EgressContext {
                tainted: true,
                seen_origin: true,
                ..EgressContext::default()
            },
            EgressContext {
                carries_private_data: true,
                seen_origin: true,
                ..EgressContext::default()
            },
        ] {
            assert_eq!(
                gate.decide(secret, &sensitive),
                EgressDecision::Ask(AskReason::SensitiveTurn),
                "a path-carried secret must ask on a sensitive turn"
            );
        }
        // A clean turn is unchanged: the seen origin still runs silently.
        let clean = EgressContext {
            seen_origin: true,
            ..EgressContext::default()
        };
        assert_eq!(gate.decide(secret, &clean), EgressDecision::Allow);
        // Percent-encoded spellings are a different path too.
        assert_eq!(
            gate.decide(
                "https://seen.example/log/GRID%2DCONTRACT%2D2026%2DAMOUNT",
                &EgressContext {
                    tainted: true,
                    seen_origin: true,
                    ..EgressContext::default()
                }
            ),
            EgressDecision::Ask(AskReason::SensitiveTurn)
        );
    }

    #[test]
    fn private_data_turn_asks_on_an_unseen_origin() {
        let gate = web_gate(WebConfig::default());
        let private = EgressContext {
            carries_private_data: true,
            ..EgressContext::default()
        };
        assert_eq!(
            gate.decide("https://evil.example/?d=secret", &private),
            EgressDecision::Ask(AskReason::SensitiveTurn)
        );
        // A clean turn in the default mode stays silent on an unseen origin.
        assert_eq!(
            gate.decide("https://evil.example/?d=secret", &EgressContext::default()),
            EgressDecision::Allow
        );
    }

    #[test]
    fn a_model_authored_url_on_a_seen_origin_asks_while_sensitive() {
        let gate = web_gate(WebConfig::default());
        let sensitive_seen = sensitive_seen();
        assert_eq!(
            gate.decide("https://example.com/?d=notes", &sensitive_seen),
            EgressDecision::Ask(AskReason::SensitiveTurn)
        );
        // A different path is model-composed egress too, not just the query.
        assert_eq!(
            gate.decide("https://example.com/notes/secret", &sensitive_seen),
            EgressDecision::Ask(AskReason::SensitiveTurn)
        );
    }

    #[test]
    fn modes_change_who_is_asked_never_the_gate() {
        // always_ask asks even on a seen, clean host.
        let gate = web_gate(WebConfig {
            mode: WebMode::AlwaysAsk,
            ..WebConfig::default()
        });
        assert_eq!(
            gate.decide(
                "https://example.com/",
                &EgressContext {
                    seen_origin: true,
                    ..EgressContext::default()
                }
            ),
            EgressDecision::Ask(AskReason::ModeAlwaysAsk)
        );
        // ask_once_per_site and smart have no memory/judge in W1: unseen asks.
        for (mode, reason) in [
            (WebMode::AskOncePerSite, AskReason::ModeAskOncePerSite),
            (WebMode::Smart, AskReason::SmartJudgeUnavailable),
        ] {
            let gate = web_gate(WebConfig {
                mode,
                ..WebConfig::default()
            });
            assert_eq!(
                gate.decide("https://example.com/", &EgressContext::default()),
                EgressDecision::Ask(reason),
                "{mode}"
            );
            // A denied URL is never asked about, whatever the mode.
            let gate = web_gate(WebConfig {
                mode,
                deny_domains: vec!["bad.example".to_string()],
                ..WebConfig::default()
            });
            assert_eq!(
                gate.decide("https://bad.example/", &EgressContext::default()),
                EgressDecision::Deny(DenyReason::DeniedDomain),
                "{mode}"
            );
        }
    }

    #[test]
    fn allowlisted_hosts_are_silent_even_in_always_ask() {
        let gate = web_gate(WebConfig {
            mode: WebMode::AlwaysAsk,
            allow_domains: vec!["docs.rs".to_string()],
            ..WebConfig::default()
        });
        assert_eq!(
            gate.decide("https://docs.rs/tokio", &EgressContext::default()),
            EgressDecision::Allow
        );
    }

    #[test]
    fn an_allowlist_never_bypasses_the_sensitive_turn_ask_rule() {
        // The allowlisted-domain abuse (Cowork's own
        // allowlisted domain was used to exfiltrate) is why the sensitive-turn
        // rule runs before the allowlist, not after it. The allowlist exempts
        // a host from the *mode*, never from the sensitive-turn rule.
        for mode in [
            WebMode::OpenRead,
            WebMode::Smart,
            WebMode::AskOncePerSite,
            WebMode::AlwaysAsk,
        ] {
            let gate = web_gate(WebConfig {
                mode,
                allow_domains: vec!["docs.rs".to_string()],
                ..WebConfig::default()
            });
            // Taint: on an unseen, allowlisted origin the card is still asked.
            for sensitive in [
                EgressContext {
                    tainted: true,
                    ..EgressContext::default()
                },
                EgressContext {
                    carries_private_data: true,
                    ..EgressContext::default()
                },
            ] {
                assert_eq!(
                    gate.decide("https://docs.rs/tokio", &sensitive),
                    EgressDecision::Ask(AskReason::SensitiveTurn),
                    "{mode}: allowlisted unseen origin on a sensitive turn must ask"
                );
            }
            // Once seen, a URL on the allowlisted origin still asks: the
            // sensitive-turn rule ignores the seen set entirely, so the bare
            // root asks too.
            let private_seen = EgressContext {
                carries_private_data: true,
                seen_origin: true,
                ..EgressContext::default()
            };
            assert_eq!(
                gate.decide("https://docs.rs/?d=private-notes", &private_seen),
                EgressDecision::Ask(AskReason::SensitiveTurn),
                "{mode}: model-composed query on the allowlisted origin"
            );
            assert_eq!(
                gate.decide("https://docs.rs/tokio", &private_seen),
                EgressDecision::Ask(AskReason::SensitiveTurn),
                "{mode}: model-composed path on the allowlisted origin"
            );
            assert_eq!(
                gate.decide("https://docs.rs/", &private_seen),
                EgressDecision::Ask(AskReason::SensitiveTurn),
                "{mode}: even the bare root of the allowlisted origin asks"
            );
        }
    }

    #[test]
    fn permissive_test_gate_allows_loopback_but_keeps_deny_and_caps() {
        let gate = WebGate::permissive_for_tests(WebConfig {
            deny_domains: vec!["bad.example".to_string()],
            max_url_bytes: 40,
            ..WebConfig::default()
        });
        assert!(gate.check("http://127.0.0.1:51234/page").is_ok());
        assert_eq!(
            gate.check("https://bad.example/").unwrap_err(),
            DenyReason::DeniedDomain
        );
        assert_eq!(
            gate.check("https://example.com/aaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap_err(),
            DenyReason::UrlTooLong
        );
    }

    #[test]
    fn budget_reserves_before_connect_and_caps_each_counter() {
        let config = WebConfig {
            fetches_per_turn: 2,
            fetches_per_day: 3,
            per_host_per_minute: 1,
            ..WebConfig::default()
        };
        let mut budget = WebBudget::new();
        budget.set_day("2026-10-07");
        let now = Instant::now();
        assert!(budget.reserve("a.example", now, &config).is_ok());
        // Same host, same minute: refused by the host cap.
        assert_eq!(
            budget.reserve("a.example", now, &config),
            Err(BudgetKind::Host)
        );
        // A different host fits under the turn cap.
        assert!(budget.reserve("b.example", now, &config).is_ok());
        // Third fetch: turn cap.
        assert_eq!(
            budget.reserve("c.example", now, &config),
            Err(BudgetKind::Turn)
        );
        // A new turn resets the turn counter, and the day cap then binds.
        budget.start_turn();
        assert!(budget.reserve("c.example", now, &config).is_ok());
        assert_eq!(
            budget.reserve("d.example", now, &config),
            Err(BudgetKind::Day)
        );
        // A new day resets the day counter.
        budget.set_day("2026-10-08");
        assert!(budget.reserve("d.example", now, &config).is_ok());
    }

    #[test]
    fn per_host_window_expires_after_a_minute() {
        let config = WebConfig {
            per_host_per_minute: 1,
            ..WebConfig::default()
        };
        let mut budget = WebBudget::new();
        let start = Instant::now();
        assert!(budget.reserve("a.example", start, &config).is_ok());
        assert_eq!(
            budget.reserve("a.example", start + Duration::from_secs(30), &config),
            Err(BudgetKind::Host)
        );
        assert!(budget
            .reserve("a.example", start + Duration::from_secs(61), &config)
            .is_ok());
    }

    #[test]
    fn audit_row_logs_host_and_query_hash_never_the_query() {
        let gate = web_gate(WebConfig::default());
        let url = reqwest::Url::parse("https://evil.example/?d=owner-private-notes").unwrap();
        let hash = gate.query_sha256(&url).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hash, "owner-private-notes");
        let event = WebFetchEvent {
            host: "evil.example".to_string(),
            query_sha256: Some(hash.clone()),
            url_sha256: None,
            bytes: 0,
            status: "refused".to_string(),
            mode: "open_read".to_string(),
            outcome: "deny:url_too_long".to_string(),
            tainted: true,
            carries_private_data: true,
        };
        let json = event.to_json();
        assert!(json.contains("\"host\":\"evil.example\""));
        assert!(json.contains(&hash));
        assert!(!json.contains("owner-private-notes"), "{json}");
        assert!(json.contains("\"carries_private_data\":true"));
        // A refused redirect hop logs the host and a URL hash, never the URL.
        let secret = reqwest::Url::parse("https://evil.example/log/GRID-SECRET-44000").unwrap();
        let hop = WebFetchEvent {
            host: "evil.example".to_string(),
            query_sha256: None,
            url_sha256: Some(sha256_hex(secret.as_str().as_bytes())),
            bytes: 0,
            status: "redirect_refused".to_string(),
            mode: "open_read".to_string(),
            outcome: "ask:sensitive_turn".to_string(),
            tainted: true,
            carries_private_data: false,
        };
        let hop_json = hop.to_json();
        assert!(hop_json.contains("\"host\":\"evil.example\""));
        assert!(!hop_json.contains("GRID-SECRET-44000"), "{hop_json}");
        assert!(!hop_json.contains("query_sha256"), "{hop_json}");
        // A URL without a query has no query hash.
        assert!(gate
            .query_sha256(&reqwest::Url::parse("https://example.com/path").unwrap())
            .is_none());
    }
}
