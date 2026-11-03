//! The simple fetch path: `reqwest` behind the SSRF guard, manual redirects
//! with a re-check on every hop, body/parse/output caps, content-type
//! classification and the readability extractor.

use super::readability::{extract_readable_before, EXTRACT_WALL_BUDGET};
use crate::net::pinned_client;
use kernel_net::AddressPolicy;
use kernel_net::{
    BrowserFetcher, FetchError, FetchResult, RenderMode, FETCH_TIMEOUT, MAX_BODY_BYTES,
    MAX_OUTPUT_BYTES, MAX_PARSE_BYTES, MAX_REDIRECTS,
};
use kernel_net::{CheckedUrl, EgressContext, EgressDecision, FetchEgress, WebGate};
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE, LOCATION};
use reqwest::{StatusCode, Url};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The browser handle the simple path carries: the WS-B placeholder.
fn unavailable_browser() -> Arc<dyn BrowserFetcher> {
    Arc::new(kernel_net::UnavailableBrowser)
}

/// Host of `url`, brackets stripped for IPv6 literals. The kernel's copy is
/// crate-private, so the same rule lives here.
fn bare_host(url: &Url) -> Option<String> {
    url.host_str().map(|host| {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    })
}

/// The egress context of a redirect hop: the turn's facts, with `seen_origin`
/// set when the hop's origin was fetched before in this conversation. The
/// kernel's copy is crate-private, so the same rule lives here.
fn redirect_context(
    egress: &FetchEgress,
    origin: &str,
    card_origin: Option<&str>,
) -> EgressContext {
    EgressContext {
        tainted: egress.context.tainted,
        carries_private_data: egress.context.carries_private_data,
        seen_origin: card_origin == Some(origin) || egress.seen_origins.contains(origin),
    }
}

/// Reserve one fetch for `host` from the turn's shared counters, or return the
/// counter that refused it. The kernel's copy is crate-private; this is the same
/// `WebBudget::reserve` under the same lock.
fn reserve_destination(
    egress: &FetchEgress,
    host: &str,
    now: Instant,
    config: &kernel_core::WebConfig,
) -> Result<(), kernel_net::BudgetKind> {
    let mut budget = match egress.budget.lock() {
        Ok(budget) => budget,
        Err(poisoned) => poisoned.into_inner(),
    };
    budget.reserve(host, now, config)
}

/// The seen-origin key of `url`: `scheme://host:effective-port`, the same key
/// the kernel's policy uses for the conversation's seen set.
fn url_origin_key(url: &Url) -> String {
    let host = bare_host(url).unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{}://{host}:{port}", url.scheme())
}

/// The knobs a fetch runs under. Production uses the module constants;
/// unit tests shrink them so boundary behaviour is cheap to exercise.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) max_body_bytes: usize,
    pub(crate) max_output_bytes: usize,
    pub(crate) max_parse_bytes: usize,
    pub(crate) max_redirects: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES,
            max_output_bytes: MAX_OUTPUT_BYTES,
            max_parse_bytes: MAX_PARSE_BYTES,
            max_redirects: MAX_REDIRECTS,
        }
    }
}

/// Fetches a page over HTTP(S) and extracts readable text.
#[derive(Clone)]
pub struct Fetcher {
    timeout: Duration,
    policy: AddressPolicy,
    browser: Arc<dyn BrowserFetcher>,
    limits: Limits,
    /// The deterministic web egress gate (`[web]`). `None` is tests-only: the
    /// SSRF guard still runs, but no policy shape check is applied — used by
    /// the address-guard tests that must reach a specific error. Production
    /// (`Fetcher::new`, `Fetcher::with_web`) always carries the gate.
    gate: Option<WebGate>,
}

impl Fetcher {
    /// The production fetcher: public addresses only, default budgets, and
    /// the [`kernel_net::UnavailableBrowser`] placeholder for the browser path.
    pub fn new() -> Self {
        Self {
            timeout: FETCH_TIMEOUT,
            policy: AddressPolicy::PublicOnly,
            browser: unavailable_browser(),
            limits: Limits::default(),
            gate: Some(WebGate::default()),
        }
    }

    /// The production fetcher configured from `[web]`: the deterministic gate
    /// (scheme/port/domain/caps), the `[web]`-derived caps and timeout.
    pub fn with_web(config: kernel_core::WebConfig) -> Self {
        let max_bytes = config.max_bytes.max(1);
        Self {
            timeout: config.timeout(),
            policy: AddressPolicy::PublicOnly,
            browser: unavailable_browser(),
            limits: Limits {
                max_body_bytes: max_bytes,
                max_output_bytes: MAX_OUTPUT_BYTES.min(max_bytes),
                max_parse_bytes: MAX_PARSE_BYTES.min(max_bytes),
                max_redirects: config.max_redirects,
            },
            gate: Some(WebGate::new(config)),
        }
    }

    /// Attach the level-2 browser engine (WS-B). Until one ships,
    /// [`RenderMode::Browser`] returns [`FetchError::BrowserUnavailable`].
    pub fn with_browser(browser: Arc<dyn BrowserFetcher>) -> Self {
        Self {
            browser,
            ..Self::new()
        }
    }

    /// Tests only: loopback is permitted so a `wiremock` server can be
    /// reached. Production code never builds this fetcher.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests() -> Self {
        Self {
            policy: AddressPolicy::AllowLoopback,
            gate: Some(WebGate::permissive_for_tests(
                kernel_core::WebConfig::default(),
            )),
            ..Self::new()
        }
    }

    /// Tests only: loopback plus a custom timeout, for the timeout test.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests_with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Self::for_tests()
        }
    }

    /// Tests only: loopback with the production address guard (public only)
    /// and **no** web-policy shape gate, so the SSRF tests can pin the exact
    /// address error.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests_public_only() -> Self {
        Self {
            policy: AddressPolicy::PublicOnly,
            gate: None,
            ..Self::new()
        }
    }

    /// Tests only: loopback plus an explicit web gate, so the gate's refusals
    /// can be exercised end to end.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests_with_gate(gate: WebGate) -> Self {
        Self {
            gate: Some(gate),
            ..Self::for_tests()
        }
    }

    /// Fetch `input` according to `mode`.
    ///
    /// `Auto` uses the simple path today and never fails because the browser
    /// is missing; when WS-B lands it may escalate for JavaScript pages.
    /// `Browser` always delegates to the configured [`BrowserFetcher`].
    ///
    /// Without a [`FetchEgress`] the redirect hops still re-enter the gate,
    /// but the ask rule cannot see the turn's taint/private-data facts: it
    /// decides with [`EgressContext::default`] and fail-closed for every
    /// mode stricter than `open_read`. Engine-dispatched tools pass the
    /// authority through [`Self::fetch_with_egress`] instead.
    pub async fn fetch(&self, input: &str, mode: RenderMode) -> Result<FetchResult, FetchError> {
        self.fetch_egress(input, mode, None).await
    }

    /// [`Fetcher::fetch`] with the engine's per-fetch egress authority: the
    /// redirect hops re-run the mode/sensitive-turn ask rule and reserve
    /// every destination from the shared counters, under the same turn facts
    /// the original URL was decided with.
    pub async fn fetch_with_egress(
        &self,
        input: &str,
        mode: RenderMode,
        egress: &FetchEgress,
    ) -> Result<FetchResult, FetchError> {
        self.fetch_egress(input, mode, Some(egress)).await
    }

    async fn fetch_egress(
        &self,
        input: &str,
        mode: RenderMode,
        egress: Option<&FetchEgress>,
    ) -> Result<FetchResult, FetchError> {
        match mode {
            RenderMode::Browser => self.browser.fetch(input).await,
            RenderMode::Simple | RenderMode::Auto => {
                // Extraction is CPU-bound and runs in an uncancellable
                // `spawn_blocking` task. Give it the same absolute deadline as
                // the fetch itself, so once this timeout fires and the caller
                // gets `Err(Timeout)` there is no parse left burning CPU.
                let deadline = Instant::now() + self.timeout;
                match tokio::time::timeout(self.timeout, self.fetch_simple(input, deadline, egress))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => Err(FetchError::Timeout {
                        seconds: self.timeout.as_secs_f64(),
                    }),
                }
            }
        }
    }

    /// Follow the redirect chain manually so every hop is re-checked.
    async fn fetch_simple(
        &self,
        input: &str,
        fetch_deadline: Instant,
        egress: Option<&FetchEgress>,
    ) -> Result<FetchResult, FetchError> {
        if let Some(gate) = &self.gate {
            if input.len() > gate.config().max_url_bytes {
                return Err(FetchError::PolicyRefused(
                    kernel_net::DenyReason::UrlTooLong,
                ));
            }
        }
        let mut url = Url::parse(input).map_err(|err| FetchError::InvalidUrl(err.to_string()))?;
        let origin_host = bare_host(&url);
        let origin_port = url.port_or_known_default();
        // The origin the card covered, so a hop that stays on it is seen.
        let card_origin = url_origin_key(&url);
        let mut previous_scheme: Option<String> = None;
        let mut seen = HashSet::new();

        for hop in 0..=self.limits.max_redirects {
            check_scheme(&url)?;
            if is_https_downgrade(previous_scheme.as_deref(), url.scheme()) {
                return Err(FetchError::PolicyRefused(
                    kernel_net::DenyReason::HttpsDowngrade,
                ));
            }
            if !url.username().is_empty() || url.password().is_some() {
                return Err(FetchError::Credentials);
            }
            if !seen.insert(url.as_str().to_string()) {
                return Err(FetchError::RedirectLoop(url.to_string()));
            }
            // Deterministic gate, before any DNS lookup: a deny-listed domain
            // or an over-long URL resolves nothing.
            if let Some(gate) = &self.gate {
                gate.check_before_resolve(&url)
                    .map_err(FetchError::PolicyRefused)?;
                // Shape and port checks are deterministic too. Run them
                // before DNS on every hop so a refused redirect never causes
                // even a lookup of a prohibited literal/IDN/port.
                gate.check_after_resolve(&url)
                    .map_err(FetchError::PolicyRefused)?;

                // A redirect destination is a new egress decision of its own.
                // The card issued for the origin URL covers that host only:
                // a cross-host hop re-runs the mode/sensitive-turn ask rule
                // before any request is sent, and every destination is
                // reserved from the shared counters so a redirect chain
                // cannot evade the per-host rate limit.
                if hop > 0 {
                    if let Some(hop_host) = bare_host(&url) {
                        let checked = CheckedUrl {
                            url: url.clone(),
                            host: hop_host.clone(),
                        };
                        let hop_ctx = match egress {
                            Some(facts) => redirect_context(
                                facts,
                                &url_origin_key(&url),
                                Some(card_origin.as_str()),
                            ),
                            None => EgressContext::default(),
                        };
                        if origin_host.as_deref() != Some(hop_host.as_str()) {
                            if let EgressDecision::Ask(reason) =
                                gate.decide_checked(&checked, &hop_ctx)
                            {
                                if let Some(facts) = egress {
                                    facts.note_refused_hop(url.as_str());
                                }
                                return Err(FetchError::RedirectNeedsApproval {
                                    url: url.to_string(),
                                    reason: reason.as_str().to_string(),
                                });
                            }
                            // Even an otherwise-open mode must stop at a
                            // cross-host redirect. The new URL needs its own
                            // fresh decision; the current card only covered
                            // the origin URL.
                            if let Some(facts) = egress {
                                facts.note_refused_hop(url.as_str());
                            }
                            return Err(FetchError::RedirectNeedsApproval {
                                url: url.to_string(),
                                reason: "cross_host_redirect".to_string(),
                            });
                        }
                        if egress.is_some()
                            && url.port_or_known_default() != origin_port
                            && (hop_ctx.tainted || hop_ctx.carries_private_data)
                        {
                            if let EgressDecision::Ask(reason) =
                                gate.decide_checked(&checked, &hop_ctx)
                            {
                                if let Some(facts) = egress {
                                    facts.note_refused_hop(url.as_str());
                                }
                                return Err(FetchError::RedirectNeedsApproval {
                                    url: url.to_string(),
                                    reason: reason.as_str().to_string(),
                                });
                            }
                        }
                    }
                }
            }

            // The approval covers the declared hosts and the URL's origin only.
            // A connection anywhere else is refused before DNS, the first hop
            // included. Redirects that need their own card were refused above.
            if let Some(facts) = egress {
                if !facts.approves(&url) {
                    return Err(FetchError::PolicyRefused(
                        kernel_net::DenyReason::OriginNotApproved,
                    ));
                }
                // Reserve this destination right before it connects, so a
                // refused or unapproved fetch never consumes budget.
                if let (Some(gate), Some(host)) = (&self.gate, bare_host(&url)) {
                    reserve_destination(facts, &host, Instant::now(), gate.config())
                        .map_err(|kind| FetchError::PolicyRefused(kind.deny_reason()))?;
                }
            }

            let client = pinned_client(self.policy, &url).await?;
            let response =
                client
                    .get(url.clone())?
                    .send()
                    .await
                    .map_err(|err| FetchError::Request {
                        url: url.to_string(),
                        message: err.to_string(),
                    })?;
            // A server answered (any status). Only a fetch that got this far
            // may let the engine record the origin as seen; a DNS/connect/TLS
            // failure above leaves the flag false.
            if let Some(facts) = egress {
                facts.note_origin_response(url.as_str(), response.status().as_u16());
            }

            if !is_followed_redirect(response.status()) {
                return self.read_body(response, &url, fetch_deadline, egress).await;
            }

            if hop == self.limits.max_redirects {
                return Err(FetchError::TooManyRedirects(self.limits.max_redirects));
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| FetchError::MissingLocation {
                    status: response.status().as_u16(),
                })?;
            previous_scheme = Some(url.scheme().to_string());
            url = url.join(location).map_err(|err| FetchError::BadRedirect {
                target: location.to_string(),
                message: err.to_string(),
            })?;
        }

        unreachable!("the redirect loop returns on its final iteration")
    }

    /// True when the response `Content-Type` may be rendered under `[web]`.
    fn content_type_allowed(&self, content_type: &str) -> bool {
        match &self.gate {
            Some(gate) => gate.content_type_allowed(content_type),
            None => true,
        }
    }

    /// Stream the body (bounded), render it, cap it.
    async fn read_body(
        &self,
        mut response: reqwest::Response,
        url: &Url,
        fetch_deadline: Instant,
        egress: Option<&FetchEgress>,
    ) -> Result<FetchResult, FetchError> {
        let status = response.status();
        if !status.is_success() {
            // Keep the start of the error body so a provider's stated reason
            // (for example Open-Meteo's `reason`) can reach the caller.
            let body = read_capped(&mut response, ERROR_BODY_BYTES).await;
            if let Some(facts) = egress {
                facts.note_origin_bytes(url.as_str(), body.len());
            }
            return Err(FetchError::HttpStatus {
                status: status.as_u16(),
                url: url.to_string(),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }

        // We never advertise encodings, so a compressed body would reach the
        // renderer as binary garbage; refuse it explicitly instead.
        let encoding = response
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("identity");
        if !encoding.eq_ignore_ascii_case("identity") {
            return Err(FetchError::Compressed(encoding.to_string()));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if !self.content_type_allowed(&content_type) {
            let shown = content_type.trim();
            let shown = if shown.is_empty() { "unknown" } else { shown };
            return Err(FetchError::UnsupportedContentType(shown.to_string()));
        }

        let mut body = Vec::new();
        let mut body_capped = false;
        while let Some(chunk) = response.chunk().await.map_err(|err| FetchError::Request {
            url: url.to_string(),
            message: err.to_string(),
        })? {
            let room = self.limits.max_body_bytes.saturating_sub(body.len());
            if chunk.len() > room {
                body.extend_from_slice(&chunk[..room]);
                body_capped = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }
        if let Some(facts) = egress {
            facts.note_origin_bytes(url.as_str(), body.len());
        }

        let mut truncated = body_capped;
        let mut title = String::new();
        let mut text = match classify(&content_type, &body) {
            ContentKind::Html => {
                let parse_len = body.len().min(self.limits.max_parse_bytes);
                let parse_capped = body.len() > parse_len;
                truncated |= parse_capped;
                let slice = body[..parse_len].to_vec();
                // Extraction is CPU-bound; keep it off the async runtime. Its
                // deadline is the earlier of the extraction budget and the
                // remaining fetch budget: `spawn_blocking` tasks cannot be
                // cancelled, so this is what stops CPU use after the fetch
                // timeout above has already returned.
                let extraction_deadline = fetch_deadline.min(Instant::now() + EXTRACT_WALL_BUDGET);
                let extracted = tokio::task::spawn_blocking(move || {
                    extract_readable_before(&slice, extraction_deadline)
                })
                .await
                .map_err(|err| FetchError::Task(err.to_string()))?;
                truncated |= extracted.truncated;
                title = extracted.title;
                let mut text = extracted.text;
                if parse_capped {
                    text.push_str(&format!("\n[html capped at {parse_len} bytes]"));
                }
                text
            }
            ContentKind::Text => String::from_utf8_lossy(&body).into_owned(),
            ContentKind::Unsupported => {
                let shown = content_type.trim();
                let shown = if shown.is_empty() { "unknown" } else { shown };
                return Err(FetchError::UnsupportedContentType(shown.to_string()));
            }
        };
        if body_capped {
            text.push_str(&format!(
                "\n[body capped at {} bytes]",
                self.limits.max_body_bytes
            ));
        }

        let (text, output_capped) = cap_output(text, self.limits.max_output_bytes);
        truncated |= output_capped;
        Ok(FetchResult {
            title,
            text,
            url: url.to_string(),
            truncated,
        })
    }
}

impl Default for Fetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Most of an error body kept for the caller (see [`FetchError::HttpStatus`]).
const ERROR_BODY_BYTES: usize = 4 * 1024;

/// Up to `cap` bytes of the body. A read error ends the read early: the caller
/// only ever sees the bytes that arrived.
async fn read_capped(response: &mut reqwest::Response, cap: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < cap {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = cap - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    body
}

fn check_scheme(url: &Url) -> Result<(), FetchError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(FetchError::UnsupportedScheme(other.to_string())),
    }
}

fn is_https_downgrade(previous_scheme: Option<&str>, next_scheme: &str) -> bool {
    previous_scheme == Some("https") && next_scheme == "http"
}

/// The five redirect statuses browsers follow; everything else is final.
fn is_followed_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// Cap `text` at `max_bytes`, keeping the head and the tail (error text and
/// the end of an article live at the end) and marking the cut.
fn cap_output(text: String, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let total = text.len();
    let head_budget = max_bytes * 3 / 4;
    let tail_budget = max_bytes - head_budget;
    let mut head_end = head_budget;
    while head_end > 0 && !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = total - tail_budget;
    while tail_start < total && !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let kept_tail = total - tail_start;
    (
        format!(
            "{}\n[truncated: showing first {head_end} and last {kept_tail} of {total} bytes]\n{}",
            &text[..head_end],
            &text[tail_start..]
        ),
        true,
    )
}

/// What the response body looks like based on `Content-Type`, with a small
/// sniff when the header is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentKind {
    Html,
    Text,
    Unsupported,
}

pub(crate) fn classify(content_type: &str, body: &[u8]) -> ContentKind {
    let ct = content_type.trim().to_ascii_lowercase();
    if ct.contains("html") || ct.contains("xhtml") {
        return ContentKind::Html;
    }
    if ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("yaml")
        || ct.contains("csv")
    {
        return ContentKind::Text;
    }
    if ct.is_empty() {
        if looks_like_html(body) {
            return ContentKind::Html;
        }
        if !body.contains(&0) {
            return ContentKind::Text;
        }
    }
    ContentKind::Unsupported
}

fn looks_like_html(body: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&body[..body.len().min(512)]).to_ascii_lowercase();
    let trimmed = head.trim_start();
    trimmed.starts_with("<!doctype html")
        || trimmed.starts_with("<html")
        || trimmed.starts_with("<head")
        || trimmed.starts_with("<body")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::readability::extract_readable;
    use std::time::Instant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn html_server(html: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(html, "text/html; charset=utf-8"))
            .mount(&server)
            .await;
        server
    }

    fn public_fetcher() -> Fetcher {
        // Public-only address guard with no web-policy shape gate: these tests
        // pin the exact SSRF error, which the policy gate would otherwise mask
        // with its own `IpLiteral`/`PortNotAllowed` refusal.
        Fetcher::for_tests_public_only()
    }

    async fn fetch(fetcher: &Fetcher, url: String) -> Result<FetchResult, FetchError> {
        fetcher.fetch(&url, RenderMode::Simple).await
    }

    // ---- W1: the deterministic web egress gate is the choke point ----

    #[tokio::test]
    async fn web_gate_refuses_a_denied_domain_before_any_connect() {
        let fetcher =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(kernel_core::WebConfig {
                deny_domains: vec!["blocked.example".to_string()],
                ..kernel_core::WebConfig::default()
            }));
        // The host does not resolve and no server listens: a refusal that
        // opened a socket or did a lookup would surface as a different error.
        let err = fetch(&fetcher, "http://blocked.example/".to_string())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::DeniedDomain)
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn web_gate_refuses_an_over_long_url_before_any_connect() {
        let fetcher =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(kernel_core::WebConfig {
                max_url_bytes: 24,
                ..kernel_core::WebConfig::default()
            }));
        let err = fetch(&fetcher, "https://example.com/a/very/long/path".to_string())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::UrlTooLong)
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn web_gate_rechecks_denied_domains_on_every_redirect_hop() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "http://blocked.example/"),
            )
            .mount(&server)
            .await;

        let fetcher =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(kernel_core::WebConfig {
                deny_domains: vec!["blocked.example".to_string()],
                ..kernel_core::WebConfig::default()
            }));
        let err = fetch(&fetcher, format!("{}/start", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::DeniedDomain)
            ),
            "{err}"
        );
    }

    // ---- W1 hardening: a redirect is a new egress decision ----

    use kernel_net::WebBudget;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// Two loopback mock servers addressed under **different host names**
    /// (`127.0.0.1` and `localhost`, both loopback-resolvable), plus the
    /// wiring: `http://127.0.0.1:{a}/cross` → `http://localhost:{b}/final`.
    /// The host strings differ, which is what the cross-host hop rule
    /// compares. The origin uses the IPv4 literal so the pin matches the
    /// address `wiremock` binds; `localhost` is a redirect target the refused
    /// hop never resolves or connects to.
    async fn cross_host_servers() -> (MockServer, MockServer) {
        let a = MockServer::start().await;
        let b = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cross"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("http://localhost:{}/final", b.address().port()),
            ))
            .mount(&a)
            .await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("CROSSED body", "text/plain"))
            .mount(&b)
            .await;
        (a, b)
    }

    /// Same-host, multi-port chain `http://127.0.0.1:{a}/chain` →
    /// `http://127.0.0.1:{b}/hop` → `http://127.0.0.1:{a}/final`. The chain
    /// stays within one host so it exercises per-hop budgets under the
    /// cross-host-stop policy.
    async fn chain_servers() -> (MockServer, MockServer) {
        let a = MockServer::start().await;
        let b = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("http://127.0.0.1:{}/hop", b.address().port()),
            ))
            .mount(&a)
            .await;
        Mock::given(method("GET"))
            .and(path("/hop"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("http://127.0.0.1:{}/final", a.address().port()),
            ))
            .mount(&b)
            .await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("CHAIN body", "text/plain"))
            .mount(&a)
            .await;
        (a, b)
    }

    /// Egress facts for a test fetch. `approved` is the call's approved origin
    /// set, as the engine would build it from the declared hosts and URL.
    fn egress(
        context: EgressContext,
        budget: Arc<Mutex<WebBudget>>,
        approved: &[String],
    ) -> FetchEgress {
        FetchEgress {
            context,
            seen_origins: Arc::new(BTreeSet::new()),
            approved_origins: Arc::new(approved.iter().cloned().collect()),
            budget,
            refused_hops: Arc::new(Mutex::new(Vec::new())),
            received_response: Arc::new(Mutex::new(false)),
            received_origins: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    #[tokio::test]
    async fn a_sensitive_turn_refuses_a_cross_host_redirect() {
        let (a, b) = cross_host_servers().await;
        let facts = egress(
            EgressContext {
                tainted: true,
                ..EgressContext::default()
            },
            Arc::new(Mutex::new(WebBudget::new())),
            &[format!("http://127.0.0.1:{}", a.address().port())],
        );
        let err = Fetcher::for_tests()
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/cross", a.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        match err {
            FetchError::RedirectNeedsApproval { url, reason } => {
                assert!(
                    url.contains(&format!("localhost:{}/final", b.address().port())),
                    "{url}"
                );
                assert_eq!(reason, "sensitive_turn");
            }
            other => panic!("expected a redirect approval refusal, got {other}"),
        }
        // Nothing left this machine towards the redirect target.
        assert!(
            b.received_requests().await.unwrap().is_empty(),
            "the refused hop must not resolve or connect"
        );
        // N3: the refused hop is reported for the engine's audit row as a
        // host plus a URL hash, never the URL text.
        let hops = facts.take_refused_hops();
        assert_eq!(hops.len(), 1, "{hops:?}");
        assert_eq!(hops[0].host, "localhost");
        assert_eq!(hops[0].url_sha256.len(), 64);
        assert!(hops[0].url_sha256.chars().all(|c| c.is_ascii_hexdigit()));
        // Taking drains: the next read is empty.
        assert!(facts.take_refused_hops().is_empty());
    }

    #[tokio::test]
    async fn a_private_data_turn_refuses_a_cross_host_redirect() {
        // P2-1: the *other* sensitive fact must be just as sticky at the hop
        // level as taint. `carries_private_data` (mail/calendar/memory/notes)
        // sends the unseen redirect host to its own card too, so the origin
        // approval never silently carries private text to a new host.
        let (a, b) = cross_host_servers().await;
        let facts = egress(
            EgressContext {
                carries_private_data: true,
                ..EgressContext::default()
            },
            Arc::new(Mutex::new(WebBudget::new())),
            &[format!("http://127.0.0.1:{}", a.address().port())],
        );
        let err = Fetcher::for_tests()
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/cross", a.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        match err {
            FetchError::RedirectNeedsApproval { url, reason } => {
                assert!(
                    url.contains(&format!("localhost:{}/final", b.address().port())),
                    "{url}"
                );
                assert_eq!(reason, "sensitive_turn");
            }
            other => panic!("expected a redirect approval refusal, got {other}"),
        }
        assert!(
            b.received_requests().await.unwrap().is_empty(),
            "the refused hop must not resolve or connect"
        );
    }

    #[tokio::test]
    async fn an_allowlisted_redirect_host_does_not_bypass_the_sensitive_hop() {
        // P2-1: `allow_domains` exempts a host from the *mode*, never from
        // the sensitive-turn card. With the redirect target allow-listed, the
        // hop must still refuse with the ask reason (`sensitive_turn`),
        // not the generic cross-host stop, proving the allowlist was not
        // consulted first.
        let (a, b) = cross_host_servers().await;
        let fetcher =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(kernel_core::WebConfig {
                allow_domains: vec!["localhost".to_string()],
                ..kernel_core::WebConfig::default()
            }));
        let facts = egress(
            EgressContext {
                tainted: true,
                ..EgressContext::default()
            },
            Arc::new(Mutex::new(WebBudget::new())),
            &[format!("http://127.0.0.1:{}", a.address().port())],
        );
        let err = fetcher
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/cross", a.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FetchError::RedirectNeedsApproval { reason, .. } if reason == "sensitive_turn"),
            "{err}"
        );
        assert!(b.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_cross_host_redirect_to_a_conversation_seen_host_stops_for_a_fresh_decision() {
        let (a, b) = cross_host_servers().await;
        let budget = Arc::new(Mutex::new(WebBudget::new()));
        let facts = egress(
            EgressContext {
                tainted: true,
                ..EgressContext::default()
            },
            Arc::clone(&budget),
            &[format!("http://127.0.0.1:{}", a.address().port())],
        );
        // The conversation already saw the redirect origin; a hop that leaves
        // the origin the card covered still stops for a fresh decision.
        let mut seen = BTreeSet::new();
        seen.insert(format!("http://localhost:{}", b.address().port()));
        let facts = FetchEgress {
            seen_origins: Arc::new(seen),
            ..facts
        };
        let err = Fetcher::for_tests()
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/cross", a.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::RedirectNeedsApproval { .. }),
            "{err}"
        );
        assert!(b.received_requests().await.unwrap().is_empty());
        // Hop 0 connected to the origin the card covered, so it reserved one
        // slot at connect. The refused cross-origin hop reserved nothing.
        assert_eq!(budget.lock().unwrap().turn_count(), 1);
    }

    #[tokio::test]
    async fn an_open_read_turn_stops_at_a_cross_host_redirect_for_a_fresh_decision() {
        let (a, b) = cross_host_servers().await;
        let facts = egress(
            EgressContext::default(),
            Arc::new(Mutex::new(WebBudget::new())),
            &[format!("http://127.0.0.1:{}", a.address().port())],
        );
        let err = Fetcher::for_tests()
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/cross", a.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FetchError::RedirectNeedsApproval { reason, .. } if reason == "cross_host_redirect"),
            "{err}"
        );
        assert!(b.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_sensitive_same_host_redirect_to_a_new_port_requires_approval() {
        let origin = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("http://127.0.0.1:{}/final", destination.address().port()),
            ))
            .mount(&origin)
            .await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw("SHOULD NOT ARRIVE", "text/plain"),
            )
            .mount(&destination)
            .await;

        let facts = egress(
            EgressContext {
                tainted: true,
                seen_origin: true,
                ..EgressContext::default()
            },
            Arc::new(Mutex::new(WebBudget::new())),
            &[format!("http://127.0.0.1:{}", origin.address().port())],
        );
        let err = Fetcher::for_tests()
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/start", origin.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FetchError::RedirectNeedsApproval { reason, .. } if reason == "sensitive_turn"),
            "{err}"
        );
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn https_downgrades_are_detected_before_lookup() {
        assert!(is_https_downgrade(Some("https"), "http"));
        assert!(!is_https_downgrade(Some("http"), "https"));
        assert!(!is_https_downgrade(Some("https"), "https"));
        assert!(!is_https_downgrade(None, "http"));
    }

    #[tokio::test]
    async fn a_received_response_is_recorded_but_a_connect_failure_is_not() {
        // The engine records an origin as seen only when the fetch actually
        // reached a server: a connection that never gets a response must leave
        // the flag false, so a DNS/connect/TLS failure cannot poison it.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("body", "text/plain"))
            .mount(&server)
            .await;
        let reached = egress(
            EgressContext::default(),
            Arc::new(Mutex::new(WebBudget::new())),
            &[server.uri()],
        );
        Fetcher::for_tests()
            .fetch_with_egress(
                &format!("{}/ok", server.uri()),
                RenderMode::Simple,
                &reached,
            )
            .await
            .unwrap();
        assert!(reached.received_response());

        // Port 1 is privileged and nothing listens on it in CI: the connect is
        // refused before any server responds. A bind-then-drop port could be
        // taken by a parallel server.
        let failed = egress(
            EgressContext::default(),
            Arc::new(Mutex::new(WebBudget::new())),
            &["http://127.0.0.1:1".to_string()],
        );
        let err = Fetcher::for_tests()
            .fetch_with_egress("http://127.0.0.1:1/none", RenderMode::Simple, &failed)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Request { .. }), "{err}");
        assert!(!failed.received_response());
    }

    #[tokio::test]
    async fn a_same_host_redirect_rides_the_original_card() {
        // The card covered this host: a same-host hop never re-asks.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/final"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("LANDED body", "text/plain"))
            .mount(&server)
            .await;

        let facts = egress(
            EgressContext {
                tainted: true,
                ..EgressContext::default()
            },
            Arc::new(Mutex::new(WebBudget::new())),
            &[server.uri()],
        );
        let out = Fetcher::for_tests()
            .fetch_with_egress(
                &format!("{}/start", server.uri()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap();
        assert!(out.text.contains("LANDED body"), "{}", out.text);
    }

    #[tokio::test]
    async fn a_stricter_mode_refuses_a_cross_host_redirect_even_for_a_clean_turn() {
        // No egress authority: the gate cannot see the turn's facts, so the
        // hop is decided with a default (clean, unseen) context — and
        // `always_ask` still asks on it. Fail closed, no request sent.
        let (a, b) = cross_host_servers().await;
        let fetcher =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(kernel_core::WebConfig {
                mode: kernel_core::WebMode::AlwaysAsk,
                ..kernel_core::WebConfig::default()
            }));
        let err = fetch(
            &fetcher,
            format!("http://127.0.0.1:{}/cross", a.address().port()),
        )
        .await
        .unwrap_err();
        match err {
            FetchError::RedirectNeedsApproval { reason, .. } => {
                assert_eq!(reason, "mode_always_ask");
            }
            other => panic!("expected a redirect approval refusal, got {other}"),
        }
        assert!(b.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_per_host_budget_counts_every_redirect_destination() {
        let (a, b) = chain_servers().await;
        let config = kernel_core::WebConfig {
            per_host_per_minute: 2,
            ..kernel_core::WebConfig::default()
        };
        // Every hop reserves its destination at connect: hop 0 takes the first
        // 127.0.0.1 slot, so the budget is shared with the fetch itself.
        let budget = Arc::new(Mutex::new(WebBudget::new()));
        let facts = egress(
            EgressContext::default(),
            Arc::clone(&budget),
            &[
                format!("http://127.0.0.1:{}", a.address().port()),
                format!("http://127.0.0.1:{}", b.address().port()),
            ],
        );

        let fetcher = Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(config));
        let err = fetcher
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/chain", a.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        // Hop 0 takes the first 127.0.0.1 slot, the first redirect destination
        // the second, and the next one is refused before it connects.
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::BudgetHost)
            ),
            "{err}"
        );
        // The second hop reached B, but nothing reached the final path.
        assert_eq!(a.received_requests().await.unwrap().len(), 1, "only /chain");
        assert_eq!(b.received_requests().await.unwrap().len(), 1, "only /hop");
        drop(b);
    }

    #[tokio::test]
    async fn the_turn_budget_refuses_a_redirect_chain_past_the_cap() {
        // A two-fetch turn cap: hop 0 and the first redirect destination take
        // the two slots, and the next destination is refused before anything
        // is sent to it.
        let turn_config = kernel_core::WebConfig {
            fetches_per_turn: 2,
            per_host_per_minute: 8,
            ..kernel_core::WebConfig::default()
        };
        let (a, b) = chain_servers().await;
        let fetcher =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(turn_config.clone()));
        let budget = Arc::new(Mutex::new(WebBudget::new()));
        let facts = egress(
            EgressContext::default(),
            Arc::clone(&budget),
            &[
                format!("http://127.0.0.1:{}", a.address().port()),
                format!("http://127.0.0.1:{}", b.address().port()),
            ],
        );
        let err = fetcher
            .fetch_with_egress(
                &format!("http://127.0.0.1:{}/chain", a.address().port()),
                RenderMode::Simple,
                &facts,
            )
            .await
            .unwrap_err();
        // Hop 0 and hop 1 reserve, hop 2 is refused before connect by the
        // two-fetch turn cap.
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::BudgetTurn)
            ),
            "{err}"
        );
        drop(b);
    }

    #[tokio::test]
    async fn a_connection_outside_the_approved_origins_is_refused_before_dns() {
        // The production fetcher would resolve a real name here, so the
        // approval check must refuse before any lookup or connect.
        let facts = egress(
            EgressContext::default(),
            Arc::new(Mutex::new(WebBudget::new())),
            &["https://declared.example:443".to_string()],
        );
        let err = Fetcher::new()
            .fetch_with_egress("https://other.example/page", RenderMode::Simple, &facts)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::OriginNotApproved)
            ),
            "{err}"
        );
        assert_eq!(
            facts.budget.lock().unwrap().turn_count(),
            0,
            "a refused origin reserves nothing"
        );
    }

    /// The declared-host gate end to end on loopback: the approved origin is
    /// fetched and its answer is attributed to it; another origin is never
    /// contacted and reserves nothing.
    #[tokio::test]
    async fn an_approved_origin_answers_and_an_unapproved_one_is_never_contacted() {
        let approved = MockServer::start().await;
        let other = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("<p>hello approved</p>", "text/html; charset=utf-8"),
            )
            .mount(&approved)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not approved"))
            .expect(0)
            .mount(&other)
            .await;
        let origin = format!("http://127.0.0.1:{}", approved.address().port());
        let other_origin = format!("http://127.0.0.1:{}", other.address().port());
        let budget = Arc::new(Mutex::new(WebBudget::new()));
        let facts = egress(
            EgressContext::default(),
            Arc::clone(&budget),
            std::slice::from_ref(&origin),
        );
        let fetcher = Fetcher::for_tests();

        let page = fetcher
            .fetch_with_egress(&format!("{origin}/a"), RenderMode::Simple, &facts)
            .await
            .unwrap();
        assert!(page.text.contains("hello approved"), "{}", page.text);
        let receipt = facts
            .origin_receipt(&origin)
            .expect("the approved origin answered");
        assert_eq!(receipt.http_status, 200);
        assert!(receipt.bytes > 0, "the body bytes are attributed");
        assert_eq!(
            budget.lock().unwrap().turn_count(),
            1,
            "one connect, one reservation"
        );

        let err = fetcher
            .fetch_with_egress(&format!("{other_origin}/x"), RenderMode::Simple, &facts)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::OriginNotApproved)
            ),
            "{err}"
        );
        assert_eq!(facts.origin_receipt(&other_origin), None);
        assert_eq!(
            budget.lock().unwrap().turn_count(),
            1,
            "a refused origin reserves nothing"
        );
    }

    #[tokio::test]
    async fn an_error_answer_keeps_only_the_start_of_its_body() {
        let server = MockServer::start().await;
        let body = format!(
            "{{\"error\":true,\"reason\":\"bad input\",\"pad\":\"{}\"}}",
            "x".repeat(20_000)
        );
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let err = Fetcher::for_tests()
            .fetch(&format!("{}/q", server.uri()), RenderMode::Simple)
            .await
            .unwrap_err();
        match err {
            FetchError::HttpStatus { status, body, .. } => {
                assert_eq!(status, 400);
                assert!(
                    body.starts_with("{\"error\":true,\"reason\":\"bad input\""),
                    "{body}"
                );
                assert_eq!(body.len(), ERROR_BODY_BYTES, "capped, never more");
            }
            other => panic!("expected an HTTP status error, got {other}"),
        }
    }

    #[tokio::test]
    async fn web_gate_refuses_a_port_outside_the_allowlist_before_connect() {
        // `localhost` is a name, not a refused IP literal, so the port check is
        // what binds. The loopback policy lets the name resolve; the gate then
        // refuses the non-80/443 port without a request.
        let server = MockServer::start().await;
        let fetcher = Fetcher::for_tests_with_gate(WebGate::new(kernel_core::WebConfig::default()));
        let err = fetch(
            &fetcher,
            format!("http://localhost:{}/page", server.address().port()),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::PolicyRefused(kernel_net::DenyReason::PortNotAllowed)
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn content_type_allowlist_refuses_types_outside_the_list() {
        let server = html_server("<body><p>hello</p></body>").await;
        let fetcher =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(kernel_core::WebConfig {
                content_types: vec!["text/plain".to_string()],
                ..kernel_core::WebConfig::default()
            }));
        let err = fetch(&fetcher, format!("{}/", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::UnsupportedContentType(ref kind) if kind.starts_with("text/html")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_missing_content_type_is_refused_unless_the_owner_allows_empty() {
        // P3-2: a 200 with no `Content-Type` must not slide past the
        // allowlist through the body sniffer. `set_body_bytes` writes a body
        // and no header, which is exactly the fail-open shape.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"<html><body>sniff me</body></html>".to_vec()),
            )
            .mount(&server)
            .await;

        let err = fetch(&Fetcher::for_tests(), format!("{}/none", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::UnsupportedContentType(ref kind) if kind == "unknown"),
            "{err}"
        );

        // The owner opts in with an explicit empty entry; only then does the
        // sniffer decide, and this headerless body renders as HTML.
        let allow_empty =
            Fetcher::for_tests_with_gate(WebGate::permissive_for_tests(kernel_core::WebConfig {
                content_types: vec!["text/html".to_string(), String::new()],
                ..kernel_core::WebConfig::default()
            }));
        let out = fetch(&allow_empty, format!("{}/none", server.uri()))
            .await
            .unwrap();
        assert!(out.text.contains("sniff me"), "{}", out.text);
        assert_eq!(out.title, "");
    }

    #[tokio::test]
    async fn html_is_rendered_to_readable_text_with_a_title() {
        let server = html_server(
            "<!doctype html><html><head><title>Page title</title>\
             <style>body { color: red }</style>\
             <script>alert('SCRIPTED')</script></head>\
             <body><main><h1>Heading One</h1><p>First <b>bold</b> paragraph.</p>\
             <ul><li>Alpha</li><li>Beta</li></ul><p>Last line.</p></main></body></html>",
        )
        .await;

        let out = fetch(&Fetcher::for_tests(), format!("{}/page", server.uri()))
            .await
            .unwrap();

        assert_eq!(out.title, "Page title");
        assert!(out.text.contains("Heading One"), "{}", out.text);
        assert!(out.text.contains("First bold paragraph."), "{}", out.text);
        assert!(out.text.contains("- Alpha\n- Beta"), "{}", out.text);
        assert!(!out.text.contains("SCRIPTED"), "script leaked");
        assert!(!out.text.contains("color: red"), "style leaked");
        assert!(out.text.contains("Last line."));
        assert!(!out.truncated);
        assert!(out.url.ends_with("/page"));
    }

    #[tokio::test]
    async fn plain_text_is_passed_through() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("plain body", "text/plain"))
            .mount(&server)
            .await;

        let out = fetch(&Fetcher::for_tests(), format!("{}/raw", server.uri()))
            .await
            .unwrap();
        assert_eq!(out.text, "plain body");
        assert_eq!(out.title, "");
    }

    #[tokio::test]
    async fn binary_content_types_are_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(vec![0u8, 1, 2], "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let err = fetch(&Fetcher::for_tests(), format!("{}/bin", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::UnsupportedContentType(ref kind) if kind == "application/octet-stream"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn compressed_bodies_are_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_raw("fake gzip", "text/html"),
            )
            .mount(&server)
            .await;

        let err = fetch(&Fetcher::for_tests(), format!("{}/gz", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::Compressed(ref name) if name == "gzip"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn http_error_status_is_reported() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("nope"))
            .mount(&server)
            .await;

        let err = fetch(&Fetcher::for_tests(), format!("{}/missing", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::HttpStatus { status: 404, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("HTTP 404"), "{err}");
    }

    #[tokio::test]
    async fn follows_safe_redirects_and_reports_the_final_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/final"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "<body><p>LANDRED payload long enough to be selected.</p></body>",
                "text/html",
            ))
            .mount(&server)
            .await;

        let out = fetch(&Fetcher::for_tests(), format!("{}/start", server.uri()))
            .await
            .unwrap();
        assert!(out.text.contains("LANDRED"), "{}", out.text);
        assert!(out.url.ends_with("/final"), "{}", out.url);
    }

    #[tokio::test]
    async fn cross_host_redirect_to_private_address_stops_before_resolution() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
            )
            .mount(&server)
            .await;

        let err = fetch(&Fetcher::for_tests(), format!("{}/go", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FetchError::RedirectNeedsApproval { reason, .. } if reason == "cross_host_redirect"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn redirect_loop_is_detected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/loop"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop"))
            .mount(&server)
            .await;

        let err = fetch(&Fetcher::for_tests(), format!("{}/loop", server.uri()))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::RedirectLoop(_)), "{err}");
        assert!(err.to_string().contains("redirect loop"), "{err}");
    }

    #[tokio::test]
    async fn redirect_chains_are_capped_at_five_hops() {
        let server = MockServer::start().await;
        for hop in 0..=MAX_REDIRECTS + 1 {
            Mock::given(method("GET"))
                .and(path(format!("/r{hop}")))
                .respond_with(
                    ResponseTemplate::new(302).insert_header("location", format!("/r{}", hop + 1)),
                )
                .mount(&server)
                .await;
        }

        let err = fetch(&Fetcher::for_tests(), format!("{}/r0", server.uri()))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::TooManyRedirects(5)), "{err}");
    }

    #[tokio::test]
    async fn timeout_is_enforced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("too late", "text/plain")
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;

        let fetcher = Fetcher::for_tests_with_timeout(Duration::from_millis(100));
        let err = fetch(&fetcher, format!("{}/slow", server.uri()))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Timeout { .. }), "{err}");
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[cfg(unix)]
    fn cpu_seconds() -> f64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: `getrusage` writes the struct when it returns 0, checked below.
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        assert_eq!(rc, 0, "getrusage failed");
        // SAFETY: the call succeeded, so the struct is initialized.
        let usage = unsafe { usage.assume_init() };
        let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        seconds(usage.ru_utime) + seconds(usage.ru_stime)
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "release-only loopback timing test; run: cargo test -p aux-runtime --release --lib --features l1-fetch -- --ignored --nocapture --test-threads=1"]
    async fn extraction_cannot_outlive_the_fetch_timeout() {
        // RV3-01: extraction runs in an uncancellable `spawn_blocking` task.
        // It must receive the earlier of its own budget and the remaining
        // fetch budget, so no CPU keeps burning after `Err(Timeout)`.
        let mut body = Vec::with_capacity(kernel_net::MAX_PARSE_BYTES + 16);
        let mut i = 0u64;
        while body.len() < kernel_net::MAX_PARSE_BYTES {
            body.extend_from_slice(format!("<b a={i}>").as_bytes());
            i += 1;
        }
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/html"))
            .mount(&server)
            .await;

        let fetcher = Fetcher::for_tests_with_timeout(Duration::from_millis(250));
        let cpu_before = cpu_seconds();
        // The extraction deadline is the same absolute instant as the fetch
        // timeout, so either can win the race: the caller times out while the
        // parse is still in a chunk, or the parse notices the deadline first
        // and returns a truncated `Ok`. Both are correct; what must hold is
        // that no CPU keeps burning after the caller has the answer.
        match fetch(&fetcher, format!("{}/hostile", server.uri())).await {
            Err(FetchError::Timeout { .. }) => {}
            Ok(result) => assert!(result.truncated, "the hostile page must be truncated"),
            Err(err) => panic!("unexpected error: {err}"),
        }
        let cpu_at_return = cpu_seconds() - cpu_before;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let burned_after_return = (cpu_seconds() - cpu_before) - cpu_at_return;
        eprintln!(
            "cpu while fetching={cpu_at_return:.3}s  cpu after return={burned_after_return:.3}s"
        );
        // Without `min(fetch deadline, extraction budget)` the parse would
        // keep going until its own ~400 ms budget, i.e. ~150 ms of CPU after
        // this caller already had its answer; the fixed code measures a few
        // milliseconds of teardown.
        assert!(
            burned_after_return < 0.1,
            "extraction kept burning {burned_after_return:.3}s of CPU after the caller returned"
        );
    }

    #[tokio::test]
    async fn blocks_loopback_private_and_metadata_targets() {
        let fetcher = public_fetcher();
        for url in [
            "http://127.0.0.1:9/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:9/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
        ] {
            let err = fetch(&fetcher, url.to_string()).await.unwrap_err();
            assert!(
                matches!(err, FetchError::BlockedAddress { .. }),
                "{url}: {err}"
            );
            assert!(
                err.to_string().contains("not globally routable"),
                "{url}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn blocks_localhost_by_name_before_any_lookup() {
        let err = fetch(&public_fetcher(), "http://localhost:9/".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::RefusedHost { .. }), "{err}");
    }

    #[tokio::test]
    async fn rejects_non_http_schemes() {
        for url in ["file:///etc/passwd", "ftp://example.com/x"] {
            let err = fetch(&public_fetcher(), url.to_string()).await.unwrap_err();
            assert!(
                matches!(err, FetchError::UnsupportedScheme(_)),
                "{url}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_urls_with_embedded_credentials() {
        let err = fetch(
            &public_fetcher(),
            "http://user:pass@example.com/".to_string(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FetchError::Credentials), "{err}");
    }

    #[tokio::test]
    async fn dns_failures_are_errors() {
        let err = fetch(
            &public_fetcher(),
            "http://no-such-host-for-auxesis-tests.invalid/".to_string(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FetchError::Dns { .. }), "{err}");
        assert!(err.to_string().contains("DNS lookup"), "{err}");
    }

    #[tokio::test]
    async fn body_cap_stops_reading_and_marks_the_result() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("x".repeat(4096), "text/plain"))
            .mount(&server)
            .await;

        let fetcher = Fetcher {
            limits: Limits {
                max_body_bytes: 1024,
                ..Limits::default()
            },
            ..Fetcher::for_tests()
        };
        let out = fetch(&fetcher, format!("{}/big", server.uri()))
            .await
            .unwrap();
        assert!(out.truncated);
        assert!(
            out.text.contains("[body capped at 1024 bytes]"),
            "{}",
            out.text
        );
        assert!(out.text.len() < 2048, "{}", out.text.len());
    }

    #[tokio::test]
    async fn output_cap_keeps_head_and_tail() {
        let body = format!("HEADMARKER {} TAILMARKER", "filler ".repeat(2000));
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/plain"))
            .mount(&server)
            .await;

        let fetcher = Fetcher {
            limits: Limits {
                max_output_bytes: 512,
                ..Limits::default()
            },
            ..Fetcher::for_tests()
        };
        let out = fetch(&fetcher, format!("{}/text", server.uri()))
            .await
            .unwrap();
        assert!(out.truncated);
        assert!(out.text.contains("HEADMARKER"), "head lost");
        assert!(out.text.contains("TAILMARKER"), "tail lost");
        assert!(out.text.contains("[truncated:"), "marker lost");
    }

    #[tokio::test]
    async fn parse_cap_marker_notes_the_html_cut() {
        let mut html = String::from("<body><p>HEADMARKER ");
        html.push_str(&"filler ".repeat(400));
        html.push_str("</p><p>TAILMARKER</p></body>");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(html, "text/html"))
            .mount(&server)
            .await;

        let fetcher = Fetcher {
            limits: Limits {
                max_parse_bytes: 256,
                ..Limits::default()
            },
            ..Fetcher::for_tests()
        };
        let out = fetch(&fetcher, format!("{}/huge", server.uri()))
            .await
            .unwrap();
        assert!(out.truncated);
        assert!(
            out.text.contains("[html capped at 256 bytes]"),
            "{}",
            out.text
        );
        assert!(
            !out.text.contains("TAILMARKER"),
            "past the parse cap leaked"
        );
    }

    #[tokio::test]
    async fn browser_mode_returns_the_typed_unavailable_error() {
        let err = Fetcher::new()
            .fetch("https://example.com/", RenderMode::Browser)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::BrowserUnavailable));
        assert_eq!(err.to_string(), "browser engine not installed yet — WS-B");
    }

    #[test]
    fn content_kind_classification() {
        assert_eq!(classify("text/html; charset=utf-8", b""), ContentKind::Html);
        assert_eq!(classify("application/xhtml+xml", b""), ContentKind::Html);
        assert_eq!(classify("text/plain", b""), ContentKind::Text);
        assert_eq!(classify("application/json", b""), ContentKind::Text);
        assert_eq!(classify("application/xml", b""), ContentKind::Text);
        assert_eq!(
            classify("application/octet-stream", b"\x00\x01"),
            ContentKind::Unsupported
        );
        assert_eq!(classify("", b"<!doctype html><p>x</p>"), ContentKind::Html);
        assert_eq!(classify("", b"just text"), ContentKind::Text);
        assert_eq!(classify("", b"\x00\x01"), ContentKind::Unsupported);
    }

    #[test]
    fn cap_output_keeps_both_ends_on_char_boundaries() {
        let text = format!("{}é{}", "a".repeat(300), "b".repeat(300));
        let (capped, bit) = cap_output(text, 100);
        assert!(bit);
        assert!(capped.starts_with('a'));
        assert!(capped.ends_with('b'));
        assert!(capped.contains("[truncated:"));
    }

    #[test]
    fn unclosed_divs_do_not_blow_up() {
        let small = b"<div>".repeat(64 * 1024 / 5 + 1);
        let started = Instant::now();
        let small_out = extract_readable(&small);
        let small_time = started.elapsed();

        let big = b"<div>".repeat(256 * 1024 / 5 + 1);
        let started = Instant::now();
        let big_out = extract_readable(&big);
        let big_time = started.elapsed();

        assert!(small_out.text.is_empty(), "{:?}", small_out.text);
        assert!(big_out.text.is_empty(), "{:?}", big_out.text);
        assert!(
            big_time < Duration::from_secs(15),
            "256 KiB of unclosed <div> took {big_time:?}"
        );
        assert!(
            big_time < small_time * 20 + Duration::from_secs(1),
            "super-linear scaling: {small_time:?} -> {big_time:?}"
        );
    }
}
