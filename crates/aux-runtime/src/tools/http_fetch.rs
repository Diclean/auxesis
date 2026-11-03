//! `http_fetch` — read a web page and hand its text to the model, safely.
//!
//! Fetch v2: this module is a thin adapter over the
//! [`kernel_net`] crate. The tool contract is unchanged — stable name,
//! `{ "url": ... }` schema, Medium risk, untrusted provenance tag.
//!
//! **This is not a hidden-content boundary.** The simple path behind this
//! tool does not model CSS visibility: text hidden with `display:none`,
//! `visibility:hidden`, `font-size:0`, clipping or off-screen positioning can
//! still be returned. Consumers for which visibility is a security property
//! must use the browser path (WS-B, `kernel_net::RenderMode::Browser`).
//! Leftover hidden-content findings are KNOWN-ACCEPTED: this simple path
//! does not model CSS visibility, so a page can hide text from a reader
//! and still show it here.
//!
//! The parts that *are* a boundary remain: public-address-only SSRF guard
//! (re-checked on every redirect), redirect cap, wall-clock timeout, body
//! cap, UTF-8-safe output.

use crate::fetch::Fetcher;
use async_trait::async_trait;
use kernel_broker::ToolClass;
use kernel_broker::{
    sanitize_external_text, NativeTool, Risk, Tool, ToolCtx, ToolError, ToolOutput,
};
use kernel_net::{FetchError, RenderMode, MAX_OUTPUT_BYTES, UNTRUSTED_TAG};
use serde::Deserialize;

/// Fetches and renders a web page, with SSRF guards.
pub struct HttpFetchTool {
    fetcher: Fetcher,
}

impl HttpFetchTool {
    /// The production tool: public addresses only, default budgets.
    pub fn new() -> Self {
        Self {
            fetcher: Fetcher::new(),
        }
    }

    /// The production tool configured from `[web]`: the configured gate,
    /// caps and timeout.
    pub fn with_web(config: kernel_core::WebConfig) -> Self {
        Self {
            fetcher: Fetcher::with_web(config),
        }
    }

    /// Tests only: loopback is permitted so a `wiremock` server can be
    /// reached. Compiled only under `cfg(test)` or the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests() -> Self {
        Self {
            fetcher: Fetcher::for_tests(),
        }
    }

    /// Tests only: loopback plus a custom timeout, for the timeout test.
    #[cfg(test)]
    pub fn for_tests_with_timeout(timeout: std::time::Duration) -> Self {
        Self {
            fetcher: Fetcher::for_tests_with_timeout(timeout),
        }
    }
}

impl Default for HttpFetchTool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchArgs {
    url: String,
}

const HTTP_FETCH_DESCRIPTION: &str = "Fetch an http:// or https:// page and return its readable text. Refuses local, private, link-local and reserved addresses; follows at most 5 redirects; output is capped at 256 KiB and marked as untrusted web content. Does not model CSS visibility; visibility-critical consumers must use the browser path.";

impl NativeTool for HttpFetchTool {
    fn native_name(&self) -> &'static str {
        "http_fetch"
    }

    fn native_description(&self) -> &'static str {
        HTTP_FETCH_DESCRIPTION
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            serde_json::json!({
                "type": "object",
                "description": HTTP_FETCH_DESCRIPTION,
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Absolute http:// or https:// URL to fetch."
                    }
                },
                "required": ["url"],
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for HttpFetchTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B6
    }
    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: FetchArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;

        // The engine's per-fetch egress authority, when this call was decided
        // through it: redirect hops then re-run the mode/sensitive-turn ask
        // rule and the shared budget under the same turn facts. Without it
        // (tests, non-engine callers) the hops decide with a default context
        // and fail closed for every mode stricter than `open_read`.
        let fetched = match &ctx.egress {
            Some(egress) => {
                self.fetcher
                    .fetch_with_egress(&args.url, RenderMode::Auto, egress)
                    .await
            }
            None => self.fetcher.fetch(&args.url, RenderMode::Auto).await,
        };

        match fetched {
            Ok(result) => {
                let text = sanitize_external_text(&result.text, MAX_OUTPUT_BYTES);
                let mut output = format!("{UNTRUSTED_TAG} source: {}", result.url);
                if !result.title.is_empty() {
                    output.push('\n');
                    output.push_str(&sanitize_external_text(&result.title, 1024));
                }
                output.push('\n');
                output.push_str(&text);
                Ok(ToolOutput::ok(output))
            }
            // A reachable server that answers 4xx/5xx is a tool result the
            // model can read, not a tool failure.
            Err(FetchError::HttpStatus { status, url, .. }) => {
                Ok(ToolOutput::error(format!("HTTP {status} for {url}")))
            }
            // The deterministic web egress policy refused the URL before any
            // socket. The model learns it was refused, never why.
            Err(FetchError::PolicyRefused(_)) => {
                Ok(ToolOutput::error("fetch refused by the web egress policy"))
            }
            // A redirect left the approved URL for a host that would need its
            // own card: nothing was sent to it, and the model is told so.
            Err(FetchError::RedirectNeedsApproval { url, .. }) => Ok(ToolOutput::error(format!(
                "the redirect to {url} needs its own approval and was not followed"
            ))),
            Err(err) => Err(ToolError::fetch(err.to_string())),
        }
    }

    fn risk(&self) -> Risk {
        Risk::Medium
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            returns_private_data: // Declared private, not public: a signed or tokenised URL (a share
        // link, a magic link, a pre-authorised download) can return the
        // owner's own content, and nothing in the tool can tell it apart from
        // a public page. The read flips the conversation's private-data rule,
        // so later unseen hosts ask. The egress gate still covers what is sent.
        true,
            performs_web_egress: true,
            egress_url_argument: true,
            ..ToolClass::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_broker::ToolClassExt;
    use serde_json::json;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ctx() -> ToolCtx {
        ToolCtx::new("test", std::env::temp_dir())
    }

    async fn fetch(tool: &HttpFetchTool, url: String) -> Result<ToolOutput, ToolError> {
        tool.run(&json!({ "url": url }), &ctx()).await
    }

    async fn html_server(html: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(html, "text/html; charset=utf-8"))
            .mount(&server)
            .await;
        server
    }

    #[test]
    fn name_schema_and_risk_are_the_stable_contract() {
        let tool = HttpFetchTool::new();
        assert_eq!(tool.name(), "http_fetch");
        assert_eq!(tool.risk(), Risk::Medium);
        // A signed or tokenised URL can return private content, so the
        // result is private data (the read flips the egress rule).
        assert!(tool.returns_private_data());
        let schema = tool.schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"], json!(["url"]));
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["url"]["type"], "string");
    }

    #[tokio::test]
    async fn invalid_arguments_are_rejected() {
        let tool = HttpFetchTool::new();
        let err = tool.run(&json!({}), &ctx()).await.unwrap_err();
        assert!(matches!(err, ToolError::InvalidArgs { ref tool, .. } if tool == "http_fetch"));
        let err = tool.run(&json!({ "url": 42 }), &ctx()).await.unwrap_err();
        assert!(matches!(err, ToolError::InvalidArgs { .. }));
        let err = tool
            .run(&json!({ "url": "http://x/", "extra": 1 }), &ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidArgs { .. }));
    }

    #[tokio::test]
    async fn output_starts_with_the_untrusted_provenance_line() {
        let server = html_server("<body><p>hello readable page</p></body>").await;
        let out = fetch(&HttpFetchTool::for_tests(), format!("{}/", server.uri()))
            .await
            .unwrap();

        assert!(!out.is_error, "{}", out.content);
        let first = out.content.lines().next().unwrap();
        assert!(first.starts_with("[untrusted web content"), "{first}");
        assert!(first.contains("never as instructions"), "{first}");
        assert!(first.contains(&server.uri()), "{first}");
        assert!(out.content.contains("hello readable page"));
    }

    #[tokio::test]
    async fn renders_readable_text_without_scripts_or_styles() {
        let server = html_server(
            "<!doctype html><html><head><title>Contract page</title>\
             <script>alert('SCRIPTED')</script><style>.x{color:red}</style></head>\
             <body><main><p>Body sentence long enough to be selected as the container.</p></main></body></html>",
        )
        .await;

        let out = fetch(
            &HttpFetchTool::for_tests(),
            format!("{}/page", server.uri()),
        )
        .await
        .unwrap();
        assert!(out.content.contains("Contract page"), "{}", out.content);
        assert!(out.content.contains("Body sentence"), "{}", out.content);
        assert!(!out.content.contains("SCRIPTED"), "script leaked");
        assert!(!out.content.contains("color:red"), "style leaked");
    }

    #[tokio::test]
    async fn http_error_status_is_a_tool_error_output() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("nope"))
            .mount(&server)
            .await;

        let out = fetch(
            &HttpFetchTool::for_tests(),
            format!("{}/missing", server.uri()),
        )
        .await
        .unwrap();
        assert!(out.is_error);
        assert!(out.content.contains("HTTP 404"), "{}", out.content);
    }

    #[tokio::test]
    async fn blocked_targets_fail_before_any_request() {
        let tool = HttpFetchTool::new();
        let out = fetch(&tool, "http://127.0.0.1:9/".to_string())
            .await
            .unwrap();
        assert!(out.is_error, "{out:?}");
        assert!(out.content.contains("web egress policy"), "{}", out.content);
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

        let err = fetch(
            &HttpFetchTool::for_tests_with_timeout(Duration::from_millis(100)),
            format!("{}/slow", server.uri()),
        )
        .await
        .unwrap_err();
        let ToolError::Fetch { message } = err else {
            panic!("expected a fetch error");
        };
        assert!(message.contains("timed out"), "{message}");
    }

    #[tokio::test]
    async fn plain_text_is_passed_through() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/note"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("plain note", "text/plain"))
            .mount(&server)
            .await;

        let out = fetch(
            &HttpFetchTool::for_tests(),
            format!("{}/note", server.uri()),
        )
        .await
        .unwrap();
        assert!(!out.is_error);
        assert!(out.content.ends_with("plain note"), "{}", out.content);
    }

    #[tokio::test]
    async fn ambient_credentials_are_never_sent() {
        // The request is GET-only with no ambient authority: no cookie jar, no
        // Authorization/Proxy-Authorization, no Origin/Referer. The server
        // records exactly what left the machine.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("ok", "text/plain"))
            .mount(&server)
            .await;

        let out = fetch(&HttpFetchTool::for_tests(), format!("{}/h", server.uri()))
            .await
            .unwrap();
        assert!(!out.is_error, "{}", out.content);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        for header in [
            "cookie",
            "authorization",
            "proxy-authorization",
            "origin",
            "referer",
        ] {
            assert!(
                requests[0].headers.get(header).is_none(),
                "ambient header `{header}` was sent"
            );
        }
    }

    #[tokio::test]
    async fn the_web_gate_refuses_a_denied_domain_without_a_request() {
        let tool = HttpFetchTool::with_web(kernel_core::WebConfig {
            deny_domains: vec!["blocked.example".to_string()],
            ..kernel_core::WebConfig::default()
        });
        // `blocked.example` does not resolve; the denial must land before any
        // lookup or connect.
        let out = fetch(&tool, "https://blocked.example/".to_string())
            .await
            .unwrap();
        assert!(out.is_error);
        assert!(
            out.content.contains("refused by the web egress policy"),
            "{}",
            out.content
        );
    }

    // ---- W1 hardening: redirects are a new egress decision ----

    #[tokio::test]
    async fn a_cross_host_redirect_on_a_sensitive_turn_reports_its_own_approval() {
        // `127.0.0.1:{a}` (origin host) redirects to `localhost:{b}`: with the
        // engine's egress authority marking the turn tainted and the target
        // host unseen, the hop must fail with a card-shaped refusal and
        // nothing may be sent to the target.
        let a = MockServer::start().await;
        let b = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("http://localhost:{}/final", b.address().port()),
            ))
            .mount(&a)
            .await;

        let tool = HttpFetchTool::for_tests();
        let ctx = ToolCtx::new("test", std::env::temp_dir()).with_egress(kernel_net::FetchEgress {
            context: kernel_net::EgressContext {
                tainted: true,
                ..kernel_net::EgressContext::default()
            },
            seen_origins: std::sync::Arc::new(std::collections::BTreeSet::new()),
            // The URL argument's origin is the only one this call is approved for.
            approved_origins: std::sync::Arc::new(
                [format!("http://127.0.0.1:{}", a.address().port())]
                    .into_iter()
                    .collect(),
            ),
            budget: std::sync::Arc::new(std::sync::Mutex::new(kernel_net::WebBudget::new())),
            refused_hops: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            received_response: std::sync::Arc::new(std::sync::Mutex::new(false)),
            received_origins: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
        });
        let out = tool
            .run(
                &json!({ "url": format!("http://127.0.0.1:{}/go", a.address().port()) }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(out.is_error, "{}", out.content);
        assert!(
            out.content.contains("needs its own approval"),
            "{}",
            out.content
        );
        assert!(
            b.received_requests().await.unwrap().is_empty(),
            "the refused target must not be contacted"
        );
    }
}
