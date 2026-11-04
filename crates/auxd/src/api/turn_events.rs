//! Engine [`TurnEvents`] → live WS frames.
//!
//! One sink per API turn: every persisted message becomes a `message.new`
//! frame, streamed text is coalesced into `message.delta` frames (see
//! [`super::deltas`]), tool calls are bracketed by `tool.start`/`tool.end`,
//! the turn end is a `message.done`, and the agent's phase follows the work
//! (`working` while a tool runs, `thinking` while the model does).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aux_engine::{ToolEndOutcome, TurnEvents};
use aux_providers::{Contact, ToolCall};
use aux_store::Message;

use super::deltas::{DeltaStream, StreamSinks};
use super::display::{live_tokens, Rehydrator};
use super::receipt::{self, ReceiptEvent, ReceiptStatus};
use super::wire;

/// The API's live-event sink for one engine turn.
pub struct ApiTurnEvents {
    sinks: StreamSinks,
    home: PathBuf,
    agent: String,
    trigger: String,
    provider_hosts: Option<Arc<dyn Fn() -> Vec<String> + Send + Sync>>,
    /// The stream currently receiving `message_delta` calls, if any. One
    /// provider round at a time within a turn; a new draft id replaces (and
    /// finishes) the previous stream.
    active: std::sync::Mutex<Option<Draft>>,
    started: String,
    /// Identity of this turn's run. Usage is summed by this identity (never
    /// by a shared row-id window), so two overlapping turns of the same agent
    /// can never claim each other's spend.
    run_id: String,
    /// Event-journal cursor captured at turn start; bounds the approval
    /// window without comparing local wall-clock strings.
    cursor: receipt::ReceiptCursor,
    tools: std::sync::Mutex<std::collections::BTreeMap<String, u32>>,
    activity: std::sync::Mutex<Vec<ReceiptEvent>>,
    /// Token identifiers already counted in this run. Tokens represent the
    /// distinct values the privacy gate replaced; the values themselves are
    /// never retained here or in receipt evidence.
    replaced_tokens: std::sync::Mutex<std::collections::BTreeSet<String>>,
    /// Largest kind count an open-mode gate reported in one provider request,
    /// by kind. Open mode removes a prohibited class without minting a token;
    /// the report is its only category evidence. The largest count (never the
    /// sum across rounds) keeps resent history from counting twice.
    reported_values: std::sync::Mutex<std::collections::BTreeMap<String, u32>>,
    /// Set on a delegated turn (`brain.where` per round).
    egress: Option<EgressWatch>,
}

/// One per provider round of a delegated turn, on its private channel only.
pub const BRAIN_WHERE: &str = "brain.where";

/// Where each provider round ran, read from the provider's append-only
/// contact log (one row per attempt), never from the tool name or the brain
/// config. Each round reads only the rows added since its own request.
struct EgressWatch {
    provider: Arc<dyn aux_providers::ChatProvider>,
    /// Log length at the pending request; `None` when the provider keeps no log.
    mark: std::sync::Mutex<Option<usize>>,
    /// A request went out and is not reported yet.
    pending: AtomicBool,
}

impl EgressWatch {
    /// A request goes out. A round a guard re-asked without a reply is still
    /// pending: its mark stays, so its attempts count toward the next report.
    fn sent(&self) {
        if !self.pending.swap(true, Ordering::SeqCst) {
            *kernel_core::lock_recover(&self.mark) = self.provider.contact_log().map(|l| l.len());
        }
    }

    /// Report the pending round, if any. With no log, an answered round on a
    /// single off-Mac endpoint is `out` and anything else `unknown`; a failed
    /// round with nothing recorded reports nothing.
    fn report(&self, answered: bool) -> Option<&'static str> {
        if !self.pending.swap(false, Ordering::SeqCst) {
            return None;
        }
        let mark = *kernel_core::lock_recover(&self.mark);
        let round = match (self.provider.contact_log(), mark) {
            (Some(log), Some(mark)) => log.get(mark..).map(<[Contact]>::to_vec),
            _ => None,
        };
        match round {
            Some(round) if !round.is_empty() => Some(step_where(&round)),
            Some(_) | None if !answered => None,
            Some(_) => Some("unknown"),
            None => Some(match self.provider.endpoint_host() {
                Some(host) if !loopback_host(&host) => "out",
                _ => "unknown",
            }),
        }
    }
}

/// `out` when any attempt went to a known host off this Mac; `local` only
/// when every attempt went to a loopback brain known to run on this Mac;
/// `unknown` otherwise (a loopback brain that may forward, an unknown host).
pub fn step_where(round: &[Contact]) -> &'static str {
    let off_mac = |c: &Contact| c.host.as_deref().is_some_and(|h| !loopback_host(h));
    let on_mac = |c: &Contact| c.on_this_mac && c.host.as_deref().is_some_and(loopback_host);
    if round.iter().any(off_mac) {
        "out"
    } else if !round.is_empty() && round.iter().all(on_mac) {
        "local"
    } else {
        "unknown"
    }
}

fn loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

struct Draft {
    draft: u64,
    /// The wire id of the stream (`draft-<session>-<run>-<round>`).
    id: String,
    stream: Arc<DeltaStream>,
}

/// Extract the full entity kind from a privacy token interior such as
/// `NATIONAL_ID_0123456789AB` (or its collision form ending in `_1`).
///
/// The digest is the final twelve uppercase hex characters before an optional
/// numeric collision suffix, so underscores inside a kind remain intact.
fn replacement_token_kind(token: &str) -> Option<&str> {
    let (prefix, suffix) = token.rsplit_once('_')?;
    let collision = if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
        prefix.rsplit_once('_').filter(|(kind, digest)| {
            valid_replacement_kind(kind) && valid_replacement_digest(digest)
        })
    } else {
        None
    };
    let (kind, digest) = collision.unwrap_or((prefix, suffix));
    if !valid_replacement_kind(kind) || !valid_replacement_digest(digest) {
        return None;
    }
    Some(kind)
}

fn valid_replacement_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_replacement_digest(digest: &str) -> bool {
    digest.len() == 12
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

impl ApiTurnEvents {
    /// A sink publishing to `events` for `agent` (and rooted at `home` so
    /// previews are scrubbed of the home path).
    pub fn new(
        sinks: StreamSinks,
        home: PathBuf,
        agent: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Arc<Self> {
        let cursor = receipt::cursor_mark(&kernel_core::store_path(&home));
        Arc::new(Self {
            sinks,
            home,
            agent: agent.into(),
            trigger: "owner_message".into(),
            provider_hosts: None,
            active: std::sync::Mutex::new(None),
            started: receipt::local_timestamp(),
            run_id: run_id.into(),
            cursor,
            tools: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            activity: std::sync::Mutex::new(Vec::new()),
            replaced_tokens: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            reported_values: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            egress: None,
        })
    }

    /// Report where each provider round ran (`brain.where`).
    pub fn with_egress_watch(
        mut self: Arc<Self>,
        provider: Arc<dyn aux_providers::ChatProvider>,
    ) -> Arc<Self> {
        if let Some(events) = Arc::get_mut(&mut self) {
            let (mark, pending) = (Default::default(), AtomicBool::new(false));
            events.egress = Some(EgressWatch {
                provider,
                mark,
                pending,
            });
        }
        self
    }

    /// The turn failed: report a round that was in flight, if the record
    /// shows it reached a host.
    pub fn egress_failed(&self) {
        if let Some(place) = self.egress.as_ref().and_then(|e| e.report(false)) {
            self.send(serde_json::json!({ "type": BRAIN_WHERE, "where": place }));
        }
    }

    /// Record the owner-visible cause of this run without retaining message text.
    pub fn with_trigger(mut self: Arc<Self>, trigger: impl Into<String>) -> Arc<Self> {
        if let Some(events) = Arc::get_mut(&mut self) {
            events.trigger = trigger.into();
        }
        self
    }

    pub fn with_provider_hosts(
        mut self: Arc<Self>,
        hosts: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    ) -> Arc<Self> {
        if let Some(events) = Arc::get_mut(&mut self) {
            events.provider_hosts = Some(hosts);
        }
        self
    }

    /// Facts captured during the run, for the failed-run receipt path.
    pub fn receipt_evidence(&self) -> Vec<ReceiptEvent> {
        let mut evidence: Vec<_> = kernel_core::lock_recover(&self.tools)
            .iter()
            .map(|(name, count)| ReceiptEvent::Tool {
                name: name.clone(),
                count: *count,
            })
            .collect();
        evidence.extend(kernel_core::lock_recover(&self.activity).iter().cloned());
        if let Some(hosts) = &self.provider_hosts {
            evidence.extend(hosts().into_iter().map(ReceiptEvent::HostContacted));
        }
        evidence
    }

    fn send(&self, value: serde_json::Value) {
        wire::send_bounded(&self.sinks.loopback, &value);
    }

    /// Flush and retire the active draft stream. The persisted message (or
    /// `message.done`) must go out *after* the last delta, so this runs before
    /// the reply's `message.new` and every `message.done`. Returns the retired draft's
    /// wire id, so the persisted message can name the stream it replaces.
    fn finish_active(&self) -> Option<String> {
        let draft = kernel_core::lock_recover(&self.active).take()?;
        draft.stream.finish();
        Some(draft.id)
    }

    /// The stream for `draft`, created on first use; a different draft
    /// finishes the previous one.
    fn stream_for(&self, session_id: i64, draft: u64) -> Arc<DeltaStream> {
        let mut active = kernel_core::lock_recover(&self.active);
        if let Some(current) = active.as_ref() {
            if current.draft == draft {
                return Arc::clone(&current.stream);
            }
            current.stream.finish();
        }
        // The run id keeps two turns of one thread apart: round 1 of the next
        // turn never appends into a draft a failed turn left behind.
        let message_id = format!("draft-{session_id}-{}-{draft}", self.run_id);
        let stream = DeltaStream::new(
            self.sinks.clone(),
            self.home.clone(),
            self.agent.clone(),
            session_id,
            message_id.clone(),
        );
        *active = Some(Draft {
            draft,
            id: message_id,
            stream: Arc::clone(&stream),
        });
        stream
    }
}

impl TurnEvents for ApiTurnEvents {
    fn request(&self, request: &aux_providers::ChatRequest) {
        if let Some(egress) = &self.egress {
            egress.sent();
        }
        // Count distinct tokens in the actual provider-bound request,
        // including tool specs. History is resent in later rounds, so only
        // tokens not already seen in this run contribute to the receipt.
        let Ok(json) = serde_json::to_string(request) else {
            return;
        };
        let mut tokens = std::collections::BTreeMap::<String, String>::new();
        let mut rest = json.as_str();
        while let Some(start) = rest.find('⟦') {
            rest = &rest[start + '⟦'.len_utf8()..];
            let Some(end) = rest.find('⟧') else {
                break;
            };
            let token = &rest[..end];
            if let Some(kind) = replacement_token_kind(token) {
                tokens
                    .entry(token.to_string())
                    .or_insert_with(|| kind.to_ascii_lowercase());
            }
            rest = &rest[end + '⟧'.len_utf8()..];
        }
        let mut seen = kernel_core::lock_recover(&self.replaced_tokens);
        let mut counts = std::collections::BTreeMap::<String, u32>::new();
        for (token, kind) in tokens {
            if seen.insert(token) {
                *counts.entry(kind).or_default() += 1;
            }
        }
        drop(seen);
        // Open mode removes a prohibited class with a fixed marker instead of
        // minting a token, so its gate report is the only category evidence.
        // Keep the largest count seen in one request (not the sum across
        // rounds): history is resent every round, and summing would count the
        // same value once per round. The report holds kinds and counts only.
        let mut reported = std::collections::BTreeMap::<String, u32>::new();
        for message in request.messages.iter() {
            for (kind, count) in message.detected() {
                if !kind.is_prohibited() {
                    continue;
                }
                let Ok(count) = u32::try_from(count) else {
                    continue;
                };
                let slot = reported
                    .entry(kind.as_str().to_ascii_lowercase())
                    .or_default();
                *slot = slot.saturating_add(count);
            }
        }
        {
            let mut seen_reports = kernel_core::lock_recover(&self.reported_values);
            let mut events = Vec::new();
            for (kind, count) in reported {
                let slot = seen_reports.entry(kind.clone()).or_default();
                if count > *slot {
                    events.push(ReceiptEvent::Replaced {
                        kind,
                        count: count - *slot,
                    });
                    *slot = count;
                }
            }
            if !events.is_empty() {
                kernel_core::lock_recover(&self.activity).extend(events);
            }
        }
        kernel_core::lock_recover(&self.activity).extend(
            counts
                .into_iter()
                .map(|(kind, count)| ReceiptEvent::Replaced { kind, count }),
        );
    }

    fn message(&self, message: &Message) {
        if message.role == "assistant" {
            if let Some(hosts) = &self.provider_hosts {
                kernel_core::lock_recover(&self.activity)
                    .extend(hosts().into_iter().map(ReceiptEvent::HostContacted));
            }
        }
        // The assistant reply that ends a streamed round names its draft, so
        // a client replaces the streamed bubble instead of adding a second.
        // Every row names its run, so a client groups one turn's rows only.
        // Only that reply retires the draft: another row (a tool result)
        // leaves it to the reply that will name it.
        let draft = if message.role == "assistant" {
            self.finish_active()
        } else {
            None
        };
        let link = |mut frame: serde_json::Value| {
            frame["message"]["run_id"] = serde_json::Value::String(self.run_id.clone());
            if let Some(id) = &draft {
                frame["message"]["draft_id"] = serde_json::Value::String(id.clone());
            }
            frame
        };
        // The loopback frame shows the session's values; the remote frame
        // carries the tokens as stored.
        let rehydrator = Rehydrator::new(live_tokens(), message.session_id, self.sinks.lang);
        let place = (message.role == "assistant")
            .then(|| self.egress.as_ref().and_then(|e| e.report(true)))
            .flatten();
        self.send(link(wire::message_new_rehydrated(
            &self.home,
            &self.agent,
            message,
            |text| rehydrator.whole(text),
        )));
        if let Some(remote) = &self.sinks.remote {
            let frame = link(wire::message_new(&self.home, &self.agent, message));
            wire::send_bounded(remote, &frame);
        }
        if let Some(place) = place {
            self.send(serde_json::json!({ "type": BRAIN_WHERE, "where": place }));
        }
    }

    fn message_delta(&self, session_id: i64, draft: u64, seq: u64, text: &str) {
        self.stream_for(session_id, draft).push(text, seq);
    }

    fn session_tokens(&self, session_id: i64, pairs: &[(String, String)]) {
        live_tokens().record(session_id, pairs);
        let mut activity = kernel_core::lock_recover(&self.activity);
        activity.push(ReceiptEvent::Trigger(self.trigger.clone()));
    }

    fn tool_start(&self, session_id: i64, message_id: i64, _index: usize, call: &ToolCall) {
        *kernel_core::lock_recover(&self.tools)
            .entry(call.name.clone())
            .or_default() += 1;
        self.send(wire::tool_start(
            &self.home,
            &self.agent,
            session_id,
            message_id,
            call,
        ));
        self.send(wire::agent_state(&self.agent, "working"));
    }

    fn tool_end(
        &self,
        session_id: i64,
        message_id: i64,
        index: usize,
        call: &ToolCall,
        outcome: ToolEndOutcome<'_>,
    ) {
        if outcome.status == "ok" {
            let mut activity = kernel_core::lock_recover(&self.activity);
            if call.name == "write_file" {
                if let Some(path) = call
                    .arguments
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                {
                    if workspace_relative(path) {
                        activity.push(ReceiptEvent::FileTouched(path.to_string()));
                    }
                }
            }
        } else {
            let detail = match outcome.error_kind {
                Some(kind) => format!("{} returned {} ({kind})", call.name, outcome.status),
                None => format!("{} returned {}", call.name, outcome.status),
            };
            kernel_core::lock_recover(&self.activity).push(ReceiptEvent::CouldNotVerify(detail));
            if outcome.status == "capped" {
                kernel_core::lock_recover(&self.activity)
                    .push(ReceiptEvent::Status(ReceiptStatus::StoppedBudget));
            }
        }
        if call.name == "http_fetch" && outcome.status == "ok" {
            if let Some(url) = call
                .arguments
                .get("url")
                .and_then(serde_json::Value::as_str)
            {
                kernel_core::lock_recover(&self.activity)
                    .push(ReceiptEvent::HostContacted(url.to_string()));
            }
        }
        if let Some(skill) = call.name.strip_prefix("skill__") {
            kernel_core::lock_recover(&self.activity).push(ReceiptEvent::Skill(skill.to_string()));
        }
        self.send(wire::tool_end(
            &self.home,
            &self.agent,
            session_id,
            message_id,
            index,
            call,
            outcome.status,
            outcome.result,
            outcome.error_kind,
        ));
        self.send(wire::agent_state(&self.agent, "thinking"));
    }

    fn read_check(&self, _session_id: i64, domain: &str, retried: bool) {
        // The receipt shows the retry and the replaced guess.
        let detail = if retried {
            format!("answered about {domain} without a tool; asked to check once")
        } else {
            format!("still no {domain} tool call; the answer was replaced")
        };
        kernel_core::lock_recover(&self.activity).push(ReceiptEvent::CouldNotVerify(detail));
    }

    fn done(&self, session_id: i64, message_id: i64) {
        self.finish_active();
        let finished = receipt::local_timestamp();
        let db_path = kernel_core::store_path(&self.home);
        let end = receipt::cursor_mark(&db_path);
        let mut facts = vec![
            ReceiptEvent::Run {
                run_id: self.run_id.clone(),
                agent: self.agent.clone(),
                started: Some(self.started.clone()),
                finished: Some(finished.clone()),
            },
            ReceiptEvent::Status(ReceiptStatus::Done),
            ReceiptEvent::Trigger(self.trigger.clone()),
            ReceiptEvent::CouldNotVerify(
                "file changes and external destinations are not fully recorded".into(),
            ),
        ];
        if let Some(usage) = receipt::usage_for_run(&db_path, &self.run_id) {
            facts.push(usage);
        }
        facts.extend(receipt::approvals_for_run(
            &db_path,
            &self.run_id,
            self.cursor,
            end,
            true,
        ));
        facts.extend(self.receipt_evidence());
        // The activity journal is the receipt store; the WS frame is emitted
        // from the same object so REST and live consumers see one receipt.
        let receipt = receipt::build_receipt(&facts);
        // Persist the receipt, retrying once on a transient journal error. A
        // receipt write is best-effort and must never fail or block the turn:
        // on a persistent failure, signal it on the live stream and write the
        // minimal fallback row so the activity list still shows the run.
        if let Err(err) = receipt::persist_receipt_retry(&db_path, &receipt) {
            tracing::warn!(
                error = %err,
                run_id = %self.run_id,
                "could not persist run receipt after retry"
            );
            self.send(receipt_failed_frame(
                &self.agent,
                session_id,
                &self.run_id,
                message_id,
            ));
            if let Err(fallback_err) = receipt::persist_fallback_receipt(&db_path, &receipt) {
                tracing::warn!(
                    error = %fallback_err,
                    run_id = %self.run_id,
                    "could not persist the fallback run receipt"
                );
            }
        }
        // The event poller publishes the persisted `run.finished` row with
        // this receipt attached; that is the single live run-finished frame.
        self.send(wire::message_done(&self.agent, session_id, message_id));
    }
}

/// A `run.receipt_failed` frame: the turn reached `done` but its receipt could
/// not be persisted, so the activity list may be missing detail for this run.
/// The `at` stamp matches the other generated frames (UTC, seconds).
fn receipt_failed_frame(
    agent: &str,
    thread_id: i64,
    run_id: &str,
    message_id: i64,
) -> serde_json::Value {
    serde_json::json!({
        "type": "run.receipt_failed",
        "at": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "agent": super::snapshot::clean_field(agent),
        "thread_id": thread_id.to_string(),
        "run_id": super::snapshot::clean_field(run_id),
        "message_id": message_id.to_string(),
    })
}

fn workspace_relative(path: &str) -> bool {
    let path = std::path::Path::new(path);
    !path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_providers::{ChatMessage, ChatRequest, SafeMessage};
    use aux_store::Message;
    use tokio::sync::broadcast;

    fn replacement_test_setup() -> (tempfile::TempDir, Arc<ApiTurnEvents>, kernel_privacy::Gate) {
        let dir = tempfile::tempdir().unwrap();
        let (sender, _receiver) = broadcast::channel(16);
        let sink = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            dir.path().into(),
            "main",
            "turn-replacements",
        );
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::A2,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::Vendor("fake".into()),
        )
        .unwrap();
        let names =
            aux_runtime::known_names::names_for(&aux_runtime::known_names::owner_contacts())
                .unwrap();
        let gate = aux_engine::session_gate(1, &grant, names).unwrap();
        (dir, sink, gate)
    }

    fn request_for(gate: &mut kernel_privacy::Gate, content: &str) -> ChatRequest {
        let message = SafeMessage::issue(gate, &ChatMessage::user(content)).unwrap();
        ChatRequest::new(vec![message])
    }

    fn open_test_setup() -> (tempfile::TempDir, Arc<ApiTurnEvents>, kernel_privacy::Gate) {
        let dir = tempfile::tempdir().unwrap();
        let (sender, _receiver) = broadcast::channel(16);
        let sink = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            dir.path().into(),
            "main",
            "turn-open-replacements",
        );
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::A2,
            kernel_core::privacy::PrivacyMode::Open,
            kernel_core::privacy::Destination::Vendor("fake".into()),
        )
        .unwrap();
        let gate = kernel_privacy::Gate::for_passthrough(&grant).unwrap();
        (dir, sink, gate)
    }

    fn replacement_receipt(sink: &ApiTurnEvents) -> crate::api::receipt::Receipt {
        crate::api::receipt::build_receipt(&kernel_core::lock_recover(&sink.activity))
    }

    fn message(id: i64, role: &str, content: &str) -> Message {
        Message {
            id,
            session_id: 3,
            role: role.to_string(),
            content: content.to_string(),
            created_at: "2026-10-04 09:30:00".to_string(),
            meta: None,
        }
    }

    fn drained(receiver: &mut broadcast::Receiver<String>) -> Vec<serde_json::Value> {
        let mut frames = Vec::new();
        while let Ok(text) = receiver.try_recv() {
            frames.push(serde_json::from_str(&text).unwrap());
        }
        frames
    }

    fn kinds(frames: &[serde_json::Value]) -> Vec<String> {
        frames
            .iter()
            .map(|frame| frame["type"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn failed_fetch_is_not_claimed_as_a_contacted_host() {
        let dir = tempfile::tempdir().unwrap();
        let (sender, _receiver) = broadcast::channel(16);
        let sink = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            dir.path().to_path_buf(),
            "main",
            "turn-host",
        );
        let call = ToolCall::new(
            "fetch-1",
            "http_fetch",
            serde_json::json!({"url":"https://user:token@example.test/private?q=secret"}),
        );
        sink.tool_end(
            1,
            1,
            0,
            &call,
            ToolEndOutcome {
                status: "error",
                result: "",
                error_kind: Some("network"),
            },
        );
        assert!(!kernel_core::lock_recover(&sink.activity)
            .iter()
            .any(|event| matches!(event, ReceiptEvent::HostContacted(_))));
        sink.tool_end(
            1,
            1,
            0,
            &call,
            ToolEndOutcome {
                status: "ok",
                result: "",
                error_kind: None,
            },
        );
        let facts = kernel_core::lock_recover(&sink.activity).clone();
        let receipt = receipt::build_receipt(&facts);
        assert_eq!(receipt.hosts_contacted, ["example.test"]);
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("user:token"));
        assert!(!json.contains("q=secret"));
    }

    #[test]
    fn completed_provider_reply_records_only_its_host() {
        let dir = tempfile::tempdir().unwrap();
        let (sender, _receiver) = broadcast::channel(16);
        let sink = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            dir.path().into(),
            "main",
            "turn-provider",
        )
        .with_provider_hosts(Arc::new(|| vec!["api.example.test".into()]));
        sink.message(&message(1, "assistant", "fictional reply"));
        let receipt = receipt::build_receipt(&kernel_core::lock_recover(&sink.activity));
        assert_eq!(receipt.hosts_contacted, ["api.example.test"]);
    }

    #[test]
    fn failed_run_evidence_keeps_all_hosts_contacted_since_the_last_reply() {
        let dir = tempfile::tempdir().unwrap();
        let (sender, _receiver) = broadcast::channel(16);
        let sink = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            dir.path().into(),
            "main",
            "turn-failed-hosts",
        )
        .with_provider_hosts(Arc::new(|| {
            vec!["first.example.test".into(), "fallback.example.test".into()]
        }));

        let receipt = receipt::build_receipt(&sink.receipt_evidence());
        assert_eq!(
            receipt.hosts_contacted,
            ["first.example.test", "fallback.example.test"]
        );
    }

    #[test]
    fn replacement_token_kinds_round_trip_for_every_kernel_entity_kind() {
        for kind in kernel_privacy::EntityKind::ALL {
            let name = kind.as_str();
            let token = format!("{name}_0123456789AB");
            assert_eq!(
                replacement_token_kind(&token).map(str::to_ascii_lowercase),
                Some(name.to_ascii_lowercase()),
                "token kind was truncated for {token}"
            );
        }
        assert_eq!(
            replacement_token_kind("NATIONAL_ID_0123456789AB_1")
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("national_id")
        );
        assert_eq!(replacement_token_kind("EMAIL_not-a-digest"), None);
    }

    #[test]
    fn one_email_across_three_provider_rounds_counts_once() {
        let (_dir, sink, mut gate) = replacement_test_setup();
        for _ in 0..3 {
            sink.request(&request_for(&mut gate, "mail fictional@example.test"));
        }

        let receipt = replacement_receipt(&sink);
        assert_eq!(receipt.replaced_values.get("email"), Some(&1));
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("fictional@example.test"));
        assert!(json.contains("\"email\":1"));
        assert!(!json.contains("EMAIL_"));
    }

    #[test]
    fn distinct_emails_count_separately() {
        let (_dir, sink, mut gate) = replacement_test_setup();
        sink.request(&request_for(
            &mut gate,
            "fictional-one@example.test and fictional-two@example.test",
        ));

        let receipt = replacement_receipt(&sink);
        assert_eq!(receipt.replaced_values.get("email"), Some(&2));
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("fictional-one@example.test"));
        assert!(!json.contains("fictional-two@example.test"));
        assert!(!json.contains("EMAIL_"));
    }

    #[test]
    fn one_email_repeated_in_a_message_counts_once() {
        let (_dir, sink, mut gate) = replacement_test_setup();
        sink.request(&request_for(
            &mut gate,
            "fictional@example.test and again fictional@example.test",
        ));

        let receipt = replacement_receipt(&sink);
        assert_eq!(receipt.replaced_values.get("email"), Some(&1));
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("fictional@example.test"));
        assert!(!json.contains("EMAIL_"));
    }

    #[test]
    fn open_mode_records_a_removed_iban_once_across_rounds() {
        let (_dir, sink, mut gate) = open_test_setup();
        let request = request_for(&mut gate, "IBAN FR76 3000 6000 0112 3456 7890 189");
        let body = serde_json::to_string(&request).unwrap();
        assert!(body.contains("[iban removed]"), "{body}");
        assert!(!body.contains("FR76 3000 6000 0112 3456 7890 189"));

        // The same request comes back as history in a later round: the
        // receipt must count the class once, not once per round.
        sink.request(&request);
        sink.request(&request);

        let receipt = replacement_receipt(&sink);
        assert_eq!(receipt.replaced_values.get("iban"), Some(&1));
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("FR76 3000 6000 0112 3456 7890 189"));
    }

    #[test]
    fn open_mode_does_not_record_a_value_it_leaves_in_clear() {
        let (_dir, sink, mut gate) = open_test_setup();
        let request = request_for(&mut gate, "mail fictional@example.test");
        assert!(serde_json::to_string(&request)
            .unwrap()
            .contains("fictional@example.test"));
        sink.request(&request);

        assert!(replacement_receipt(&sink).replaced_values.is_empty());
    }

    #[test]
    fn overlapping_turns_each_persist_only_their_own_usage() {
        use kernel_core::budget::UsageKind;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let store = aux_store::Store::open(&db_path).unwrap();

        let (sender, _receiver) = broadcast::channel(32);
        // Two turns of the same agent are live at once.
        let run_a = receipt::new_run_id(3);
        let run_b = receipt::new_run_id(3);
        let sink_a = ApiTurnEvents::new(
            StreamSinks::loopback(sender.clone()),
            home.clone(),
            "main",
            run_a.clone(),
        );
        let sink_b = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            home.clone(),
            "main",
            run_b.clone(),
        );

        // Their provider calls interleave.
        store
            .record_usage_for(&run_a, "main", UsageKind::TokensIn, 12, "tokens")
            .unwrap();
        store
            .record_usage_for(&run_b, "main", UsageKind::TokensIn, 100, "tokens")
            .unwrap();
        store
            .record_usage_for(&run_a, "main", UsageKind::TokensOut, 7, "tokens")
            .unwrap();
        store
            .record_usage_for(&run_b, "main", UsageKind::TokensOut, 200, "tokens")
            .unwrap();

        sink_a.done(3, 5);
        sink_b.done(3, 6);

        let receipts = receipt::read_receipts(&db_path, Some("main"), 10).unwrap();
        let by_run: std::collections::BTreeMap<&str, (u64, u64)> = receipts
            .iter()
            .map(|receipt| {
                (
                    receipt.run_id.as_str(),
                    (receipt.tokens_in, receipt.tokens_out),
                )
            })
            .collect();
        assert_eq!(by_run.get(run_a.as_str()), Some(&(12, 7)));
        assert_eq!(by_run.get(run_b.as_str()), Some(&(100, 200)));
    }

    #[test]
    fn a_panic_after_settle_keeps_the_usage_and_writes_no_receipt() {
        // Receipts cover the normal lifecycle only. If the turn task
        // panics after the engine settled (so unwinding drops the sink and
        // `done` — which persists the receipt — never runs), the already
        // committed usage must survive, count in the daily budget, and leave
        // no receipt. This is accepted, not repaired.
        use kernel_core::budget::UsageKind;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let store = aux_store::Store::open(&db_path).unwrap();
        let run_id = receipt::new_run_id(3);

        // The engine settles the turn's usage before the turn end...
        store
            .record_usage_for(&run_id, "main", UsageKind::UsdCents, 10, "cents")
            .unwrap();

        // ...then the turn task panics. The panic is contained, and the
        // dropped sink never writes the `run.finished` receipt.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (sender, _receiver) = broadcast::channel(8);
            let _sink = ApiTurnEvents::new(
                StreamSinks::loopback(sender),
                home.clone(),
                "main",
                run_id.clone(),
            );
            panic!("simulated mid-turn panic after settle");
        }));
        assert!(panicked.is_err(), "the simulated panic must unwind");

        // The persisted usage is not lost and still counts in the day's budget.
        let day = store.local_day().unwrap();
        assert_eq!(store.usage_totals("main", &day).unwrap().usd_cents, 10);
        assert_eq!(store.usage_totals_for_run(&run_id).unwrap().usd_cents, 10);
        // No receipt was ever persisted for the interrupted turn.
        assert_eq!(store.event_count("run.finished").unwrap(), 0);
        let receipts = receipt::read_receipts(&db_path, Some("main"), 10).unwrap();
        assert!(
            receipts.iter().all(|receipt| receipt.run_id != run_id),
            "a dropped sink must leave no receipt for the turn"
        );
    }

    #[test]
    fn a_persisted_reply_shows_its_values_locally_and_its_tokens_remotely() {
        const SESSION: i64 = 4_100_102;
        const TOKEN: &str = "EMAIL_0123456789CD";
        const VALUE: &str = "anne.dupont@example.org";
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (loopback, mut loopback_rx) = broadcast::channel(32);
        let (remote, mut remote_rx) = broadcast::channel(32);
        let sinks = StreamSinks {
            loopback,
            remote: Some(remote),
            lang: kernel_core::Lang::Fr,
        };
        let sink = ApiTurnEvents::new(sinks, home, "main", "turn-display");
        sink.session_tokens(SESSION, &[(TOKEN.to_string(), VALUE.to_string())]);

        let content = format!("Bonjour ⟦{TOKEN}⟧, ⟦EMAIL_FFFFFFFFFFFF⟧");
        sink.message(&Message {
            session_id: SESSION,
            ..message(9, "assistant", &content)
        });

        let shown = drained(&mut loopback_rx);
        assert_eq!(
            shown[0]["message"]["blocks"][0]["text"].as_str().unwrap(),
            format!("Bonjour {VALUE}, [nom masqué]")
        );
        let tokens = drained(&mut remote_rx);
        assert_eq!(
            tokens[0]["message"]["blocks"][0]["text"].as_str().unwrap(),
            content
        );
        assert!(!format!("{tokens:?}").contains(VALUE));
    }

    #[test]
    fn sink_publishes_the_turn_stream_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (sender, mut receiver) = broadcast::channel(32);
        let sink = ApiTurnEvents::new(StreamSinks::loopback(sender), home, "main", "turn-test");

        sink.message(&message(2, "user", "hello"));
        sink.message_delta(3, 1, 1, "wor");
        sink.message_delta(3, 1, 2, "king");
        sink.message(&message(3, "assistant", "working"));
        let call = ToolCall::new("call_1", "shell", serde_json::json!({"command": "ls"}));
        sink.tool_start(3, 3, 0, &call);
        sink.tool_end(
            3,
            3,
            0,
            &call,
            ToolEndOutcome {
                status: "ok",
                result: "file.txt",
                error_kind: None,
            },
        );
        sink.message(&message(4, "tool", "file.txt"));
        sink.message_delta(3, 2, 1, "done");
        sink.message(&message(5, "assistant", "done"));
        sink.done(3, 5);

        let frames = drained(&mut receiver);
        assert_eq!(
            kinds(&frames),
            vec![
                "message.new",
                "message.delta",
                "message.new",
                "tool.start",
                "agent.state",
                "tool.end",
                "agent.state",
                "message.new",
                "message.delta",
                "message.new",
                "message.done",
            ],
            "frames: {frames:#?}"
        );
        assert_eq!(frames[1]["text"], "working");
        assert_eq!(frames[1]["message_id"], "draft-3-turn-test-1");
        assert_eq!(frames[1]["seq"], 2);
        assert_eq!(frames[8]["text"], "done");
        assert_eq!(frames[8]["message_id"], "draft-3-turn-test-2");
        assert_eq!(frames[8]["seq"], 1);
        // CHAT-DOUBLE-1: each streamed reply names the draft it replaces;
        // the owner's words and tool rows never carry one.
        assert_eq!(frames[2]["message"]["draft_id"], "draft-3-turn-test-1");
        assert_eq!(frames[9]["message"]["draft_id"], "draft-3-turn-test-2");
        assert!(frames[0]["message"].get("draft_id").is_none());
        assert!(frames[7]["message"].get("draft_id").is_none());
    }

    #[test]
    fn an_unstreamed_reply_names_no_draft() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (sender, mut receiver) = broadcast::channel(32);
        let sink = ApiTurnEvents::new(StreamSinks::loopback(sender), home, "main", "turn-test");
        sink.message(&message(2, "user", "hello"));
        sink.message(&message(3, "assistant", "hi"));
        let frames = drained(&mut receiver);
        assert!(frames[1]["message"].get("draft_id").is_none());
    }

    #[test]
    fn a_draft_belongs_to_one_run_and_its_reply() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let _store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
        let (sender, mut receiver) = broadcast::channel(32);
        let sink = |run| {
            ApiTurnEvents::new(
                StreamSinks::loopback(sender.clone()),
                home.clone(),
                "main",
                run,
            )
        };
        let (first, second) = (sink("turn-a"), sink("turn-b"));
        // The first turn's stream fails: no stored reply ever names its draft.
        first.message(&message(2, "user", "hello"));
        first.message_delta(3, 1, 1, "half an ans");
        first.done(3, 2);
        // A tool row leaves the draft to the reply that names it.
        second.message_delta(3, 1, 1, "hi");
        second.message(&message(4, "tool", "file.txt"));
        second.message(&message(5, "assistant", "hi"));
        let frames = drained(&mut receiver);
        let pick = |kind: &str, field: fn(&serde_json::Value) -> serde_json::Value| {
            serde_json::Value::from(
                frames
                    .iter()
                    .filter(|f| f["type"] == kind)
                    .map(field)
                    .collect::<Vec<_>>(),
            )
        };
        let ids = pick("message.delta", |f| f["message_id"].clone());
        assert_eq!(
            ids,
            serde_json::json!(["draft-3-turn-a-1", "draft-3-turn-b-1"])
        );
        let runs = pick("message.new", |f| f["message"]["run_id"].clone());
        assert_eq!(runs, serde_json::json!(["turn-a", "turn-b", "turn-b"]));
        let drafts = pick("message.new", |f| f["message"]["draft_id"].clone());
        assert_eq!(drafts, serde_json::json!([null, null, "draft-3-turn-b-1"]));
    }

    #[test]
    fn sink_frames_carry_the_app_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (sender, mut receiver) = broadcast::channel(32);
        let sink = ApiTurnEvents::new(StreamSinks::loopback(sender), home, "main", "turn-test");
        sink.message(&message(2, "user", "hello"));
        sink.done(3, 2);

        let frames = drained(&mut receiver);
        assert_eq!(
            frames[0]["message"]["author"],
            serde_json::json!({"kind": "you"})
        );
        assert_eq!(frames[0]["message"]["thread_id"], "3");
        assert_eq!(frames[1]["message_id"], "2");
    }

    #[tokio::test]
    async fn deltas_are_coalesced_and_flushed_before_the_message() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (sender, mut receiver) = broadcast::channel(64);
        let sink = ApiTurnEvents::new(StreamSinks::loopback(sender), home, "main", "turn-test");

        sink.message(&message(2, "user", "hello"));
        for seq in 1..=10 {
            sink.message_delta(3, 1, seq, "tok ");
        }
        // The message is persisted: the held tail flushes before `message.new`.
        sink.message(&message(3, "assistant", &"tok ".repeat(10)));

        let frames = drained(&mut receiver);
        assert_eq!(
            kinds(&frames),
            vec!["message.new", "message.delta", "message.new"]
        );
        assert_eq!(frames[1]["text"], "tok ".repeat(10));
        assert_eq!(frames[1]["seq"], 10);
    }

    #[test]
    fn a_new_draft_finishes_the_previous_stream() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (sender, mut receiver) = broadcast::channel(64);
        let sink = ApiTurnEvents::new(StreamSinks::loopback(sender), home, "main", "turn-test");

        sink.message_delta(3, 1, 1, "round one");
        sink.message_delta(3, 2, 1, "round two");
        sink.done(3, 3);
        let frames = drained(&mut receiver);
        assert_eq!(
            kinds(&frames),
            vec!["message.delta", "message.delta", "message.done"]
        );
        assert_eq!(frames[0]["text"], "round one");
        assert_eq!(frames[0]["message_id"], "draft-3-turn-test-1");
        assert_eq!(frames[1]["message_id"], "draft-3-turn-test-2");
    }

    /// Clears the receipt test seam even if an assertion unwinds first.
    struct SeamReset;

    impl Drop for SeamReset {
        fn drop(&mut self) {
            receipt::test_seam::clear();
        }
    }

    #[test]
    fn a_transient_receipt_write_failure_recovers_on_the_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (sender, mut receiver) = broadcast::channel(32);
        let sink = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            home,
            "main",
            "turn-transient",
        );

        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        receipt::test_seam::set(move || {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                Some(Err(anyhow::anyhow!("injected transient journal failure")))
            } else {
                None
            }
        });
        let _reset = SeamReset;

        sink.done(3, 5);

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "the write must be retried exactly once"
        );
        let frames = drained(&mut receiver);
        assert_eq!(
            kinds(&frames),
            vec!["message.done"],
            "a recovered write emits no failure signal"
        );
        let receipts = receipt::read_receipts(&db_path, Some("main"), 10).unwrap();
        assert_eq!(receipts.len(), 1, "the retry persisted the receipt");
        assert_eq!(receipts[0].run_id, "turn-transient");
        assert!(!receipts[0].receipt_error);
    }

    #[test]
    fn a_persistent_receipt_write_failure_signals_and_writes_a_fallback_row() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let db_path = kernel_core::store_path(&home);
        let _store = aux_store::Store::open(&db_path).unwrap();
        let (sender, mut receiver) = broadcast::channel(32);
        let sink = ApiTurnEvents::new(
            StreamSinks::loopback(sender),
            home,
            "main",
            "turn-persistent",
        );

        receipt::test_seam::set(|| {
            Some(Err(anyhow::anyhow!("injected persistent journal failure")))
        });
        let _reset = SeamReset;

        sink.done(3, 5);

        let frames = drained(&mut receiver);
        let kinds = kinds(&frames);
        assert!(
            kinds.contains(&"run.receipt_failed".to_string()),
            "the live stream must carry the failure signal: {kinds:?}"
        );
        assert_eq!(
            kinds.last().map(String::as_str),
            Some("message.done"),
            "the turn still completes"
        );
        let signal = frames
            .iter()
            .find(|frame| frame["type"] == "run.receipt_failed")
            .expect("signal frame");
        assert_eq!(signal["run_id"], "turn-persistent");
        assert_eq!(signal["thread_id"], "3");

        let receipts = receipt::read_receipts(&db_path, Some("main"), 10).unwrap();
        assert_eq!(
            receipts.len(),
            1,
            "the fallback row is the persisted run.finished"
        );
        assert!(receipts[0].receipt_error, "the fallback row is flagged");
        assert_eq!(receipts[0].run_id, "turn-persistent");
        assert_eq!(receipts[0].agent, "main");
        assert_eq!(receipts[0].status, ReceiptStatus::DoneUnverified);
        assert_eq!((receipts[0].tokens_in, receipts[0].tokens_out), (0, 0));
    }
}
