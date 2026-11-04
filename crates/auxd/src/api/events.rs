//! `WS /v1/events` — the v1 live channel.
//!
//! **Fan-out mode: poll-based.** A single background task polls the store
//! every [`ApiState::event_poll`] (1 s in production) and publishes to a
//! `tokio::sync::broadcast` channel; every connected socket gets a copy.
//! There is no event bus in `auxd` yet, so polling is the honest v1 mode —
//! it is also what makes `daemon.*` / `budget.denied` journal entries and
//! `agent.state` changes observable without touching the engine.
//!
//! Messages are JSON objects:
//!
//! ```json
//! {"type":"agent.state","at":"2026-10-03 09:00:00","agent":"main","state":{"name":"main", …}}
//! {"type":"budget.denied","at":"2026-10-03 09:00:01","agent":"main","seq":42,
//!  "summary":"daily cap reached","payload":{"agent":"main","reason":"daily cap reached"}}
//! ```
//!
//! - `agent.state` is emitted for every agent on connect and whenever its
//!   serialized state changes (running job, STOP, today's usage, last
//!   activity).
//! - every new `events` row is emitted with its kind as `type`, its sanitized
//!   digest as `summary`, its id as `seq`, and a size-capped, sanitized
//!   `payload`. B-API v3 writes (`agent.created`, `agent.updated`, `agent.paused`,
//!   `agent.resumed`, `agent.killed`, `daemon.stop_all`) ride this generic path
//!   unchanged.
//! - live turn frames (B-API v2, [`super::wire`]): `message.new`,
//!   `message.delta`, `message.done`, `tool.start`/`tool.end`,
//!   `approval.new`/`approval.resolved`, and app-shaped `agent.state`
//!   transitions (`thinking`/`working`/`idle`). These are pushed by the
//!   engine as they happen, not polled.
//!
//! `message.delta` carries transient streamed assistant text: the engine's
//! token deltas are coalesced (roughly one frame per 40 ms), scrubbed of the
//! home path and key-shaped strings even when a secret is split across two
//! deltas ([`super::deltas`]), and always followed by the authoritative
//! persisted `message.new`. Its `message_id` is a transient draft id
//! (`draft-<thread>-<round>`); clients merge the text and replace it with the
//! completed message. `seq` is monotonic per draft so a lagging client can
//! detect a gap and fall back to `GET /v1/threads/{id}/messages`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::Response;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::time::interval;

use super::snapshot::{self, AgentJson};
use super::ApiState;

/// Capacity of the in-process broadcast ring. A slow client that lags beyond
/// this simply misses events (`seq` lets it notice).
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Most journal rows read per poll tick.
const MAX_EVENTS_PER_POLL: i64 = 256;

/// Whole-payload cap (serialized bytes); larger payloads are dropped from
/// the message and only the sanitized `summary` remains.
const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// Per-string cap inside a payload.
const MAX_PAYLOAD_STRING_BYTES: usize = 2 * 1024;

/// Recursion and collection bounds for payload sanitizing.
const PAYLOAD_DEPTH: usize = 8;
const PAYLOAD_ITEMS: usize = 100;

/// One message on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct WsMessage {
    /// `agent.state` or the journal kind (`daemon.started`, `budget.denied`…).
    #[serde(rename = "type")]
    pub kind: String,
    /// UTC timestamp (`YYYY-MM-DD HH:MM:SS`).
    pub at: String,
    /// Agent the event belongs to, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Journal row id (gap detector for lagging clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    /// One-line sanitized digest of the payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Sanitized, size-capped payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Full agent snapshot for `agent.state`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<AgentJson>,
    /// Plain-data receipt on `run.finished` activity frames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<super::receipt::Receipt>,
}

/// One journal row as read back from the store.
#[derive(Debug, Clone)]
pub struct JournalRow {
    /// Row id.
    pub id: i64,
    /// Event kind.
    pub kind: String,
    /// Raw JSON payload.
    pub payload: String,
    /// UTC timestamp.
    pub at: String,
}

/// Upgrade an authenticated request to an events socket.
pub async fn events_socket(State(state): State<Arc<ApiState>>, ws: WebSocketUpgrade) -> Response {
    // Subscribe before the 101 reply: an event published right after the client sees the
    // handshake must not fall in the gap before `pump` starts.
    let receiver = state.events.subscribe();
    ws.on_upgrade(move |socket| pump(socket, state, receiver))
}

/// Send the current agent snapshot, then forward broadcast messages until the
/// client goes away.
async fn pump(
    mut socket: WebSocket,
    state: Arc<ApiState>,
    mut receiver: broadcast::Receiver<String>,
) {
    let initial = {
        let home = state.home.clone();
        tokio::task::spawn_blocking(move || snapshot::agents_snapshot(&home))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default()
    };
    for agent in initial {
        let message = WsMessage {
            kind: "agent.state".to_string(),
            at: now_stamp(),
            agent: Some(agent.name.clone()),
            seq: None,
            summary: None,
            payload: None,
            state: Some(agent),
            receipt: None,
        };
        if send_json(&mut socket, &message).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Ping(payload))) => {
                    if socket.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(_)) => {}
            },
            event = receiver.recv() => match event {
                Ok(text) => {
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                // A lagging client missed events. Journal frames carry `seq`
                // so gaps are visible; live turn frames do not (BAPIV2-11,
                // known limitation — a client can fall back to
                // `GET /v1/threads/{id}/messages`).
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
}

async fn send_json(socket: &mut WebSocket, message: &WsMessage) -> Result<(), ()> {
    let text = serde_json::to_string(message).map_err(|_| ())?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| ())
}

/// Start the store poller. Returns its task handle (aborted at shutdown).
///
/// Each tick first computes a cheap [`snapshot::change_stamp`]; when it is
/// unchanged the tick does **no** store reads and re-serialises no agent at all
/// (E-23). Only a real change (new event/message/usage/job, a session or run
/// update, config/STOP/agent-directory change, or the local day rolling over)
/// triggers the full snapshot.
pub fn start_broadcaster(state: Arc<ApiState>) -> tokio::task::JoinHandle<()> {
    // Read the cursor now, not inside the task: under load the task may first
    // run after a client has already written a row, which would then be
    // skipped forever (flaky `ws_publishes_agent_write_events_in_the_journal_shape`).
    let mut cursor = max_event_id(&state.db_path).unwrap_or(0);
    tokio::spawn(async move {
        let mut previous: Option<Vec<AgentJson>> = None;
        let mut stamp: Option<snapshot::StoreChangeStamp> = None;
        let mut ticker = interval(state.event_poll);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(current) = poll_stamp(&state).await else {
                continue;
            };
            if !stamp_changed(stamp.as_ref(), &current) {
                continue;
            }
            let Some((events, agents)) = poll_once(&state, cursor).await else {
                continue;
            };
            for row in &events {
                cursor = cursor.max(row.id);
                let message = journal_message(&state.home, row);
                if let Ok(text) = serde_json::to_string(&message) {
                    let _ = state.events.send(text);
                }
            }
            for agent in changed_agents(previous.as_deref(), &agents) {
                let message = WsMessage {
                    kind: "agent.state".to_string(),
                    at: now_stamp(),
                    agent: Some(agent.name.clone()),
                    seq: None,
                    summary: None,
                    payload: None,
                    state: Some(agent.clone()),
                    receipt: None,
                };
                if let Ok(text) = serde_json::to_string(&message) {
                    let _ = state.events.send(text);
                }
            }
            previous = Some(agents);
            stamp = Some(current);
        }
    })
}

/// True when the stamp differs from the last polled one (first tick always
/// polls, so a fresh connection gets its initial agent states).
fn stamp_changed(
    previous: Option<&snapshot::StoreChangeStamp>,
    current: &snapshot::StoreChangeStamp,
) -> bool {
    previous != Some(current)
}

async fn poll_stamp(state: &Arc<ApiState>) -> Option<snapshot::StoreChangeStamp> {
    let home = state.home.clone();
    tokio::task::spawn_blocking(move || snapshot::change_stamp(&home))
        .await
        .ok()
}

async fn poll_once(
    state: &Arc<ApiState>,
    cursor: i64,
) -> Option<(Vec<JournalRow>, Vec<AgentJson>)> {
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || {
        let events = read_events_since(&state.db_path, cursor, MAX_EVENTS_PER_POLL).ok()?;
        let agents = snapshot::agents_snapshot(&state.home).ok()?;
        Some((events, agents))
    })
    .await
    .ok()
    .flatten()
}

/// Agents whose serialized state differs from the previous tick, plus any new
/// agent. Names are unique, so a map lookup is enough.
fn changed_agents(previous: Option<&[AgentJson]>, current: &[AgentJson]) -> Vec<AgentJson> {
    let mut by_name: HashMap<&str, &AgentJson> = HashMap::new();
    if let Some(previous) = previous {
        for agent in previous {
            by_name.insert(agent.name.as_str(), agent);
        }
    }
    current
        .iter()
        .filter(|agent| by_name.get(agent.name.as_str()) != Some(agent))
        .cloned()
        .collect()
}

/// Journal row → wire message, sanitized, secret-scrubbed and size-capped.
///
/// F-03 (audit C P2-1): `summary`, every payload string and every display
/// field run through the shared [`super::error::scrub_preview`], so the WS
/// feed cannot re-expose a secret the messages view hides.
pub fn journal_message(home: &Path, row: &JournalRow) -> WsMessage {
    let payload = serde_json::from_str::<serde_json::Value>(&row.payload).ok();
    let payload = payload.and_then(|mut value| {
        // B3-02: mask credential-keyed values in the tree first, so the
        // re-serialised payload cannot encode a key behind an escape the
        // string scrubber would have to parse back out.
        kernel_broker::scrub_json_value(&mut value);
        let value = sanitize_json(home, value, 0);
        let encoded = serde_json::to_string(&value).ok()?;
        (encoded.len() <= MAX_PAYLOAD_BYTES).then_some(value)
    });
    WsMessage {
        kind: {
            let kind = snapshot::scrub_field(home, &row.kind);
            if kind.is_empty() {
                "unknown".to_string()
            } else {
                kind
            }
        },
        at: snapshot::scrub_field(home, &row.at),
        agent: payload_agent(home, row),
        seq: Some(row.id),
        summary: Some(snapshot::event_summary(home, &row.kind, &row.payload)),
        payload,
        state: None,
        receipt: if row.kind == "run.finished" {
            serde_json::from_str::<super::receipt::Receipt>(&row.payload)
                .ok()
                .map(|receipt| super::receipt::sanitize_receipt(&receipt))
        } else {
            None
        },
    }
}

fn payload_agent(home: &Path, row: &JournalRow) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(&row.payload).ok()?;
    let agent = snapshot::scrub_field(home, value.get("agent")?.as_str()?);
    (!agent.is_empty()).then_some(agent)
}

/// Recursively sanitize and secret-scrub string values, cap collection sizes
/// and depth (F-03: the same [`super::error::scrub_preview`] as everything
/// else visible to a client).
fn sanitize_json(home: &Path, value: serde_json::Value, depth: usize) -> serde_json::Value {
    use serde_json::Value;
    if depth > PAYLOAD_DEPTH {
        return Value::Null;
    }
    match value {
        Value::String(text) => Value::String(kernel_broker::scrub_external_preview(
            home,
            &text,
            MAX_PAYLOAD_STRING_BYTES,
        )),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .take(PAYLOAD_ITEMS)
                .map(|item| sanitize_json(home, item, depth + 1))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .take(PAYLOAD_ITEMS)
                .map(|(key, value)| {
                    let key: String = key.chars().take(128).collect();
                    (
                        kernel_broker::scrub_external_preview(home, &key, 128),
                        sanitize_json(home, value, depth + 1),
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

/// Highest journal row id, or 0 when the store/table is absent.
fn max_event_id(db_path: &Path) -> anyhow::Result<i64> {
    let conn = open_events_connection(db_path)?;
    let Some(conn) = conn else {
        return Ok(0);
    };
    if !table_exists(&conn, "events")? {
        return Ok(0);
    }
    let id: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
        row.get(0)
    })?;
    Ok(id)
}

/// Journal rows with `id > cursor`, oldest first.
fn read_events_since(db_path: &Path, cursor: i64, limit: i64) -> anyhow::Result<Vec<JournalRow>> {
    let conn = open_events_connection(db_path)?;
    let Some(conn) = conn else {
        return Ok(Vec::new());
    };
    if !table_exists(&conn, "events")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, kind, payload, created_at FROM events
         WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![cursor, limit], |row| {
        Ok(JournalRow {
            id: row.get(0)?,
            kind: row.get(1)?,
            payload: row.get(2)?,
            at: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn open_events_connection(db_path: &Path) -> anyhow::Result<Option<rusqlite::Connection>> {
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = aux_store::open_keyed_readonly(db_path)?;
    let _ = conn.busy_timeout(Duration::from_secs(2));
    Ok(Some(conn))
}

fn table_exists(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// A `YYYY-MM-DD HH:MM:SS` UTC stamp for generated state events.
fn now_stamp() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(name: &str, running: Option<&str>) -> AgentJson {
        AgentJson {
            name: name.to_string(),
            enabled: true,
            jobs_total: 1,
            jobs_enabled: 1,
            running_job: running.map(str::to_string),
            stop: false,
            paused: false,
            killed: false,
            usage_today: snapshot::UsageTotalsJson {
                tokens_in: 0,
                tokens_out: 0,
                usd_cents: 0,
            },
            last_activity: None,
            thread_id: None,
            role: None,
            glyph: None,
            brain: None,
            privacy_mode: "private".to_string(),
            unread: false,
            waiting: 0,
            live_line: None,
        }
    }

    #[test]
    fn changed_agents_reports_new_and_mutated_agents_only() {
        let first = vec![agent("main", None), agent("axis", None)];
        assert_eq!(changed_agents(None, &first).len(), 2);

        let unchanged = changed_agents(Some(&first), &first.clone());
        assert!(unchanged.is_empty());

        let mut second = first.clone();
        second[0].running_job = Some("veille".to_string());
        let changed = changed_agents(Some(&first), &second);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].name, "main");
    }

    #[test]
    fn the_poll_gate_skips_unchanged_ticks_and_polls_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();

        let first = snapshot::change_stamp(&home);
        // First tick (no previous stamp) always polls.
        assert!(stamp_changed(None, &first));
        // Nothing happened: the tick is skipped entirely.
        assert!(!stamp_changed(Some(&first), &snapshot::change_stamp(&home)));

        // One write of each kind moves the stamp, so the tick polls.
        store.log_event("daemon.started", "{}").unwrap();
        let after_event = snapshot::change_stamp(&home);
        assert!(stamp_changed(Some(&first), &after_event));
        store.create_session("main", None).unwrap();
        assert!(stamp_changed(
            Some(&after_event),
            &snapshot::change_stamp(&home)
        ));
    }

    #[test]
    fn journal_messages_carry_kind_summary_seq_and_sanitized_payload() {
        let home = Path::new("/nonexistent-home");
        let row = JournalRow {
            id: 7,
            kind: "budget.denied".to_string(),
            payload: r#"{"agent":"main","reason":"daily cap reached","junk":"\u001b[31m\u200b"}"#
                .to_string(),
            at: "2026-10-03 09:00:00".to_string(),
        };
        let message = journal_message(home, &row);
        assert_eq!(message.kind, "budget.denied");
        assert_eq!(message.agent.as_deref(), Some("main"));
        assert_eq!(message.seq, Some(7));
        assert_eq!(message.summary.as_deref(), Some("daily cap reached"));
        let payload = message.payload.unwrap();
        assert_eq!(payload["agent"], "main");
        assert_eq!(
            payload["junk"].as_str().unwrap(),
            "",
            "an ANSI SGR sequence is dropped whole, not left as `[31m`"
        );
    }

    #[test]
    fn journal_messages_scrub_secrets_like_the_messages_view() {
        // F-03: the WS journal used to expose exactly the shapes the REST
        // message scrub hides.
        let home = Path::new("/Users/secret/.auxesis");
        let row = JournalRow {
            id: 9,
            kind: "tool.end".to_string(),
            payload: serde_json::json!({
                "agent": "main",
                "summary": "wrote ghp_0123456789abcdefghijklmnop into notes.txt",
                "detail": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.signatureABCDEFGHIJKL",
                "path": "/Users/secret/.auxesis/agents/main/notes.txt"
            })
            .to_string(),
            at: "2026-10-03 09:00:00".to_string(),
        };
        let message = journal_message(home, &row);
        let summary = message.summary.clone().unwrap();
        assert!(
            !summary.contains("ghp_0123456789abcdefghijklmnop"),
            "{summary}"
        );
        assert!(summary.contains("ghp_<redacted>"), "{summary}");
        let encoded = serde_json::to_string(&message).unwrap();
        assert!(
            !encoded.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "JWT leaked into the WS frame: {encoded}"
        );
        assert!(!encoded.contains("/Users/secret/.auxesis"), "{encoded}");
        assert!(
            encoded.contains("<home>/agents/main/notes.txt"),
            "{encoded}"
        );
    }

    #[test]
    fn oversized_payloads_are_dropped_but_summaries_stay() {
        let home = Path::new("/nonexistent-home");
        // The per-string cap only limits each value; many values still make a
        // payload that must not be shipped whole.
        let mut map = serde_json::Map::new();
        map.insert("summary".to_string(), serde_json::json!("ok"));
        for index in 0..100 {
            map.insert(format!("k{index}"), serde_json::json!("x".repeat(2000)));
        }
        let row = JournalRow {
            id: 1,
            kind: "job.completed".to_string(),
            payload: serde_json::Value::Object(map).to_string(),
            at: "2026-10-03 09:00:00".to_string(),
        };
        let message = journal_message(home, &row);
        assert!(message.payload.is_none());
        assert_eq!(message.summary.as_deref(), Some("ok"));
    }

    #[test]
    fn malformed_payloads_keep_the_raw_digest() {
        let home = Path::new("/nonexistent-home");
        let row = JournalRow {
            id: 2,
            kind: "junk".to_string(),
            payload: "not json".to_string(),
            at: "2026-10-03 09:00:00".to_string(),
        };
        let message = journal_message(home, &row);
        assert!(message.payload.is_none());
        assert_eq!(message.summary.as_deref(), Some("not json"));
    }

    #[test]
    fn every_canary_is_scrubbed_from_journal_frames() {
        // The WS journal is the audit-row surface: summary, payload strings
        // and display fields all run through the shared scrubber, and the
        // payload tree is scrubbed before it is serialised.
        let home = Path::new("/Users/secret/.auxesis");
        for (raw, secret) in crate::api::canary::all_canaries() {
            let row = JournalRow {
                id: 1,
                kind: "tool.end".to_string(),
                payload: serde_json::json!({
                    "agent": "main",
                    "summary": raw,
                    "detail": raw,
                })
                .to_string(),
                at: "2026-10-03 09:00:00".to_string(),
            };
            let message = journal_message(home, &row);
            let summary = message.summary.clone().unwrap();
            assert!(!summary.contains(&secret), "summary leaked {secret:?}");
            let encoded = serde_json::to_string(&message).unwrap();
            assert!(!encoded.contains(&secret), "frame leaked {secret:?}");
            let payload = message.payload.unwrap();
            assert!(
                !payload.to_string().contains(&secret),
                "payload leaked {secret:?}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_row_written_before_the_broadcaster_first_runs_is_published() {
        // On a current-thread runtime the spawned broadcaster cannot run until
        // this test yields, so the row below lands before its first tick. The
        // cursor must already predate it.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            kernel_core::config_path(&home),
            "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
        )
        .unwrap();
        let _ = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
        let options = super::super::ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            ..super::super::ApiOptions::default()
        };
        let handle = super::super::spawn(&home, options).unwrap();
        let mut receiver = handle.state.events.subscribe();
        aux_store::Store::open(&kernel_core::store_path(&home))
            .unwrap()
            .log_event("agent.created", r#"{"agent":"scout","by":"test"}"#)
            .unwrap();
        assert!(max_event_id(&kernel_core::store_path(&home)).unwrap() > 0);
        let found = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let text = receiver.recv().await.unwrap();
                if text.contains("agent.created") && text.contains("scout") {
                    return;
                }
            }
        })
        .await;
        handle.shutdown();
        assert!(found.is_ok(), "the early row must reach the socket");
    }
}
