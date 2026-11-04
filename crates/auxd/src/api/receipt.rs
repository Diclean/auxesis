//! Small, bounded run receipts projected from recorded activity.
//!
//! The builder deliberately accepts facts, not model output or tool arguments.
//!
//! Coverage is the **normal lifecycle**: a turn that returns through the
//! lifecycle (including failed and cancelled returns) persists a
//! `run.finished` receipt. A panic or `kill -9` mid-turn can leave `usage`
//! rows stamped with a `run_id` but with no receipt; that is accepted and not
//! repaired (no started-run recovery), and those rows still count in the daily
//! budget totals.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const MAX_RECEIPT_ITEMS: usize = 64;
pub const MAX_RECEIPT_TEXT: usize = 512;
/// Distinct tool names a receipt keeps. Further names collapse into
/// [`RECEIPT_TOOLS_OVERFLOW`] so a turn that touches hundreds of tools still
/// yields a bounded, stable map.
pub const MAX_RECEIPT_TOOLS: usize = 64;
/// Bucket that absorbs every distinct tool name past [`MAX_RECEIPT_TOOLS`].
pub const RECEIPT_TOOLS_OVERFLOW: &str = "other";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Done,
    DoneUnverified,
    PausedNeedsYou,
    StoppedBudget,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub run_id: String,
    pub agent: String,
    /// Where the run was initiated; absent in older journal rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    /// Skill tool names used by this run, without any skill contents.
    #[serde(default)]
    pub skills: Vec<String>,
    /// Distinct values replaced (or that private mode would replace) in this
    /// run, by kind. Repeated tokens across messages, resent history, and
    /// provider rounds count once. Open mode removes a prohibited class with
    /// a fixed marker instead of a token; that class is counted too, from the
    /// gate's kind/count report. Only counts and kinds are persisted.
    #[serde(default)]
    pub replaced_values: BTreeMap<String, u32>,
    pub started: Option<String>,
    pub finished: Option<String>,
    pub status: ReceiptStatus,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_cents: u64,
    pub tools: BTreeMap<String, u32>,
    pub files_touched: Vec<String>,
    pub hosts_contacted: Vec<String>,
    pub messages_sent: Vec<String>,
    pub approvals_asked: Vec<String>,
    pub approvals_answered: Vec<String>,
    pub could_not_verify: Vec<String>,
    pub tainted: bool,
    /// Set on the minimal fallback row written when the full receipt could not
    /// be persisted. `false` on every ordinary receipt, and absent from rows
    /// written before this field existed, so older journals still parse.
    #[serde(default)]
    pub receipt_error: bool,
}

/// Existing recorded facts normalized for receipt projection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Variants model the existing activity facts, including sources absent on some run paths.
pub enum ReceiptEvent {
    Run {
        run_id: String,
        agent: String,
        started: Option<String>,
        finished: Option<String>,
    },
    Status(ReceiptStatus),
    Usage {
        tokens_in: u64,
        tokens_out: u64,
        cost_cents: u64,
    },
    Tool {
        name: String,
        count: u32,
    },
    FileTouched(String),
    HostContacted(String),
    Trigger(String),
    Skill(String),
    Replaced {
        kind: String,
        count: u32,
    },
    MessageSent(String),
    ApprovalAsked(String),
    ApprovalAnswered(String),
    CouldNotVerify(String),
    Tainted,
}

/// Build a receipt without consulting providers or making any new calls.
pub fn build_receipt(events: &[ReceiptEvent]) -> Receipt {
    let mut receipt = Receipt {
        run_id: "unknown".into(),
        agent: "unknown".into(),
        trigger: None,
        skills: Vec::new(),
        replaced_values: BTreeMap::new(),
        started: None,
        finished: None,
        status: ReceiptStatus::Done,
        tokens_in: 0,
        tokens_out: 0,
        cost_cents: 0,
        tools: BTreeMap::new(),
        files_touched: Vec::new(),
        hosts_contacted: Vec::new(),
        messages_sent: Vec::new(),
        approvals_asked: Vec::new(),
        approvals_answered: Vec::new(),
        could_not_verify: Vec::new(),
        tainted: false,
        receipt_error: false,
    };
    let mut unverified = false;
    for event in events {
        match event {
            ReceiptEvent::Run {
                run_id,
                agent,
                started,
                finished,
            } => {
                receipt.run_id = clean(run_id);
                receipt.agent = clean(agent);
                receipt.started = started.as_deref().map(clean);
                receipt.finished = finished.as_deref().map(clean);
            }
            ReceiptEvent::Status(status) => receipt.status = *status,
            ReceiptEvent::Usage {
                tokens_in,
                tokens_out,
                cost_cents,
            } => {
                receipt.tokens_in = receipt.tokens_in.saturating_add(*tokens_in);
                receipt.tokens_out = receipt.tokens_out.saturating_add(*tokens_out);
                receipt.cost_cents = receipt.cost_cents.saturating_add(*cost_cents);
            }
            ReceiptEvent::Tool { name, count } => {
                add_tool(&mut receipt.tools, name, *count);
            }
            ReceiptEvent::FileTouched(path) => {
                push_unique(&mut receipt.files_touched, clean_path(path))
            }
            ReceiptEvent::HostContacted(host) => {
                push_unique(&mut receipt.hosts_contacted, clean_host(host))
            }
            ReceiptEvent::Trigger(trigger) => receipt.trigger = Some(clean(trigger)),
            ReceiptEvent::Skill(skill) => push_unique(&mut receipt.skills, clean(skill)),
            ReceiptEvent::Replaced { kind, count } => {
                let value = receipt.replaced_values.entry(clean(kind)).or_default();
                *value = value.saturating_add(*count);
            }
            ReceiptEvent::MessageSent(target) => {
                push_unique(&mut receipt.messages_sent, clean(target))
            }
            ReceiptEvent::ApprovalAsked(tool) => {
                push_unique(&mut receipt.approvals_asked, clean(tool))
            }
            ReceiptEvent::ApprovalAnswered(answer) => {
                push_unique(&mut receipt.approvals_answered, clean(answer))
            }
            ReceiptEvent::CouldNotVerify(reason) => {
                unverified = true;
                push_unique(&mut receipt.could_not_verify, clean(reason));
            }
            ReceiptEvent::Tainted => receipt.tainted = true,
        }
    }
    if receipt.status == ReceiptStatus::Done && unverified {
        receipt.status = ReceiptStatus::DoneUnverified;
    }
    receipt
}

/// Fold one tool observation into the bounded tool map.
///
/// The first [`MAX_RECEIPT_TOOLS`] `- 1` distinct names get their own entry;
/// every further name is summed into [`RECEIPT_TOOLS_OVERFLOW`]. The rule
/// reads only the current map, so [`sanitize_receipt`] re-applying it is
/// idempotent: an already-bounded map never spills a previously named entry.
fn add_tool(tools: &mut BTreeMap<String, u32>, name: &str, count: u32) {
    let key = clean(name);
    if let Some(value) = tools.get_mut(&key) {
        *value = value.saturating_add(count);
        return;
    }
    let has_overflow = tools.contains_key(RECEIPT_TOOLS_OVERFLOW);
    let named = tools.len() - usize::from(has_overflow);
    if key == RECEIPT_TOOLS_OVERFLOW || named < MAX_RECEIPT_TOOLS - 1 {
        tools.insert(key, count);
        return;
    }
    let value = tools.entry(RECEIPT_TOOLS_OVERFLOW.to_string()).or_default();
    *value = value.saturating_add(count);
}

/// Re-apply receipt bounds and scrubbing at each external read boundary.
pub fn sanitize_receipt(receipt: &Receipt) -> Receipt {
    let mut events = vec![
        ReceiptEvent::Run {
            run_id: receipt.run_id.clone(),
            agent: receipt.agent.clone(),
            started: receipt.started.clone(),
            finished: receipt.finished.clone(),
        },
        ReceiptEvent::Status(receipt.status),
        ReceiptEvent::Usage {
            tokens_in: receipt.tokens_in,
            tokens_out: receipt.tokens_out,
            cost_cents: receipt.cost_cents,
        },
    ];
    if let Some(trigger) = &receipt.trigger {
        events.push(ReceiptEvent::Trigger(trigger.clone()));
    }
    events.extend(receipt.skills.iter().cloned().map(ReceiptEvent::Skill));
    events.extend(
        receipt
            .replaced_values
            .iter()
            .map(|(kind, count)| ReceiptEvent::Replaced {
                kind: kind.clone(),
                count: *count,
            }),
    );
    for (name, count) in &receipt.tools {
        events.push(ReceiptEvent::Tool {
            name: name.clone(),
            count: *count,
        });
    }
    events.extend(
        receipt
            .files_touched
            .iter()
            .cloned()
            .map(ReceiptEvent::FileTouched),
    );
    events.extend(
        receipt
            .hosts_contacted
            .iter()
            .cloned()
            .map(ReceiptEvent::HostContacted),
    );
    events.extend(
        receipt
            .messages_sent
            .iter()
            .cloned()
            .map(ReceiptEvent::MessageSent),
    );
    events.extend(
        receipt
            .approvals_asked
            .iter()
            .cloned()
            .map(ReceiptEvent::ApprovalAsked),
    );
    events.extend(
        receipt
            .approvals_answered
            .iter()
            .cloned()
            .map(ReceiptEvent::ApprovalAnswered),
    );
    events.extend(
        receipt
            .could_not_verify
            .iter()
            .cloned()
            .map(ReceiptEvent::CouldNotVerify),
    );
    if receipt.tainted {
        events.push(ReceiptEvent::Tainted);
    }
    let mut clean = build_receipt(&events);
    // The fallback flag is not derived from an event: carry it through the
    // re-boundary explicitly so a fallback row stays flagged on every read.
    clean.receipt_error = receipt.receipt_error;
    clean
}

fn clean(value: &str) -> String {
    let scrubbed = kernel_broker::scrub_external_preview(Path::new(""), value, MAX_RECEIPT_TEXT);
    if scrubbed.len() <= MAX_RECEIPT_TEXT {
        scrubbed
    } else {
        let mut end = MAX_RECEIPT_TEXT;
        while !scrubbed.is_char_boundary(end) {
            end -= 1;
        }
        scrubbed[..end].to_string()
    }
}

fn clean_path(value: &str) -> String {
    let path = Path::new(value);
    let relative = path.strip_prefix(Path::new(".")).unwrap_or(path);
    let normalized = if relative.is_absolute() {
        relative.file_name().map(PathBuf::from).unwrap_or_default()
    } else {
        relative.to_path_buf()
    };
    clean(&normalized.to_string_lossy())
}

pub(crate) fn clean_host(value: &str) -> String {
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|end| &authority[..=end])
            .unwrap_or(authority)
    } else {
        authority.split(':').next().unwrap_or("")
    };
    clean(host)
}

/// Retention ceiling for the `run.finished` journal: keep the newest rows
/// **per agent** and the most recent days, whichever retains **fewer** rows.
pub const RECEIPT_RETENTION_ROWS: i64 = 5_000;
pub const RECEIPT_RETENTION_DAYS: i64 = 90;

/// The local wall clock a receipt displays (`started`/`finished`). Display
/// only: attribution never compares these strings, because at a DST fall-back
/// (or any backward clock adjustment) `finished` can sort before `started`.
pub fn local_timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Identity of one turn's run, unique across the store.
///
/// A receipt attributes spend by this identity, never by a shared row-id
/// window over `usage`: two overlapping turns of the same agent each own
/// their own rows.
pub fn new_run_id(thread_id: i64) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    // A process-local sequence makes two turns started in the same nanosecond
    // distinct; the process id and timestamp keep ids apart across daemon
    // restarts.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("turn-{thread_id}-{}-{nanos}-{seq}", std::process::id())
}

/// The session a [`new_run_id`] was minted for.
pub fn run_thread(run_id: &str) -> Option<i64> {
    run_id
        .strip_prefix("turn-")?
        .split('-')
        .next()?
        .parse()
        .ok()
}

/// Monotonic cursor bounding one turn's approval window.
///
/// The local `started`/`finished` display strings can reverse at a DST
/// fall-back; the append-only `events.id` window cannot. Approval rows are
/// additionally filtered by `thread_id`, and one thread runs one turn at a
/// time, so the window covers exactly this turn's rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiptCursor {
    pub events_id: i64,
}

/// Read the current high-water mark of the append-only `events` table. A
/// missing or unreadable store yields an all-zero cursor, which leaves the
/// matching window empty rather than unbounded.
pub fn cursor_mark(db_path: &Path) -> ReceiptCursor {
    let Ok(conn) = aux_store::open_keyed_readonly(db_path) else {
        return ReceiptCursor::default();
    };
    let events_id: i64 = conn
        .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    ReceiptCursor { events_id }
}

/// Usage recorded under one turn identity (`run_id`), regardless of agent or
/// day. Attribution is by identity, so two overlapping turns of the same
/// agent can never claim each other's spend, and a turn with no rows reports
/// honest zeros instead of borrowing another turn's.
pub fn usage_for_run(db_path: &Path, run_id: &str) -> Option<ReceiptEvent> {
    let conn = aux_store::open_keyed_readonly(db_path).ok()?;
    let (tokens_in, tokens_out, cost): (i64, i64, i64) = conn
        .query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN kind = 'tokens_in' THEN amount END), 0),
                 COALESCE(SUM(CASE WHEN kind = 'tokens_out' THEN amount END), 0),
                 COALESCE(SUM(CASE WHEN kind = 'usd_cents' THEN amount END), 0)
             FROM usage WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .ok()?;
    Some(ReceiptEvent::Usage {
        tokens_in: tokens_in.max(0) as u64,
        tokens_out: tokens_out.max(0) as u64,
        cost_cents: cost.max(0) as u64,
    })
}

/// Persist the already-built receipt in the existing activity journal, then
/// prune the journal back under [`RECEIPT_RETENTION_ROWS`] /
/// [`RECEIPT_RETENTION_DAYS`].
///
/// The write is idempotent by `run_id` at the store level
/// ([`aux_store::Store::log_run_finished_once`]): a run keeps **at most one**
/// `run.finished` row, so a retry after an error whose insert nevertheless
/// took effect is a no-op, and a later fallback cannot add a second row.
pub fn persist_receipt(db_path: &Path, receipt: &Receipt) -> anyhow::Result<()> {
    let payload = serde_json::to_string(receipt)?;
    let store = aux_store::Store::open(db_path)?;
    store.log_run_finished_once(&receipt.run_id, &payload)?;
    prune_receipts(&store);
    Ok(())
}

/// Apply the run-receipt retention ceilings to an open store. Best-effort:
/// a failed prune must never fail the write that triggered it.
pub fn prune_receipts(store: &aux_store::Store) {
    if let Err(err) = store.prune_run_receipts(RECEIPT_RETENTION_ROWS, RECEIPT_RETENTION_DAYS) {
        tracing::warn!(error = %err, "could not prune run receipts");
    }
}

/// How long to wait before the single bounded retry of a receipt write.
///
/// Short by design: a transient SQLite busy/lock error usually clears within a
/// scheduler tick, and the turn must not wait on a receipt. The retry is one
/// attempt only, so the total added latency is bounded.
pub const RECEIPT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Persist a receipt, retrying exactly once after [`RECEIPT_RETRY_DELAY`].
///
/// A receipt write is best-effort: it must never fail the turn. The retry
/// gives a transient journal error (busy/locked) one chance to clear; when the
/// second attempt also fails, the first error is returned so the caller can
/// emit the live signal and write the minimal fallback row. The write itself
/// is idempotent by `run_id`, so a retry whose first insert actually took
/// effect cannot append a duplicate receipt.
pub fn persist_receipt_retry(db_path: &Path, receipt: &Receipt) -> anyhow::Result<()> {
    match write_receipt_row(db_path, receipt) {
        Ok(()) => Ok(()),
        Err(first) => {
            std::thread::sleep(RECEIPT_RETRY_DELAY);
            match write_receipt_row(db_path, receipt) {
                Ok(()) => Ok(()),
                Err(_) => Err(first),
            }
        }
    }
}

/// One receipt write, through the (test-only) seam. `persist_receipt` is the
/// production write; a test can replace it to inject a transient or persistent
/// journal failure without a real I/O fault.
fn write_receipt_row(db_path: &Path, receipt: &Receipt) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        if let Some(result) = test_seam::next() {
            return result;
        }
    }
    persist_receipt(db_path, receipt)
}

/// Write the minimal fallback `run.finished` row when the full receipt could
/// not be persisted.
///
/// The row keeps only identity, status and timestamps, and is flagged
/// [`Receipt::receipt_error`], so the activity list still shows the finished
/// run even though its detail could not be written. This write deliberately
/// bypasses [`persist_receipt_retry`]'s seam: the fallback exists for a
/// corrupted or oversized full payload, not for a broken store.
///
/// The rule is **first-write-wins**: at most one `run.finished` row per
/// `run_id`, so this is a no-op when the run already has a full receipt (its
/// insert took effect even if it reported an error), and a later full receipt
/// is likewise skipped while the fallback row stands.
pub fn persist_fallback_receipt(db_path: &Path, receipt: &Receipt) -> anyhow::Result<()> {
    let fallback = fallback_receipt(receipt);
    let payload = serde_json::to_string(&fallback)?;
    let store = aux_store::Store::open(db_path)?;
    store.log_run_finished_once(&fallback.run_id, &payload)?;
    prune_receipts(&store);
    Ok(())
}

/// The bounded fallback row: no usage, tools, files or approvals.
pub fn fallback_receipt(receipt: &Receipt) -> Receipt {
    let mut fallback = build_receipt(&[
        ReceiptEvent::Run {
            run_id: receipt.run_id.clone(),
            agent: receipt.agent.clone(),
            started: receipt.started.clone(),
            finished: receipt.finished.clone(),
        },
        ReceiptEvent::Status(receipt.status),
    ]);
    if let Some(trigger) = &receipt.trigger {
        fallback.trigger = Some(clean(trigger));
    }
    fallback.skills = receipt.skills.iter().map(|skill| clean(skill)).collect();
    fallback.hosts_contacted = receipt
        .hosts_contacted
        .iter()
        .map(|host| clean_host(host))
        .collect();
    fallback.replaced_values = receipt
        .replaced_values
        .iter()
        .map(|(kind, count)| (clean(kind), *count))
        .collect();
    fallback.receipt_error = true;
    fallback
}

/// Test-only injection point for [`write_receipt_row`].
///
/// A closure returns `Some(result)` to replace the write for one attempt, or
/// `None` to fall through to the real journal write. Thread-local so parallel
/// tests never share an injected failure.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::RefCell;

    type Writer = Box<dyn FnMut() -> Option<anyhow::Result<()>>>;

    thread_local! {
        static WRITE: RefCell<Option<Writer>> = const { RefCell::new(None) };
    }

    /// Install the per-attempt writer replacement for the current thread.
    pub(crate) fn set(writer: impl FnMut() -> Option<anyhow::Result<()>> + 'static) {
        WRITE.with(|slot| *slot.borrow_mut() = Some(Box::new(writer)));
    }

    /// Remove any installed replacement.
    pub(crate) fn clear() {
        WRITE.with(|slot| *slot.borrow_mut() = None);
    }

    /// The next replacement result, or `None` to do the real write.
    pub(crate) fn next() -> Option<anyhow::Result<()>> {
        WRITE.with(|slot| slot.borrow_mut().as_mut().and_then(|writer| writer()))
    }
}

/// Approval facts for one turn identity (`run_id`): the asks this turn wrote,
/// plus their answers, and any usage-settlement failure it recorded.
///
/// Attribution is by identity: the `approval.pending` rows are selected by the
/// turn's own `run_id`, never by a row-id window that a second overlapping
/// turn of the same thread could also fall inside. The row-id window only
/// bounds the scan. An answer is matched to this turn's ask by its approval
/// id, so another turn's answer can never be borrowed either.
///
/// `completed` is whether the turn reached its normal end. A denied or
/// timed-out approval only means the run still needs its owner when the turn
/// did **not** complete: a turn that finished after a denial keeps `Done`.
///
/// This is also the one per-run journal reader both receipt writers already
/// call, so the usage-settlement marker (P3) rides here: a settle that failed
/// must surface as `could_not_verify` on the receipt rather than imply usage
/// settled at zero.
pub fn approvals_for_run(
    db_path: &Path,
    run_id: &str,
    from: ReceiptCursor,
    to: ReceiptCursor,
    completed: bool,
) -> Vec<ReceiptEvent> {
    let Ok(conn) = aux_store::open_keyed_readonly(db_path) else {
        return Vec::new();
    };
    let mut pending = std::collections::BTreeMap::<String, String>::new();
    let mut tainted = false;
    if let Ok(mut stmt) = conn.prepare(
        "SELECT payload FROM events
         WHERE kind='approval.pending' AND id > ?1 AND id <= ?2
           AND json_extract(payload, '$.run_id') = ?3",
    ) {
        if let Ok(rows) = stmt.query_map(
            rusqlite::params![from.events_id, to.events_id, run_id],
            |row| row.get::<_, String>(0),
        ) {
            for raw in rows.flatten() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if value.get("tainted").and_then(serde_json::Value::as_bool) == Some(true) {
                        tainted = true;
                    }
                    if let (Some(id), Some(tool)) = (
                        value.get("id").and_then(serde_json::Value::as_str),
                        value.get("tool").and_then(serde_json::Value::as_str),
                    ) {
                        pending.insert(id.to_string(), tool.to_string());
                    }
                }
            }
        }
    }
    let mut events = Vec::new();
    for tool in pending.values() {
        events.push(ReceiptEvent::ApprovalAsked(tool.clone()));
    }
    if tainted {
        events.push(ReceiptEvent::Tainted);
    }
    if !pending.is_empty() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT payload FROM events WHERE kind='approval.answered' AND id > ?1 AND id <= ?2",
        ) {
            if let Ok(rows) = stmt
                .query_map(rusqlite::params![from.events_id, to.events_id], |row| {
                    row.get::<_, String>(0)
                })
            {
                for raw in rows.flatten() {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                        let id = value.get("id").and_then(serde_json::Value::as_str);
                        let decision = value
                            .get("decision")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown");
                        if let Some(tool) = id.and_then(|id| pending.get(id)) {
                            events.push(ReceiptEvent::ApprovalAnswered(format!(
                                "{tool}: {decision}"
                            )));
                            if matches!(decision, "deny" | "timeout") && !completed {
                                events.push(ReceiptEvent::Status(ReceiptStatus::PausedNeedsYou));
                            }
                        }
                    }
                }
            }
        }
    }
    events.extend(usage_settle_failures_for_run(db_path, run_id, from, to));
    events
}

/// A usage-settlement failure this run recorded (P3).
///
/// When the ACP settle could not write its fixed cost — for example an
/// out-of-range estimate — the journal carries a `usage.settle_failed` marker
/// under the turn's `run_id`. The receipt must say usage could not be verified
/// rather than imply it settled at zero.
fn usage_settle_failures_for_run(
    db_path: &Path,
    run_id: &str,
    from: ReceiptCursor,
    to: ReceiptCursor,
) -> Vec<ReceiptEvent> {
    let Ok(conn) = aux_store::open_keyed_readonly(db_path) else {
        return Vec::new();
    };
    let mut events = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT payload FROM events
         WHERE kind='usage.settle_failed' AND id > ?1 AND id <= ?2
           AND json_extract(payload, '$.run_id') = ?3",
    ) {
        if let Ok(rows) = stmt.query_map(
            rusqlite::params![from.events_id, to.events_id, run_id],
            |row| row.get::<_, String>(0),
        ) {
            for raw in rows.flatten() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let reason = value
                        .get("reason")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("settling the turn's usage failed");
                    events.push(ReceiptEvent::CouldNotVerify(format!(
                        "usage could not be verified: {reason}"
                    )));
                }
            }
        }
    }
    events
}

/// Read newest persisted receipts, optionally filtered by agent.
pub fn read_receipts(
    db_path: &Path,
    agent: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<Receipt>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    read_receipts_from(db_path, agent, limit, false)
}

/// [`read_receipts`] without its shortcuts: a store that is not there, cannot
/// be opened, or holds a `run.finished` row that does not decode is an error,
/// never a shorter or empty list.
pub fn read_receipts_strict(
    db_path: &Path,
    agent: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<Receipt>> {
    read_receipts_from(db_path, agent, limit, true)
}

fn read_receipts_from(
    db_path: &Path,
    agent: Option<&str>,
    limit: i64,
    strict: bool,
) -> anyhow::Result<Vec<Receipt>> {
    let conn = aux_store::open_keyed_readonly(db_path)?;
    let sql = if agent.is_some() {
        "SELECT payload FROM events WHERE kind='run.finished' AND json_extract(payload, '$.agent')=?1 ORDER BY id DESC LIMIT ?2"
    } else {
        "SELECT payload FROM events WHERE kind='run.finished' ORDER BY id DESC LIMIT ?1"
    };
    let mut stmt = conn.prepare(sql)?;
    let payloads: Vec<String> = if let Some(agent) = agent {
        stmt.query_map(rusqlite::params![agent, limit], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<_, _>>()?
    } else {
        stmt.query_map([limit], |row| row.get::<_, String>(0))?
            .collect::<Result<_, _>>()?
    };
    let mut out = Vec::new();
    for payload in payloads {
        let receipt = match serde_json::from_str::<Receipt>(&payload) {
            Ok(receipt) => sanitize_receipt(&receipt),
            Err(err) if strict => anyhow::bail!("a run.finished row does not decode: {err}"),
            Err(_) => continue,
        };
        if agent.is_none_or(|wanted| wanted == receipt.agent) {
            out.push(receipt);
        }
    }
    Ok(out)
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if list.len() < MAX_RECEIPT_ITEMS && !list.contains(&item) {
        list.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Vec<ReceiptEvent> {
        vec![ReceiptEvent::Run {
            run_id: "turn-7".into(),
            agent: "main".into(),
            started: Some("2026-10-07 09:00:00".into()),
            finished: Some("2026-10-07 09:00:02".into()),
        }]
    }

    #[test]
    fn success_receipt_is_plain_bounded_data() {
        let mut events = base();
        events.extend([
            ReceiptEvent::Usage {
                tokens_in: 12,
                tokens_out: 7,
                cost_cents: 1,
            },
            ReceiptEvent::Tool {
                name: "read_file".into(),
                count: 1,
            },
        ]);
        let r = build_receipt(&events);
        assert_eq!(r.status, ReceiptStatus::Done);
        assert_eq!((r.tokens_in, r.tokens_out, r.cost_cents), (12, 7, 1));
        assert_eq!(r.tools["read_file"], 1);
    }

    #[test]
    fn tool_error_is_done_unverified() {
        let mut events = base();
        events.push(ReceiptEvent::CouldNotVerify(
            "tool returned an error".into(),
        ));
        assert_eq!(build_receipt(&events).status, ReceiptStatus::DoneUnverified);
    }

    #[test]
    fn budget_stop_is_preserved() {
        let mut events = base();
        events.push(ReceiptEvent::Status(ReceiptStatus::StoppedBudget));
        assert_eq!(build_receipt(&events).status, ReceiptStatus::StoppedBudget);
    }

    #[test]
    fn denied_approval_needs_owner() {
        let mut events = base();
        events.extend([
            ReceiptEvent::ApprovalAsked("shell".into()),
            ReceiptEvent::ApprovalAnswered("denied".into()),
            ReceiptEvent::Status(ReceiptStatus::PausedNeedsYou),
        ]);
        let r = build_receipt(&events);
        assert_eq!(r.status, ReceiptStatus::PausedNeedsYou);
        assert_eq!(r.approvals_answered, ["denied"]);
    }

    #[test]
    fn display_clock_and_meter_clock_agree_in_every_timezone() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = aux_store::Store::open(&db).unwrap();
        // The meter stamps `at` with SQLite's local clock; the display strings
        // are built with the receipt clock. They must agree in every timezone,
        // not only UTC, so this fails if the display is stamped in UTC on a
        // non-UTC box.
        let started = local_timestamp();
        let run_id = new_run_id(7);
        store
            .record_usage_for(
                &run_id,
                "main",
                kernel_core::budget::UsageKind::TokensIn,
                12,
                "tokens",
            )
            .unwrap();
        let finished = local_timestamp();

        let row_at: String = aux_store::open_keyed(&db)
            .unwrap()
            .query_row("SELECT at FROM usage ORDER BY id LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            started <= row_at && row_at <= finished,
            "meter clock {row_at} is not inside the display window [{started}, {finished}]"
        );
        assert_eq!(
            usage_for_run(&db, &run_id),
            Some(ReceiptEvent::Usage {
                tokens_in: 12,
                tokens_out: 0,
                cost_cents: 0,
            })
        );
    }

    #[test]
    #[cfg(feature = "acp")]
    fn an_unlimited_acp_turn_receipt_carries_its_fixed_cost() {
        // P2-A end to end: an ACP turn on an `unlimited` agent takes no store
        // reservation, yet its fixed per-turn cost must still land in its
        // receipt under its own run identity.
        use aux_acp::ledger::{StoreTurnHost, TurnHost};
        use aux_acp::UsageUpdate;
        use kernel_core::budget::Budgets;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = Arc::new(Mutex::new(aux_store::Store::open(&db).unwrap()));
        let session = kernel_core::lock_recover(&store)
            .create_session("main", Some("acp receipt"))
            .unwrap();
        let run_id = new_run_id(session.id);
        let mut budgets = Budgets::default();
        budgets.default.unlimited = true;
        let mut host = StoreTurnHost::new(
            Arc::clone(&store),
            "main".to_string(),
            session.id,
            budgets,
            None,
        )
        .with_run_id(run_id.clone());

        let reservation = host.reserve_turn(10).unwrap();
        assert!(
            reservation.is_none(),
            "unlimited budgets place no store reservation"
        );
        host.settle_turn(None, &UsageUpdate::default()).unwrap();

        assert_eq!(
            usage_for_run(&db, &run_id),
            Some(ReceiptEvent::Usage {
                tokens_in: 0,
                tokens_out: 0,
                cost_cents: 10,
            }),
            "the fixed cost must reach an unlimited ACP turn's receipt"
        );
    }

    #[test]
    fn overlapping_turns_of_one_agent_each_own_their_usage() {
        use kernel_core::budget::UsageKind;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = aux_store::Store::open(&db).unwrap();
        let run_a = new_run_id(1);
        let run_b = new_run_id(1);
        assert_ne!(run_a, run_b, "two turns must not share an identity");

        // The two turns' rows interleave, the way two overlapping turns of the
        // same agent would write them: each receipt may claim only its own.
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
        store
            .record_usage_for(&run_a, "main", UsageKind::UsdCents, 1, "cents")
            .unwrap();
        store
            .record_usage_for(&run_b, "main", UsageKind::UsdCents, 9, "cents")
            .unwrap();

        assert_eq!(
            usage_for_run(&db, &run_a),
            Some(ReceiptEvent::Usage {
                tokens_in: 12,
                tokens_out: 7,
                cost_cents: 1,
            })
        );
        assert_eq!(
            usage_for_run(&db, &run_b),
            Some(ReceiptEvent::Usage {
                tokens_in: 100,
                tokens_out: 200,
                cost_cents: 9,
            })
        );

        // An unstamped legacy row is never borrowed by either turn.
        store
            .record_usage("main", UsageKind::TokensIn, 500, "tokens")
            .unwrap();
        assert_eq!(
            usage_for_run(&db, &run_a),
            Some(ReceiptEvent::Usage {
                tokens_in: 12,
                tokens_out: 7,
                cost_cents: 1,
            })
        );
    }

    #[test]
    fn a_turn_with_no_usage_reports_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let _store = aux_store::Store::open(&db).unwrap();
        assert_eq!(
            usage_for_run(&db, &new_run_id(9)),
            Some(ReceiptEvent::Usage {
                tokens_in: 0,
                tokens_out: 0,
                cost_cents: 0,
            })
        );
    }

    #[test]
    fn failed_turn_reports_its_own_partial_usage() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = aux_store::Store::open(&db).unwrap();
        let run_id = new_run_id(11);
        // A provider call completed before the turn failed or was cancelled.
        store
            .record_usage_for(
                &run_id,
                "main",
                kernel_core::budget::UsageKind::TokensIn,
                34,
                "tokens",
            )
            .unwrap();
        let mut events = vec![
            ReceiptEvent::Run {
                run_id: run_id.clone(),
                agent: "main".into(),
                started: None,
                finished: None,
            },
            ReceiptEvent::Status(ReceiptStatus::Failed),
            ReceiptEvent::CouldNotVerify("provider dropped the stream".into()),
        ];
        events.extend(usage_for_run(&db, &run_id));
        let receipt = build_receipt(&events);
        assert_eq!(receipt.status, ReceiptStatus::Failed);
        assert_eq!(
            (receipt.tokens_in, receipt.tokens_out, receipt.cost_cents),
            (34, 0, 0)
        );
    }

    #[test]
    fn dst_fall_back_keeps_its_own_usage_and_approvals() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = aux_store::Store::open(&db).unwrap();

        // A turn that starts at the first 02:50 and finishes at the second
        // 02:10 (after a fall-back). The display strings reverse; the event
        // row-id window and the run identity must not.
        let started = "2026-11-01 02:50:00";
        let finished = "2026-11-01 02:10:00";
        assert!(
            finished < started,
            "the simulated fall-back must reverse the clock text"
        );

        let run_id = new_run_id(7);
        let start = cursor_mark(&db);
        store
            .record_usage_for(
                &run_id,
                "main",
                kernel_core::budget::UsageKind::TokensIn,
                12,
                "tokens",
            )
            .unwrap();
        store
            .record_usage_for(
                &run_id,
                "main",
                kernel_core::budget::UsageKind::TokensOut,
                7,
                "tokens",
            )
            .unwrap();
        store
            .record_usage_for(
                &run_id,
                "main",
                kernel_core::budget::UsageKind::UsdCents,
                1,
                "cents",
            )
            .unwrap();
        store
            .log_event(
                "approval.pending",
                &format!(r#"{{"thread_id":7,"id":"a1","tool":"shell","run_id":"{run_id}"}}"#),
            )
            .unwrap();
        store
            .log_event("approval.answered", r#"{"id":"a1","decision":"deny"}"#)
            .unwrap();
        let end = cursor_mark(&db);

        assert_eq!(
            usage_for_run(&db, &run_id),
            Some(ReceiptEvent::Usage {
                tokens_in: 12,
                tokens_out: 7,
                cost_cents: 1,
            })
        );

        let mut events = vec![
            ReceiptEvent::Run {
                run_id: run_id.clone(),
                agent: "main".into(),
                started: Some(started.into()),
                finished: Some(finished.into()),
            },
            ReceiptEvent::Usage {
                tokens_in: 12,
                tokens_out: 7,
                cost_cents: 1,
            },
        ];
        events.extend(approvals_for_run(&db, &run_id, start, end, false));
        let receipt = build_receipt(&events);
        assert_eq!(receipt.approvals_answered, ["shell: deny"]);
        assert_eq!(receipt.status, ReceiptStatus::PausedNeedsYou);
        // Local strings stay for display even though they reverse.
        assert_eq!(receipt.started.as_deref(), Some(started));
        assert_eq!(receipt.finished.as_deref(), Some(finished));
    }

    #[test]
    fn completed_turn_with_a_denied_approval_stays_done() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = aux_store::Store::open(&db).unwrap();
        let run_id = new_run_id(7);
        let start = cursor_mark(&db);
        store
            .log_event(
                "approval.pending",
                &format!(r#"{{"thread_id":7,"id":"a1","tool":"shell","run_id":"{run_id}"}}"#),
            )
            .unwrap();
        store
            .log_event("approval.answered", r#"{"id":"a1","decision":"deny"}"#)
            .unwrap();
        let end = cursor_mark(&db);

        let mut completed = vec![ReceiptEvent::Status(ReceiptStatus::Done)];
        completed.extend(approvals_for_run(&db, &run_id, start, end, true));
        let r = build_receipt(&completed);
        assert_eq!(r.status, ReceiptStatus::Done);
        assert_eq!(r.approvals_answered, ["shell: deny"]);

        let mut unfinished = vec![ReceiptEvent::Status(ReceiptStatus::Failed)];
        unfinished.extend(approvals_for_run(&db, &run_id, start, end, false));
        assert_eq!(
            build_receipt(&unfinished).status,
            ReceiptStatus::PausedNeedsYou
        );
    }

    #[test]
    fn overlapping_turns_of_one_thread_keep_their_own_approvals() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = aux_store::Store::open(&db).unwrap();
        let run_a = new_run_id(7);
        let run_b = new_run_id(7);
        let start = cursor_mark(&db);
        // Two overlapping turns of the *same thread*: before the run identity,
        // each turn's row-id window contained the other's ask and each receipt
        // claimed both.
        store
            .log_event(
                "approval.pending",
                &format!(r#"{{"thread_id":7,"id":"a1","tool":"shell","run_id":"{run_a}"}}"#),
            )
            .unwrap();
        store
            .log_event(
                "approval.pending",
                &format!(r#"{{"thread_id":7,"id":"b1","tool":"write_file","run_id":"{run_b}"}}"#),
            )
            .unwrap();
        store
            .log_event("approval.answered", r#"{"id":"a1","decision":"allow"}"#)
            .unwrap();
        store
            .log_event("approval.answered", r#"{"id":"b1","decision":"deny"}"#)
            .unwrap();
        let end = cursor_mark(&db);

        let a = approvals_for_run(&db, &run_a, start, end, true);
        let b = approvals_for_run(&db, &run_b, start, end, true);
        let a = build_receipt(&a);
        let b = build_receipt(&b);
        assert_eq!(a.approvals_asked, ["shell"]);
        assert_eq!(a.approvals_answered, ["shell: allow"]);
        assert_eq!(b.approvals_asked, ["write_file"]);
        assert_eq!(b.approvals_answered, ["write_file: deny"]);
    }

    #[test]
    fn tools_overflow_into_a_single_bucket_and_stay_bounded() {
        let mut events = base();
        for n in 0..100 {
            events.push(ReceiptEvent::Tool {
                name: format!("tool_{n:03}"),
                count: 1,
            });
        }
        let receipt = build_receipt(&events);
        assert_eq!(receipt.tools.len(), MAX_RECEIPT_TOOLS);
        assert_eq!(
            receipt.tools[RECEIPT_TOOLS_OVERFLOW],
            100 - (MAX_RECEIPT_TOOLS as u32 - 1)
        );
        let total: u32 = receipt.tools.values().sum();
        assert_eq!(total, 100, "no tool observation is lost");

        // Re-applying the bound (every external read) must not re-shuffle an
        // already-bounded map.
        assert_eq!(sanitize_receipt(&receipt).tools, receipt.tools);
    }

    #[test]
    fn a_tool_named_other_shares_the_overflow_bucket() {
        let mut events = base();
        events.push(ReceiptEvent::Tool {
            name: RECEIPT_TOOLS_OVERFLOW.into(),
            count: 2,
        });
        for n in 0..MAX_RECEIPT_TOOLS {
            events.push(ReceiptEvent::Tool {
                name: format!("tool_{n:03}"),
                count: 1,
            });
        }
        let receipt = build_receipt(&events);
        assert!(receipt.tools.len() <= MAX_RECEIPT_TOOLS);
        assert_eq!(receipt.tools[RECEIPT_TOOLS_OVERFLOW], 2 + 1);
    }

    #[test]
    fn web_hosts_are_listed_without_paths_or_arguments() {
        let mut events = base();
        events.extend([
            ReceiptEvent::Tool {
                name: "web.fetch".into(),
                count: 2,
            },
            ReceiptEvent::HostContacted(
                "https://user:sk-live-0123456789abcdefghijkl@example.com:443/private?q=secret"
                    .into(),
            ),
        ]);
        let r = build_receipt(&events);
        assert_eq!(r.hosts_contacted, ["example.com"]);
        assert_eq!(r.tools["web.fetch"], 2);
    }

    #[test]
    fn receipt_records_trigger_and_replacement_counts_without_values() {
        let events = [
            ReceiptEvent::Trigger("owner_message".into()),
            ReceiptEvent::Replaced {
                kind: "email".into(),
                count: 2,
            },
            ReceiptEvent::Replaced {
                kind: "email".into(),
                count: 1,
            },
        ];
        let receipt = build_receipt(&events);
        let json = serde_json::to_string(&receipt).unwrap();
        assert_eq!(receipt.trigger.as_deref(), Some("owner_message"));
        assert_eq!(receipt.replaced_values.get("email"), Some(&3));
        assert!(!json.contains("owner@example.test"));
    }

    #[test]
    fn old_receipt_rows_keep_new_fields_absent() {
        let old = r#"{"run_id":"old","agent":"scout","started":null,"finished":null,"status":"done","tokens_in":0,"tokens_out":0,"cost_cents":0,"tools":{},"files_touched":[],"hosts_contacted":[],"messages_sent":[],"approvals_asked":[],"approvals_answered":[],"could_not_verify":[],"tainted":false}"#;
        let receipt: Receipt = serde_json::from_str(old).unwrap();
        assert_eq!(receipt.trigger, None);
        assert!(receipt.skills.is_empty());
        assert!(receipt.replaced_values.is_empty());
    }

    #[test]
    fn tainted_turn_is_flagged() {
        let mut events = base();
        events.push(ReceiptEvent::Tainted);
        assert!(build_receipt(&events).tainted);
    }

    #[test]
    fn secret_looking_text_is_scrubbed() {
        let mut events = base();
        events.push(ReceiptEvent::CouldNotVerify(
            "failed with sk-live-0123456789abcdefghijkl".into(),
        ));
        let r = build_receipt(&events);
        assert!(!r.could_not_verify[0].contains("sk-live-0123456789abcdefghijkl"));
    }

    #[test]
    fn a_fallback_row_is_flagged_and_survives_the_read_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let _store = aux_store::Store::open(&db).unwrap();
        let mut facts = base();
        facts.extend([
            ReceiptEvent::Trigger("owner_message".into()),
            ReceiptEvent::Skill("research".into()),
            ReceiptEvent::Replaced {
                kind: "email".into(),
                count: 2,
            },
            ReceiptEvent::HostContacted("https://user:secret@example.test/private?q=secret".into()),
        ]);
        let full = build_receipt(&facts);
        persist_fallback_receipt(&db, &full).unwrap();

        let receipts = read_receipts(&db, Some("main"), 10).unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].receipt_error, "the fallback stays flagged");
        assert_eq!(receipts[0].run_id, "turn-7");
        assert_eq!(receipts[0].agent, "main");
        assert_eq!(
            (
                receipts[0].tokens_in,
                receipts[0].tokens_out,
                receipts[0].cost_cents
            ),
            (0, 0, 0),
            "the fallback carries no usage detail"
        );
        assert!(receipts[0].tools.is_empty());
        assert_eq!(receipts[0].trigger.as_deref(), Some("owner_message"));
        assert_eq!(receipts[0].skills, ["research"]);
        assert_eq!(receipts[0].replaced_values.get("email"), Some(&2));
        assert_eq!(receipts[0].hosts_contacted, ["example.test"]);
    }

    #[test]
    #[cfg(feature = "acp")]
    fn a_failed_acp_settle_marks_usage_could_not_verify() {
        // P3 end to end: an out-of-range estimate makes the ACP settle fail
        // after the turn was admitted. The failed settle must be recorded
        // under the run so its receipt says usage could not be verified.
        use aux_acp::ledger::{StoreTurnHost, TurnHost};
        use aux_acp::UsageUpdate;
        use kernel_core::budget::Budgets;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = Arc::new(Mutex::new(aux_store::Store::open(&db).unwrap()));
        let session = kernel_core::lock_recover(&store)
            .create_session("main", Some("acp settle"))
            .unwrap();
        let run_id = new_run_id(session.id);
        let mut host = StoreTurnHost::new(
            Arc::clone(&store),
            "main".to_string(),
            session.id,
            Budgets::default(),
            None,
        )
        .with_run_id(run_id.clone());

        let start = cursor_mark(&db);
        let reservation = host.reserve_turn(10).unwrap().unwrap();
        // The store refuses every new usage row: the settle fails.
        aux_store::open_keyed(&db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_usage BEFORE INSERT ON usage
                 BEGIN SELECT RAISE(ABORT, 'usage refused'); END;",
            )
            .unwrap();
        assert!(
            host.settle_turn(Some(reservation), &UsageUpdate::default())
                .is_err(),
            "a refused usage row must fail the settle"
        );
        let end = cursor_mark(&db);

        let mut facts = vec![ReceiptEvent::Status(ReceiptStatus::Failed)];
        facts.extend(approvals_for_run(&db, &run_id, start, end, false));
        let receipt = build_receipt(&facts);
        assert!(
            receipt
                .could_not_verify
                .iter()
                .any(|message| message.starts_with("usage could not be verified")),
            "a failed settle must mark usage unverified: {:?}",
            receipt.could_not_verify
        );
    }

    /// Clears the receipt test seam even if an assertion unwinds first.
    struct SeamReset;

    impl Drop for SeamReset {
        fn drop(&mut self) {
            test_seam::clear();
        }
    }

    /// A full receipt with usage detail, so a test can tell it apart from the
    /// minimal fallback row written for the same run.
    fn full_receipt(run_id: &str, tokens_in: u64) -> Receipt {
        build_receipt(&[
            ReceiptEvent::Run {
                run_id: run_id.into(),
                agent: "main".into(),
                started: Some("2026-10-07 09:00:00".into()),
                finished: Some("2026-10-07 09:00:02".into()),
            },
            ReceiptEvent::Usage {
                tokens_in,
                tokens_out: 0,
                cost_cents: 0,
            },
        ])
    }

    #[test]
    fn a_retry_after_a_taken_effect_error_leaves_one_full_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let _store = aux_store::Store::open(&db).unwrap();
        let receipt = full_receipt("turn-7", 12);

        // The first attempt really persists the row and then reports an error,
        // as when an insert committed but its acknowledgement was lost. The
        // retry must see the existing row and leave exactly one full receipt.
        let seam_db = db.clone();
        let seam_receipt = receipt.clone();
        let mut first = true;
        test_seam::set(move || {
            if first {
                first = false;
                persist_receipt(&seam_db, &seam_receipt).unwrap();
                return Some(Err(anyhow::anyhow!(
                    "injected: insert took effect but reported an error"
                )));
            }
            None
        });
        let _reset = SeamReset;

        persist_receipt_retry(&db, &receipt).unwrap();

        let receipts = read_receipts(&db, Some("main"), 10).unwrap();
        assert_eq!(
            receipts.len(),
            1,
            "the retry must not duplicate the receipt"
        );
        assert_eq!(receipts[0].run_id, "turn-7");
        assert!(
            !receipts[0].receipt_error,
            "the full receipt is the one row"
        );
        assert_eq!(receipts[0].tokens_in, 12, "the full detail survived");
    }

    #[test]
    fn double_persist_of_one_receipt_leaves_one_row() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let _store = aux_store::Store::open(&db).unwrap();
        let receipt = full_receipt("turn-7", 12);

        persist_receipt(&db, &receipt).unwrap();
        persist_receipt(&db, &receipt).unwrap();

        let receipts = read_receipts(&db, Some("main"), 10).unwrap();
        assert_eq!(receipts.len(), 1, "at most one run.finished row per run_id");
        assert!(!receipts[0].receipt_error);
    }

    #[test]
    fn a_fallback_after_a_successful_write_adds_no_second_row() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let _store = aux_store::Store::open(&db).unwrap();
        let full = full_receipt("turn-7", 12);

        persist_receipt(&db, &full).unwrap();
        persist_fallback_receipt(&db, &full).unwrap();

        let receipts = read_receipts(&db, Some("main"), 10).unwrap();
        assert_eq!(receipts.len(), 1, "the full receipt already covers the run");
        assert!(
            !receipts[0].receipt_error,
            "the full row is kept, not replaced"
        );
    }

    #[test]
    fn a_later_full_receipt_does_not_replace_an_existing_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let _store = aux_store::Store::open(&db).unwrap();
        let full = full_receipt("turn-7", 12);

        persist_fallback_receipt(&db, &full).unwrap();
        persist_receipt(&db, &full).unwrap();

        let receipts = read_receipts(&db, Some("main"), 10).unwrap();
        assert_eq!(receipts.len(), 1, "first-write-wins keeps one row");
        assert!(receipts[0].receipt_error, "the fallback row stands");
    }

    #[test]
    fn parallel_runs_isolate_an_injected_failure() {
        use std::collections::BTreeMap;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let _store = aux_store::Store::open(&db).unwrap();
        let healthy = full_receipt("turn-healthy", 12);
        let failing = full_receipt("turn-failing", 99);

        // Only this worker's thread-local seam fails; the main thread's write
        // must be unaffected. A failure writes the fallback for its own run.
        let failing_db = db.clone();
        let failing_receipt = failing.clone();
        let worker = std::thread::spawn(move || {
            test_seam::set(|| Some(Err(anyhow::anyhow!("injected failure for one run only"))));
            let result = persist_receipt_retry(&failing_db, &failing_receipt);
            assert!(result.is_err(), "the injected failure persists");
            test_seam::clear();
            persist_fallback_receipt(&failing_db, &failing_receipt).unwrap();
        });

        persist_receipt_retry(&db, &healthy).unwrap();
        worker.join().unwrap();

        let receipts = read_receipts(&db, None, 10).unwrap();
        assert_eq!(receipts.len(), 2, "one row per run, no cross-talk");
        let by_run: BTreeMap<&str, &Receipt> =
            receipts.iter().map(|r| (r.run_id.as_str(), r)).collect();
        let healthy = by_run.get("turn-healthy").expect("healthy run row");
        assert!(
            !healthy.receipt_error,
            "the healthy run kept its full receipt"
        );
        assert_eq!(healthy.tokens_in, 12);
        let failing = by_run.get("turn-failing").expect("failing run row");
        assert!(
            failing.receipt_error,
            "the failing run got its fallback row"
        );
    }
}
