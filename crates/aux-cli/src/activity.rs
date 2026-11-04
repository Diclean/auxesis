//! `aux activity` — a read-only timeline of what Auxesis has been doing.
//!
//! The timeline merges two sources from the store:
//!
//! - **messages** (`message.<role>` kinds), joined to `sessions` to attribute
//!   each one to its agent;
//! - **events** (`events.kind`) — `tool.decision` audit rows, `daemon.*`
//!   lifecycle rows, and whatever future slices log (`budget.*`, `job.*`);
//!   unknown kinds still show up with their payload summarized.
//!
//! The command is strictly read-only: the store is opened
//! `SQLITE_OPEN_READ_ONLY`, no migration is ever run, and a missing home or
//! missing tables simply yield an empty timeline. Timestamps are the UTC
//! `YYYY-MM-DD HH:MM:SS` strings written by `datetime('now')`; ordering is
//! ascending, with same-second entries ordered messages before events and
//! then by row id, so output is deterministic.

use clap::Args;
use kernel_core::{auxesis_home, clean_field, store_path, truncate_chars};
use rusqlite::Connection;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use thiserror::Error;

/// Default `--limit`: the N most recent entries.
pub const DEFAULT_LIMIT: i64 = 50;

/// Summaries are capped after sanitizing so `--json` stays bounded.
const SUMMARY_MAX_CHARS: usize = 200;

/// Column widths of the compact table.
const TIME_WIDTH: usize = 19;
const KIND_WIDTH: usize = 20;
const AGENT_WIDTH: usize = 12;
const SUMMARY_WIDTH: usize = 56;

/// Arguments of `aux activity`.
#[derive(Debug, Args)]
pub struct ActivityArgs {
    /// Only entries belonging to this agent (exact match).
    #[arg(long, value_name = "AGENT")]
    pub agent: Option<String>,
    /// Only entries at or after this UTC time: `YYYY-MM-DD`,
    /// `YYYY-MM-DD HH:MM:SS` (a `T` separator and trailing `Z` are accepted),
    /// or a relative span like `30m`, `2h`, `7d`.
    #[arg(long, value_name = "WHEN")]
    pub since: Option<String>,
    /// Show at most the N most recent matching entries (0 = no limit).
    #[arg(long, default_value_t = DEFAULT_LIMIT, value_name = "N")]
    pub limit: i64,
    /// Print a JSON array instead of a table.
    #[arg(long)]
    pub json: bool,
}

/// One line of the timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActivityEntry {
    /// UTC timestamp (`YYYY-MM-DD HH:MM:SS`).
    pub at: String,
    /// Entry type: `message.<role>`, `tool.decision`, `daemon.*`, …
    pub kind: String,
    /// Agent this entry belongs to, when known.
    pub agent: Option<String>,
    /// Single-line, sanitized digest of the entry.
    pub summary: String,
    /// Row id within its source (ordering tie-breaker).
    #[serde(skip)]
    seq: i64,
    /// Source rank (messages sort before events at equal timestamps).
    #[serde(skip)]
    source: Source,
}

/// Where an entry came from; declaration order is the tie-break order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    Message,
    Event,
}

/// Errors that abort `aux activity`.
#[derive(Debug, Error)]
pub enum ActivityError {
    /// `--since` is not one of the documented forms.
    #[error(
        "invalid --since `{input}`: expected `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, \
         or a relative span like `30m`, `2h`, `7d`"
    )]
    Since {
        /// The offending argument.
        input: String,
    },
    /// `--limit` is negative.
    #[error("invalid --limit {value}: must be >= 0")]
    Limit {
        /// The offending value.
        value: i64,
    },
    /// The store exists but could not be read.
    #[error("reading store {path}: {source}")]
    Store {
        /// Store path.
        path: PathBuf,
        /// Underlying SQLite error.
        source: rusqlite::Error,
    },
    /// The store could not be opened with its key: the key files are missing
    /// or do not unlock it, or the store is still plaintext (only the daemon
    /// migrates it).
    #[error("opening store {path}: {source}")]
    StoreKey {
        /// Store path.
        path: PathBuf,
        /// Why the keyed open was refused.
        source: aux_store::StoreError,
    },
    /// Writing the rendered timeline to stdout failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A parsed `--since` bound.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Since {
    /// Ready-to-compare `YYYY-MM-DD HH:MM:SS` string.
    Absolute(String),
    /// SQLite modifier for `datetime('now', ?)` (e.g. `-2 hours`).
    Relative(String),
}

/// Run `aux activity`, printing errors to stderr and mapping them to an exit code.
pub fn run(args: ActivityArgs) -> ExitCode {
    let home = auxesis_home();
    // The CLI process has its own (empty) scrubber registry;
    // register the same known secrets the daemon holds so `aux activity`
    // redacts a key in prose exactly like the API surfaces do.
    kernel_broker::scrub::register_known_secrets_from_home(&home);
    match run_inner(&home, &args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux activity: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner(home: &Path, args: &ActivityArgs) -> Result<(), ActivityError> {
    let entries = collect(home, args)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // A closed pipe (`aux activity | head`) is normal, not an error.
    match emit(&entries, args.json, &mut out) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Read the timeline from the store at `home`, newest `limit` entries kept.
///
/// Never creates or migrates anything; a missing store is an empty timeline.
pub fn collect(home: &Path, args: &ActivityArgs) -> Result<Vec<ActivityEntry>, ActivityError> {
    let limit = checked_limit(args.limit)?;
    let since = args.since.as_deref().map(parse_since).transpose()?;

    let path = store_path(home);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let conn = aux_store::open_keyed_readonly(&path).map_err(|source| ActivityError::StoreKey {
        path: path.clone(),
        source,
    })?;
    // A daemon may be mid-write; wait instead of failing on a transient lock.
    let _ = conn.busy_timeout(Duration::from_secs(2));
    let store_err = |source| ActivityError::Store {
        path: path.clone(),
        source,
    };

    let mut entries = read_events(home, &conn, args.agent.as_deref(), since.as_ref(), limit)
        .map_err(store_err)?;
    entries.extend(
        read_messages(home, &conn, args.agent.as_deref(), since.as_ref(), limit)
            .map_err(store_err)?,
    );

    entries.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.seq.cmp(&b.seq))
    });

    // Most recent N overall: each source contributed at most N, so the global
    // tail is guaranteed to be complete after the merge.
    if let Some(limit) = limit {
        let limit = limit as usize;
        if entries.len() > limit {
            entries = entries.split_off(entries.len() - limit);
        }
    }
    Ok(entries)
}

/// Validate `--limit`; `0` means "no limit".
fn checked_limit(raw: i64) -> Result<Option<i64>, ActivityError> {
    match raw {
        value if value < 0 => Err(ActivityError::Limit { value }),
        0 => Ok(None),
        value => Ok(Some(value)),
    }
}

/// Parse `--since` into a comparison bound. Only the documented forms are
/// accepted; everything else is rejected instead of guessed.
fn parse_since(raw: &str) -> Result<Since, ActivityError> {
    let input = raw.trim();
    if let Some(modifier) = parse_relative(input) {
        return Ok(Since::Relative(modifier));
    }
    if let Some(absolute) = parse_absolute(input) {
        return Ok(Since::Absolute(absolute));
    }
    Err(ActivityError::Since {
        input: raw.trim().to_string(),
    })
}

/// Relative spans: `<count><s|m|h|d>`, e.g. `45s`, `30m`, `2h`, `7d`.
fn parse_relative(input: &str) -> Option<String> {
    let unit = input.chars().last()?;
    let digits = &input[..input.len() - unit.len_utf8()];
    let word = match unit {
        's' => "seconds",
        'm' => "minutes",
        'h' => "hours",
        'd' => "days",
        _ => return None,
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let count: u64 = digits.parse().ok()?;
    // Bound the span so SQLite's date math can never overflow to NULL.
    if count == 0 || count > 1_000_000 {
        return None;
    }
    Some(format!("-{count} {word}"))
}

/// Absolute timestamps: `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`, with `T` and a
/// trailing `Z` tolerated. Output is normalized to the store's format.
fn parse_absolute(input: &str) -> Option<String> {
    let input = input.strip_suffix('Z').unwrap_or(input);
    let input = input.replace('T', " ");
    match input.len() {
        10 if valid_date(&input) => Some(format!("{input} 00:00:00")),
        19 if valid_datetime(&input) => Some(input),
        _ => None,
    }
}

fn valid_date(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !digit_at(bytes, 0)
        || !digit_at(bytes, 1)
        || !digit_at(bytes, 2)
        || !digit_at(bytes, 3)
        || !digit_at(bytes, 5)
        || !digit_at(bytes, 6)
        || !digit_at(bytes, 8)
        || !digit_at(bytes, 9)
    {
        return false;
    }
    let year = number(input, 0, 4);
    let month = number(input, 5, 7);
    let day = number(input, 8, 10);
    (1970..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
}

/// Days in a month, Gregorian leap years included.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn valid_datetime(input: &str) -> bool {
    let bytes = input.as_bytes();
    bytes.len() == 19
        && bytes[10] == b' '
        && bytes[13] == b':'
        && bytes[16] == b':'
        && valid_date(&input[..10])
        && digit_at(bytes, 11)
        && digit_at(bytes, 12)
        && digit_at(bytes, 14)
        && digit_at(bytes, 15)
        && digit_at(bytes, 17)
        && digit_at(bytes, 18)
        && number(input, 11, 13) <= 23
        && number(input, 14, 16) <= 59
        && number(input, 17, 19) <= 59
}

fn digit_at(bytes: &[u8], position: usize) -> bool {
    bytes.get(position).is_some_and(u8::is_ascii_digit)
}

/// Parse a zero-padded number from `input[start..end]` (ASCII digits only).
fn number(input: &str, start: usize, end: usize) -> u32 {
    input[start..end].parse().unwrap_or(0)
}

fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Newest `limit` events matching the filters, ascending once merged.
fn read_events(
    home: &Path,
    conn: &Connection,
    agent: Option<&str>,
    since: Option<&Since>,
    limit: Option<i64>,
) -> rusqlite::Result<Vec<ActivityEntry>> {
    if !table_exists(conn, "events")? {
        return Ok(Vec::new());
    }

    let mut sql = String::from("SELECT id, kind, payload, created_at FROM events WHERE 1 = 1");
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(agent) = agent {
        // `CASE` guarantees `json_extract` only sees valid JSON, so one junk
        // payload can never fail the whole query. Rows written before the rename
        // carry the agent under `dot`, so both keys match.
        sql.push_str(
            " AND (CASE WHEN json_valid(payload) THEN COALESCE(json_extract(payload, '$.agent'), json_extract(payload, '$.dot')) END) = ?",
        );
        params.push(Box::new(agent.to_string()));
    }
    append_since(&mut sql, "created_at", since, &mut params);
    sql.push_str(" ORDER BY created_at DESC, id DESC");
    if let Some(limit) = limit {
        sql.push_str(" LIMIT ?");
        params.push(Box::new(limit));
    }

    let mut stmt = conn.prepare(&sql)?;
    let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|param| param.as_ref()).collect();
    let rows = stmt.query_map(refs.as_slice(), |row| {
        let id: i64 = row.get(0)?;
        let kind: String = row.get(1)?;
        let payload: String = row.get(2)?;
        let at: String = row.get(3)?;
        Ok((id, kind, payload, at))
    })?;

    let mut entries = Vec::new();
    for row in rows {
        let (id, kind, payload, at) = row?;
        entries.push(ActivityEntry {
            at: clean_field(&at),
            kind: kind_display(home, &kind),
            agent: payload_agent(home, &payload),
            summary: event_summary(home, &kind, &payload),
            seq: id,
            source: Source::Event,
        });
    }
    Ok(entries)
}

/// Newest `limit` messages matching the filters, attributed to their agent.
fn read_messages(
    home: &Path,
    conn: &Connection,
    agent: Option<&str>,
    since: Option<&Since>,
    limit: Option<i64>,
) -> rusqlite::Result<Vec<ActivityEntry>> {
    if !table_exists(conn, "sessions")? || !table_exists(conn, "messages")? {
        return Ok(Vec::new());
    }

    // A private channel turn's rows live only while it runs (G1): never shown.
    let mut sql = format!(
        "SELECT m.id, s.agent, m.role, m.content, m.created_at
         FROM messages m JOIN sessions s ON s.id = m.session_id
         WHERE s.kind <> '{}'",
        auxd::gateway::imessage::PRIVATE_SESSION_KIND
    );
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(agent) = agent {
        sql.push_str(" AND s.agent = ?");
        params.push(Box::new(agent.to_string()));
    }
    append_since(&mut sql, "m.created_at", since, &mut params);
    sql.push_str(" ORDER BY m.created_at DESC, m.id DESC");
    if let Some(limit) = limit {
        sql.push_str(" LIMIT ?");
        params.push(Box::new(limit));
    }

    let mut stmt = conn.prepare(&sql)?;
    let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|param| param.as_ref()).collect();
    let rows = stmt.query_map(refs.as_slice(), |row| {
        let id: i64 = row.get(0)?;
        let agent: String = row.get(1)?;
        let role: String = row.get(2)?;
        let content: String = row.get(3)?;
        let at: String = row.get(4)?;
        Ok((id, agent, role, content, at))
    })?;

    let mut entries = Vec::new();
    for row in rows {
        let (id, agent, role, content, at) = row?;
        let role = scrub_cli_field(home, &role);
        let role = if role.is_empty() {
            "unknown".to_string()
        } else {
            role
        };
        let agent = scrub_cli_field(home, &agent);
        entries.push(ActivityEntry {
            at: clean_field(&at),
            kind: format!("message.{role}"),
            agent: (!agent.is_empty()).then_some(agent),
            summary: preview(home, &content),
            seq: id,
            source: Source::Message,
        });
    }
    Ok(entries)
}

/// Append the `--since` predicate for a timestamp column.
fn append_since(
    sql: &mut String,
    column: &str,
    since: Option<&Since>,
    params: &mut Vec<Box<dyn rusqlite::ToSql>>,
) {
    match since {
        None => {}
        Some(Since::Absolute(value)) => {
            sql.push_str(&format!(" AND {column} >= ?"));
            params.push(Box::new(value.clone()));
        }
        Some(Since::Relative(modifier)) => {
            sql.push_str(&format!(" AND {column} >= datetime('now', ?)"));
            params.push(Box::new(modifier.clone()));
        }
    }
}

/// Display kind: sanitized, scrubbed, single-line, capped like any other
/// field.
fn kind_display(home: &Path, kind: &str) -> String {
    let cleaned = scrub_cli_field(home, kind);
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        truncate_chars(&cleaned, SUMMARY_MAX_CHARS)
    }
}

/// Agent named in an event payload, when present and well-formed.
fn payload_agent(home: &Path, payload: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    let name = value.get("agent").or_else(|| value.get("dot"))?.as_str()?;
    let agent = scrub_cli_field(home, name);
    (!agent.is_empty()).then_some(agent)
}

/// One-line digest of an event: the CLI applies the same shared
/// scrubber as the API, including the structured pass over the payload tree).
fn event_summary(home: &Path, kind: &str, payload: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return preview(home, payload);
    };
    kernel_broker::scrub_json_value(&mut value);
    match kind.trim() {
        "tool.decision" => {
            let tool = value.get("tool").and_then(|v| v.as_str()).unwrap_or("tool");
            let outcome = value
                .get("outcome")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            match value.get("reason").and_then(|v| v.as_str()) {
                Some(reason) if !reason.trim().is_empty() => {
                    preview(home, &format!("{tool} {outcome} — {reason}"))
                }
                _ => preview(home, &format!("{tool} {outcome}")),
            }
        }
        "daemon.started" => match value.get("version").and_then(|v| v.as_str()) {
            Some(version) if !version.trim().is_empty() => {
                // Scrub the version *before* gluing the `v` marker —
                // scrubbing after the glue hides every prefixed shape behind
                // a non-boundary leading character.
                let cleaned = scrub_cli_field(home, version);
                truncate_chars(&format!("v{cleaned}"), SUMMARY_MAX_CHARS)
            }
            _ => preview(home, &compact_json(&value)),
        },
        _ => {
            for key in ["summary", "reason", "message"] {
                if let Some(text) = value.get(key).and_then(|v| v.as_str()) {
                    if !text.trim().is_empty() {
                        return preview(home, text);
                    }
                }
            }
            preview(home, &compact_json(&value))
        }
    }
}

fn compact_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

/// One field through the shared scrubber, then collapsed to one line.
fn scrub_cli_field(home: &Path, raw: &str) -> String {
    clean_field(&kernel_broker::scrub_external_preview(
        home,
        raw,
        SUMMARY_MAX_CHARS * 4,
    ))
}

/// One-line summary: sanitized, secret-scrubbed, collapsed, capped.
fn preview(home: &Path, raw: &str) -> String {
    let cleaned = scrub_cli_field(home, raw);
    if cleaned.is_empty() {
        return "(empty)".to_string();
    }
    truncate_chars(&cleaned, SUMMARY_MAX_CHARS)
}

/// Render the compact table (time, kind, agent, summary).
pub fn render_table(entries: &[ActivityEntry]) -> String {
    if entries.is_empty() {
        return "(no activity)\n".to_string();
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{:<TIME_WIDTH$}  {:<KIND_WIDTH$}  {:<AGENT_WIDTH$}  {}\n",
        "TIME", "KIND", "AGENT", "SUMMARY"
    ));
    for entry in entries {
        out.push_str(&format!(
            "{:<TIME_WIDTH$}  {:<KIND_WIDTH$}  {:<AGENT_WIDTH$}  {}\n",
            fit(&entry.at, TIME_WIDTH),
            fit(&entry.kind, KIND_WIDTH),
            fit(entry.agent.as_deref().unwrap_or("-"), AGENT_WIDTH),
            fit(&entry.summary, SUMMARY_WIDTH),
        ));
    }
    out
}

/// Render the JSON array used by `--json`.
pub fn render_json(entries: &[ActivityEntry]) -> String {
    let mut out = serde_json::to_string_pretty(entries).unwrap_or_else(|_| "[]".to_string());
    out.push('\n');
    out
}

/// Write the timeline to `out` in the requested format.
pub fn emit(entries: &[ActivityEntry], json: bool, out: &mut impl Write) -> std::io::Result<()> {
    let rendered = if json {
        render_json(entries)
    } else {
        render_table(entries)
    };
    out.write_all(rendered.as_bytes())
}

/// Fit `text` into `width` characters, appending `…` when cut.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        truncate_chars(text, width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    #[test]
    fn shared_secret_redaction_canaries_are_scrubbed_in_activity() {
        redaction_canaries::assert_no_canaries(|text| {
            scrub_cli_field(Path::new("/tmp/auxesis-canary-home"), text)
        });
    }
    use aux_store::Store;
    use tempfile::tempdir;

    fn args() -> ActivityArgs {
        ActivityArgs {
            agent: None,
            since: None,
            limit: DEFAULT_LIMIT,
            json: false,
        }
    }

    /// A home directory containing an initialized store.
    fn home_with_store() -> (tempfile::TempDir, Store) {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::open(&store_path(&home)).unwrap();
        (dir, store)
    }

    /// Pin a row's timestamp through a separate connection (`Store` has no
    /// public setter; tests need deterministic timestamps).
    fn set_time(home: &Path, table: &str, id: i64, at: &str) {
        let conn = aux_store::open_keyed(&store_path(home)).unwrap();
        conn.execute(
            &format!("UPDATE {table} SET created_at = ?1 WHERE id = ?2"),
            rusqlite::params![at, id],
        )
        .unwrap();
    }

    fn kinds(entries: &[ActivityEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.kind.as_str()).collect()
    }

    // ---- empty home ----

    #[test]
    fn empty_home_yields_an_empty_timeline_without_creating_anything() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("missing");
        let entries = collect(&home, &args()).unwrap();
        assert!(entries.is_empty());
        assert!(!home.exists(), "activity must not create the home");
        assert_eq!(render_table(&entries), "(no activity)\n");
        assert_eq!(render_json(&entries), "[]\n");
    }

    #[test]
    fn agent_filter_on_empty_home_is_still_empty() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("missing");
        let mut filters = args();
        filters.agent = Some("main".to_string());
        filters.since = Some("7d".to_string());
        assert!(collect(&home, &filters).unwrap().is_empty());
        assert!(!home.exists());
    }

    #[test]
    fn zero_byte_store_is_treated_as_empty() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(store_path(&home), b"").unwrap();
        let entries = collect(&home, &args()).unwrap();
        assert!(entries.is_empty());
    }

    // ---- ordering ----

    #[test]
    fn timeline_is_ascending_and_interleaves_messages_and_events() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        let m1 = store
            .append_message(session.id, "user", "one", None)
            .unwrap();
        let m2 = store
            .append_message(session.id, "assistant", "two", None)
            .unwrap();
        store
            .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
            .unwrap();
        store.log_event("daemon.stopped", "{}").unwrap();

        set_time(&home, "messages", m1.id, "2026-10-03 09:00:00");
        set_time(&home, "events", 1, "2026-10-03 09:00:01");
        set_time(&home, "messages", m2.id, "2026-10-03 09:00:02");
        set_time(&home, "events", 2, "2026-10-03 09:00:03");

        let entries = collect(&home, &args()).unwrap();
        assert_eq!(
            kinds(&entries),
            vec![
                "message.user",
                "daemon.started",
                "message.assistant",
                "daemon.stopped"
            ]
        );
        let times: Vec<&str> = entries.iter().map(|entry| entry.at.as_str()).collect();
        let mut sorted = times.clone();
        sorted.sort_unstable();
        assert_eq!(times, sorted, "timeline must be ascending");
    }

    #[test]
    fn same_second_entries_break_ties_messages_first_then_ids() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        let first = store.append_message(session.id, "user", "a", None).unwrap();
        let second = store.append_message(session.id, "user", "b", None).unwrap();
        store
            .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
            .unwrap();
        store.log_event("daemon.stopped", "{}").unwrap();

        for id in [first.id, second.id] {
            set_time(&home, "messages", id, "2026-10-03 09:00:00");
        }
        set_time(&home, "events", 1, "2026-10-03 09:00:00");
        set_time(&home, "events", 2, "2026-10-03 09:00:00");

        let entries = collect(&home, &args()).unwrap();
        assert_eq!(
            kinds(&entries),
            vec![
                "message.user",
                "message.user",
                "daemon.started",
                "daemon.stopped"
            ]
        );
        assert_eq!(entries[0].summary, "a");
        assert_eq!(entries[1].summary, "b");
    }

    #[test]
    fn limit_keeps_the_most_recent_entries_still_in_ascending_order() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        for index in 0..5 {
            store
                .log_event("tick", &format!(r#"{{"n":{index}}}"#))
                .unwrap();
            set_time(
                &home,
                "events",
                index + 1,
                &format!("2026-10-03 09:00:0{index}"),
            );
        }

        let mut limited = args();
        limited.limit = 2;
        let entries = collect(&home, &limited).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(kinds(&entries), vec!["tick", "tick"]);
        assert_eq!(entries[0].summary, r#"{"n":3}"#);
        assert_eq!(entries[1].summary, r#"{"n":4}"#);
    }

    // ---- filters ----

    #[test]
    fn agent_filter_still_finds_rows_written_before_the_rename() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        // The old shape: the kind and the payload key both say `dot`.
        store.log_event("dot.created", r#"{"dot":"main"}"#).unwrap();
        store
            .log_event("agent.created", r#"{"agent":"main"}"#)
            .unwrap();
        store.log_event("dot.created", r#"{"dot":"axis"}"#).unwrap();

        let mut filtered = args();
        filtered.agent = Some("main".to_string());
        let entries = collect(&home, &filtered).unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert!(entries
            .iter()
            .all(|entry| entry.agent.as_deref() == Some("main")));
        assert_eq!(entries[0].kind, "dot.created");
    }

    #[test]
    fn agent_filter_keeps_only_matching_messages_and_events() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let main = store.create_session("main", None).unwrap();
        let axis = store.create_session("axis", None).unwrap();
        store
            .append_message(main.id, "user", "from main", None)
            .unwrap();
        store
            .append_message(axis.id, "user", "from axis", None)
            .unwrap();
        store
            .log_event(
                "tool.decision",
                r#"{"agent":"main","tool":"shell","outcome":"allowed","reason":"rule 0: allow"}"#,
            )
            .unwrap();
        store
            .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
            .unwrap();
        store.log_event("junk", "not json").unwrap();
        store.log_event("dotless", r#"{"agent":42}"#).unwrap();

        let mut filtered = args();
        filtered.agent = Some("main".to_string());
        let entries = collect(&home, &filtered).unwrap();
        assert_eq!(kinds(&entries), vec!["message.user", "tool.decision"]);
        assert_eq!(entries[0].agent.as_deref(), Some("main"));
        assert_eq!(entries[1].agent.as_deref(), Some("main"));

        // Unfiltered: dotless and malformed events survive with agent = None.
        let all = collect(&home, &args()).unwrap();
        assert_eq!(all.len(), 6);
        let dotless = all
            .iter()
            .find(|entry| entry.kind == "daemon.started")
            .unwrap();
        assert_eq!(dotless.agent, None);
        let junk = all.iter().find(|entry| entry.kind == "junk").unwrap();
        assert_eq!(junk.agent, None);
        assert_eq!(junk.summary, "not json");
    }

    #[test]
    fn agent_filter_treats_json_agents_of_other_types_as_non_matching() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        store.log_event("dotless", r#"{"agent":42}"#).unwrap();
        let mut filtered = args();
        filtered.agent = Some("42".to_string());
        assert!(collect(&home, &filtered).unwrap().is_empty());
    }

    #[test]
    fn since_as_a_date_cuts_at_midnight_and_outranks_old_entries() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        store.log_event("old", "{}").unwrap();
        store.log_event("new", "{}").unwrap();
        set_time(&home, "events", 1, "2000-01-01 00:00:00");
        set_time(&home, "events", 2, "2026-10-03 08:00:00");

        let mut filtered = args();
        filtered.since = Some("2026-10-03".to_string());
        assert_eq!(kinds(&collect(&home, &filtered).unwrap()), vec!["new"]);

        // Inclusive boundary.
        filtered.since = Some("2026-10-03 08:00:00".to_string());
        assert_eq!(kinds(&collect(&home, &filtered).unwrap()), vec!["new"]);

        // One second later excludes the boundary row.
        filtered.since = Some("2026-10-03 08:00:01".to_string());
        assert!(collect(&home, &filtered).unwrap().is_empty());
    }

    #[test]
    fn since_in_the_future_is_empty_not_an_error() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        store.log_event("now", "{}").unwrap();
        let mut filtered = args();
        filtered.since = Some("2999-01-01".to_string());
        assert!(collect(&home, &filtered).unwrap().is_empty());
    }

    #[test]
    fn since_relative_uses_sqlite_now() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        store.log_event("old", "{}").unwrap();
        store.log_event("fresh", "{}").unwrap();
        set_time(&home, "events", 1, "2000-01-01 00:00:00");

        let mut filtered = args();
        filtered.since = Some("1h".to_string());
        assert_eq!(kinds(&collect(&home, &filtered).unwrap()), vec!["fresh"]);
    }

    #[test]
    fn since_applies_to_messages_too() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        let old = store
            .append_message(session.id, "user", "old", None)
            .unwrap();
        store
            .append_message(session.id, "user", "fresh", None)
            .unwrap();
        set_time(&home, "messages", old.id, "2000-01-01 00:00:00");

        let mut filtered = args();
        filtered.since = Some("7d".to_string());
        let entries = collect(&home, &filtered).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].summary, "fresh");
    }

    #[test]
    fn since_parser_accepts_documented_forms() {
        assert_eq!(
            parse_since("2026-10-03").unwrap(),
            Since::Absolute("2026-10-03 00:00:00".to_string())
        );
        assert_eq!(
            parse_since(" 2026-10-03 08:30:00 ").unwrap(),
            Since::Absolute("2026-10-03 08:30:00".to_string())
        );
        assert_eq!(
            parse_since("2026-10-03T08:30:00Z").unwrap(),
            Since::Absolute("2026-10-03 08:30:00".to_string())
        );
        assert_eq!(
            parse_since("45s").unwrap(),
            Since::Relative("-45 seconds".to_string())
        );
        assert_eq!(
            parse_since("30m").unwrap(),
            Since::Relative("-30 minutes".to_string())
        );
        assert_eq!(
            parse_since("2h").unwrap(),
            Since::Relative("-2 hours".to_string())
        );
        assert_eq!(
            parse_since("7d").unwrap(),
            Since::Relative("-7 days".to_string())
        );
        // Gregorian leap years are honored.
        assert_eq!(
            parse_since("2024-02-29").unwrap(),
            Since::Absolute("2024-02-29 00:00:00".to_string())
        );
        assert_eq!(
            parse_since("2000-02-29").unwrap(),
            Since::Absolute("2000-02-29 00:00:00".to_string())
        );
    }

    #[test]
    fn since_parser_rejects_malformed_input() {
        for input in [
            "",
            "yesterday",
            "2026-13-01",
            "2026-10-32",
            "2026-02-31",
            "2026-02-29",
            "2026-04-31",
            "2026-00-10",
            "2026-10-00",
            "26-10-03",
            "2026-10-03 25:00:00",
            "2026-10-03 08:60:00",
            "2026-10-03 08:30",
            "10x",
            "0m",
            "-2h",
            "999999999999d",
            "now",
        ] {
            assert!(
                matches!(parse_since(input), Err(ActivityError::Since { .. })),
                "`{input}` should be rejected"
            );
        }
    }

    #[test]
    fn limit_zero_means_no_limit_and_negative_is_rejected() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        for index in 0..4 {
            store.log_event("tick", "{}").unwrap();
            let _ = index;
        }

        let mut unlimited = args();
        unlimited.limit = 0;
        assert_eq!(collect(&home, &unlimited).unwrap().len(), 4);

        let mut negative = args();
        negative.limit = -1;
        assert!(matches!(
            collect(&home, &negative),
            Err(ActivityError::Limit { value: -1 })
        ));
    }

    #[test]
    fn large_limits_are_accepted_and_return_everything() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        for _ in 0..3 {
            store.log_event("tick", "{}").unwrap();
        }

        for limit in [1_000, 1_000_000, i64::MAX] {
            let mut huge = args();
            huge.limit = limit;
            assert_eq!(collect(&home, &huge).unwrap().len(), 3, "limit {limit}");
        }
    }

    // ---- summaries ----

    #[test]
    fn tool_decisions_get_a_structured_summary() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        store
            .log_event(
                "tool.decision",
                r#"{"agent":"main","tool":"shell","risk":"high","action":"ask",
                    "outcome":"allowed","reason":"rule 0 matched: ask","approved":true}"#,
            )
            .unwrap();
        let entries = collect(&home, &args()).unwrap();
        assert_eq!(entries[0].summary, "shell allowed — rule 0 matched: ask");
        assert_eq!(entries[0].agent.as_deref(), Some("main"));

        // Without a reason the summary stays useful.
        store
            .log_event(
                "tool.decision",
                r#"{"agent":"main","tool":"read_file","outcome":"denied"}"#,
            )
            .unwrap();
        let entries = collect(&home, &args()).unwrap();
        assert_eq!(entries[1].summary, "read_file denied");
    }

    #[test]
    fn daemon_events_and_generic_events_summarize_their_payloads() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        store
            .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
            .unwrap();
        store.log_event("daemon.stopped", "{}").unwrap();
        store
            .log_event(
                "job.completed",
                r#"{"agent":"main","summary":"backup done"}"#,
            )
            .unwrap();
        store
            .log_event("budget.denied", r#"{"agent":"main","reason":"daily cap"}"#)
            .unwrap();
        store.log_event("weird", r#"{"other":true}"#).unwrap();
        store.log_event("broken", "not json at all").unwrap();

        let entries = collect(&home, &args()).unwrap();
        let by_kind = |kind: &str| {
            entries
                .iter()
                .find(|entry| entry.kind == kind)
                .unwrap_or_else(|| panic!("missing {kind}: {entries:?}"))
                .summary
                .clone()
        };
        assert_eq!(by_kind("daemon.started"), "v0.1.0");
        assert_eq!(by_kind("daemon.stopped"), "{}");
        assert_eq!(by_kind("job.completed"), "backup done");
        assert_eq!(by_kind("budget.denied"), "daily cap");
        assert_eq!(by_kind("weird"), r#"{"other":true}"#);
        assert_eq!(by_kind("broken"), "not json at all");
    }

    #[test]
    fn messages_collapse_to_a_single_sanitized_line() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        store
            .append_message(
                session.id,
                "assistant",
                "line one\nline two\u{1b}[31m red\u{200b}",
                None,
            )
            .unwrap();
        store.append_message(session.id, "tool", "", None).unwrap();

        let entries = collect(&home, &args()).unwrap();
        // The ANSI SGR sequence is dropped whole (`line two[31m red` was the
        // old, spoofable residue).
        assert_eq!(entries[0].summary, "line one line two red");
        assert_eq!(entries[1].summary, "(empty)");
        assert_eq!(entries[1].kind, "message.tool");
    }

    #[test]
    fn long_summaries_are_capped_by_json_too() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        store
            .append_message(session.id, "user", &"x".repeat(5_000), None)
            .unwrap();
        let entries = collect(&home, &args()).unwrap();
        assert_eq!(entries[0].summary.chars().count(), SUMMARY_MAX_CHARS);
        assert!(entries[0].summary.ends_with('…'));
    }

    // ---- rendering ----

    #[test]
    fn table_has_the_documented_columns_and_truncates() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        store
            .append_message(session.id, "user", &"y".repeat(100), None)
            .unwrap();
        set_time(&home, "messages", 1, "2026-10-03 09:00:00");

        let entries = collect(&home, &args()).unwrap();
        let table = render_table(&entries);
        let mut lines = table.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("TIME"));
        assert!(header.contains("KIND"));
        assert!(header.contains("AGENT"));
        assert!(header.contains("SUMMARY"));
        let row = lines.next().unwrap();
        assert!(row.starts_with("2026-10-03 09:00:00  message.user"));
        assert!(row.contains("main"));
        assert!(row.contains(&format!("{}…", "y".repeat(SUMMARY_WIDTH - 1))));
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn table_is_empty_message_when_there_is_nothing() {
        assert_eq!(render_table(&[]), "(no activity)\n");
    }

    #[test]
    fn json_shape_is_a_stable_object_array() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        store
            .append_message(session.id, "user", "hello", None)
            .unwrap();
        store
            .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
            .unwrap();
        set_time(&home, "messages", 1, "2026-10-03 09:00:00");
        set_time(&home, "events", 1, "2026-10-03 09:00:01");

        let entries = collect(&home, &args()).unwrap();
        let raw = render_json(&entries);
        assert!(raw.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let array = value.as_array().unwrap();
        assert_eq!(array.len(), 2);

        let message = &array[0];
        let mut keys: Vec<&str> = message
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["agent", "at", "kind", "summary"]);
        assert_eq!(message["at"], "2026-10-03 09:00:00");
        assert_eq!(message["kind"], "message.user");
        assert_eq!(message["agent"], "main");
        assert_eq!(message["summary"], "hello");

        let event = &array[1];
        assert_eq!(event["kind"], "daemon.started");
        assert!(event["agent"].is_null());
        assert_eq!(event["summary"], "v0.1.0");
    }

    #[test]
    fn emit_writes_both_formats() {
        let entry = ActivityEntry {
            at: "2026-10-03 09:00:00".to_string(),
            kind: "message.user".to_string(),
            agent: Some("main".to_string()),
            summary: "hi".to_string(),
            seq: 1,
            source: Source::Message,
        };
        let entries = vec![entry];

        let mut json = Vec::new();
        emit(&entries, true, &mut json).unwrap();
        assert_eq!(String::from_utf8(json).unwrap(), render_json(&entries));

        let mut table = Vec::new();
        emit(&entries, false, &mut table).unwrap();
        assert_eq!(String::from_utf8(table).unwrap(), render_table(&entries));
    }

    // ---- store robustness / read-only ----

    #[test]
    fn v1_store_is_read_only_and_never_migrated() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let path = store_path(&home);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    kind       TEXT NOT NULL,
                    payload    TEXT NOT NULL
                );
                INSERT INTO meta(key, value) VALUES ('schema_version', '1');
                INSERT INTO events(kind, payload) VALUES ('legacy.boot', '{"m0":true}');
                "#,
            )
            .unwrap();
        }

        // A plaintext store is refused, not read: only the daemon's writer
        // migrates it, and the read-only path never does.
        let err = collect(&home, &args()).unwrap_err();
        assert!(
            matches!(
                err,
                ActivityError::StoreKey {
                    source: aux_store::StoreError::NotEncrypted,
                    ..
                }
            ),
            "got {err}"
        );

        // Still v1 and plaintext on disk, with no messages table. Raw on purpose:
        // this is the untouched legacy fixture, not a keyed store.
        let conn = Connection::open(&path).unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
        let message_tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('sessions', 'messages')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(message_tables, 0);
    }

    #[test]
    fn missing_tables_yield_an_empty_timeline_not_an_error() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        drop(Store::open(&store_path(&home)).unwrap());
        aux_store::open_keyed(&store_path(&home))
            .unwrap()
            .execute_batch("DROP TABLE events;")
            .unwrap();

        assert!(collect(&home, &args()).unwrap().is_empty());
    }

    #[test]
    fn corrupted_store_is_reported_not_panicked() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(store_path(&home), b"this is not a sqlite database").unwrap();

        let err = collect(&home, &args()).unwrap_err();
        assert!(matches!(err, ActivityError::StoreKey { .. }), "got {err}");
    }

    // ---- The CLI scrubs like the API ----

    #[test]
    fn activity_scrubs_secrets_like_the_api() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        let secrets: &[&str] = &[
            "CANARYJSONKEY0001",
            "CANARYCLIURL04",
            "CANARYCLI4AAA111BBB",
            "CANARYCLIHDR06ABCDEFGH",
            "CANARYCLINEST01",
            "CANARYCLIVERS01",
            "CANARYCLIMULTI01",
            "CANARYCLICOOKIE01",
        ];
        store
            .append_message(
                session.id,
                "assistant",
                "{\"api_key\":\"CANARYJSONKEY0001\"}",
                None,
            )
            .unwrap();
        store
            .append_message(
                session.id,
                "user",
                "postgres://app:CANARYCLIURL04@db.internal/prod",
                None,
            )
            .unwrap();
        store
            .append_message(
                session.id,
                "tool",
                &format!("AKIA{}", "CANARYCLI4AAA111BBB"),
                None,
            )
            .unwrap();
        store
            .log_event(
                "tool.decision",
                r#"{"agent":"main","tool":"shell","outcome":"allowed","reason":"X-Api-Key: CANARYCLIHDR06ABCDEFGH"}"#, // gitleaks:allow
            )
            .unwrap();
        store
            .log_event(
                "job.completed",
                "{\"agent\":\"main\",\"summary\":\"{\\\"detail\\\":\\\"{\\\\\\\"api_key\\\\\\\":\\\\\\\"CANARYCLINEST01\\\\\\\"}\\\"}\"}",
            )
            .unwrap();
        store
            .log_event("daemon.started", r#"{"version":"api_key=CANARYCLIVERS01"}"#) // gitleaks:allow
            .unwrap();
        store
            .log_event(
                "job.completed",
                "{\"agent\":\"main\",\"summary\":\"api_key:\\n  CANARYCLIMULTI01\"}",
            )
            .unwrap();
        store
            .log_event(
                "job.completed",
                "{\"agent\":\"main\",\"summary\":\"session=CANARYCLICOOKIE01abcdefghij; Path=/\"}",
            )
            .unwrap();

        let entries = collect(&home, &args()).unwrap();
        let rendered = render_json(&entries);
        let table = render_table(&entries);
        for secret in secrets {
            assert!(
                !rendered.contains(secret),
                "activity --json leaked {secret:?}:\n{rendered}"
            );
            assert!(
                !table.contains(secret),
                "activity table leaked {secret:?}:\n{table}"
            );
        }
        assert!(rendered.contains("<redacted>"), "{rendered}");

        // The same rows read back raw from the store still hold the secrets:
        // the command is read-only display, not a migration.
        let conn = aux_store::open_keyed(&store_path(&home)).unwrap();
        let raw: String = conn
            .query_row("SELECT content FROM messages WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(raw.contains("CANARYJSONKEY0001"), "{raw}");
    }

    #[test]
    fn activity_keeps_the_false_positives() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        let session = store.create_session("main", None).unwrap();
        let uuid = "7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8";
        let keep = [
            format!("token_id: {uuid}"),
            "token: 1699999999999".to_string(),
            "password: MySecretValue123".to_string(),
            "commit 9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90".to_string(),
            "https://example.com/docs?page=2".to_string(),
            "task-sk-1234".to_string(),
            "bearer of bad news".to_string(),
            "hash=9f2a1b3c".to_string(),
        ];
        for raw in &keep {
            store
                .append_message(session.id, "assistant", raw, None)
                .unwrap();
        }
        let entries = collect(&home, &args()).unwrap();
        let rendered = render_json(&entries);
        for raw in &keep {
            assert!(
                rendered.contains(raw.as_str()),
                "activity mangled {raw:?}:\n{rendered}"
            );
        }
    }

    // ---- `--json` keeps number lexemes and key order ----

    #[test]
    fn activity_json_keeps_number_lexemes_and_key_order() {
        let (dir, store) = home_with_store();
        let home = dir.path().join("home");
        // A realistic run-summary payload: insertion order is z-then-a (a
        // BTreeMap render would sort it) and the numbers span u64::MAX, an
        // exponent literal, floats and i64::MIN.
        let payload = r#"{"z":18446744073709551615,"tool":"shell","a":1e+22,"ratio":0.1,"scale":1.0,"eps":1e-7,"neg":-9223372036854775808,"ms":12}"#;
        store.log_event("run.summary", payload).unwrap();

        let entries = collect(&home, &args()).unwrap();
        let rendered = render_json(&entries);
        for lexeme in [
            "18446744073709551615",
            "1e+22",
            "0.1",
            "1.0",
            "1e-7",
            "-9223372036854775808",
        ] {
            assert!(rendered.contains(lexeme), "{lexeme} mangled:\n{rendered}");
        }
        // The summary string escapes its quotes, so the payload keys appear
        // as `\"z\"` / `\"a\"`; z must still precede a.
        let z = rendered.find(r#"\"z\""#).unwrap();
        let a = rendered.find(r#"\"a\""#).unwrap();
        assert!(z < a, "key order changed in --json:\n{rendered}");
    }
}
