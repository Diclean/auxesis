//! Read-only Apple Calendar and Reminders snapshots provided by the bundled app.
//! The daemon never links EventKit or asks macOS for permission. The app sends
//! this bounded snapshot over the bearer-authenticated loopback API.

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Local, Utc};
use kernel_broker::ToolClass;
use kernel_broker::{NativeTool, Risk, Tool, ToolCtx, ToolError, ToolOutput};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_ITEMS: usize = 100;
/// Hard cap on the attendee addresses one published event may carry.
pub const MAX_ATTENDEES: usize = 100;
const MAX_SNAPSHOT_BYTES: u64 = 128 * 1024;
/// The encrypted snapshot: a one-row SQLCipher database under the store's key.
const SNAPSHOT_FILE: &str = "apple-eventkit.db";
const DATABASE_FILES: [&str; 4] = [
    SNAPSHOT_FILE,
    "apple-eventkit.db-journal",
    "apple-eventkit.db-wal",
    "apple-eventkit.db-shm",
];
/// The database is built under this name, read back, then written as
/// `SNAPSHOT_FILE`. A crash can leave these behind, so they are swept too.
const STAGING_FILES: [&str; 4] = [
    "apple-eventkit.db.new",
    "apple-eventkit.db.new-journal",
    "apple-eventkit.db.new-wal",
    "apple-eventkit.db.new-shm",
];
/// The plaintext JSON that older builds wrote. Nothing writes it now; it is
/// removed wherever it is found.
const LEGACY_FILE: &str = "apple-eventkit.json";

/// Bounds every calendar/reminder instant must fall in.
///
/// The app only publishes upcoming items (a few days either side of now), so a
/// date before 2000 or after 2100 is corrupt or hostile, never a real entry.
/// Bounding the instants also stops a crafted `9999-…` from flowing to a model
/// as a plausible deadline.
const MIN_INSTANT: i64 = 946_684_800; // 2000-01-01T00:00:00Z
const MAX_INSTANT: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventKitSnapshot {
    pub authorized: bool,
    pub events: Vec<EventItem>,
    pub reminders: Vec<ReminderItem>,
    /// The UTC instant the app read EventKit (not when it published). Absent
    /// on a snapshot from a build before CAL-PAGE-1: then its age is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    /// The exact UTC window the app queried (the start of its local day, out
    /// [`COVERS_DAYS`] days). The app converts the zone; the daemon never does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covers_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covers_to: Option<String>,
    /// The id of the owner's default calendar (CAL-DEFAULT-ID): the calendar
    /// new events go to. The daemon compares ids, never titles, so a shared
    /// calendar named `primary` is never the default one. Absent on an older
    /// copy: then no calendar is known to be the default one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_calendar_id: Option<String>,
    /// CAL-COMPLETE-DEDUP: the app found more events than [`MAX_ITEMS`] and
    /// kept only the first ones. A cut list never proves the owner free, and
    /// the calendar read names it incomplete. Absent on an older copy: then
    /// the list is not known to be cut (a full-length list still fails
    /// closed in the free-times read).
    #[serde(default)]
    pub events_truncated: bool,
    /// The same fact for the reminder list.
    #[serde(default)]
    pub reminders_truncated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventItem {
    /// EventKit's stable event identifier, when the app publishes one. A
    /// snapshot written before B3 has none; the timeline builder skips an
    /// event with no id because it cannot be de-duplicated.
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    pub start: String,
    pub end: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_day: Option<bool>,
    pub calendar: String,
    pub location: Option<String>,
    /// Attendee addresses (`mailto:…` or a plain address), when the app
    /// publishes them. `None` when the app sent no list (a build before B3):
    /// unknown guests, never "no guests" (CAL-UPDATE-1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attendees: Option<Vec<String>>,
    /// The id of the calendar this event sits on (CAL-DEFAULT-ID): the daemon
    /// tells the default calendar from a shared one by id, never by title.
    /// Absent on an older copy: then the event's calendar is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_id: Option<String>,
    /// The event is part of a recurring series, or a detached occurrence of
    /// one (CAL-DEFAULT-ID r2). Such an event never takes the approval-free
    /// path: EventKit's lookup can return the first occurrence, not the one
    /// the copy saw. Absent on an older copy: then it is not marked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurring: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReminderItem {
    pub title: String,
    pub due: Option<String>,
    pub list: String,
    pub completed: bool,
}

pub fn snapshot_path(home: &Path) -> PathBuf {
    home.join(SNAPSHOT_FILE)
}

/// The app refreshes its snapshot every 30 minutes; a copy older than this
/// means the refreshes stopped (the app is closed or lost Calendar access).
pub const STALE_AFTER_HOURS: i64 = 2;
/// The app queries from the start of its local day out this many days.
pub const COVERS_DAYS: i64 = 8;
/// A `captured_at` further ahead of this Mac's clock than this is a clock
/// change, not a capture: the copy is not fresh.
const FUTURE_SKEW_MINUTES: i64 = 5;

/// What the stored calendar copy says about itself (CAL-SNAPSHOT-STALE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotAge {
    /// When the app read EventKit; `None` on a copy from an older build.
    pub updated_at: Option<DateTime<Utc>>,
    pub covers_from: Option<DateTime<Utc>>,
    pub covers_to: Option<DateTime<Utc>>,
    /// Read within [`STALE_AFTER_HOURS`], not in the future, and covering now.
    pub fresh: bool,
}

fn instant(value: Option<&str>) -> Option<DateTime<Utc>> {
    checked_instant(value?)
}

/// Whether `snapshot` can answer for `from..to` at `now`: only when its
/// capture time is known, not in the future, within `max_age` of `now`, and
/// its queried window holds `from..to`. Anything unknown, or a reversed
/// `from..to`, fails closed.
///
/// This is the copy's age and window, not its completeness: a truncated list
/// is still fresh. [`EventKitSnapshot::events_truncated`] answers that, and a
/// free-time read refuses a cut list.
pub fn snapshot_covers(
    snapshot: &EventKitSnapshot,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    now: DateTime<Utc>,
    max_age: chrono::Duration,
) -> bool {
    let (Some(captured), Some(covers_from), Some(covers_to)) = (
        instant(snapshot.captured_at.as_deref()),
        instant(snapshot.covers_from.as_deref()),
        instant(snapshot.covers_to.as_deref()),
    ) else {
        return false;
    };
    captured <= now + chrono::Duration::minutes(FUTURE_SKEW_MINUTES)
        && now - captured <= max_age
        && covers_from <= from
        && from <= to
        && to <= covers_to
}

/// The age of a stored copy at `now`.
pub fn snapshot_age(snapshot: &EventKitSnapshot, now: DateTime<Utc>) -> SnapshotAge {
    SnapshotAge {
        updated_at: instant(snapshot.captured_at.as_deref()),
        covers_from: instant(snapshot.covers_from.as_deref()),
        covers_to: instant(snapshot.covers_to.as_deref()),
        fresh: snapshot_covers(
            snapshot,
            now,
            now,
            now,
            chrono::Duration::hours(STALE_AFTER_HOURS),
        ),
    }
}

/// The engine-written line every calendar read of `snapshot` carries once it
/// is not fresh, in the owner's UI language; `None` while it is fresh.
pub fn stale_note(home: &Path, snapshot: &EventKitSnapshot) -> Option<String> {
    let age = snapshot_age(snapshot, Utc::now());
    if age.fresh {
        return None;
    }
    let lang = crate::api::load_config_verified(home)
        .map(|config| config.ui.language)
        .unwrap_or_default();
    let at = age.updated_at.map(|at| at.with_timezone(&Local));
    Some(match lang {
        kernel_core::Lang::En => {
            let when = at.map_or("at an unknown time".to_string(), |at| {
                at.format("%a %-d %b, %H:%M").to_string()
            });
            format!(
                "Calendar last updated {when}; it may be out of date — open Auxesis to refresh."
            )
        }
        kernel_core::Lang::Fr => {
            const DAYS: [&str; 7] = ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."];
            const MONTHS: [&str; 12] = [
                "janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.",
                "nov.", "déc.",
            ];
            let when = at.map_or("à une heure inconnue".to_string(), |at| {
                format!(
                    "le {} {} {}, {}",
                    DAYS[at.weekday().num_days_from_monday() as usize],
                    at.day(),
                    MONTHS[at.month0() as usize],
                    at.format("%H:%M")
                )
            });
            format!("Agenda mis à jour {when} ; il n'est peut-être plus à jour — ouvrez Auxesis pour l'actualiser.")
        }
    })
}

/// The engine-written line every read of a cut list carries, in the owner's
/// UI language: the app kept only [`MAX_ITEMS`] items, so one may be missing
/// and the list never proves the owner free.
pub fn truncated_note(home: &Path, reminders: bool) -> String {
    let lang = crate::api::load_config_verified(home)
        .map(|config| config.ui.language)
        .unwrap_or_default();
    match (lang, reminders) {
        (kernel_core::Lang::En, false) => format!(
            "This calendar list is incomplete: the app kept only the first {MAX_ITEMS} events, \
             so a busy one may be missing — never read it as free time."
        ),
        (kernel_core::Lang::Fr, false) => format!(
            "Cette liste du calendrier est incomplète : l'app n'a gardé que les {MAX_ITEMS} \
             premiers événements, un rendez-vous occupé peut manquer — ne jamais en déduire \
             du temps libre."
        ),
        (kernel_core::Lang::En, true) => format!(
            "This reminder list is incomplete: the app kept only the first {MAX_ITEMS} reminders."
        ),
        (kernel_core::Lang::Fr, true) => format!(
            "Cette liste de rappels est incomplète : l'app n'a gardé que les {MAX_ITEMS} \
             premiers rappels."
        ),
    }
}

pub fn validate_snapshot(value: &mut EventKitSnapshot) -> Result<(), &'static str> {
    if value.events.len() > MAX_ITEMS || value.reminders.len() > MAX_ITEMS {
        return Err("too many items");
    }
    if !value.authorized && (!value.events.is_empty() || !value.reminders.is_empty()) {
        return Err("unauthorized snapshot contains items");
    }
    for event in &mut value.events {
        event.title = clean(&event.title, 240);
        event.calendar = clean(&event.calendar, 120);
        event.location = event.location.as_deref().map(|s| clean(s, 240));
        event.id = event
            .id
            .as_deref()
            .map(|value| clean(value, 240))
            .filter(|value| !value.is_empty());
        event.attendees = event.attendees.as_ref().map(|list| {
            list.iter()
                .map(|address| clean(address, 320))
                .filter(|address| !address.trim().is_empty())
                .take(MAX_ATTENDEES)
                .collect()
        });
        event.calendar_id = event
            .calendar_id
            .as_deref()
            .map(|value| clean(value, 240))
            .filter(|value| !value.is_empty());
        let start = checked_instant(&event.start).ok_or("invalid event start date")?;
        let end = checked_instant(&event.end).ok_or("invalid event end date")?;
        if end < start {
            return Err("event ends before it starts");
        }
    }
    for field in [&value.captured_at, &value.covers_from, &value.covers_to] {
        if let Some(text) = field.as_deref() {
            checked_instant(text).ok_or("invalid capture instant")?;
        }
    }
    // The default calendar's id is a name, never an instant: it is only
    // cleaned and bounded, and an empty one is no id at all.
    value.default_calendar_id = value
        .default_calendar_id
        .as_deref()
        .map(|id| clean(id, 240))
        .filter(|id| !id.is_empty());
    if let (Some(from), Some(to)) = (
        instant(value.covers_from.as_deref()),
        instant(value.covers_to.as_deref()),
    ) {
        if to < from {
            return Err("covered window ends before it starts");
        }
    }
    for reminder in &mut value.reminders {
        reminder.title = clean(&reminder.title, 240);
        reminder.list = clean(&reminder.list, 120);
        if let Some(due) = reminder.due.as_deref() {
            checked_instant(due).ok_or("invalid reminder due date")?;
        }
    }
    Ok(())
}

/// Parse an RFC 3339 instant and refuse a value outside
/// [`MIN_INSTANT`]`..=`[`MAX_INSTANT`].
fn checked_instant(value: &str) -> Option<DateTime<Utc>> {
    let instant = DateTime::parse_from_rfc3339(value)
        .ok()?
        .with_timezone(&Utc);
    (MIN_INSTANT..=MAX_INSTANT)
        .contains(&instant.timestamp())
        .then_some(instant)
}

fn clean(value: &str, cap: usize) -> String {
    kernel_broker::sanitize_external_text(value, cap)
}

/// Store a snapshot encrypted, in every mode (B11).
///
/// The snapshot is local data at rest on this Mac, written as an encrypted
/// database and never a plaintext copy, so private mode keeps it too. What a
/// model may see of it is the session gate's job, not this file's.
pub fn save_snapshot(home: &Path, snapshot: &EventKitSnapshot) -> std::io::Result<()> {
    if !snapshot.authorized {
        // Authorization revoked or the integration disabled: keep no personal
        // items at rest, remove the stored snapshot instead of a stub.
        return purge_snapshot(home);
    }
    let body = serde_json::to_string(snapshot).map_err(std::io::Error::other)?;
    if body.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot too large",
        ));
    }
    let gateway = kernel_core::verified_home_or_verify(home)?;
    write_encrypted(&gateway, &body)?;
    // An older build's plaintext copy goes once the encrypted one is in place.
    purge_names(&gateway, [LEGACY_FILE])
}

/// Build the snapshot as a one-row SQLCipher database under the store's
/// derived key, then write its bytes with the sandboxed atomic writer.
///
/// The staging file is created through the gateway, mode 0600 and `O_NOFOLLOW`,
/// after the old copy is swept, so a planted link is never followed. The
/// staging copy is swept whether or not the write succeeded; it holds the same
/// ciphertext as the final file.
fn write_encrypted(gateway: &kernel_core::SandboxHome, body: &str) -> std::io::Result<()> {
    let key = aux_store::store_key(gateway.path()).map_err(std::io::Error::other)?;
    purge_names(gateway, STAGING_FILES)?;
    drop(gateway.open_append(Path::new(STAGING_FILES[0]), 0o600)?);
    let staging = gateway.path().join(STAGING_FILES[0]);
    let stored = seal_database(&staging, &key, body)
        .and_then(|()| std::fs::read(&staging))
        .and_then(|bytes| gateway.write_atomic(Path::new(SNAPSHOT_FILE), &bytes, 0o600));
    purge_names(gateway, STAGING_FILES)?;
    stored
}

/// Write `body` as the one row of a SQLCipher database at `path`, keyed with
/// `key`. The pragmas match the store's own connections: freed pages are wiped
/// and temporary data stays in memory.
fn seal_database(path: &Path, key: &aux_store::Key, body: &str) -> std::io::Result<()> {
    let hex: String = key
        .expose()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let conn = rusqlite::Connection::open(path).map_err(std::io::Error::other)?;
    conn.execute_batch(&format!(
        "PRAGMA key = \"x'{hex}'\"; \
         PRAGMA cipher_memory_security = ON; \
         PRAGMA temp_store = MEMORY; \
         CREATE TABLE snapshot (id INTEGER PRIMARY KEY CHECK (id = 1), body TEXT NOT NULL);"
    ))
    .map_err(std::io::Error::other)?;
    conn.execute("INSERT INTO snapshot (id, body) VALUES (1, ?1)", [body])
        .map_err(std::io::Error::other)?;
    conn.close()
        .map_err(|(_, err)| std::io::Error::other(err))?;
    std::fs::File::open(path)?.sync_all()
}

/// Delete the stored EventKit snapshot and every file beside it, if any.
///
/// Called when authorization is revoked or the integration is off, so no
/// calendar or reminder extract survives on disk.
pub fn purge_snapshot(home: &Path) -> std::io::Result<()> {
    let gateway = kernel_core::verified_home_or_verify(home)?;
    purge_names(
        &gateway,
        DATABASE_FILES
            .into_iter()
            .chain(STAGING_FILES)
            .chain([LEGACY_FILE]),
    )
}

/// The at-rest rule for EventKit: no plaintext copy, in any mode.
///
/// Removes crash leftovers and a legacy plaintext copy, and keeps the
/// encrypted database, in private mode too. Its callers are the daemon start
/// (before the API listens) and the turn path before any privacy refusal.
pub fn sweep_stored(home: &Path) -> std::io::Result<()> {
    let gateway = kernel_core::verified_home_or_verify(home)?;
    purge_names(&gateway, STAGING_FILES.into_iter().chain([LEGACY_FILE]))
}

/// The at-rest watch for EventKit: remove a legacy plaintext copy on every
/// tick, in either mode, so one dropped into the home later does not stay. It
/// leaves the staging files alone, as a save may be building one.
pub fn spawn_at_rest_watch(home: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(crate::privacy_wiring::WATCH_INTERVAL);
        loop {
            tick.tick().await;
            let swept = kernel_core::verified_home_or_verify(&home)
                .and_then(|gateway| purge_names(&gateway, [LEGACY_FILE]));
            if let Err(err) = swept {
                tracing::warn!(error = %err, "EventKit at-rest sweep failed");
            }
        }
    })
}

/// Remove each named file under the verified home: truncate it, then unlink
/// it, so its bytes do not outlive the directory entry. An absent name is
/// skipped.
fn purge_names<'a>(
    gateway: &kernel_core::SandboxHome,
    names: impl IntoIterator<Item = &'a str>,
) -> std::io::Result<()> {
    for name in names {
        let rel = Path::new(name);
        if !gateway.exists_no_follow(rel)? {
            continue;
        }
        let file = gateway.open_append(rel, 0o600)?;
        file.set_len(0)?;
        file.sync_all()?;
        drop(file);
        gateway.remove_file(rel)?;
    }
    Ok(())
}

/// Parse a snapshot as the app publishes it. Every field the app sends is
/// one the daemon keeps — CAL-DEFAULT-ID added the default calendar's id and
/// each event's own calendar id — so the strict shape still refuses every
/// other unknown field.
pub fn parse_published(body: &[u8]) -> Option<EventKitSnapshot> {
    serde_json::from_slice(body).ok()
}

pub(crate) fn read_snapshot(home: &Path) -> Option<EventKitSnapshot> {
    let conn = aux_store::open_keyed_readonly(&snapshot_path(home)).ok()?;
    let body: String = conn
        .query_row("SELECT body FROM snapshot WHERE id = 1", [], |row| {
            row.get(0)
        })
        .ok()?;
    if body.len() as u64 > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let mut snapshot: EventKitSnapshot = serde_json::from_str(&body).ok()?;
    // Re-validate on every read: a snapshot written before the date bounds
    // existed, or planted on disk, must never be served with an out-of-range
    // instant. Rejecting it also purges it, so it cannot be served later.
    if validate_snapshot(&mut snapshot).is_err() {
        let _ = purge_snapshot(home);
        return None;
    }
    Some(snapshot)
}

struct AppleEventKitTool {
    home: PathBuf,
    reminders: bool,
}

impl AppleEventKitTool {
    fn new(home: &Path, reminders: bool) -> Self {
        Self {
            home: home.to_path_buf(),
            reminders,
        }
    }
}

impl NativeTool for AppleEventKitTool {
    fn native_name(&self) -> &'static str {
        if self.reminders {
            "apple_reminders_list"
        } else {
            "apple_calendar_list_events"
        }
    }

    fn native_description(&self) -> &'static str {
        if self.reminders {
            "List the owner's Apple Reminders. Returns the owner's own reminders."
        } else {
            "List the owner's Apple Calendar events. Returns the owner's own events."
        }
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(
            || serde_json::json!({"type":"object","properties":{},"required":[],"additionalProperties":false}),
        );
        std::sync::LazyLock::force(&SCHEMA)
    }
}

/// Titles compare without case, apostrophe style or extra spaces, so two
/// calendars spelling "Heure d'hiver" / "Heure d’hiver" count once.
fn title_key(title: &str) -> String {
    title
        .replace(['\u{2019}', '\u{2018}'], "'")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Merge `other` into `first`, naming every source calendar the copies came
/// from: one public holiday listed by two holiday calendars keeps both names.
fn merge_calendar(first: &mut EventItem, other: &EventItem) {
    if first
        .calendar
        .split(", ")
        .any(|name| name == other.calendar)
    {
        return;
    }
    first.calendar = match first.calendar.is_empty() {
        true => other.calendar.clone(),
        false => format!("{}, {}", first.calendar, other.calendar),
    };
}

/// The same public holiday from two holiday calendars is one row
/// (CAL-DEDUPE-AGENT). Nothing else is: two timed "Review" meetings at the
/// same hour on different calendars are two commitments, so a timed event
/// merges only with a copy carrying the same stable EventKit id (a stale and
/// a fresh read of one event). A timed event with no id is never merged.
fn deduplicated_events(events: &[EventItem]) -> Vec<EventItem> {
    let mut unique: Vec<EventItem> = Vec::with_capacity(events.len());
    for event in events {
        let duplicate = unique.iter_mut().find(|first| {
            if title_key(&event.title) != title_key(&first.title) {
                return false;
            }
            if event.all_day == Some(true)
                && first.all_day == Some(true)
                && event.start.get(..10).is_some()
                && event.start.get(..10) == first.start.get(..10)
            {
                return true;
            }
            matches!(
                (event.id.as_deref(), first.id.as_deref()),
                (Some(event_id), Some(first_id)) if !event_id.is_empty() && event_id == first_id
            )
        });
        match duplicate {
            Some(first) => merge_calendar(first, event),
            None => unique.push(event.clone()),
        }
    }
    unique
}

/// The "access not granted" answer, in the owner's UI language.
fn not_granted(home: &Path) -> &'static str {
    let lang = crate::api::load_config_verified(home)
        .map(|config| config.ui.language)
        .unwrap_or_default();
    match lang {
        kernel_core::Lang::En => "Access not granted. The owner can allow Apple Calendar and Reminders in System Settings.",
        kernel_core::Lang::Fr => "Accès non accordé. La personne propriétaire peut autoriser Calendrier et Rappels Apple dans Réglages.",
    }
}

#[async_trait]
impl Tool for AppleEventKitTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B11
    }
    fn name(&self) -> &str {
        self.native_name()
    }
    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }
    async fn run(&self, args: &serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        if !args.as_object().is_some_and(|map| map.is_empty()) {
            return Err(ToolError::invalid_args(
                self.name(),
                "expected an empty object",
            ));
        }
        let Some(snapshot) = read_snapshot(&self.home).filter(|s| s.authorized) else {
            return Ok(ToolOutput::ok(not_granted(&self.home)));
        };
        let output = if self.reminders {
            serde_json::to_string(&snapshot.reminders)
        } else {
            serde_json::to_string(&deduplicated_events(&snapshot.events))
        }
        .unwrap_or_else(|_| "[]".to_string());
        // CAL-COMPLETE-DEDUP: a list the app cut at its cap is named
        // incomplete before its JSON, so a model never reads it as whole.
        let truncated = match self.reminders {
            true => snapshot.reminders_truncated,
            false => snapshot.events_truncated,
        };
        let mut notes: Vec<String> = Vec::new();
        if truncated {
            notes.push(truncated_note(&self.home, self.reminders));
        }
        // CAL-SNAPSHOT-STALE: a stale copy is never served as current.
        if let Some(note) = stale_note(&self.home, &snapshot) {
            notes.push(note);
        }
        if notes.is_empty() {
            Ok(ToolOutput::ok(output))
        } else {
            Ok(ToolOutput::ok(format!("{}\n{output}", notes.join("\n"))))
        }
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

pub fn register_tools(home: &Path, registry: &mut kernel_broker::ToolRegistry) {
    // Every turn builds its tools here, so a legacy plaintext copy is cleared
    // before any read.
    if let Err(err) = sweep_stored(home) {
        tracing::warn!(error = %err, "EventKit snapshot sweep failed");
    }
    registry.register_native(Box::new(AppleEventKitTool::new(home, false)));
    registry.register_native(Box::new(AppleEventKitTool::new(home, true)));
    registry.mark_read_only("apple_calendar_list_events");
    registry.mark_read_only("apple_reminders_list");
    registry.mark_untrusted_output("apple_calendar_list_events");
    registry.mark_untrusted_output("apple_reminders_list");
    // Explicit class, independent of the tool name and of the name hook.
    registry.mark_private_data("apple_calendar_list_events");
    registry.mark_private_data("apple_reminders_list");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_broker::ToolClassExt;
    use kernel_broker::ToolCtx;

    /// A home whose config is in `mode` and whose store (so its master key)
    /// exists, the way the daemon's first start leaves it.
    fn home_in(mode: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            kernel_core::config_path(dir.path()),
            format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n"),
        )
        .unwrap();
        aux_store::Store::open(&kernel_core::store_path(dir.path())).unwrap();
        dir
    }

    const CANARY_TITLE: &str = "EVENTKIT-CANARY-dentist";
    const CANARY_PHONE: &str = "+33 6 12 34 56 78";

    fn canary_snapshot() -> EventKitSnapshot {
        EventKitSnapshot {
            authorized: true,
            events: vec![EventItem {
                id: None,
                attendees: None,
                calendar_id: None,
                recurring: None,
                title: CANARY_TITLE.into(),
                start: "2026-10-10T09:00:00Z".into(),
                end: "2026-10-10T10:00:00Z".into(),
                all_day: None,
                calendar: "Work".into(),
                location: Some(CANARY_PHONE.into()),
            }],
            reminders: vec![],
            ..Default::default()
        }
    }

    fn calendar_event(
        title: &str,
        start: &str,
        end: &str,
        calendar: &str,
        all_day: bool,
    ) -> EventItem {
        EventItem {
            id: None,
            title: title.to_string(),
            start: start.to_string(),
            end: end.to_string(),
            all_day: Some(all_day),
            calendar: calendar.to_string(),
            location: None,
            attendees: None,
            calendar_id: None,
            recurring: None,
        }
    }

    fn identified_calendar_event(
        id: &str,
        title: &str,
        start: &str,
        end: &str,
        calendar: &str,
        all_day: bool,
    ) -> EventItem {
        EventItem {
            id: Some(id.to_string()),
            ..calendar_event(title, start, end, calendar, all_day)
        }
    }

    #[test]
    fn calendar_tool_dedupe_ignores_apostrophe_style_case_and_spaces() {
        let events = vec![
            calendar_event(
                "Heure d'hiver",
                "2026-10-25T00:00:00Z",
                "2026-10-26T00:00:00Z",
                "Fêtes",
                true,
            ),
            calendar_event(
                "heure  d\u{2019}hiver",
                "2026-10-25T00:00:00Z",
                "2026-10-26T00:00:00Z",
                "Public Holidays",
                true,
            ),
            calendar_event(
                "Heure d'été",
                "2026-10-25T00:00:00Z",
                "2026-10-26T00:00:00Z",
                "Fêtes",
                true,
            ),
        ];
        let unique = deduplicated_events(&events);
        assert_eq!(unique.len(), 2);
        assert!(
            unique[0].calendar.contains("Fêtes") && unique[0].calendar.contains("Public Holidays"),
            "a merged holiday keeps every source calendar: {}",
            unique[0].calendar
        );
    }

    #[test]
    fn calendar_tool_deduplicates_all_day_holidays_but_keeps_distinct_timed_events() {
        let events = vec![
            calendar_event(
                "Jour férié",
                "2026-10-25T00:00:00Z",
                "2026-10-26T00:00:00Z",
                "Public Holidays",
                true,
            ),
            calendar_event(
                "Jour férié",
                "2026-10-25T01:00:00Z",
                "2026-10-26T01:00:00Z",
                "Fêtes",
                true,
            ),
            calendar_event(
                "Review",
                "2026-10-25T09:00:00Z",
                "2026-10-25T10:00:00Z",
                "Work",
                false,
            ),
            calendar_event(
                "Review",
                "2026-10-25T09:00:00Z",
                "2026-10-25T10:00:00Z",
                "Personal",
                false,
            ),
            calendar_event(
                "Review",
                "2026-10-25T11:00:00Z",
                "2026-10-25T12:00:00Z",
                "Personal",
                false,
            ),
        ];

        let unique = deduplicated_events(&events);
        assert_eq!(unique.len(), 4, "{unique:?}");
        assert!(
            unique[0].calendar.contains("Public Holidays") && unique[0].calendar.contains("Fêtes"),
            "both holiday calendars are named: {}",
            unique[0].calendar
        );
        assert_eq!(unique[1].calendar, "Work");
        assert_eq!(unique[2].calendar, "Personal");
        assert_eq!(unique[3].start, "2026-10-25T11:00:00Z");
    }

    /// CAL-COMPLETE-DEDUP: two timed "Review" meetings at the same hour on
    /// different calendars are two commitments, not one copy. The old key
    /// (title + start + end) dropped one and the fact with it.
    #[test]
    fn two_timed_events_at_the_same_hour_on_different_calendars_are_both_kept() {
        let events = vec![
            identified_calendar_event(
                "E-personal",
                "Review",
                "2026-10-25T09:00:00Z",
                "2026-10-25T10:00:00Z",
                "Personal",
                false,
            ),
            identified_calendar_event(
                "E-work",
                "Review",
                "2026-10-25T09:00:00Z",
                "2026-10-25T10:00:00Z",
                "Work",
                false,
            ),
        ];
        let unique = deduplicated_events(&events);
        assert_eq!(unique.len(), 2, "{unique:?}");
        let calendars: Vec<&str> = unique.iter().map(|event| event.calendar.as_str()).collect();
        assert_eq!(calendars, ["Personal", "Work"]);
    }

    /// The same EventKit event read twice (a stale and a fresh copy, or a
    /// move) is one row, and the row names every calendar it was seen on.
    #[test]
    fn copies_of_one_timed_event_merge_and_keep_every_calendar_name() {
        let events = vec![
            identified_calendar_event(
                "E1",
                "Review",
                "2026-10-25T09:00:00Z",
                "2026-10-25T10:00:00Z",
                "Work",
                false,
            ),
            identified_calendar_event(
                "E1",
                "Review",
                "2026-10-25T09:00:00Z",
                "2026-10-25T10:00:00Z",
                "Personal",
                false,
            ),
        ];
        let unique = deduplicated_events(&events);
        assert_eq!(unique.len(), 1, "{unique:?}");
        assert!(
            unique[0].calendar.contains("Work") && unique[0].calendar.contains("Personal"),
            "both source calendars are named: {}",
            unique[0].calendar
        );
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    /// CAL-COMPLETE-DEDUP: a copy the app cut at its cap is named incomplete
    /// in the read, so a model never treats the list as the whole calendar.
    #[tokio::test]
    async fn a_truncated_calendar_list_says_it_is_incomplete() {
        let dir = home_in("open");
        let home = dir.path();
        let now = Utc::now();
        let mut snapshot = canary_snapshot();
        snapshot.events_truncated = true;
        snapshot.captured_at = Some(now.to_rfc3339());
        snapshot.covers_from = Some((now - chrono::Duration::hours(1)).to_rfc3339());
        snapshot.covers_to = Some((now + chrono::Duration::days(8)).to_rfc3339());
        save_snapshot(home, &snapshot).unwrap();
        let tool = AppleEventKitTool::new(home, false);
        let output = tool
            .run(&serde_json::json!({}), &ToolCtx::new("test", home))
            .await
            .unwrap();
        assert!(!output.is_error);
        assert!(
            output.content.contains("incomplete"),
            "the read names the cut list: {}",
            output.content
        );
        assert!(output.content.contains(CANARY_TITLE), "{}", output.content);
    }

    #[test]
    fn private_mode_keeps_the_snapshot_encrypted_at_rest() {
        let dir = home_in("private");
        let home = dir.path();
        save_snapshot(home, &canary_snapshot()).unwrap();
        let on_disk = std::fs::read(snapshot_path(home)).unwrap();
        assert!(!contains(&on_disk, CANARY_TITLE), "plaintext title on disk");
        assert!(!home.join("apple-eventkit.json").exists());
        let read = read_snapshot(home).expect("private mode serves the encrypted snapshot");
        assert_eq!(read.events[0].title, CANARY_TITLE);
    }

    #[test]
    fn open_mode_keeps_the_snapshot_encrypted_at_rest() {
        let dir = home_in("open");
        let home = dir.path();
        save_snapshot(home, &canary_snapshot()).unwrap();
        let on_disk = std::fs::read(snapshot_path(home)).unwrap();
        assert!(!contains(&on_disk, CANARY_TITLE), "plaintext title on disk");
        assert!(!contains(&on_disk, CANARY_PHONE), "plaintext phone on disk");
        assert!(
            !home.join("apple-eventkit.json").exists(),
            "no plaintext JSON file"
        );
        let read = read_snapshot(home).expect("the encrypted snapshot reads back");
        assert_eq!(read.events[0].title, CANARY_TITLE);
    }

    #[test]
    fn sweep_removes_a_legacy_plaintext_snapshot_in_private_mode_and_keeps_the_database() {
        let dir = home_in("private");
        let home = dir.path();
        let legacy = home.join("apple-eventkit.json");
        std::fs::write(&legacy, serde_json::to_vec(&canary_snapshot()).unwrap()).unwrap();
        save_snapshot(home, &canary_snapshot()).unwrap();
        std::fs::write(&legacy, serde_json::to_vec(&canary_snapshot()).unwrap()).unwrap();
        sweep_stored(home).unwrap();
        assert!(!legacy.exists(), "a legacy plaintext snapshot is removed");
        assert!(snapshot_path(home).exists(), "the encrypted database stays");
    }

    #[test]
    fn sweep_keeps_the_encrypted_snapshot_in_open_mode_and_drops_the_legacy_copy() {
        let dir = home_in("open");
        let home = dir.path();
        save_snapshot(home, &canary_snapshot()).unwrap();
        let legacy = home.join("apple-eventkit.json");
        std::fs::write(&legacy, serde_json::to_vec(&canary_snapshot()).unwrap()).unwrap();
        sweep_stored(home).unwrap();
        assert!(!legacy.exists(), "the legacy copy goes in open mode too");
        assert!(snapshot_path(home).exists(), "the encrypted database stays");
    }

    #[test]
    fn a_stored_snapshot_survives_a_switch_to_private_and_a_sweep() {
        let dir = home_in("open");
        let home = dir.path();
        save_snapshot(home, &canary_snapshot()).unwrap();
        std::fs::write(
            kernel_core::config_path(home),
            "version = 1\n\n[privacy]\nmode = \"private\"\n",
        )
        .unwrap();
        sweep_stored(home).unwrap();
        let read = read_snapshot(home).expect("private mode still serves it");
        assert_eq!(read.events[0].title, CANARY_TITLE);
        assert!(snapshot_path(home).exists(), "the stored copy stays");
    }

    #[tokio::test]
    async fn access_is_not_granted_until_the_authenticated_app_publishes_permission() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = kernel_broker::ToolRegistry::new();
        register_tools(dir.path(), &mut registry);
        for name in ["apple_calendar_list_events", "apple_reminders_list"] {
            assert!(registry.is_read_only(name));
            assert!(registry.is_untrusted_output(name));
        }
        let tool = AppleEventKitTool::new(dir.path(), false);
        let output = tool
            .run(&serde_json::json!({}), &ToolCtx::new("test", dir.path()))
            .await
            .unwrap();
        assert!(!output.is_error);
        assert!(
            output.content.starts_with("Access not granted"),
            "English by default"
        );
    }

    #[test]
    fn eventkit_reads_are_private_owner_data() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = kernel_broker::ToolRegistry::new();
        register_tools(dir.path(), &mut registry);
        for name in ["apple_calendar_list_events", "apple_reminders_list"] {
            assert!(registry.is_private_data(name), "{name}");
        }
        // The class is declared by each tool too, not only by the registry set.
        assert!(AppleEventKitTool::new(dir.path(), false).returns_private_data());
        assert!(AppleEventKitTool::new(dir.path(), true).returns_private_data());
    }

    #[test]
    fn a_snapshot_shaped_like_the_apps_is_accepted() {
        let body = br#"{"authorized": true, "reminders": [], "default_calendar_id": "CAL-1",
            "events": [{"id": "E1",
            "title": "Call", "start": "2026-10-31T09:00:00Z", "end": "2026-10-31T10:00:00Z",
            "calendar": "Work", "location": null, "calendar_id": "CAL-1", "all_day": false,
            "attendees": []}]}"#;
        let snapshot = parse_published(body).expect("the app's own shape");
        assert_eq!(snapshot.events[0].id.as_deref(), Some("E1"));
        assert_eq!(snapshot.events[0].attendees, Some(Vec::new()));
        // CAL-COMPLETE-DEDUP: an older payload has no truncation flag, and
        // reads as a list not known to be cut.
        assert!(!snapshot.events_truncated);
        assert!(!snapshot.reminders_truncated);
        let cut = String::from_utf8_lossy(body).replace(
            "\"reminders\": []",
            "\"reminders\": [], \"events_truncated\": true",
        );
        let cut = parse_published(cut.as_bytes()).expect("the cut flag parses");
        assert!(cut.events_truncated);
        assert!(!cut.reminders_truncated);
        // CAL-DEFAULT-ID: the calendar ids are kept, not dropped.
        assert_eq!(snapshot.default_calendar_id.as_deref(), Some("CAL-1"));
        assert_eq!(snapshot.events[0].calendar_id.as_deref(), Some("CAL-1"));
        let planted = String::from_utf8_lossy(body).replace("calendar_id", "surprise");
        assert!(parse_published(planted.as_bytes()).is_none());
        // CAL-DEFAULT-ID: a copy from a build before the ids still parses; the
        // calendar is then unknown, never the default one.
        let old = String::from_utf8_lossy(body).replace("\"default_calendar_id\": \"CAL-1\",", "");
        let old = parse_published(old.as_bytes()).expect("an older payload still parses");
        assert_eq!(old.default_calendar_id, None);
        assert_eq!(old.events[0].calendar_id.as_deref(), Some("CAL-1"));
    }

    #[test]
    fn snapshot_is_bounded_and_external_text_is_cleaned() {
        let mut value = EventKitSnapshot {
            authorized: true,
            events: vec![EventItem {
                id: None,
                attendees: None,
                calendar_id: None,
                recurring: None,
                title: "meeting\u{202e}\u{0007}".into(),
                start: "2026-10-08T09:00:00Z".into(),
                end: "2026-10-08T10:00:00Z".into(),
                all_day: None,
                calendar: "Work".into(),
                location: Some("Room\u{2066}A\u{2069}".into()),
            }],
            reminders: vec![],
            ..Default::default()
        };
        validate_snapshot(&mut value).unwrap();
        assert!(!value.events[0].title.contains('\u{202e}'));
        assert!(!value.events[0].title.contains('\u{0007}'));
        assert!(!value.events[0]
            .location
            .as_ref()
            .unwrap()
            .contains('\u{2066}'));
        value.events = vec![value.events[0].clone(); MAX_ITEMS + 1];
        assert!(validate_snapshot(&mut value).is_err());
    }

    #[test]
    fn snapshot_dates_are_bounded_and_ordered() {
        let base = EventKitSnapshot {
            authorized: true,
            events: vec![EventItem {
                id: None,
                attendees: None,
                calendar_id: None,
                recurring: None,
                title: "meeting".into(),
                start: "2026-10-08T09:00:00Z".into(),
                end: "2026-10-08T10:00:00Z".into(),
                all_day: None,
                calendar: "Work".into(),
                location: None,
            }],
            reminders: vec![],
            ..Default::default()
        };
        let mut valid = base.clone();
        assert!(validate_snapshot(&mut valid).is_ok());

        // The end must not precede the start.
        let mut reversed = base.clone();
        reversed.events[0].end = "2026-10-08T08:00:00Z".into();
        assert!(validate_snapshot(&mut reversed).is_err());

        // Unparseable and absurd instants are refused on either end.
        for bad in [
            "",
            "not-a-date",
            "2999-01-01T00:00:00Z",
            "1999-12-31T23:59:59Z",
        ] {
            let mut value = base.clone();
            value.events[0].start = bad.into();
            assert!(
                validate_snapshot(&mut value).is_err(),
                "start {bad:?} must be refused"
            );
            let mut value = base.clone();
            value.events[0].end = bad.into();
            assert!(
                validate_snapshot(&mut value).is_err(),
                "end {bad:?} must be refused"
            );
        }

        // A reminder due date takes the same bounds; `None` stays allowed.
        let mut reminder = base.clone();
        reminder.reminders = vec![ReminderItem {
            title: "pay rent".into(),
            due: Some("2026-10-09T12:00:00Z".into()),
            list: "Home".into(),
            completed: false,
        }];
        assert!(validate_snapshot(&mut reminder).is_ok());
        reminder.reminders[0].due = Some("0001-01-01T00:00:00Z".into());
        assert!(validate_snapshot(&mut reminder).is_err());
        reminder.reminders[0].due = None;
        assert!(validate_snapshot(&mut reminder).is_ok());
    }

    #[test]
    fn revoked_or_disabled_authorization_purges_the_snapshot() {
        let dir = home_in("open");
        let home = dir.path();
        let mut authorised = EventKitSnapshot {
            authorized: true,
            events: vec![EventItem {
                id: None,
                attendees: None,
                calendar_id: None,
                recurring: None,
                title: "private meeting".into(),
                start: "2026-10-08T09:00:00Z".into(),
                end: "2026-10-08T10:00:00Z".into(),
                all_day: None,
                calendar: "Work".into(),
                location: None,
            }],
            reminders: vec![],
            ..Default::default()
        };
        validate_snapshot(&mut authorised).unwrap();
        save_snapshot(home, &authorised).unwrap();
        assert!(read_snapshot(home).is_some());

        let revoked = EventKitSnapshot {
            authorized: false,
            events: vec![],
            reminders: vec![],
            ..Default::default()
        };
        save_snapshot(home, &revoked).unwrap();
        assert!(
            read_snapshot(home).is_none(),
            "a revoked snapshot must be purged from disk"
        );
        // `snapshot_path` must resolve to the one file the reader and writer use.
        assert_eq!(snapshot_path(home), home.join(SNAPSHOT_FILE));
        assert!(!snapshot_path(home).exists());

        // Purging an already-absent snapshot stays a no-op, not an error.
        purge_snapshot(home).unwrap();
    }

    #[test]
    fn stale_out_of_bounds_snapshot_is_never_served_and_is_purged() {
        let dir = home_in("open");
        let home = dir.path();
        // Write directly, bypassing validation: this is what an old on-disk
        // snapshot (written before the bounds existed) looks like.
        let stale = EventKitSnapshot {
            authorized: true,
            events: vec![EventItem {
                id: None,
                attendees: None,
                calendar_id: None,
                recurring: None,
                title: "planted".into(),
                start: "2999-01-01T00:00:00Z".into(),
                end: "2999-01-01T01:00:00Z".into(),
                all_day: None,
                calendar: "Work".into(),
                location: None,
            }],
            reminders: vec![],
            ..Default::default()
        };
        save_snapshot(home, &stale).unwrap();
        assert!(snapshot_path(home).exists());
        assert!(
            read_snapshot(home).is_none(),
            "an out-of-bounds date must never be served to a model"
        );
        assert!(
            !snapshot_path(home).exists(),
            "the rejected snapshot must be purged, not left to be retried"
        );

        // A valid snapshot keeps reading back.
        let mut valid = EventKitSnapshot {
            authorized: true,
            events: vec![EventItem {
                id: None,
                attendees: None,
                calendar_id: None,
                recurring: None,
                title: "meeting".into(),
                start: "2026-10-08T09:00:00Z".into(),
                end: "2026-10-08T10:00:00Z".into(),
                all_day: None,
                calendar: "Work".into(),
                location: None,
            }],
            reminders: vec![],
            ..Default::default()
        };
        validate_snapshot(&mut valid).unwrap();
        save_snapshot(home, &valid).unwrap();
        assert!(read_snapshot(home).is_some());
    }
}
