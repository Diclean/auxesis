//! Routines: recurring agent jobs the owner creates and manages (WO-ROUTINES-1).
//!
//! A routine is a normal `agent` job (`{"kind":"agent","prompt":…}`) in the
//! `jobs` table, so a run is exactly one scheduled agent turn: it goes through
//! the gate, and every `ask` is denied because nobody is there to answer.
//!
//! | Method | Path | Meaning |
//! |---|---|---|
//! | POST | `/v1/jobs` | `{agent, name, schedule, prompt}` → `201` with the job row |
//! | PATCH | `/v1/jobs/{id}` | `{enabled}` pauses or resumes |
//! | DELETE | `/v1/jobs/{id}` | removes the routine and its run history |
//!
//! Only `agent` jobs are managed here; the morning brief and the CRM timeline
//! refresh answer `403 system_job`. Each write is audited with the name and
//! schedule, never the prompt.
//!
//! # Schedule grammar (local time zone of the Mac)
//!
//! `every <N>m|h` · `daily HH:MM` · `weekdays HH:MM` · `weekly <mon..sun> HH:MM`
//! · a 5-field cron expression (`0 9 * * 1`: lists, ranges and steps, no
//! names). Nothing may fire more often than every [`MIN_INTERVAL_MINUTES`].

use std::path::Path;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{
    DateTime, Datelike, Days, Duration, Local, LocalResult, NaiveDate, TimeZone, Timelike, Utc,
};
use kernel_core::job::{Schedule, ScheduleError};
use serde::Deserialize;

use aux_store::{Job, Store, StoreError};

use super::error;
use super::routes::read_body;
use super::snapshot::JobJson;
use super::ApiState;

/// Shortest gap allowed between two runs of a routine.
pub const MIN_INTERVAL_MINUTES: i64 = 5;

/// Most routines the owner may keep.
const MAX_ROUTINES: usize = 50;

/// Longest routine name (characters) and prompt (bytes).
const MAX_NAME_CHARS: usize = 80;
const MAX_PROMPT_BYTES: usize = 8_192;

/// Longest schedule string accepted (bytes).
const MAX_SCHEDULE_BYTES: usize = 64;

/// Names the system jobs own; a routine may not take them.
const RESERVED_NAMES: [&str; 2] = ["morning-brief", crate::crm::TIMELINE_JOB];

/// How far ahead a calendar schedule looks for its next day (≈ 8 years, so
/// `0 0 29 2 *` still resolves).
const LOOKAHEAD_DAYS: u64 = 366 * 8;

/// Occurrences sampled to prove a calendar schedule keeps the minimum gap.
const GAP_SAMPLES: usize = 64;

const GRAMMAR: &str = "unsupported schedule: use `every 30m`, `daily 08:30`, `weekdays 09:00`, \
                       `weekly mon 09:00` or a 5-field cron expression like `0 9 * * 1`";

const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// A parsed routine schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutineSchedule {
    /// `every …` and `daily …`, as the kernel scheduler has always parsed them.
    Basic(Schedule),
    /// `weekdays …`, `weekly …` and cron expressions.
    Calendar(Calendar),
}

/// A cron-style calendar: one bit per allowed minute, hour, day, month, weekday.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calendar {
    minutes: u64,
    hours: u64,
    days: u64,
    months: u64,
    weekdays: u64,
    /// The day-of-month / weekday field started with `*`. When both are
    /// restricted, either may match (classic cron); otherwise both must.
    any_day: bool,
    any_weekday: bool,
}

impl RoutineSchedule {
    /// Parse any supported schedule. Errors are one-line, owner-readable.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.len() > MAX_SCHEDULE_BYTES {
            return Err(format!(
                "schedule is longer than {MAX_SCHEDULE_BYTES} bytes"
            ));
        }
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        let head = words.first().map(|w| w.to_ascii_lowercase());
        let calendar = match (head.as_deref(), words.as_slice()) {
            (Some("weekdays"), [_, time]) => Calendar::at(time, "1-5")?,
            (Some("weekly"), [_, day, time]) => {
                let day = DAYS
                    .iter()
                    .position(|name| name.eq_ignore_ascii_case(day))
                    .ok_or_else(|| format!("unknown weekday {day:?}: use mon, tue, … sun"))?;
                Calendar::at(time, &day.to_string())?
            }
            (_, [m, h, d, mo, w]) => Calendar::cron(m, h, d, mo, w)?,
            _ => {
                return Schedule::parse(trimmed)
                    .map(Self::Basic)
                    .map_err(|error| match error {
                        ScheduleError::Unsupported(_) => GRAMMAR.to_string(),
                        other => other.to_string(),
                    })
            }
        };
        Ok(Self::Calendar(calendar))
    }

    /// Next occurrence strictly after `after`.
    pub fn next_after_utc(&self, after: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            Self::Basic(schedule) => schedule.next_after_utc(after),
            // Unreachable for a validated schedule; stay total.
            Self::Calendar(calendar) => calendar
                .next_after_in(after, Local)
                .unwrap_or(after + Duration::days(1)),
        }
    }

    /// The run after one that started at `started`, computed from `now`. A
    /// calendar occurrence closer than the minimum interval to `started` (a
    /// DST gap folding two wall-clock times together) is skipped, so the
    /// floor holds on every transition, not only the sampled ones.
    pub fn next_after_run(&self, started: DateTime<Utc>, now: DateTime<Utc>) -> DateTime<Utc> {
        self.next_after_run_in(started, now, Local)
    }

    /// [`Self::next_after_run`] in an explicit zone, for deterministic DST
    /// tests. Basic interval schedules are elapsed-time and ignore the zone.
    pub(crate) fn next_after_run_in<Tz: TimeZone + Copy>(
        &self,
        started: DateTime<Utc>,
        now: DateTime<Utc>,
        tz: Tz,
    ) -> DateTime<Utc> {
        match self {
            Self::Calendar(calendar) => calendar.next_after_run_in(started, now, tz),
            Self::Basic(_) => self.next_after_utc(now),
        }
    }

    /// Check the minimum interval and return the first run after `now`.
    fn first_run(&self, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
        let min = Duration::minutes(MIN_INTERVAL_MINUTES);
        let too_often =
            format!("a routine may not run more often than every {MIN_INTERVAL_MINUTES} minutes");
        match self {
            Self::Basic(Schedule::Interval { period }) if *period < min => Err(too_often),
            Self::Basic(_) => Ok(self.next_after_utc(now)),
            Self::Calendar(calendar) => {
                let never = || "this schedule never fires".to_string();
                let first = calendar.next_after_in(now, Local).ok_or_else(never)?;
                let mut at = first;
                for _ in 0..GAP_SAMPLES {
                    let next = calendar.next_after_in(at, Local).ok_or_else(never)?;
                    if next - at < min {
                        return Err(too_often);
                    }
                    at = next;
                }
                Ok(first)
            }
        }
    }
}

impl Calendar {
    /// Every matching day at one `HH:MM`.
    fn at(time: &str, weekdays: &str) -> Result<Self, String> {
        let (hour, minute) = time
            .split_once(':')
            .ok_or_else(|| format!("invalid time {time:?}: expected HH:MM"))?;
        Self::cron(minute, hour, "*", "*", weekdays)
    }

    fn cron(m: &str, h: &str, d: &str, mo: &str, w: &str) -> Result<Self, String> {
        let weekdays = field(w, 0, 7)?;
        Ok(Self {
            minutes: field(m, 0, 59)?.0,
            hours: field(h, 0, 23)?.0,
            days: field(d, 1, 31)?.0,
            months: field(mo, 1, 12)?.0,
            // 7 is Sunday too.
            weekdays: weekdays.0 | (weekdays.0 >> 7 & 1),
            any_day: d.starts_with('*'),
            any_weekday: weekdays.1,
        })
    }

    fn day_matches(&self, date: NaiveDate) -> bool {
        let bit = |mask: u64, n: u32| mask >> n & 1 == 1;
        let day = bit(self.days, date.day());
        let weekday = bit(self.weekdays, date.weekday().num_days_from_sunday());
        bit(self.months, date.month())
            && if self.any_day || self.any_weekday {
                day && weekday
            } else {
                day || weekday
            }
    }

    /// The next calendar run after a start. For schedules pinned to one or
    /// more hours, the first copy of a repeated wall-clock slot covers the
    /// second copy in a fold. Schedules spanning every hour remain elapsed-
    /// time schedules through the fold (for example `*/5 * * * *`).
    fn next_after_run_in<Tz: TimeZone + Copy>(
        &self,
        started: DateTime<Utc>,
        now: DateTime<Utc>,
        tz: Tz,
    ) -> DateTime<Utc> {
        let floor = started + Duration::minutes(MIN_INTERVAL_MINUTES);
        let mut next = self
            .next_after_in(now, tz)
            .unwrap_or(now + Duration::days(1));
        if next < floor {
            // `floor - 1 s` keeps an occurrence that lands exactly on the floor; a
            // sub-second `started` can still put that candidate just before it.
            next = self
                .next_after_in(floor - Duration::seconds(1), tz)
                .unwrap_or(floor + Duration::days(1));
            if next < floor {
                next = self
                    .next_after_in(floor, tz)
                    .unwrap_or(floor + Duration::days(1));
            }
        }

        let every_hour = self.hours == ((1u64 << 24) - 1);
        let started_local = started.with_timezone(&tz).naive_local();
        let next_local = next.with_timezone(&tz).naive_local();
        if !every_hour
            && next_local.date() == started_local.date()
            && next_local.hour() == started_local.hour()
            && next_local.minute() == started_local.minute()
            && matches!(
                tz.from_local_datetime(&started_local),
                LocalResult::Ambiguous(_, _)
            )
        {
            return self
                .next_after_in(next, tz)
                .unwrap_or(next + Duration::days(1));
        }
        next
    }

    /// Next local wall-clock match strictly after `after`. In a DST fold, use
    /// the first occurrence that is still in the future; in a gap, move to
    /// the first valid local minute after the missing wall time.
    fn next_after_in<Tz: TimeZone>(&self, after: DateTime<Utc>, tz: Tz) -> Option<DateTime<Utc>> {
        let first = after.with_timezone(&tz).date_naive();
        let set = |mask: u64| (0..64u32).filter(move |bit| mask >> bit & 1 == 1);
        for offset in 0..LOOKAHEAD_DAYS {
            let date = first.checked_add_days(Days::new(offset))?;
            if !self.day_matches(date) {
                continue;
            }
            let mut next_on_date = None;
            for hour in set(self.hours) {
                for minute in set(self.minutes) {
                    let naive = date.and_hms_opt(hour, minute, 0)?;
                    let candidates = match tz.from_local_datetime(&naive) {
                        LocalResult::Single(at) => vec![at.to_utc()],
                        LocalResult::Ambiguous(a, b) => vec![a.to_utc(), b.to_utc()],
                        LocalResult::None => {
                            // Calendar precision is one minute. Probe to the
                            // transition boundary rather than assuming a one-hour gap.
                            let mut next_valid = naive;
                            let mut resolved = None;
                            for _ in 0..=24 * 60 {
                                next_valid += Duration::minutes(1);
                                match tz.from_local_datetime(&next_valid) {
                                    LocalResult::Single(at) => {
                                        resolved = Some(vec![at.to_utc()]);
                                        break;
                                    }
                                    LocalResult::Ambiguous(a, b) => {
                                        resolved = Some(vec![a.to_utc(), b.to_utc()]);
                                        break;
                                    }
                                    LocalResult::None => {}
                                }
                            }
                            resolved.unwrap_or_default()
                        }
                    };
                    if let Some(at) = candidates.into_iter().filter(|at| *at > after).min() {
                        next_on_date =
                            Some(next_on_date.map_or(at, |next: DateTime<Utc>| next.min(at)));
                    }
                }
            }
            if next_on_date.is_some() {
                return next_on_date;
            }
        }
        None
    }
}

/// One cron field: `*`, `a`, `a-b`, `*/n`, `a-b/n`, `a/n`, comma-separated.
/// Returns the allowed values as a bit mask and whether it started with `*`.
fn field(raw: &str, min: u32, max: u32) -> Result<(u64, bool), String> {
    let bad = || format!("invalid cron field {raw:?}: expected values {min}-{max}");
    let number = |text: &str| -> Result<u32, String> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        text.parse().map_err(|_| bad())
    };
    let mut mask = 0u64;
    for part in raw.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => (range, number(step).ok().filter(|s| *s > 0).ok_or_else(bad)?),
            None => (part, 1),
        };
        let (low, high) = match range.split_once('-') {
            _ if range == "*" => (min, max),
            Some((low, high)) => (number(low)?, number(high)?),
            None if part.contains('/') => (number(range)?, max),
            None => (number(range)?, number(range)?),
        };
        if low < min || high > max || low > high {
            return Err(bad());
        }
        (low..=high)
            .step_by(step as usize)
            .for_each(|value| mask |= 1 << value);
    }
    Ok((mask, raw.starts_with('*')))
}

// ---------------------------------------------------------------------------
// the shared write path (HTTP and the chat tools)
// ---------------------------------------------------------------------------

/// Why a routine write was refused.
#[derive(Debug)]
pub struct RoutineError {
    /// HTTP status the API answers.
    pub status: StatusCode,
    /// Stable machine code.
    pub code: &'static str,
    /// One-line owner-readable reason.
    pub message: String,
}

fn refuse(status: StatusCode, code: &'static str, message: impl Into<String>) -> RoutineError {
    RoutineError {
        status,
        code,
        message: message.into(),
    }
}

fn invalid(code: &'static str, message: impl Into<String>) -> RoutineError {
    refuse(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

fn store_failed(err: StoreError) -> RoutineError {
    tracing::error!(error = %err, "routine store write failed");
    refuse(
        StatusCode::INTERNAL_SERVER_ERROR,
        "routine_write_failed",
        "the change could not be saved",
    )
}

/// True for the jobs this API manages: plain `agent` jobs. The morning brief,
/// the CRM timeline refresh and any payload we cannot read stay untouchable.
pub fn is_routine(job: &Job) -> bool {
    serde_json::from_str::<serde_json::Value>(&job.payload)
        .ok()
        .and_then(|payload| {
            let kind = payload.get("kind")?.as_str()?;
            Some(kind == "agent" || kind == crate::watch::KIND)
        })
        .unwrap_or(false)
}

fn timestamp(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// The audit row: name and schedule only, never the prompt.
fn audit(store: &Store, kind: &str, job: &Job) {
    let payload = serde_json::json!({
        "id": job.id, "agent": job.agent, "name": job.name,
        "schedule": job.schedule, "enabled": job.enabled,
    });
    if let Err(err) = store.log_event(kind, &payload.to_string()) {
        tracing::warn!(kind, error = %err, "routine audit failed");
    }
}

/// Validate and create a routine with a ready payload (an agent prompt or a
/// watcher); returns the stored row with `next_run_at`.
pub fn create_routine(
    home: &Path,
    store: &Store,
    agent: &str,
    name: &str,
    schedule: &str,
    payload: &str,
) -> Result<Job, RoutineError> {
    let name = name.trim();
    if aux_engine::validate_agent(agent).is_err() || !crate::agent::exists(home, agent) {
        return Err(invalid("invalid_agent", "that agent does not exist"));
    }
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(invalid(
            "invalid_name",
            format!("name must be 1-{MAX_NAME_CHARS} printable characters"),
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(invalid("invalid_name", "that name belongs to a system job"));
    }
    let schedule = schedule.trim();
    let first_run = RoutineSchedule::parse(schedule)
        .and_then(|parsed| parsed.first_run(Utc::now()))
        .map_err(|message| invalid("invalid_schedule", message))?;

    let jobs = store.list_jobs().map_err(store_failed)?;
    if jobs.iter().any(|job| job.name == name) {
        return Err(refuse(
            StatusCode::CONFLICT,
            "duplicate_name",
            "a job with that name already exists",
        ));
    }
    if jobs.iter().filter(|job| is_routine(job)).count() >= MAX_ROUTINES {
        return Err(refuse(
            StatusCode::CONFLICT,
            "too_many_routines",
            format!("at most {MAX_ROUTINES} routines"),
        ));
    }
    let job = store
        .create_job(agent, name, schedule, payload, Some(&timestamp(first_run)))
        .map_err(store_failed)?;
    audit(store, "routine.created", &job);
    Ok(job)
}

/// The routine `id`, or the reason it cannot be managed.
fn managed(store: &Store, id: i64) -> Result<Job, RoutineError> {
    let job = store
        .job_by_id(id)
        .map_err(store_failed)?
        .ok_or_else(|| refuse(StatusCode::NOT_FOUND, "job_not_found", "no such job"))?;
    if is_routine(&job) {
        Ok(job)
    } else {
        Err(refuse(
            StatusCode::FORBIDDEN,
            "system_job",
            "system jobs cannot be edited or deleted here",
        ))
    }
}

/// Pause or resume a routine. Resuming recomputes the next run from now, so
/// a long pause never fires a stale occurrence at once.
pub fn set_routine_enabled(store: &Store, id: i64, enabled: bool) -> Result<Job, RoutineError> {
    let job = managed(store, id)?;
    store.set_job_enabled(id, enabled).map_err(store_failed)?;
    if let (true, Ok(schedule)) = (enabled, RoutineSchedule::parse(&job.schedule)) {
        // The floor still holds against the last start: a pause and resume
        // never fit a run within the minimum interval of the previous one.
        let now = Utc::now();
        let last_start = job.last_run_at.as_deref().and_then(|at| {
            chrono::NaiveDateTime::parse_from_str(at, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|at| at.and_utc())
        });
        let next = timestamp(match last_start {
            Some(started) => schedule.next_after_run(started, now),
            None => schedule.next_after_utc(now),
        });
        store
            .reschedule_job(id, job.last_run_at.as_deref(), Some(&next))
            .map_err(store_failed)?;
    }
    let job = store.job_by_id(id).map_err(store_failed)?.unwrap_or(job);
    audit(store, "routine.updated", &job);
    Ok(job)
}

/// Delete a routine and its run history.
pub fn delete_routine(store: &Store, id: i64) -> Result<Job, RoutineError> {
    let job = managed(store, id)?;
    store.delete_job(id).map_err(store_failed)?;
    audit(store, "routine.deleted", &job);
    Ok(job)
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoutine {
    agent: String,
    name: String,
    schedule: String,
    prompt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchRoutine {
    enabled: bool,
}

fn view(job: &Job) -> JobJson {
    JobJson {
        id: job.id,
        agent: job.agent.clone(),
        name: job.name.clone(),
        schedule: job.schedule.clone(),
        enabled: job.enabled,
        next_run_at: job.next_run_at.clone(),
        last_run_at: job.last_run_at.clone(),
        // Write responses do not re-read the run history; GET /v1/jobs does.
        health: crate::job_health::HealthState::Unknown.as_str().to_string(),
        reason: None,
        reason_kind: None,
        reason_at: None,
    }
}

/// Open the store through the verified home, run `work`, map its refusal.
#[allow(clippy::result_large_err)]
async fn blocking(
    state: &ApiState,
    work: impl FnOnce(&Path, &Store) -> Result<Job, RoutineError> + Send + 'static,
) -> Result<Job, Response> {
    let (home, db_path) = (state.home.clone(), state.db_path.clone());
    let result = tokio::task::spawn_blocking(move || {
        let home_path = db_path.parent().unwrap_or(&db_path);
        let store = kernel_core::verified_home_or_verify(home_path)
            .map_err(StoreError::from)
            .and_then(|verified| Store::open_verified(&verified))
            .map_err(store_failed)?;
        work(&home, &store)
    })
    .await;
    match result {
        Ok(Ok(job)) => Ok(job),
        Ok(Err(e)) => Err(error::error_response(e.status, e.code, e.message, None)),
        Err(_) => Err(error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "routine_write_failed",
            "the change could not be saved",
            None,
        )),
    }
}

fn bad_json(hint: &'static str) -> Response {
    error::error_response(StatusCode::BAD_REQUEST, "invalid_json", hint, None)
}

/// `POST /v1/jobs`.
pub async fn create(
    State(state): State<Arc<ApiState>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Ok(request) = serde_json::from_slice::<CreateRoutine>(&body) else {
        return bad_json("the body must be {agent, name, schedule, prompt}, all strings");
    };
    let work = move |home: &Path, store: &Store| {
        let prompt = request.prompt.trim();
        if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES {
            let message = format!("prompt must be 1-{MAX_PROMPT_BYTES} bytes");
            return Err(invalid("invalid_prompt", message));
        }
        let payload = serde_json::json!({"kind": "agent", "prompt": prompt}).to_string();
        create_routine(
            home,
            store,
            &request.agent,
            &request.name,
            &request.schedule,
            &payload,
        )
    };
    match blocking(&state, work).await {
        Ok(job) => (StatusCode::CREATED, Json(view(&job))).into_response(),
        Err(response) => response,
    }
}

/// `PATCH /v1/jobs/{id}`.
pub async fn update(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<i64>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Ok(request) = serde_json::from_slice::<PatchRoutine>(&body) else {
        return bad_json("the body must be {enabled: true|false}");
    };
    match blocking(&state, move |_, store| {
        set_routine_enabled(store, id, request.enabled)
    })
    .await
    {
        Ok(job) => Json(view(&job)).into_response(),
        Err(response) => response,
    }
}

/// `DELETE /v1/jobs/{id}`.
pub async fn delete(State(state): State<Arc<ApiState>>, AxumPath(id): AxumPath<i64>) -> Response {
    match blocking(&state, move |_, store| delete_routine(store, id)).await {
        Ok(job) => Json(serde_json::json!({"id": job.id, "deleted": true})).into_response(),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDateTime, Weekday};

    fn local(at: DateTime<Utc>) -> NaiveDateTime {
        at.with_timezone(&Local).naive_local()
    }

    fn next(raw: &str, after: DateTime<Utc>) -> NaiveDateTime {
        local(RoutineSchedule::parse(raw).unwrap().next_after_utc(after))
    }

    fn utc(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw).unwrap().to_utc()
    }

    #[test]
    fn resuming_right_after_a_run_keeps_the_floor() {
        let store = Store::open_in_memory().unwrap();
        let started = utc("2026-10-24T12:00:00Z");
        let job = store
            .create_job(
                "main",
                "tick",
                "* * * * *",
                r#"{"kind":"agent","prompt":"hi"}"#,
                None,
            )
            .unwrap();
        store
            .reschedule_job(job.id, Some(&timestamp(started)), None)
            .unwrap();
        set_routine_enabled(&store, job.id, false).unwrap();
        let resumed = set_routine_enabled(&store, job.id, true).unwrap();
        let next = chrono::NaiveDateTime::parse_from_str(
            resumed.next_run_at.as_deref().unwrap(),
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap()
        .and_utc();
        assert!(next >= started + Duration::minutes(MIN_INTERVAL_MINUTES) - Duration::seconds(1));
    }

    #[test]
    fn a_calendar_run_never_follows_the_last_start_within_the_floor() {
        let schedule = RoutineSchedule::parse("* * * * *").unwrap();
        let minute = utc("2026-10-24T12:00:00Z");
        for started in [1, 250, 500, 999].map(|ms| minute + Duration::milliseconds(ms)) {
            let next = schedule.next_after_run(started, started + Duration::seconds(30));
            assert!(next >= started + Duration::minutes(MIN_INTERVAL_MINUTES));
            assert!(next < started + Duration::minutes(MIN_INTERVAL_MINUTES + 1));
        }
    }

    #[test]
    fn calendar_minute_schedule_advances_through_both_dst_folds() {
        let schedule = match RoutineSchedule::parse("* * * * *").unwrap() {
            RoutineSchedule::Calendar(calendar) => calendar,
            _ => unreachable!(),
        };
        let cases = [
            (chrono_tz::Europe::Paris, "2026-10-25T00:30:00Z"),
            (chrono_tz::Europe::Paris, "2026-10-25T00:59:00Z"),
            (chrono_tz::Europe::Paris, "2026-10-25T01:00:00Z"),
            (chrono_tz::Europe::Paris, "2026-10-25T01:30:00Z"),
            (chrono_tz::America::New_York, "2026-11-01T05:30:00Z"),
            (chrono_tz::America::New_York, "2026-11-01T05:59:00Z"),
            (chrono_tz::America::New_York, "2026-11-01T06:00:00Z"),
            (chrono_tz::America::New_York, "2026-11-01T06:30:00Z"),
        ];
        for (zone, raw) in cases {
            let after = utc(raw);
            assert_eq!(
                schedule.next_after_in(after, zone).unwrap(),
                after + Duration::minutes(1),
                "zone={zone}, after={after}"
            );
        }
    }

    #[test]
    fn fixed_wall_clock_schedules_fire_once_at_the_first_copy_in_dst_folds() {
        let cases = [
            (
                chrono_tz::Europe::Paris,
                "0 2 * * *",
                "2026-10-25T00:00:00Z",
                "2026-10-25T01:00:00Z",
                "2026-10-26T01:00:00Z",
            ),
            (
                chrono_tz::America::New_York,
                "0 1 * * *",
                "2026-11-01T05:00:00Z",
                "2026-11-01T06:00:00Z",
                "2026-11-02T06:00:00Z",
            ),
            (
                chrono_tz::Europe::Paris,
                "30 2 * * *",
                "2026-10-25T00:30:00Z",
                "2026-10-25T01:30:00Z",
                "2026-10-26T01:30:00Z",
            ),
            (
                chrono_tz::America::New_York,
                "30 1 * * *",
                "2026-11-01T05:30:00Z",
                "2026-11-01T06:30:00Z",
                "2026-11-02T06:30:00Z",
            ),
        ];

        for (zone, raw, first, second, next_day) in cases {
            let schedule = match RoutineSchedule::parse(raw).unwrap() {
                RoutineSchedule::Calendar(calendar) => calendar,
                _ => unreachable!(),
            };
            let started = utc(first) + Duration::seconds(37);
            assert_eq!(
                schedule.next_after_run_in(started, started + Duration::minutes(5), zone),
                utc(next_day),
                "schedule={raw}, zone={zone}, second={second}"
            );
        }
    }

    #[test]
    fn calendar_schedule_moves_to_the_first_valid_minute_after_dst_gaps() {
        let parse = |raw| match RoutineSchedule::parse(raw).unwrap() {
            RoutineSchedule::Calendar(calendar) => calendar,
            _ => unreachable!(),
        };
        let every_minute = parse("* * * * *");
        let paris_gap = utc("2026-03-29T00:59:00Z");
        assert_eq!(
            every_minute
                .next_after_in(paris_gap, chrono_tz::Europe::Paris)
                .unwrap(),
            utc("2026-03-29T01:00:00Z")
        );
        let ny_gap = utc("2026-03-08T06:59:00Z");
        assert_eq!(
            every_minute
                .next_after_in(ny_gap, chrono_tz::America::New_York)
                .unwrap(),
            utc("2026-03-08T07:00:00Z")
        );

        // The configured 02:30 wall time does not exist. It moves to 03:00,
        // the first valid local minute, instead of assuming a one-hour offset.
        assert_eq!(
            parse("30 2 * * *")
                .next_after_in(utc("2026-03-29T00:00:00Z"), chrono_tz::Europe::Paris)
                .unwrap(),
            utc("2026-03-29T01:00:00Z")
        );
    }

    #[test]
    fn every_documented_form_parses_and_the_rest_is_refused() {
        for ok in [
            "every 5m",
            "EVERY 2h",
            "daily 08:30",
            "weekdays 9:00",
            "weekly SUN 23:59",
            "0 9 * * 1",
            "*/15 9-17 * * 1-5",
            "0 0 1,15 * 7",
        ] {
            assert!(RoutineSchedule::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "hourly",
            "weekly 09:00",
            "weekly mon",
            "weekdays 24:00",
            "0 9 * *",
            "60 9 * * *",
            "0 9 * * 8",
            "*/0 * * * *",
            "1- 9 * * *",
            "0 9 * * mon",
            &"x".repeat(65),
        ] {
            assert!(RoutineSchedule::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn calendar_schedules_land_on_local_wall_clock_times() {
        let after = utc("2026-06-15T12:00:00Z");
        let monday = next("weekly mon 09:00", after);
        assert_eq!(
            (monday.weekday(), monday.hour(), monday.minute()),
            (Weekday::Mon, 9, 0)
        );
        let weekday = next("weekdays 07:45", after);
        assert!(
            weekday.weekday().num_days_from_monday() < 5
                && (weekday.hour(), weekday.minute()) == (7, 45)
        );
        let cron = next("*/15 9-17 * * 1-5", after);
        assert!(
            cron.weekday().num_days_from_monday() < 5
                && (9..=17).contains(&cron.hour())
                && cron.minute().is_multiple_of(15)
        );
        // Sunday may be written 0 or 7.
        assert_eq!(next("0 6 * * 7", after).weekday(), Weekday::Sun);
        assert_eq!(next("0 6 * * 0", after).weekday(), Weekday::Sun);
        // Day-of-month and weekday both restricted: either matches.
        let either = next("0 0 13 * 5", after);
        assert!(either.day() == 13 || either.weekday() == Weekday::Fri);
    }

    #[test]
    fn the_next_run_is_strictly_after_and_a_daily_run_moves_forward() {
        let schedule = RoutineSchedule::parse("weekly mon 09:00").unwrap();
        let first = schedule.next_after_utc(utc("2026-06-15T12:00:00Z"));
        let second = schedule.next_after_utc(first);
        assert!(second > first && second - first <= Duration::days(7) + Duration::hours(1));
    }

    #[test]
    fn the_minimum_interval_is_enforced_for_every_form() {
        let now = utc("2026-06-15T12:00:00Z");
        for refused in [
            "every 1m",
            "every 4m",
            "* * * * *",
            "*/3 * * * *",
            "0,2 9 * * *",
            "*/7 * * * *",
            "0 9 31 2 *",
        ] {
            let parsed = RoutineSchedule::parse(refused).unwrap();
            assert!(parsed.first_run(now).is_err(), "{refused}");
        }
        for accepted in ["every 5m", "*/5 * * * *", "0,5 9 * * *", "0 0 29 2 *"] {
            assert!(
                RoutineSchedule::parse(accepted)
                    .unwrap()
                    .first_run(now)
                    .is_ok(),
                "{accepted}"
            );
        }
    }

    #[test]
    fn only_plain_agent_jobs_are_routines() {
        let job = |payload: &str| Job {
            id: 1,
            agent: "main".into(),
            name: "n".into(),
            schedule: "daily 08:00".into(),
            payload: payload.into(),
            enabled: true,
            created_at: String::new(),
            last_run_at: None,
            next_run_at: None,
        };
        assert!(is_routine(&job(r#"{"kind":"agent","prompt":"p"}"#)));
        for other in [
            r#"{"kind":"morning-brief"}"#,
            r#"{"kind":"crm-timeline"}"#,
            r#"{"prompt":"p"}"#,
            "{}",
            "not json",
        ] {
            assert!(!is_routine(&job(other)), "{other}");
        }
    }
}
