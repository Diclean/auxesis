//! `POST /v1/brief/run` — run the morning brief once, now.
//!
//! The route is a thin owner-only trigger over the same inner function the
//! scheduled 08:00 job uses ([`run_brief_now`]): the daemon's own source, the
//! F2 privacy gate, the configured quiet hours, the notify router and the
//! store's daily idempotency. The full brief text never goes to a log: it
//! lives in the store and in this loopback response only.

use std::path::Path;
use std::sync::Arc;

use aux_brief::{
    run_once, BriefError, BriefResult, BriefSource, BriefSourceError, CalendarItem, MailHeader,
    Prospect, WeatherSummary, MAX_SOURCE_READS,
};
use aux_notify::{Notification, Notifier};
use aux_store::Store;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Local, SecondsFormat, Utc};
use kernel_core::privacy::{admit_call, Destination, PathId};
use kernel_core::Config;
use serde::{Deserialize, Serialize};

use crate::gateway::router::{BriefOutcome, NotifyRouter, BRIEF_REPORT_WAIT};
use crate::gateway::SendCause;

use super::error;
use super::ApiState;

/// Response of `POST /v1/brief/run`.
#[derive(Debug, Serialize)]
struct BriefRunResponse {
    /// `written`, `already_today`, `skipped_quiet_hours` or `source_unavailable`.
    status: &'static str,
    /// The full brief text on `written`; `None` otherwise.
    brief: Option<String>,
}

/// Map one `BriefResult` to the route's public status, in one place.
///
/// Four statuses for five variants: a latched source budget reports
/// `source_unavailable` (no brief could be produced from its sources).
/// `Stopped` is not a brief status but an owner action, so the handler
/// answers `409 stopped` before this mapping.
fn status_for(result: &BriefResult) -> Option<&'static str> {
    match result {
        BriefResult::Sent { .. } => Some("written"),
        BriefResult::AlreadySent { .. } => Some("already_today"),
        BriefResult::QuietHours { .. } => Some("skipped_quiet_hours"),
        BriefResult::BudgetStopped { .. } => Some("source_unavailable"),
        BriefResult::Stopped => None,
    }
}

/// Holds the notification `run_once` produced, so the shared runner decides
/// the router and the source never delivers on its own.
#[derive(Default)]
struct CaptureNotifier {
    seen: std::sync::Mutex<Option<Notification>>,
}

impl CaptureNotifier {
    fn take(&self) -> Option<Notification> {
        kernel_core::lock_recover(&self.seen).take()
    }
}

impl Notifier for CaptureNotifier {
    fn notify(&self, notification: &Notification) -> Result<(), aux_notify::NotifyError> {
        *kernel_core::lock_recover(&self.seen) = Some(notification.clone());
        Ok(())
    }
}

/// Errors of [`run_brief_now`].
#[derive(Debug)]
pub enum BriefNowError {
    /// The F2 privacy gate refused the run.
    Refused(String),
    /// The brief run failed before any write.
    Run(BriefError),
}

/// Run one morning brief now through the shared inner path.
///
/// This is the exact code the scheduled 08:00 job runs: the F2 privacy gate,
/// the daemon's [`BriefSource`], the store's daily idempotency and the same
/// counts-only notification through `router`. `[brief].enabled` is the
/// scheduler's gate and is deliberately not checked here: an explicit owner
/// action (`aux brief now`) runs even a disabled schedule.
pub fn run_brief_now(
    home: &Path,
    config: &Config,
    source: &dyn BriefSource,
    router: &NotifyRouter,
    store: &Store,
    now: DateTime<Local>,
    stopped: impl Fn() -> bool,
) -> Result<BriefResult, BriefNowError> {
    run_inner(home, config, source, router, store, now, stopped).map(|(result, ..)| result)
}

/// [`run_brief_now`] that also records the run for `GET /v1/brief/status`:
/// time, trigger, sections built or skipped and the delivery outcome. Only
/// labels and a timestamp are stored, never brief content.
#[allow(clippy::too_many_arguments)]
pub fn run_brief_traced(
    home: &Path,
    config: &Config,
    source: &Arc<dyn BriefSource>,
    router: &NotifyRouter,
    store: &Store,
    now: DateTime<Local>,
    stopped: impl Fn() -> bool,
    trigger: BriefTrigger,
) -> Result<BriefResult, BriefNowError> {
    let traced = TracedSource {
        inner: Arc::clone(source),
        seen: Default::default(),
    };
    let run = run_inner(home, config, &traced, router, store, now, stopped);
    let (result, (outcome, reason), cause) = match &run {
        Ok((result, delivery, cause)) => (RunResult::from(result), *delivery, *cause),
        Err(BriefNowError::Refused(_)) => (
            RunResult::Refused,
            (Outcome::Held, Some(Reason::PrivacyMode)),
            None,
        ),
        Err(BriefNowError::Run(BriefError::Store(_))) => (
            RunResult::Failed,
            (Outcome::Failed, Some(Reason::Store)),
            None,
        ),
        Err(BriefNowError::Run(_)) => (
            RunResult::Failed,
            (Outcome::Failed, Some(Reason::Config)),
            None,
        ),
    };
    let seen = kernel_core::lock_recover(&traced.seen).clone();
    let section = |name| seen.get(name).copied().unwrap_or_default();
    let record = RunRecord {
        day: now.format("%Y-%m-%d").to_string(),
        at: now.to_rfc3339_opts(SecondsFormat::Secs, false),
        trigger,
        result,
        sections: Sections {
            calendar: section("calendar"),
            weather: match config.location.city {
                None => SectionState::NoCity,
                Some(_) => section("weather"),
            },
            mail: section("mail"),
        },
        delivery: DeliveryRecord {
            outcome,
            reason,
            cause,
        },
    };
    // A failed write is logged and never fails the brief.
    let written =
        serde_json::to_string(&record).map(|payload| store.log_event("brief.run", &payload));
    if !matches!(written, Ok(Ok(()))) {
        tracing::warn!("brief run not recorded");
    }
    run.map(|(result, ..)| result)
}

/// Who started a brief run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BriefTrigger {
    /// The 08:00 job on the scheduler.
    Scheduled,
    /// An owner action (`aux brief now`, `POST /v1/brief/run`).
    Manual,
}

/// Every value a recorded run can hold. The same enums write and read the
/// row, so the writer cannot emit a value the reader does not know, and a
/// stored string outside them (a foreign or damaged row) drops the row
/// instead of being echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunResult {
    Written,
    AlreadyToday,
    SkippedQuietHours,
    SourceUnavailable,
    Stopped,
    Refused,
    Failed,
}

impl From<&BriefResult> for RunResult {
    fn from(result: &BriefResult) -> Self {
        match result {
            BriefResult::Sent { .. } => Self::Written,
            BriefResult::AlreadySent { .. } => Self::AlreadyToday,
            BriefResult::QuietHours { .. } => Self::SkippedQuietHours,
            BriefResult::BudgetStopped { .. } => Self::SourceUnavailable,
            BriefResult::Stopped => Self::Stopped,
        }
    }
}

/// `built`, or why a section was skipped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SectionState {
    Built,
    Unavailable,
    NotConnected,
    PrivateMode,
    ReconnectNeeded,
    NoCity,
    #[default]
    NotRead,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct Sections {
    #[serde(default)]
    calendar: SectionState,
    #[serde(default)]
    weather: SectionState,
    #[serde(default)]
    mail: SectionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Sent,
    /// Private mode: the phone got only the fixed notice; the brief is in the app.
    NoticeSent,
    Held,
    Failed,
    /// Handed to a sink that cannot report delivery (tests only).
    Queued,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    QuietHours,
    KillSwitch,
    PrivacyMode,
    AlreadyToday,
    NothingToSend,
    Store,
    Config,
    NotDelivered,
    NotConfirmed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct DeliveryRecord {
    outcome: Outcome,
    reason: Option<Reason>,
    /// Why the channel send failed, when the transport said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cause: Option<SendCause>,
}

/// The fix shown when Messages refused or never answered the send.
pub const AUTOMATION_FIX: &str =
    "Allow Auxesis to control Messages: System Settings → Privacy & Security → Automation";

impl DeliveryRecord {
    /// The status view: the stored labels plus the fixed fix, if one fits.
    fn view(&self) -> serde_json::Value {
        let mut view = serde_json::json!(self);
        let hung = self.reason == Some(Reason::NotConfirmed);
        if hung
            || matches!(
                self.cause,
                Some(SendCause::NotAuthorized | SendCause::Timeout)
            )
        {
            view["fix"] = serde_json::json!(AUTOMATION_FIX);
        }
        view
    }
}

/// One recorded run: labels and a timestamp, never brief content.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunRecord {
    day: String,
    at: String,
    trigger: BriefTrigger,
    result: RunResult,
    sections: Sections,
    delivery: DeliveryRecord,
}

/// Delivery outcome and the reason, if any.
type Delivery = (Outcome, Option<Reason>);

/// Wraps the daemon's source and notes, per section, whether it answered.
struct TracedSource {
    inner: Arc<dyn BriefSource>,
    seen: std::sync::Mutex<std::collections::BTreeMap<&'static str, SectionState>>,
}

impl TracedSource {
    fn note<T>(
        &self,
        name: &'static str,
        read: Result<T, BriefSourceError>,
    ) -> Result<T, BriefSourceError> {
        let state = match &read {
            Ok(_) => SectionState::Built,
            Err(BriefSourceError::Unavailable) => SectionState::Unavailable,
            Err(BriefSourceError::NotConnected) => SectionState::NotConnected,
            Err(BriefSourceError::PrivateMode) => SectionState::PrivateMode,
            Err(BriefSourceError::ReconnectNeeded) => SectionState::ReconnectNeeded,
        };
        kernel_core::lock_recover(&self.seen).insert(name, state);
        read
    }
}

impl BriefSource for TracedSource {
    fn calendar_today(&self, day: &str) -> Result<Vec<CalendarItem>, BriefSourceError> {
        self.note("calendar", self.inner.calendar_today(day))
    }

    fn weather(
        &self,
        city: &str,
        country: &str,
        day: &str,
    ) -> Result<WeatherSummary, BriefSourceError> {
        self.note("weather", self.inner.weather(city, country, day))
    }

    fn mail_headers(&self, day: &str) -> Result<Vec<MailHeader>, BriefSourceError> {
        self.note("mail", self.inner.mail_headers(day))
    }

    fn possible_clients(&self, day: &str) -> Result<Vec<Prospect>, BriefSourceError> {
        self.inner.possible_clients(day)
    }
}

fn run_inner(
    home: &Path,
    config: &Config,
    source: &dyn BriefSource,
    router: &NotifyRouter,
    store: &Store,
    now: DateTime<Local>,
    stopped: impl Fn() -> bool,
) -> Result<(BriefResult, Delivery, Option<SendCause>), BriefNowError> {
    // F2: the brief is deterministic (no model) and its sources are local, so
    // private mode admits it; the mode is read live and an unknown one is
    // refused. The source itself skips a non-loopback mailbox in private mode.
    let mode = crate::privacy_wiring::current_mode(home);
    admit_call(PathId::F2, mode, Destination::LocalDisplay)
        .map_err(|refused| BriefNowError::Refused(refused.to_string()))?;
    let capture = CaptureNotifier::default();
    let result = run_once(
        store,
        source,
        &capture,
        config,
        now,
        MAX_SOURCE_READS,
        &stopped,
    )
    .map_err(BriefNowError::Run)?;
    // The brief goes through the policy and the gateway, not the local
    // display; the kill switch still suppresses it.
    let mut delivery: Delivery = match &result {
        BriefResult::AlreadySent { .. } => (Outcome::None, Some(Reason::AlreadyToday)),
        BriefResult::QuietHours { .. } => (Outcome::Held, Some(Reason::QuietHours)),
        BriefResult::Stopped => (Outcome::Held, Some(Reason::KillSwitch)),
        _ => (Outcome::None, Some(Reason::NothingToSend)),
    };
    let mut cause = None;
    if let Some(notification) = capture.take() {
        delivery = (Outcome::Held, Some(Reason::KillSwitch));
        if !stopped() {
            let title = cap_chars(
                &kernel_broker::scrub_external_preview(home, &notification.title, 512),
                128,
            );
            let body = cap_chars(
                &kernel_broker::scrub_external_preview(
                    home,
                    &notification.body,
                    aux_brief::MAX_NOTIFICATION_CHARS * 4,
                ),
                aux_brief::MAX_NOTIFICATION_CHARS,
            );
            // `sent` means a channel took the full brief, as the worker reports.
            delivery = match router.brief_reported(&format!("{title}\n{body}"), BRIEF_REPORT_WAIT) {
                BriefOutcome::Sent => (Outcome::Sent, None),
                BriefOutcome::NoticeSent => (Outcome::NoticeSent, Some(Reason::PrivacyMode)),
                BriefOutcome::Held => (Outcome::Held, Some(Reason::PrivacyMode)),
                BriefOutcome::Quiet => (Outcome::Held, Some(Reason::QuietHours)),
                BriefOutcome::Failed(why) => {
                    cause = why;
                    (Outcome::Failed, Some(Reason::NotDelivered))
                }
                BriefOutcome::Unconfirmed => (Outcome::Failed, Some(Reason::NotConfirmed)),
                BriefOutcome::Queued => (Outcome::Queued, None),
            };
        }
    }
    Ok((result, delivery, cause))
}

fn cap_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut output: String = value.chars().take(max.saturating_sub(1)).collect();
    output.push('…');
    output
}

/// One failed run, before the response is shaped.
enum RouteError {
    Config(kernel_core::ConfigError),
    Store(aux_store::StoreError),
    Refused(String),
    Run(BriefError),
}

impl From<BriefNowError> for RouteError {
    fn from(error: BriefNowError) -> Self {
        match error {
            BriefNowError::Refused(reason) => Self::Refused(reason),
            BriefNowError::Run(error) => Self::Run(error),
        }
    }
}

/// `POST /v1/brief/run` — run the brief once, now.
pub async fn run(State(state): State<Arc<ApiState>>) -> Response {
    let (Some(source), Some(router)) = (state.brief_source.clone(), state.notify_router.clone())
    else {
        return Json(BriefRunResponse {
            status: "source_unavailable",
            brief: None,
        })
        .into_response();
    };
    let home = state.home.clone();
    let outcome = tokio::task::spawn_blocking(
        move || -> Result<(BriefResult, Option<String>), RouteError> {
            let config = super::load_config_verified(&home).map_err(RouteError::Config)?;
            let store = Store::open(&kernel_core::store_path(&home)).map_err(RouteError::Store)?;
            let result = run_brief_traced(
                &home,
                &config,
                &source,
                router.as_ref(),
                &store,
                Local::now(),
                || kernel_core::killswitch::is_stopped(&home),
                BriefTrigger::Manual,
            )
            .map_err(RouteError::from)?;
            let brief = match &result {
                BriefResult::Sent { message_id, .. } => {
                    read_brief(&store, *message_id).map_err(RouteError::Store)?
                }
                _ => None,
            };
            Ok((result, brief))
        },
    )
    .await;
    match outcome {
        Ok(Ok((result, brief))) => match status_for(&result) {
            Some(status) => Json(BriefRunResponse { status, brief }).into_response(),
            None => error::error_response(
                StatusCode::CONFLICT,
                "stopped",
                "the kill switch is engaged; resume before running the brief",
                None,
            ),
        },
        Ok(Err(RouteError::Config(err))) => {
            internal_error("reading the brief configuration", &anyhow::Error::from(err))
        }
        Ok(Err(RouteError::Store(err))) => {
            internal_error("opening the brief store", &anyhow::Error::from(err))
        }
        Ok(Err(RouteError::Refused(reason))) => error::error_response_with_detail(
            StatusCode::FORBIDDEN,
            "privacy_disabled",
            "the morning brief is not allowed in the current privacy mode",
            error::sanitize_detail(&state.home, &reason),
        ),
        Ok(Err(RouteError::Run(err))) => {
            let detail = error::sanitize_detail(&state.home, &err.to_string());
            tracing::error!(error = %detail, "brief run failed");
            error::error_response_with_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "brief_failed",
                "the brief could not be produced",
                detail,
            )
        }
        Err(join) => internal_error("joining the brief runner", &anyhow::Error::from(join)),
    }
}

/// `GET /v1/brief/today` — today's stored brief, for the Today view.
///
/// Answers the structured parts stored with the text when the brief was
/// written, so the app never parses prose. `404 no_brief` until one exists
/// for today. No source is read here: it is a loopback read of the store.
pub async fn today(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let outcome = tokio::task::spawn_blocking(
        move || -> Result<Option<serde_json::Value>, aux_store::StoreError> {
            let day = Local::now().format("%Y-%m-%d").to_string();
            let store = Store::open(&kernel_core::store_path(&home))?;
            let Some(mut brief) = stored_brief(&store, &day)? else {
                return Ok(None);
            };
            brief["day"] = serde_json::json!(day);
            // Added or ignored since the brief was written: no longer suggested.
            let stored: Vec<Prospect> =
                serde_json::from_value(brief["prospects"].take()).unwrap_or_default();
            let open = aux_brief::unknown_senders(&store, stored)?;
            brief["prospects"] = serde_json::json!(open);
            Ok(Some(brief))
        },
    )
    .await;
    match outcome {
        Ok(Ok(Some(brief))) => Json(brief).into_response(),
        Ok(Ok(None)) => error::error_response(
            StatusCode::NOT_FOUND,
            "no_brief",
            "no brief is stored for today yet",
            None,
        ),
        Ok(Err(err)) => internal_error("reading today's brief", &anyhow::Error::from(err)),
        Err(join) => internal_error("joining the brief reader", &anyhow::Error::from(join)),
    }
}

/// Today's stored brief parts. `None` when no brief exists, or when it was
/// written before the parts were stored: absent rather than an empty day.
fn stored_brief(
    store: &Store,
    day: &str,
) -> Result<Option<serde_json::Value>, aux_store::StoreError> {
    let Some(message) = store.daily_brief("main", day)? else {
        return Ok(None);
    };
    let meta: serde_json::Value = message
        .meta
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    Ok(meta.get("brief").cloned())
}

/// The open suggestion for `account` and `email` in today's brief, if any.
/// Add and ignore act only on a sender the brief suggested.
fn open_prospect(
    store: &Store,
    account: &str,
    email: &str,
) -> Result<Option<Prospect>, aux_store::StoreError> {
    let day = Local::now().format("%Y-%m-%d").to_string();
    let Some(mut brief) = stored_brief(store, &day)? else {
        return Ok(None);
    };
    let stored: Vec<Prospect> =
        serde_json::from_value(brief["prospects"].take()).unwrap_or_default();
    let open = aux_brief::unknown_senders(store, stored)?;
    Ok(open.into_iter().find(|prospect| {
        prospect.account == account.trim() && prospect.email.eq_ignore_ascii_case(email.trim())
    }))
}

/// `POST /v1/brief/prospects/add` and `/ignore`: the sender a "Possible new
/// clients" row names. `add` makes a party tagged `prospect`; `ignore` stops the
/// suggestion. Nothing is logged but the outcome.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProspectRequest {
    account: String,
    /// Accepted from the app but never used: the suggestion's name wins.
    #[serde(default, rename = "name")]
    _name: String,
    email: String,
}

pub async fn prospect_add(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<ProspectRequest>,
) -> Response {
    prospect_call(state, req, true).await
}

pub async fn prospect_ignore(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<ProspectRequest>,
) -> Response {
    prospect_call(state, req, false).await
}

async fn prospect_call(state: Arc<ApiState>, req: ProspectRequest, add: bool) -> Response {
    let home = state.home.clone();
    let outcome = tokio::task::spawn_blocking(move || -> Result<_, aux_crm::CrmError> {
        let store = Store::open(&kernel_core::store_path(&home))?;
        // Only a sender today's brief suggested: the name comes from the
        // suggestion, never from the caller.
        let Some(prospect) = open_prospect(&store, &req.account, &req.email)? else {
            return Ok(None);
        };
        let crm = aux_crm::Crm::new(&store);
        if add {
            let seeded = crm.add_prospect(&prospect.account, &prospect.name, &prospect.email)?;
            Ok(Some(
                serde_json::json!({ "status": "added", "party_id": seeded.party().id }),
            ))
        } else {
            crm.ignore_prospect(&prospect.email)?;
            Ok(Some(serde_json::json!({ "status": "ignored" })))
        }
    })
    .await;
    match outcome {
        Ok(Ok(Some(body))) => Json::<serde_json::Value>(body).into_response(),
        Ok(Ok(None)) => error::error_response(
            StatusCode::NOT_FOUND,
            "prospect_unknown",
            "today's brief does not suggest this sender",
            None,
        ),
        Ok(Err(aux_crm::CrmError::InvalidEmail { .. }))
        | Ok(Err(aux_crm::CrmError::EmptyOrigin)) => error::error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "prospect_invalid",
            "the sender or the mail account is not valid",
            None,
        ),
        Ok(Err(err)) => internal_error("saving a prospect", &anyhow::Error::from(err)),
        Err(join) => internal_error("joining the prospect writer", &anyhow::Error::from(join)),
    }
}

/// How many recent `brief.run` rows the status read looks at.
const STATUS_WINDOW: usize = 100;

/// One stored run for `day`. `None` when the row is not JSON, is for another
/// day, has a timestamp that is not a plain one or holds any value outside the
/// closed enums above.
fn clean_run(raw: &str, day: &str) -> Option<RunRecord> {
    let record: RunRecord = serde_json::from_str(raw).ok()?;
    let plain_time = record.at.len() <= 32
        && record
            .at
            .bytes()
            .all(|b| b.is_ascii_digit() || b"T:+-Z.".contains(&b));
    (record.day == day && plain_time).then_some(record)
}

/// `GET /v1/brief/status` — did today's brief run, and what happened to it.
///
/// Content-free by construction: run labels, section states and timestamps
/// only, rebuilt field by field from the recorded rows. Malformed rows are
/// skipped. A loopback read of the store; no source is read.
pub async fn status(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let config = super::load_config_verified(&home)?;
        let store = Store::open(&kernel_core::store_path(&home))?;
        let day = Local::now().format("%Y-%m-%d").to_string();
        let runs: Vec<RunRecord> = store
            .recent_event_payloads("brief.run", STATUS_WINDOW)?
            .iter()
            .filter_map(|raw| clean_run(raw, &day))
            .collect();
        // The run that wrote the brief wins over a later "already today" one.
        let last = runs
            .iter()
            .find(|run| run.result == RunResult::Written)
            .or(runs.first());
        let status = match last {
            Some(run) if run.result == RunResult::Written => "written",
            Some(_) => "attempted",
            None => "not_run",
        };
        let next = aux_brief::next_run(&config.brief, Utc::now())
            .ok()
            .map(|next| {
                next.with_timezone(&Local)
                    .to_rfc3339_opts(SecondsFormat::Secs, false)
            });
        Ok(serde_json::json!({
            "day": day,
            "status": status,
            "runs_today": runs.len(),
            "last_run": last.map(|run| {
                serde_json::json!({
                    "at": run.at, "trigger": run.trigger, "result": run.result,
                    "sections": run.sections, "delivery": run.delivery.view(),
                })
            }),
            "enabled": config.brief.enabled,
            "scheduled_time": config.brief.time,
            "next_scheduled": next,
        }))
    })
    .await;
    match outcome {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(err)) => internal_error("reading the brief status", &err),
        Err(join) => internal_error(
            "joining the brief status reader",
            &anyhow::Error::from(join),
        ),
    }
}

/// The full brief text just written, read back by message id.
///
/// The text never goes to a log; it lives in the store and in this loopback
/// response only.
fn read_brief(store: &Store, message_id: i64) -> Result<Option<String>, aux_store::StoreError> {
    for session in store.list_sessions()? {
        if let Some(message) = store
            .list_messages(session.id)?
            .into_iter()
            .find(|message| message.id == message_id)
        {
            return Ok(Some(message.content));
        }
    }
    Ok(None)
}

fn internal_error(what: &str, err: &anyhow::Error) -> Response {
    tracing::error!(error = %err, task = what, "local API failure");
    error::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "the daemon could not complete this request",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The status view of a stored row with this delivery, if the row is kept.
    fn view(delivery: &str) -> Option<serde_json::Value> {
        let row = format!(
            r#"{{"day":"2026-10-17","at":"2026-10-17T08:00:20+02:00","trigger":"scheduled",
            "result":"written","sections":{{}},"delivery":{delivery}}}"#
        );
        Some(clean_run(&row, "2026-10-17")?.delivery.view())
    }

    #[test]
    fn a_failed_send_shows_its_cause_and_the_automation_fix() {
        for cause in ["not_authorized", "timeout"] {
            let row =
                format!(r#"{{"outcome":"failed","reason":"not_delivered","cause":"{cause}"}}"#);
            let shown = view(&row).unwrap();
            assert_eq!(shown["cause"], cause, "{shown}");
            assert_eq!(shown["fix"], AUTOMATION_FIX, "{shown}");
        }
        // No report in time: most often the same hung Automation prompt.
        let shown = view(r#"{"outcome":"failed","reason":"not_confirmed"}"#).unwrap();
        assert_eq!(shown["fix"], AUTOMATION_FIX, "{shown}");
        let row = r#"{"outcome":"failed","reason":"not_delivered","cause":"messages_unavailable"}"#;
        assert!(view(row).unwrap().get("fix").is_none());
        // A cause outside the closed set drops the row instead of echoing it.
        assert!(
            view(r#"{"outcome":"failed","reason":"not_delivered","cause":"hi +33600000001"}"#)
                .is_none()
        );
    }
}
