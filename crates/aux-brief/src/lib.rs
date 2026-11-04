//! Deterministic, offline-first morning brief generation.
//!
//! M0 deliberately ships only fake sources. The closed [`BriefSource`] seam
//! keeps calendar, weather and mail-header reads replaceable when real
//! integrations arrive. Source text is data: this crate has no tool loop,
//! prompt, network client or write-capable action.

mod prospects;
pub use prospects::{classify, count_line, unknown_senders, Inbound, Prospect, Reason};

use aux_notify::{Notification, Notifier};
use aux_store::{Store, StoreError};
use chrono::{DateTime, Local, LocalResult, NaiveTime};
use kernel_core::{BriefConfig, Config, Lang, Message, QuietConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// Hard ceiling: one read per source.
pub const MAX_SOURCE_READS: usize = 3;
/// Full message limit: 2 000 characters.
pub const MAX_BRIEF_CHARS: usize = 2_000;
/// Lock-screen notification limit: 400 characters.
pub const MAX_NOTIFICATION_CHARS: usize = 400;
/// Events and unread headers kept in the stored brief parts.
const MAX_PART_ITEMS: usize = 20;

/// A calendar item exposed to the renderer; notes and invitees are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarItem {
    pub title: String,
    pub start: Option<String>,
    pub end: Option<String>,
    pub all_day: bool,
}

/// Weather summary for one city and day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeatherSummary {
    pub description: String,
    pub temperature_c: Option<i16>,
}

/// Mail headers only; no body field exists in the M0 contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailHeader {
    pub sender: String,
    pub subject: String,
    pub received: String,
    pub unread: bool,
}

/// A source can fail normally or ask the owner to reconnect Google.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BriefSourceError {
    Unavailable,
    NotConnected,
    /// Private mode skipped a remote mailbox: the section says so, rather than
    /// the generic "not available".
    PrivateMode,
    ReconnectNeeded,
}

/// Calendar, weather and mail-header data source. Implementations are
/// synchronous and bounded; the daemon provides the Google-backed source.
pub trait BriefSource: Send + Sync + 'static {
    fn calendar_today(&self, day: &str) -> Result<Vec<CalendarItem>, BriefSourceError>;
    fn weather(
        &self,
        city: &str,
        country: &str,
        day: &str,
    ) -> Result<WeatherSummary, BriefSourceError>;
    fn mail_headers(&self, day: &str) -> Result<Vec<MailHeader>, BriefSourceError>;
    /// A returned list at this length may be truncated. The owner-facing data
    /// must call its count a lower bound rather than an exact total.
    fn mail_headers_cap(&self) -> Option<usize> {
        None
    }
    /// Inbound mail that looks like a lead (see [`classify`]). Sources that
    /// cannot read bodies locally have none.
    fn possible_clients(&self, _day: &str) -> Result<Vec<Prospect>, BriefSourceError> {
        Ok(Vec::new())
    }
}

/// The owner's local time now, for callers that run a brief on demand.
pub fn now_local() -> DateTime<Local> {
    Local::now()
}

/// Fixed offline fixtures used by M0, tests, and `aux brief now`.
#[derive(Debug, Clone, Default)]
pub struct FakeBriefSource {
    /// Optional source name to fail, useful in tests (`calendar`, `weather`,
    /// or `mail`).
    pub fail: Option<String>,
}

impl FakeBriefSource {
    fn check(&self, name: &str) -> Result<(), BriefSourceError> {
        if self.fail.as_deref() == Some(name) {
            Err(BriefSourceError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl BriefSource for FakeBriefSource {
    fn calendar_today(&self, _day: &str) -> Result<Vec<CalendarItem>, BriefSourceError> {
        self.check("calendar")?;
        Ok(vec![CalendarItem {
            title: "Point d’équipe".to_string(),
            start: Some("10:00".to_string()),
            end: Some("10:30".to_string()),
            all_day: false,
        }])
    }

    fn weather(
        &self,
        _city: &str,
        _country: &str,
        _day: &str,
    ) -> Result<WeatherSummary, BriefSourceError> {
        self.check("weather")?;
        Ok(WeatherSummary {
            description: "éclaircies".to_string(),
            temperature_c: Some(18),
        })
    }

    fn mail_headers(&self, _day: &str) -> Result<Vec<MailHeader>, BriefSourceError> {
        self.check("mail")?;
        Ok(vec![MailHeader {
            sender: "Camille".to_string(),
            subject: "Réunion de jeudi".to_string(),
            received: "hier".to_string(),
            unread: true,
        }])
    }
}

/// Why the brief runner did not write a regular brief.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BriefResult {
    Sent { day: String, message_id: i64 },
    AlreadySent { day: String },
    QuietHours { day: String },
    BudgetStopped { day: String },
    Stopped,
}

/// Errors that prevent safely recording or rendering a brief.
#[derive(Debug, Error)]
pub enum BriefError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("heure calme de début invalide dans la configuration (format attendu HH:MM)")]
    InvalidQuietStart,
    #[error("heure calme de fin invalide dans la configuration (format attendu HH:MM)")]
    InvalidQuietEnd,
    #[error("heure calme de fin non résolvable dans le fuseau local")]
    UnresolvableQuietEnd,
}

impl BriefError {
    pub fn localized_message(&self, lang: Lang) -> String {
        let message = match self {
            Self::Store(error) => return error.to_string(),
            Self::InvalidQuietStart => Message::BriefInvalidQuietStart,
            Self::InvalidQuietEnd => Message::BriefInvalidQuietEnd,
            Self::UnresolvableQuietEnd => Message::BriefUnresolvableQuietEnd,
        };
        kernel_core::i18n::text(message, lang).to_string()
    }
}

/// Run one brief with a source, a notifier and the caller's local `now`.
/// `source_read_budget` is clamped to the M0 maximum of three source calls.
pub fn run_once<F>(
    store: &Store,
    source: &dyn BriefSource,
    notifier: &dyn Notifier,
    config: &Config,
    now: DateTime<Local>,
    source_read_budget: usize,
    stopped: F,
) -> Result<BriefResult, BriefError>
where
    F: Fn() -> bool,
{
    let day = now.format("%Y-%m-%d").to_string();
    if stopped() {
        return Ok(BriefResult::Stopped);
    }
    if in_quiet_hours(now.time(), &config.quiet)? {
        return Ok(BriefResult::QuietHours { day });
    }

    let allowed_reads = source_read_budget.min(MAX_SOURCE_READS);
    if allowed_reads < MAX_SOURCE_READS {
        let reason =
            format!("morning-brief source budget exhausted ({allowed_reads}/{MAX_SOURCE_READS})");
        store.latch_budget_stop("main", &day, &reason)?;
        notify(
            notifier,
            kernel_core::i18n::text(Message::MorningBrief, config.ui.language),
            kernel_core::i18n::text(Message::BriefQuotaPaused, config.ui.language),
        );
        return Ok(BriefResult::BudgetStopped { day });
    }

    let mut calendar = source.calendar_today(&day);
    // All-day first, then by start time: the order the owner reads the day in.
    if let Ok(items) = &mut calendar {
        items.sort_by(|a, b| (!a.all_day, &a.start).cmp(&(!b.all_day, &b.start)));
    }
    if stopped() {
        return Ok(BriefResult::Stopped);
    }
    // No city, no weather request: the brief says so instead of guessing one.
    // The country is informational, so an unset one passes as empty.
    let weather = config.location.city.as_deref().map(|city| {
        source.weather(
            city,
            config.location.country.as_deref().unwrap_or_default(),
            &day,
        )
    });
    if stopped() {
        return Ok(BriefResult::Stopped);
    }
    let mail = source.mail_headers(&day);
    if stopped() {
        return Ok(BriefResult::Stopped);
    }
    for (name, failed) in [
        ("calendar", calendar.is_err()),
        ("weather", matches!(&weather, Some(Err(_)))),
        ("mail", mail.is_err()),
    ] {
        if failed {
            store.log_event(
                "brief.source_unavailable",
                &serde_json::json!({ "source": name, "day": day }).to_string(),
            )?;
        }
    }
    // A failed read or store lookup just means no suggestions.
    let found = source.possible_clients(&day).unwrap_or_default();
    let prospects = unknown_senders(store, found).unwrap_or_default();
    let mail_truncated = mail_list_is_lower_bound(source.mail_headers_cap(), &mail);
    let mut summary = notification_summary(&calendar, &mail, mail_truncated, config.ui.language);
    if let Some(line) = count_line(prospects.len()) {
        summary = format!("{summary} {line}.");
    }
    let mut parts = brief_parts(now, &calendar, weather.as_ref(), &mail, config.ui.language);
    parts["mail_truncated"] = serde_json::json!(mail_truncated);
    parts["prospects"] = serde_json::json!(prospects);
    let text = render(
        &day,
        config.location.city.as_deref(),
        calendar,
        weather,
        mail,
        config.ui.language,
    );
    let text = cap_chars(&with_prospects(text, &prospects), MAX_BRIEF_CHARS);
    match store.append_daily_brief_once("main", &day, &text, &parts)? {
        Some(message) => {
            notify(
                notifier,
                kernel_core::i18n::text(Message::MorningBrief, config.ui.language),
                &cap_chars(&summary, MAX_NOTIFICATION_CHARS),
            );
            Ok(BriefResult::Sent {
                day,
                message_id: message.id,
            })
        }
        None => Ok(BriefResult::AlreadySent { day }),
    }
}

fn mail_list_is_lower_bound(
    cap: Option<usize>,
    mail: &Result<Vec<MailHeader>, BriefSourceError>,
) -> bool {
    cap.is_some_and(|cap| mail.as_ref().is_ok_and(|headers| headers.len() >= cap))
}

/// The default offline source behind the daemon job runner.
pub fn fake_source() -> Arc<dyn BriefSource> {
    Arc::new(FakeBriefSource::default())
}

/// Turn the configured local time into the scheduler's established format.
pub fn schedule(config: &BriefConfig) -> String {
    format!("daily {}", config.time)
}

/// Return the next local quiet-hours end when `now` falls inside that window.
pub fn next_quiet_end(
    now: DateTime<Local>,
    quiet: &QuietConfig,
) -> Result<Option<DateTime<chrono::Utc>>, BriefError> {
    let start = parse_time(&quiet.start).ok_or(BriefError::InvalidQuietStart)?;
    let end = parse_time(&quiet.end).ok_or(BriefError::InvalidQuietEnd)?;
    if !in_quiet_hours(now.time(), quiet)? {
        return Ok(None);
    }
    let tomorrow = now.time() >= start && start > end;
    let date = if tomorrow {
        now.date_naive()
            .succ_opt()
            .ok_or(BriefError::UnresolvableQuietEnd)?
    } else {
        now.date_naive()
    };
    let local = date.and_time(end);
    let instant = match local.and_local_timezone(Local) {
        LocalResult::Single(value) | LocalResult::Ambiguous(value, _) => value,
        // If the configured end falls in a DST gap, use the first hour after
        // the missing wall-clock instant so the deferred job remains due.
        LocalResult::None => (local + chrono::Duration::hours(1))
            .and_local_timezone(Local)
            .earliest()
            .ok_or(BriefError::UnresolvableQuietEnd)?,
    };
    Ok(Some(instant.to_utc()))
}

/// Compute the next daily run after the given `now` using the existing
/// `Schedule::Daily` rules (including local DST handling).
pub fn next_run(
    config: &BriefConfig,
    now: DateTime<chrono::Utc>,
) -> Result<DateTime<chrono::Utc>, String> {
    kernel_core::Schedule::parse(&schedule(config))
        .map(|schedule| schedule.next_after_utc(now))
        .map_err(|error| error.to_string())
}

/// The brief as data, stored beside its text for `GET /v1/brief/today`: the
/// same facts `render` prints, plus the notes for sources that degraded.
fn brief_parts(
    now: DateTime<Local>,
    calendar: &Result<Vec<CalendarItem>, BriefSourceError>,
    weather: Option<&Result<WeatherSummary, BriefSourceError>>,
    mail: &Result<Vec<MailHeader>, BriefSourceError>,
    lang: Lang,
) -> serde_json::Value {
    let text = |message: Message| kernel_core::i18n::text(message, lang).to_string();
    let mut notes = Vec::new();
    match calendar {
        Err(BriefSourceError::NotConnected | BriefSourceError::PrivateMode) => {
            notes.push(text(Message::BriefCalendarNotAvailable))
        }
        Err(BriefSourceError::Unavailable) => notes.push(text(Message::BriefAgendaUnavailable)),
        _ => {}
    }
    match weather {
        None => notes.push(text(Message::BriefWeatherNoCity)),
        Some(Err(_)) => notes.push(text(Message::BriefWeatherUnavailable)),
        Some(Ok(_)) => {}
    }
    match mail {
        Err(BriefSourceError::NotConnected) => notes.push(text(Message::BriefMailNotAvailable)),
        Err(BriefSourceError::PrivateMode) => notes.push(text(Message::BriefMailPrivate)),
        Err(BriefSourceError::Unavailable) => notes.push(text(Message::BriefMailUnavailable)),
        _ => {}
    }
    let reconnect = matches!(calendar, Err(BriefSourceError::ReconnectNeeded))
        || matches!(mail, Err(BriefSourceError::ReconnectNeeded));
    if reconnect {
        notes.push(text(Message::BriefGoogleReconnect));
    }
    let events = calendar.as_ref().ok().map(|items| {
        items
            .iter()
            .take(MAX_PART_ITEMS)
            .map(|item| {
                serde_json::json!({
                    "title": clean(&item.title, 120),
                    "start": item.start.as_deref().map(|value| clean(value, 16)),
                    "end": item.end.as_deref().map(|value| clean(value, 16)),
                    "all_day": item.all_day,
                })
            })
            .collect::<Vec<_>>()
    });
    let mail = mail.as_ref().ok().map(|headers| {
        headers
            .iter()
            .filter(|header| header.unread)
            .take(MAX_PART_ITEMS)
            .map(|header| {
                serde_json::json!({
                    "sender": clean(&header.sender, 64),
                    "subject": clean(&header.subject, 120),
                })
            })
            .collect::<Vec<_>>()
    });
    serde_json::json!({
        "written_at": now.format("%H:%M").to_string(),
        "events": events,
        "mail": mail,
        "notes": notes,
    })
}

/// The "Possible new clients" section: name, address, reason code and date.
fn with_prospects(mut text: String, prospects: &[Prospect]) -> String {
    if !prospects.is_empty() {
        text.push_str("\n\nPossible new clients\n");
        for p in prospects {
            let name = if p.name.is_empty() {
                String::new()
            } else {
                format!("{} ", p.name)
            };
            text.push_str(&format!(
                "• {name}<{}> — {} ({})\n",
                p.email,
                serde_json::json!(p.reason).as_str().unwrap_or_default(),
                p.date
            ));
        }
    }
    text.trim_end().to_string()
}

/// `weather` is `None` when no city is set, so no source was asked.
pub fn render(
    day: &str,
    city: Option<&str>,
    calendar: Result<Vec<CalendarItem>, BriefSourceError>,
    weather: Option<Result<WeatherSummary, BriefSourceError>>,
    mail: Result<Vec<MailHeader>, BriefSourceError>,
    lang: Lang,
) -> String {
    let mut out = format!(
        "{} — {day}\n",
        kernel_core::i18n::text(Message::BriefToday, lang)
    );
    let google_reconnect = matches!(&calendar, Err(BriefSourceError::ReconnectNeeded))
        || matches!(&mail, Err(BriefSourceError::ReconnectNeeded));
    match calendar {
        Ok(items) if items.is_empty() => {
            out.push_str(kernel_core::i18n::text(Message::BriefAgendaNone, lang));
            out.push('\n');
        }
        Ok(items) => {
            out.push_str(kernel_core::i18n::text(Message::BriefAgenda, lang));
            out.push('\n');
            for item in items.into_iter().take(8) {
                let title = clean(&item.title, 120);
                if item.all_day {
                    out.push_str(&format!(
                        "• {title} {}\n",
                        kernel_core::i18n::text(Message::BriefAllDay, lang)
                    ));
                } else if let Some(start) = item.start {
                    let time = clean(&start, 16);
                    if let Some(end) = item.end {
                        let end = clean(&end, 16);
                        out.push_str(&format!("• {time}–{end} {title}\n"));
                    } else {
                        out.push_str(&format!("• {time} {title}\n"));
                    }
                } else {
                    out.push_str(&format!("• {title}\n"));
                }
            }
        }
        Err(BriefSourceError::NotConnected | BriefSourceError::PrivateMode) => {
            out.push_str(kernel_core::i18n::text(
                Message::BriefCalendarNotAvailable,
                lang,
            ));
            out.push('\n');
        }
        Err(BriefSourceError::ReconnectNeeded) => {}
        Err(BriefSourceError::Unavailable) => {
            out.push_str(kernel_core::i18n::text(
                Message::BriefAgendaUnavailable,
                lang,
            ));
            out.push('\n');
        }
    }
    if google_reconnect {
        out.push_str(kernel_core::i18n::text(Message::BriefGoogleReconnect, lang));
        out.push('\n');
    }
    match (city, weather) {
        (Some(city), Some(Ok(weather))) => {
            let temperature = weather
                .temperature_c
                .map(|t| format!(", {t} °C"))
                .unwrap_or_default();
            out.push_str(&format!(
                "{} {} : {}{}.\n",
                kernel_core::i18n::text(Message::BriefWeather, lang),
                clean(city, 64),
                clean(&weather.description, 64),
                temperature
            ));
        }
        (Some(_), Some(Err(_))) => {
            out.push_str(kernel_core::i18n::text(
                Message::BriefWeatherUnavailable,
                lang,
            ));
            out.push('\n');
        }
        (None, _) | (Some(_), None) => {
            out.push_str(kernel_core::i18n::text(Message::BriefWeatherNoCity, lang));
            out.push('\n');
        }
    }
    out.push_str(if lang == Lang::Fr {
        "\nÀ décider\n"
    } else {
        "\nTo decide\n"
    });
    out.push_str(kernel_core::i18n::text(Message::BriefNothingToDecide, lang));
    out.push_str(if lang == Lang::Fr {
        "\n\nÀ savoir\n"
    } else {
        "\n\nFor your information\n"
    });
    match mail {
        Ok(headers) if headers.is_empty() => {
            out.push_str(kernel_core::i18n::text(Message::BriefNoUnreadMail, lang));
            out.push('\n');
        }
        Ok(headers) => {
            let unread = headers.iter().filter(|header| header.unread).count();
            let unread_label = if unread == 1 {
                kernel_core::i18n::text(Message::BriefUnreadOne, lang).to_string()
            } else {
                kernel_core::i18n::format(Message::BriefUnreadMany, lang, &[&unread.to_string()])
            };
            out.push_str(&unread_label);
            out.push('\n');
            for header in headers.into_iter().filter(|header| header.unread).take(6) {
                out.push_str(&format!(
                    "• {} — {}\n",
                    clean(&header.sender, 64),
                    clean(&header.subject, 120)
                ));
            }
        }
        Err(BriefSourceError::NotConnected) => {
            out.push_str(kernel_core::i18n::text(
                Message::BriefMailNotAvailable,
                lang,
            ));
            out.push('\n');
        }
        Err(BriefSourceError::PrivateMode) => {
            out.push_str(kernel_core::i18n::text(Message::BriefMailPrivate, lang));
            out.push('\n');
        }
        Err(BriefSourceError::ReconnectNeeded) => {}
        Err(BriefSourceError::Unavailable) => {
            out.push_str(kernel_core::i18n::text(Message::BriefMailUnavailable, lang));
            out.push('\n');
        }
    }
    out.trim_end().to_string()
}

fn in_quiet_hours(now: NaiveTime, quiet: &QuietConfig) -> Result<bool, BriefError> {
    let start = parse_time(&quiet.start).ok_or(BriefError::InvalidQuietStart)?;
    let end = parse_time(&quiet.end).ok_or(BriefError::InvalidQuietEnd)?;
    Ok(if start <= end {
        now >= start && now < end
    } else {
        now >= start || now < end
    })
}

/// Parse one configured `HH:MM` quiet-hours bound.
///
/// Returns `None` on any malformed value: callers map that to a
/// field-named [`BriefError`] that never echoes the raw configuration value,
/// so a bad paste can never reach a lock-screen notification.
fn parse_time(raw: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(raw, "%H:%M").ok()
}

/// One untrusted source field: strip terminal control, Unicode `Cf`
/// format/bidi controls and line/paragraph separators through the shared
/// [`kernel_core::sanitize_text`], drop the remaining newlines/tabs, collapse to
/// a single line, then cap by characters.
fn clean(value: &str, limit: usize) -> String {
    let flat: String = kernel_core::sanitize_text(value)
        .chars()
        .filter(|ch| !ch.is_control())
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    kernel_core::truncate_chars(&flat, limit)
}

/// Cut `value` to at most `max` characters, ending with `…` when cut.
///
/// Counts characters, not bytes. Shared by the brief itself and the daemon's
/// job and API previews, so a cut preview reads the same everywhere.
pub fn cap_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut output: String = value.chars().take(max.saturating_sub(1)).collect();
    output.push('…');
    output
}

/// The notification summary: counts and a pointer only.
///
/// The notification may leave the Mac (the daemon routes it through the
/// gateway, which can reach iMessage), so it must never carry a mail subject,
/// a sender or an event title. The full brief stays in the store and the app;
/// only the counts below are sent.
fn notification_summary(
    calendar: &Result<Vec<CalendarItem>, BriefSourceError>,
    mail: &Result<Vec<MailHeader>, BriefSourceError>,
    mail_truncated: bool,
    lang: Lang,
) -> String {
    let events = calendar.as_ref().map(Vec::len).unwrap_or(0);
    let unread = mail
        .as_ref()
        .map(|headers| headers.iter().filter(|header| header.unread).count())
        .unwrap_or(0);
    let unread_label = if mail_truncated {
        kernel_core::i18n::format(Message::BriefUnreadAtLeast, lang, &[&unread.to_string()])
    } else if unread == 1 {
        kernel_core::i18n::text(Message::BriefUnreadOne, lang).to_string()
    } else {
        kernel_core::i18n::format(Message::BriefUnreadMany, lang, &[&unread.to_string()])
    };
    kernel_core::i18n::format(
        Message::BriefReady,
        lang,
        &[&events.to_string(), &unread_label],
    )
}

fn notify(notifier: &dyn Notifier, title: &str, body: &str) {
    if let Err(error) = notifier.notify(&Notification::new(title, body)) {
        tracing::warn!(error = %error, "morning brief notification failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_notify::FakeNotifier;
    use chrono::{LocalResult, TimeZone};
    use tempfile::tempdir;

    #[test]
    fn capped_mail_list_is_reported_as_a_lower_bound() {
        let one = MailHeader {
            sender: "fake@example.test".into(),
            subject: "subject".into(),
            received: String::new(),
            unread: true,
        };
        assert!(mail_list_is_lower_bound(Some(1), &Ok(vec![one.clone()])));
        assert!(!mail_list_is_lower_bound(Some(2), &Ok(vec![one])));
        assert!(!mail_list_is_lower_bound(
            Some(1),
            &Err(BriefSourceError::Unavailable)
        ));
        assert!(!mail_list_is_lower_bound(None, &Ok(Vec::new())));
    }

    fn at(hour: u32, minute: u32) -> DateTime<Local> {
        match Local.with_ymd_and_hms(2026, 10, 7, hour, minute, 0) {
            LocalResult::Single(value) | LocalResult::Ambiguous(value, _) => value,
            LocalResult::None => panic!("test date is a local-time gap"),
        }
    }

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("brief.sqlite")).unwrap();
        (dir, store)
    }

    #[test]
    fn reconnect_needed_renders_one_google_line() {
        let output = render(
            "2026-10-08",
            Some("Budapest"),
            Err(BriefSourceError::ReconnectNeeded),
            Some(Ok(WeatherSummary {
                description: "ensoleillé".to_string(),
                temperature_c: None,
            })),
            Err(BriefSourceError::ReconnectNeeded),
            Lang::Fr,
        );
        assert_eq!(output.matches("Google : reconnexion demandée.").count(), 1);
        assert!(!output.contains("source indisponible"));
    }

    #[test]
    fn hostile_mail_headers_are_cleaned_and_bounded_during_rendering() {
        let output = render(
            "2026-10-08",
            Some("Budapest"),
            Ok(Vec::new()),
            Some(Ok(WeatherSummary {
                description: "ensoleillé".to_string(),
                temperature_c: None,
            })),
            Ok(vec![MailHeader {
                sender: "sender\u{0007}\nname".to_string(),
                subject: format!("{}tail", "s".repeat(300)),
                received: String::new(),
                unread: true,
            }]),
            Lang::Fr,
        );
        assert!(!output.contains('\u{0007}'));
        assert!(!output.contains("sender\nname"));
        assert!(output.contains("sendername"));
        let subject = output
            .lines()
            .find(|line| line.starts_with("• sender"))
            .unwrap();
        assert!(subject.chars().count() <= 2 + 64 + 3 + 120);
        assert!(!subject.contains("tail"));
    }

    #[test]
    fn bidi_and_invisible_format_controls_never_reach_the_brief() {
        // Bidi overrides/isolates, marks and a line separator: all `Cf`/`Zl`,
        // none of them `is_control()`, so the old cleaner let them through.
        let hostile = "\u{202E}\u{2066}\u{200F}\u{061C}\u{2028}";
        let output = render(
            "2026-10-08",
            Some("Budapest"),
            Ok(Vec::new()),
            Some(Ok(WeatherSummary {
                description: "ensoleillé".to_string(),
                temperature_c: None,
            })),
            Ok(vec![MailHeader {
                sender: format!("{hostile}AliceRéunion"),
                subject: format!("Objet{hostile}{hostile}"),
                received: String::new(),
                unread: true,
            }]),
            Lang::Fr,
        );
        for control in hostile.chars() {
            assert!(
                !output.contains(control),
                "U+{:04X} survived into the brief: {output:?}",
                control as u32
            );
        }
        // The visible text is untouched and stays readable.
        assert!(output.contains("• AliceRéunion — Objet"));
    }

    #[test]
    fn invalid_quiet_start_error_never_echoes_the_raw_value() {
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        let mut config = Config::default();
        config.quiet.start = "canari-PERSO-123".to_string();
        let error = run_once(
            &store,
            &FakeBriefSource::default(),
            &notifier,
            &config,
            at(8, 0),
            3,
            || false,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(!message.contains("canari-PERSO-123"));
        assert!(message.contains("début"));
        assert!(message.contains("HH:MM"));
        // The bad bound aborts before the quiet-hours check can notify.
        assert_eq!(notifier.count(), 0);
    }

    #[test]
    fn fires_once_at_eight_and_restart_does_not_duplicate() {
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        let config = Config::default();
        let before = at(7, 59).with_timezone(&chrono::Utc);
        assert_eq!(
            next_run(&config.brief, before)
                .unwrap()
                .with_timezone(&Local)
                .time(),
            at(8, 0).time()
        );
        assert!(matches!(
            run_once(
                &store,
                &FakeBriefSource::default(),
                &notifier,
                &config,
                at(8, 0),
                3,
                || false
            )
            .unwrap(),
            BriefResult::Sent { .. }
        ));
        assert!(matches!(
            run_once(
                &store,
                &FakeBriefSource::default(),
                &notifier,
                &config,
                at(8, 1),
                3,
                || false
            )
            .unwrap(),
            BriefResult::AlreadySent { .. }
        ));
        assert_eq!(notifier.count(), 1);
        let sessions = store.list_sessions().unwrap();
        assert_eq!(store.list_messages(sessions[0].id).unwrap().len(), 1);
    }

    #[test]
    fn skips_quiet_hours_without_message_or_notification() {
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        assert!(matches!(
            run_once(
                &store,
                &FakeBriefSource::default(),
                &notifier,
                &Config::default(),
                at(4, 0),
                3,
                || false
            )
            .unwrap(),
            BriefResult::QuietHours { .. }
        ));
        assert!(store.list_sessions().unwrap().is_empty());
        assert_eq!(notifier.count(), 0);
    }

    #[test]
    fn quiet_hours_defer_to_seven_instead_of_skipping() {
        let now = at(23, 0);
        let next = next_quiet_end(now, &QuietConfig::default())
            .unwrap()
            .unwrap()
            .with_timezone(&Local);
        assert_eq!(next.date_naive(), now.date_naive().succ_opt().unwrap());
        assert_eq!(next.time(), NaiveTime::from_hms_opt(7, 0, 0).unwrap());
    }

    #[test]
    fn private_mode_mail_line_says_private_mode() {
        for (lang, line) in [
            (Lang::En, "Mail: not available in private mode."),
            (Lang::Fr, "Mail : indisponible en mode privé."),
        ] {
            let brief = render(
                "2026-10-07",
                None,
                Ok(Vec::new()),
                None,
                Err(BriefSourceError::PrivateMode),
                lang,
            );
            assert!(brief.contains(line), "{brief}");
        }
    }

    #[test]
    fn not_connected_source_names_itself_and_never_google() {
        let calendar_off = render(
            "2026-10-07",
            None,
            Err(BriefSourceError::NotConnected),
            None,
            Ok(Vec::new()),
            Lang::En,
        );
        assert!(calendar_off.contains("Calendar: not available."));
        assert!(!calendar_off.contains("Mail: not available."));
        assert!(!calendar_off.contains("Google"));

        let mail_off = render(
            "2026-10-07",
            None,
            Ok(Vec::new()),
            None,
            Err(BriefSourceError::NotConnected),
            Lang::Fr,
        );
        assert!(mail_off.contains("Mail : indisponible."));
        assert!(!mail_off.contains("Agenda : indisponible."));
        assert!(!mail_off.contains("Google"));
    }

    #[test]
    fn brief_renders_in_english_and_french_with_english_fallback() {
        let fr = render(
            "2026-10-08",
            Some("Budapest"),
            Ok(Vec::new()),
            Some(Err(BriefSourceError::Unavailable)),
            Ok(Vec::new()),
            Lang::Fr,
        );
        let en = render(
            "2026-10-08",
            Some("Budapest"),
            Ok(Vec::new()),
            Some(Err(BriefSourceError::Unavailable)),
            Ok(Vec::new()),
            Lang::En,
        );
        assert!(fr.starts_with("Aujourd’hui —"));
        assert!(en.starts_with("Today —"));
        assert!(en.contains("Calendar: no events."));
        assert!(!en.contains("Agenda"));
        assert_eq!(Lang::parse("unknown").unwrap_or_default(), Lang::En);
    }

    #[test]
    fn disabled_flag_is_respected_by_daemon_job_setup_contract() {
        assert!(!Config::default().brief.enabled);
        assert_eq!(Config::default().brief.time, "08:00");
        assert_eq!(Config::default().location.city, None);
        assert_eq!(Config::default().location.country, None);
    }

    #[test]
    fn unset_city_skips_the_weather_source_and_says_so() {
        struct NoWeather;
        impl BriefSource for NoWeather {
            fn calendar_today(&self, _day: &str) -> Result<Vec<CalendarItem>, BriefSourceError> {
                Ok(Vec::new())
            }
            fn weather(
                &self,
                _city: &str,
                _country: &str,
                _day: &str,
            ) -> Result<WeatherSummary, BriefSourceError> {
                panic!("no city is set, so the weather source must not be asked");
            }
            fn mail_headers(&self, _day: &str) -> Result<Vec<MailHeader>, BriefSourceError> {
                Ok(Vec::new())
            }
        }
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        let mut config = Config::default();
        config.ui.language = Lang::En;
        assert!(config.location.city.is_none());
        run_once(&store, &NoWeather, &notifier, &config, at(7, 0), 3, || {
            false
        })
        .unwrap();
        let session = store.list_sessions().unwrap().remove(0);
        let message = store.list_messages(session.id).unwrap().remove(0);
        assert!(message.content.contains("Weather: no city set yet."));
        assert!(!message.content.contains("source unavailable"));
    }

    #[test]
    fn budget_exhaustion_logs_stop_and_sends_quota_notice_only() {
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        let outcome = run_once(
            &store,
            &FakeBriefSource::default(),
            &notifier,
            &Config::default(),
            at(7, 0),
            0,
            || false,
        )
        .unwrap();
        assert!(matches!(outcome, BriefResult::BudgetStopped { .. }));
        assert!(store
            .budget_stop_reason("main", "2026-10-07")
            .unwrap()
            .is_some());
        assert!(store.list_sessions().unwrap().is_empty());
        assert_eq!(notifier.count(), 1);
        assert!(notifier.last().unwrap().body.contains("quota"));
    }

    #[test]
    fn failed_source_degrades_with_the_required_line() {
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        let source = FakeBriefSource {
            fail: Some("weather".to_string()),
        };
        let mut config = Config::default();
        config.location.city = Some("Lyon".to_string());
        config.ui.language = Lang::En;
        assert!(matches!(
            run_once(&store, &source, &notifier, &config, at(7, 0), 3, || false).unwrap(),
            BriefResult::Sent { .. }
        ));
        let session = store.list_sessions().unwrap().remove(0);
        let message = store.list_messages(session.id).unwrap().remove(0);
        assert!(message.content.contains("Weather: source unavailable."));
        assert!(message.content.contains("Today"));
        assert!(message.content.contains("To decide"));
        assert!(message.content.contains("For your information"));
    }

    #[test]
    fn fake_data_has_no_effectful_surface_and_notification_is_bounded() {
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        run_once(
            &store,
            &FakeBriefSource::default(),
            &notifier,
            &Config::default(),
            at(7, 0),
            3,
            || false,
        )
        .unwrap();
        assert!(notifier.last().unwrap().body.chars().count() <= MAX_NOTIFICATION_CHARS);
        assert!(
            store
                .list_messages(store.list_sessions().unwrap()[0].id)
                .unwrap()[0]
                .content
                .len()
                <= MAX_BRIEF_CHARS * 4
        );
    }

    #[test]
    fn notification_is_counts_only_and_never_carries_mail_or_event_text() {
        let (_dir, store) = store();
        let notifier = FakeNotifier::new();
        let mut config = Config::default();
        config.ui.language = Lang::En;
        run_once(
            &store,
            &FakeBriefSource::default(),
            &notifier,
            &config,
            at(7, 0),
            3,
            || false,
        )
        .unwrap();
        let body = notifier.last().unwrap().body.clone();
        // The fake's one event title and one mail sender/subject never leave.
        assert!(!body.contains("Point d’équipe"), "{body}");
        assert!(!body.contains("Réunion de jeudi"), "{body}");
        assert!(!body.contains("Camille"), "{body}");
        // Only the counts and the pointer do.
        assert!(body.contains("1 event(s) today, 1 unread"), "{body}");
        assert!(!body.contains("new message"), "{body}");
        assert!(body.contains("aux brief"), "{body}");
    }

    #[test]
    fn notification_calls_the_count_unread_and_marks_capped_lists_in_english_and_french() {
        let headers = || {
            Ok((0..20)
                .map(|_| MailHeader {
                    sender: String::new(),
                    subject: String::new(),
                    received: String::new(),
                    unread: true,
                })
                .collect::<Vec<_>>())
        };
        let calendar = Ok(Vec::new());

        let english = notification_summary(&calendar, &headers(), true, Lang::En);
        assert!(english.contains("At least 20 unread"), "{english}");
        assert!(!english.contains("new message"), "{english}");

        let french = notification_summary(&calendar, &headers(), true, Lang::Fr);
        assert!(french.contains("Au moins 20 non lus"), "{french}");
        assert!(!french.contains("nouveau"), "{french}");

        let uncapped = notification_summary(
            &calendar,
            &Ok(vec![headers().unwrap().remove(0)]),
            false,
            Lang::Fr,
        );
        assert!(uncapped.contains("1 non lu"), "{uncapped}");
    }
}
