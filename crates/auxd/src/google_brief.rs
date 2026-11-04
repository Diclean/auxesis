//! Google-backed morning-brief source.
//!
//! This adapter lives in auxd because it is the crate that already depends on
//! both aux-brief and aux-google. aux-brief stays connector-independent.

use aux_brief::{BriefSource, BriefSourceError, CalendarItem, MailHeader, WeatherSummary};
use aux_google::tools::{GoogleApiError, GoogleTools};
use aux_google::MacConnection;
use aux_store::Store;
use chrono::{Local, NaiveDate, TimeZone};
use kernel_core::budget::Budgets;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const MAX_UNREAD_MAIL: usize = 20;
const MAX_SENDER_CHARS: usize = 256;
const MAX_SUBJECT_CHARS: usize = 512;

/// Bounded, read-only Google source for the morning brief.
pub struct GoogleBriefSource {
    home: PathBuf,
    store: Arc<Mutex<Store>>,
}

impl GoogleBriefSource {
    /// Create a source using the daemon's Auxesis home and shared usage ledger.
    pub fn new(home: impl Into<PathBuf>, store: Arc<Mutex<Store>>) -> Self {
        Self {
            home: home.into(),
            store,
        }
    }

    fn google(&self) -> Result<GoogleTools, BriefSourceError> {
        // Every brief read asks the live mode, so a switch to private
        // ends the run's remaining reads.
        if crate::privacy_wiring::private_now(&self.home) {
            return Err(BriefSourceError::Unavailable);
        }
        let connection = MacConnection::at(&self.home);
        if !connection.connected() {
            return Err(BriefSourceError::NotConnected);
        }
        let client = connection.client().map_err(|error| match error {
            aux_google::AuthError::ReauthRequired | aux_google::AuthError::InvalidScopes => {
                BriefSourceError::ReconnectNeeded
            }
            _ => BriefSourceError::Unavailable,
        })?;
        GoogleTools::new(
            Arc::new(client),
            Arc::clone(&self.store),
            Budgets::default(),
        )
        .map_err(|_| BriefSourceError::Unavailable)
    }

    fn source_error(error: GoogleApiError) -> BriefSourceError {
        match error {
            GoogleApiError::ReconnectNeeded | GoogleApiError::InsufficientScope => {
                BriefSourceError::ReconnectNeeded
            }
            _ => BriefSourceError::Unavailable,
        }
    }
}

impl BriefSource for GoogleBriefSource {
    fn calendar_today(&self, day: &str) -> Result<Vec<CalendarItem>, BriefSourceError> {
        let date = NaiveDate::parse_from_str(day, "%Y-%m-%d")
            .map_err(|_| BriefSourceError::Unavailable)?;
        let next_day = date.succ_opt().ok_or(BriefSourceError::Unavailable)?;
        let start = local_midnight(date).ok_or(BriefSourceError::Unavailable)?;
        let end = local_midnight(next_day).ok_or(BriefSourceError::Unavailable)?;
        let google = self.google()?;
        let events = crate::turn_runtime::block_on(
            google.brief_calendar_events(&start.to_rfc3339(), &end.to_rfc3339()),
        )
        .map_err(|_| BriefSourceError::Unavailable)?
        .map_err(Self::source_error)?;
        Ok(events
            .into_iter()
            .map(|event| CalendarItem {
                title: event.title,
                start: event.start,
                end: event.end,
                all_day: event.all_day,
            })
            .collect())
    }

    fn weather(
        &self,
        _city: &str,
        _country: &str,
        _day: &str,
    ) -> Result<WeatherSummary, BriefSourceError> {
        Err(BriefSourceError::Unavailable)
    }

    fn mail_headers(&self, _day: &str) -> Result<Vec<MailHeader>, BriefSourceError> {
        let google = self.google()?;
        let headers = crate::turn_runtime::block_on(google.brief_unread_headers(MAX_UNREAD_MAIL))
            .map_err(|_| BriefSourceError::Unavailable)?
            .map_err(Self::source_error)?;
        Ok(headers
            .into_iter()
            .take(MAX_UNREAD_MAIL)
            .map(|header| MailHeader {
                sender: truncate(&header.sender, MAX_SENDER_CHARS),
                subject: truncate(&header.subject, MAX_SUBJECT_CHARS),
                received: String::new(),
                unread: true,
            })
            .collect())
    }
}

fn local_midnight(date: NaiveDate) -> Option<chrono::DateTime<Local>> {
    let midnight = date.and_hms_opt(0, 0, 0)?;
    match Local.from_local_datetime(&midnight) {
        chrono::LocalResult::Single(value) => Some(value),
        chrono::LocalResult::Ambiguous(first, _) => Some(first),
        chrono::LocalResult::None => None,
    }
}

/// Cut to at most `max` characters with no marker. Deliberately not
/// [`aux_brief::cap_chars`]: these are calendar and mail fields, not previews,
/// so a cut must not add a character.
fn truncate(value: &str, max: usize) -> String {
    let mut chars = value.chars();
    let output = chars.by_ref().take(max).collect::<String>();
    if chars.next().is_some() {
        output
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_and_insufficient_scope_have_the_distinct_source_state() {
        assert_eq!(
            GoogleBriefSource::source_error(GoogleApiError::ReconnectNeeded),
            BriefSourceError::ReconnectNeeded
        );
        assert_eq!(
            GoogleBriefSource::source_error(GoogleApiError::InsufficientScope),
            BriefSourceError::ReconnectNeeded
        );
        assert_eq!(
            GoogleBriefSource::source_error(GoogleApiError::Network),
            BriefSourceError::Unavailable
        );
    }

    #[test]
    fn header_truncation_is_character_bounded() {
        assert_eq!(truncate("aé🙂b", 3), "aé🙂");
        assert_eq!(truncate("short", 20), "short");
    }
}
