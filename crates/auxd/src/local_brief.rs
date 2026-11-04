//! The morning brief reads the Mac's local data instead of a parked
//! Google connector.
//!
//! The calendar comes from the EventKit snapshot the Mac app already publishes
//! ([`crate::apple_eventkit`]); the mail comes from the configured
//! `[connectors.mail]` account(s) through aux-mail's existing bounded read path
//! and `<home>/.env` credentials (never the Keychain). Weather is unchanged:
//! no working brief weather source exists, so it stays unavailable.
//!
//! Private mode (F2): both sources are this Mac's own data, so the brief still
//! runs. The calendar reads the encrypted EventKit snapshot (local data at
//! rest; nothing here sends it anywhere). Mail is read only when every
//! configured IMAP host is loopback (the owner's simulated mailbox); a remote
//! host skips the mail section before any socket is opened and the brief says
//! "not available in private mode". A config that does not parse is skipped
//! the same way, with the generic "not available".
//!
//! Source text is data: nothing here writes, and no event note is ever read.
//! The lead search reads INBOX messages whole, but only on this Mac: no model
//! sees them, and the brief and its notification never carry a body.

use aux_brief::{
    classify, BriefSource, BriefSourceError, CalendarItem, Inbound, MailHeader, Prospect,
    WeatherSummary,
};
use aux_mail::ListQuery;
use chrono::{DateTime, Local, NaiveDate};
use kernel_core::privacy::{ModeFn, PrivacyMode};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The most INBOX headers one run reads, matching the Google source's cap.
const MAX_MAIL_HEADERS: usize = 20;

/// The most INBOX messages read whole to look for leads in one run.
const MAX_PROSPECT_READS: usize = 10;

/// A bounded, read-only brief source over the Mac's local calendar snapshot
/// and configured mailboxes.
pub struct LocalBriefSource {
    home: PathBuf,
    mode: ModeFn,
}

impl LocalBriefSource {
    /// Read from one Auxesis home.
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let mode = crate::privacy_wiring::live_mode_fn(&home);
        Self { home, mode }
    }

    /// Read the privacy mode from `mode` instead of the config, so a test can
    /// flip it between the up-front check and the dial.
    pub fn with_mode(mut self, mode: ModeFn) -> Self {
        self.mode = mode;
        self
    }

    fn private(&self) -> bool {
        (self.mode)() == PrivacyMode::Private
    }
}

/// The configured `[connectors.mail]` accounts, or `None` when there is none
/// or the table does not parse. The loopback check and the dial share this one
/// parse, so they cannot disagree about the host.
fn mail_config(home: &Path) -> Option<aux_mail::MailConfig> {
    let text = std::fs::read_to_string(kernel_core::config_path(home)).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let mail = toml::to_string(value.get("connectors")?.get("mail")?).ok()?;
    let config = aux_mail::MailConfig::from_toml(&mail).ok()?;
    (!config.accounts.is_empty()).then_some(config)
}

/// Whether every account reads from a loopback IMAP host. An empty or odd host
/// is not loopback, so it fails closed.
pub(crate) fn all_imap_hosts_loopback(config: &aux_mail::MailConfig) -> bool {
    config
        .accounts
        .iter()
        .all(|account| aux_mail::tlsutil::is_loopback_host(&account.imap.host))
}

impl BriefSource for LocalBriefSource {
    fn mail_headers_cap(&self) -> Option<usize> {
        Some(MAX_MAIL_HEADERS)
    }

    fn calendar_today(&self, day: &str) -> Result<Vec<CalendarItem>, BriefSourceError> {
        // No private-mode guard here: the snapshot is encrypted local data and
        // the brief makes no model call.
        let target = NaiveDate::parse_from_str(day, "%Y-%m-%d")
            .map_err(|_| BriefSourceError::Unavailable)?;
        // No snapshot, or one the owner did not authorize, means the local
        // calendar is not connected: the brief keeps its existing line.
        let snapshot = crate::apple_eventkit::read_snapshot(&self.home)
            .filter(|snapshot| snapshot.authorized)
            .ok_or(BriefSourceError::NotConnected)?;
        let mut items = Vec::new();
        for event in snapshot.events {
            let Ok(start) = DateTime::parse_from_rfc3339(&event.start) else {
                continue;
            };
            if start.with_timezone(&Local).date_naive() != target {
                continue;
            }
            items.push(CalendarItem {
                title: event.title,
                start: local_hhmm(&event.start),
                end: local_hhmm(&event.end),
                all_day: event.all_day.unwrap_or(false),
            });
        }
        Ok(items)
    }

    fn weather(
        &self,
        _city: &str,
        _country: &str,
        _day: &str,
    ) -> Result<WeatherSummary, BriefSourceError> {
        // Weather stays as it was: the brief has no working weather source.
        Err(BriefSourceError::Unavailable)
    }

    fn mail_headers(&self, _day: &str) -> Result<Vec<MailHeader>, BriefSourceError> {
        let (service, config) = self.mail_service()?;
        let accounts: Vec<String> = config.accounts.iter().map(|a| a.id.clone()).collect();
        let headers = crate::turn_runtime::block_on(async move {
            let mut headers = Vec::new();
            for account in accounts {
                let items = service
                    .list(
                        &account,
                        &ListQuery {
                            folder: None,
                            limit: MAX_MAIL_HEADERS,
                            unread: Some(true),
                            days: None,
                        },
                    )
                    .await
                    .map_err(|_| BriefSourceError::Unavailable)?;
                headers.extend(items.into_iter().map(|item| MailHeader {
                    sender: item.from,
                    subject: item.subject,
                    received: item.date,
                    unread: item.unread,
                }));
            }
            headers.truncate(MAX_MAIL_HEADERS);
            Ok(headers)
        })
        .map_err(|_| BriefSourceError::Unavailable)??;
        Ok(headers)
    }

    /// Possible new clients: the newest INBOX mails of the day, read whole
    /// (bounded) and classified locally. Same loopback-only rule as the headers.
    fn possible_clients(&self, day: &str) -> Result<Vec<Prospect>, BriefSourceError> {
        let (service, config) = self.mail_service()?;
        let owner: Vec<String> = config.accounts.iter().map(|a| a.email.clone()).collect();
        let accounts: Vec<String> = config.accounts.iter().map(|a| a.id.clone()).collect();
        let day = day.to_string();
        let found = crate::turn_runtime::block_on(async move {
            let mut found = Vec::new();
            for account in accounts {
                let items = service
                    .list_on(&account, &day_query(MAX_PROSPECT_READS), &day)
                    .await
                    .map_err(|_| BriefSourceError::Unavailable)?;
                for item in items {
                    // One unreadable message skips that message only.
                    let Ok(raw) = service.read(&account, item.uid, "INBOX", 0).await else {
                        continue;
                    };
                    let Ok(mail) = aux_mail::parse_message(&raw) else {
                        continue;
                    };
                    let inbound = Inbound {
                        account: &account,
                        from: &mail.from,
                        subject: &mail.subject,
                        body: &mail.text,
                        date: &mail.date,
                        raw: &raw.bytes,
                    };
                    found.extend(classify(&inbound, &owner));
                }
            }
            Ok(found)
        })
        .map_err(|_| BriefSourceError::Unavailable)??;
        Ok(found)
    }
}

impl LocalBriefSource {
    /// The mail service over the configured accounts, or why there is none.
    fn mail_service(
        &self,
    ) -> Result<(aux_mail::MailService, aux_mail::MailConfig), BriefSourceError> {
        let Some(config) = mail_config(&self.home) else {
            // No configured account (or one that does not parse): the mail
            // side is not connected.
            return Err(BriefSourceError::NotConnected);
        };
        // F2: in private mode the mailbox must be on this Mac. A remote host is
        // never dialled; the section says it is not available in private mode.
        if self.private() && !all_imap_hosts_loopback(&config) {
            return Err(BriefSourceError::PrivateMode);
        }
        // The check above can go stale before a socket opens. The credential
        // source re-reads the live mode when the password is asked for, which
        // is the last step before the dial: if the mode has turned private by
        // then, a remote account gets no password and is never dialled.
        let local: std::collections::HashSet<String> = config
            .accounts
            .iter()
            .filter(|account| aux_mail::tlsutil::is_loopback_host(&account.imap.host))
            .map(|account| account.id.clone())
            .collect();
        let credentials = crate::crm::ModeGatedCredentials::new(
            Arc::new(aux_mail::EnvCredentials::new(self.home.clone())),
            Arc::clone(&self.mode),
            local,
        );
        let limits = config.limits.limits();
        let service = aux_mail::MailService::new(
            aux_mail::Dialer::new(limits.connect_timeout),
            limits,
            config.accounts.clone(),
            Arc::new(credentials),
        );
        Ok((service, config))
    }
}

/// "For the day": the window starts yesterday, counted from the brief's own
/// local day (`list_on`), not from the system clock.
fn day_query(limit: usize) -> ListQuery {
    ListQuery {
        folder: None,
        limit,
        unread: None,
        days: Some(1),
    }
}

/// The local wall-clock `HH:MM` of an RFC 3339 instant. The snapshot validator
/// already bounds the value, so an unparsable one is simply omitted.
fn local_hhmm(value: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|instant| instant.with_timezone(&Local).format("%H:%M").to_string())
}
