//! M3: the bounded IMAP read path.
//!
//! Every method opens one connection, does one bounded unit of work and closes
//! it. The whole operation runs inside
//! [`Limits::call_timeout`], the message count is clamped by
//! [`Limits::clamp_messages`], and a message larger than
//! [`Limits::max_message_bytes`] is refused with [`MailError::TooLarge`]
//! **before** its body is fetched. Nothing here ever writes: the only commands
//! are `LIST`, `SELECT`, `UID SEARCH` and `UID FETCH`, and the body fetch is
//! `BODY.PEEK[]`, so `\Seen` is never set.

use std::sync::Arc;

use async_imap::types::{Fetch, Uid};
use async_imap::Session;
use futures_util::TryStreamExt;
use imap_proto::{BodyContentCommon, BodyParams, BodyStructure, SectionPath};
use sha2::{Digest, Sha256};

use crate::config::MailAccount;
use crate::dial::{BoxedStream, Dialer};
use crate::error::MailError;
use crate::folders::{self, Folder};
use crate::imap_query::{days_before_date, envelope_item, group_thread, imap_quote};
use crate::limits::Limits;
use crate::mailbox;
use crate::send::{self, OutgoingMail, SendOutcome};

pub use crate::imap_query::days_ago_date;

/// Supplies the password for one account at call time.
///
/// The production implementation (slice MA3) reads `AUX_MAIL_<ID>` from the
/// `~/.auxesis/.env` store; tests use a static fake. The password never leaves
/// this process, is never logged, and is never part of a result.
pub trait Credentials: Send + Sync {
    /// The password for `account`, or `None` when none is configured.
    fn password(&self, account: &str) -> Option<String>;
}

/// The production credential source: `AUX_MAIL_<ACCOUNT_ID_UPPER>` in the
/// process environment or `<home>/.env` (mode 0600, read through the
/// verified-home gateway).
///
/// Never the macOS Keychain, never a log line: the value is returned only into
/// the login exchange.
pub struct EnvCredentials {
    home: std::path::PathBuf,
}

impl EnvCredentials {
    /// Read credentials for a home.
    pub fn new(home: impl Into<std::path::PathBuf>) -> Self {
        Self { home: home.into() }
    }

    fn lookup(&self, account: &str) -> Option<String> {
        let name = crate::config::env_var_name(account);
        if let Ok(value) = std::env::var(&name) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        let handle = kernel_core::SandboxHome::open_existing(&self.home).ok()?;
        let mut file = handle
            .open_read_existing(std::path::Path::new(".env"), 1024 * 1024)
            .ok()?;
        let mut text = String::new();
        std::io::Read::read_to_string(&mut file, &mut text).ok()?;
        for line in text.lines() {
            if let Some(value) = line.trim_start().strip_prefix(&format!("{name}=")) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }
}

impl Credentials for EnvCredentials {
    fn password(&self, account: &str) -> Option<String> {
        self.lookup(account)
    }
}

/// What `mail.list` asks for.
#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    /// Folder to read; the account's INBOX when absent.
    pub folder: Option<String>,
    /// Requested message count; `0` means the hard bound.
    pub limit: usize,
    /// Restrict to unread messages.
    pub unread: Option<bool>,
    /// Search window in days; `None` means no `SINCE`.
    pub days: Option<u32>,
}

/// Most headers one [`MailService::list_headers`] call returns.
pub const MAX_HEADER_SCAN: usize = 2000;

/// What `mail.search` asks for.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    /// The server-side text to look for.
    pub query: String,
    /// Folder to search; the account's INBOX when absent.
    pub folder: Option<String>,
    /// Requested message count; `0` means the hard bound.
    pub limit: usize,
    /// Search window in days; `None` means the hard bound.
    pub days: Option<u32>,
}

/// One message header, the unit `list`/`search`/`thread` return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeItem {
    /// IMAP UID.
    pub uid: u32,
    /// `Message-ID` from the server's `ENVELOPE`.
    pub message_id: String,
    /// `Subject` from the server's `ENVELOPE`.
    pub subject: String,
    /// The first `From` address, formatted `Name <address>`.
    pub from: String,
    /// Every `To` address, formatted `Name <address>`.
    pub to: Vec<String>,
    /// Every `Cc` address, formatted `Name <address>`.
    pub cc: Vec<String>,
    /// `Date` from the server's `ENVELOPE`.
    pub date: String,
    /// `RFC822.SIZE`.
    pub size: u32,
    /// True when `\Seen` is absent.
    pub unread: bool,
    /// `In-Reply-To` from the server's `ENVELOPE`, when present.
    pub in_reply_to: Option<String>,
}

/// The raw bytes of one message, the input to [`crate::parse_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMail {
    /// IMAP UID.
    pub uid: u32,
    /// The folder it was read from.
    pub folder: String,
    /// The RFC822 bytes (`BODY.PEEK[]`), still hostile.
    pub bytes: Vec<u8>,
}

/// One attachment body downloaded for the local evidence registry.
///
/// The bytes are consumed locally by an [`crate::tools::EvidenceSink`] and are
/// never part of a tool result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedAttachment {
    /// The IMAP part specifier (`2`, `2.1`, …).
    pub part: String,
    /// The sender-declared file name.
    pub file_name: String,
    /// The declared `type/subtype`.
    pub mime: String,
    /// The decoded length in bytes.
    pub size: usize,
    /// SHA-256 of the decoded bytes, lowercase hex.
    pub sha256: String,
    /// The decoded bytes, for the registry write only.
    pub bytes: Vec<u8>,
}

/// One attachment part that was not downloaded, and why (docs/mail.md §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedAttachment {
    /// The IMAP part specifier.
    pub part: String,
    /// The sender-declared file name, when any.
    pub file_name: String,
    /// The declared `type/subtype`.
    pub mime: String,
    /// A short, model-readable reason.
    pub reason: String,
}

/// What `mail_fetch_attachments` found: the message id and each part's fate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedAttachments {
    /// `Message-ID` from the server's `ENVELOPE`, when present.
    pub message_id: String,
    /// Every part whose bytes were downloaded.
    pub downloaded: Vec<DownloadedAttachment>,
    /// Every attachment-like part left behind, with a reason.
    pub skipped: Vec<SkippedAttachment>,
}

/// The MIME types MA3 downloads (docs/mail.md §6), parameters ignored.
pub fn attachment_mime_allowed(mime: &str) -> bool {
    let base = mime
        .split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "application/pdf"
            | "application/xml"
            | "text/xml"
            | "image/jpeg"
            | "image/png"
            | "image/heic"
    )
}

/// Which read guard a connection is armed with.
///
/// `Reads` bounds the connection by the message cap (sealed MA2's posture);
/// `Attachments` bounds it by the per-call attachment budget and accepts a
/// single literal no larger than the per-part cap plus one byte (the partial
/// the attachment fetch asks for).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    Reads,
    Attachments,
}

/// The read-side mailbox service: dial, one bounded command, log out.
pub struct MailService {
    dialer: Dialer,
    limits: Limits,
    accounts: Vec<MailAccount>,
    credentials: Arc<dyn Credentials>,
}

impl MailService {
    /// Build the service from the resolved accounts and a credential source.
    pub fn new(
        dialer: Dialer,
        limits: Limits,
        accounts: Vec<MailAccount>,
        credentials: Arc<dyn Credentials>,
    ) -> Self {
        Self {
            dialer,
            limits,
            accounts,
            credentials,
        }
    }

    /// The effective bounds.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The configured account slugs, in owner order.
    pub fn account_ids(&self) -> Vec<String> {
        self.accounts
            .iter()
            .map(|account| account.id.clone())
            .collect()
    }

    /// The configured account addresses, in owner order.
    pub fn account_addresses(&self) -> Vec<String> {
        self.accounts
            .iter()
            .map(|account| account.email.clone())
            .collect()
    }

    /// `LIST "" *`, mapped.
    pub async fn folders(&self, account: &str) -> Result<Vec<Folder>, MailError> {
        self.with_budget(async {
            let (mut session, _) = self.logged_in(account, Guard::Reads).await?;
            let result = folders::list(&mut session).await;
            let _ = mailbox::logout(session, self.limits.connect_timeout).await;
            result
        })
        .await
    }

    /// `mail_list`: envelope headers only.
    pub async fn list(&self, account: &str, q: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
        let since = q.days.filter(|days| *days > 0).map(days_ago_date);
        self.fetch_list(account, q, since).await
    }

    /// `mail_list` for a window counted from `day` (the caller's local
    /// `YYYY-MM-DD`), not from the system clock: the morning brief passes its
    /// own day, so its window matches the day it reports on in any zone.
    pub async fn list_on(
        &self,
        account: &str,
        q: &ListQuery,
        day: &str,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        let since = match q.days.filter(|days| *days > 0) {
            Some(days) => {
                Some(days_before_date(day, days).ok_or(MailError::Config { field: "day" })?)
            }
            None => None,
        };
        self.fetch_list(account, q, since).await
    }

    async fn fetch_list(
        &self,
        account: &str,
        q: &ListQuery,
        since: Option<String>,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        let folder = self.folder_for(account, q.folder.as_deref())?;
        let criteria = list_criteria(q, since);
        let cap = self.limits.clamp_messages(q.limit);
        self.with_budget(async {
            let (mut session, _) = self.logged_in(account, Guard::Reads).await?;
            let result = fetch_envelopes(&mut session, &folder, &criteria, cap, None).await;
            let _ = mailbox::logout(session, self.limits.connect_timeout).await;
            result
        })
        .await
    }

    /// `mail_search`: envelope headers only, server-side `SINCE` + `TEXT`.
    pub async fn search(
        &self,
        account: &str,
        q: &SearchQuery,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        let folder = self.folder_for(account, q.folder.as_deref())?;
        let criteria = self.search_criteria(q);
        let cap = self.limits.clamp_messages(q.limit);
        self.with_budget(async {
            let (mut session, _) = self.logged_in(account, Guard::Reads).await?;
            let result = fetch_envelopes(&mut session, &folder, &criteria, cap, None).await;
            let _ = mailbox::logout(session, self.limits.connect_timeout).await;
            result
        })
        .await
    }

    /// `mail_read`: `BODY.PEEK[]`, refused before the fetch when too large.
    ///
    /// `_max_chars` is the caller's render-time request; the
    /// bytes themselves are capped by `max_message_bytes`, and the char cap is
    /// applied by [`crate::sanitize::render_untrusted_capped`] in `mail_read`.
    pub async fn read(
        &self,
        account: &str,
        uid: u32,
        folder: &str,
        _max_chars: usize,
    ) -> Result<RawMail, MailError> {
        let folder = self.folder_for(account, Some(folder))?;
        self.with_budget(async {
            let (mut session, _) = self.logged_in(account, Guard::Reads).await?;
            let result = read_body(&mut session, uid, &folder, &self.limits).await;
            let _ = mailbox::logout(session, self.limits.connect_timeout).await;
            result
        })
        .await
    }

    /// `mail_fetch_attachments`: enumerate the parts from `BODYSTRUCTURE`, then
    /// fetch each allowed one as a bounded `BODY.PEEK[<part>]<0.N>` partial
    /// (docs/mail.md §6).
    ///
    /// Nothing here downloads the whole message: the body cap
    /// ([`Limits::max_message_bytes`]) never limits an attachment, and the
    /// per-attachment and per-call attachment budgets are the only ceilings.
    /// `requested_bytes` is the caller's per-attachment request; `0` means the
    /// configured ceiling. Bytes stay in the returned struct.
    pub async fn fetch_attachments(
        &self,
        account: &str,
        folder: &str,
        uid: u32,
        requested_bytes: usize,
    ) -> Result<FetchedAttachments, MailError> {
        let folder = self.folder_for(account, Some(folder))?;
        let per_attachment = self.limits.clamp_attachment_bytes(requested_bytes);
        let per_call = self.limits.clamp_attachment_call_bytes(0);
        self.with_budget(async {
            let (mut session, _) = self.logged_in(account, Guard::Attachments).await?;
            let result = fetch_parts(&mut session, uid, &folder, per_attachment, per_call).await;
            let _ = mailbox::logout(session, self.limits.connect_timeout).await;
            result
        })
        .await
    }

    /// `mail.send`: one SMTP submission, exactly once (`docs/mail.md` §5).
    ///
    /// The `.ics`, when present, was built by the runtime from rehydrated event
    /// arguments. The composed message is capped before any socket opens; a
    /// refusal or a transient `4xx` is returned typed and the exchange is never
    /// retried.
    pub async fn send(
        &self,
        account_id: &str,
        mail: &OutgoingMail,
    ) -> Result<SendOutcome, MailError> {
        // An omitted account means the one configured mailbox. A named account
        // must be a canonical slug that exists in the config; anything else is
        // refused before any socket opens, so a raw model value can never reach
        // a Ledger row or a dial.
        let account = match account_id {
            "" => self.accounts.first().cloned(),
            id if crate::config::is_account_slug(id) => self
                .accounts
                .iter()
                .find(|account| account.id == id)
                .cloned(),
            _ => None,
        }
        .ok_or(MailError::InvalidField("account"))?;
        let account_id = account.id.as_str();
        let Some(smtp) = account.smtp.as_ref() else {
            return Err(MailError::InvalidField("smtp"));
        };
        // `from` is the account's own address, never a caller-supplied one.
        let mut mail = mail.clone();
        mail.from = account.email.clone();
        send::validate(&mail)?;
        let message = send::compose(&mail)?;
        if message.len() > self.limits.max_message_bytes {
            return Err(MailError::TooLarge {
                limit: self.limits.max_message_bytes,
                seen: message.len(),
            });
        }
        // An encrypted account with no credential cannot authenticate; a plain
        // account with no credential is a local relay (the `smtp` path refuses
        // a plain account that *does* carry a password, before any socket).
        let password = self.credentials.password(account_id);
        if smtp.security.is_encrypted() && password.is_none() {
            return Err(MailError::Auth);
        }
        let password = password.unwrap_or_default();
        let recipients: Vec<String> = mail.to.iter().chain(mail.cc.iter()).cloned().collect();
        let outcome = crate::smtp::send_once(
            smtp,
            &account.email,
            &password,
            &mail.from,
            &recipients,
            &message,
            &self.dialer,
            &self.limits,
        )
        .await?;
        Ok(outcome)
    }

    /// Up to `max` (at most [`MAX_HEADER_SCAN`]) headers of one folder, newest
    /// first, paged down by UID: one session and read guard per page.
    pub async fn list_headers(
        &self,
        account: &str,
        folder: Option<&str>,
        max: usize,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        let folder = self.folder_for(account, folder)?;
        let cap = max.min(MAX_HEADER_SCAN);
        let mut items: Vec<EnvelopeItem> = Vec::new();
        let mut below: Option<Uid> = None;
        while items.len() < cap && below.is_none_or(|uid| uid > 1) {
            let criteria = below.map_or("ALL".to_string(), |uid| format!("UID 1:{}", uid - 1));
            let want = self.limits.max_messages.clamp(1, cap - items.len());
            let batch = self
                .with_budget(async {
                    let (mut session, _) = self.logged_in(account, Guard::Reads).await?;
                    let page = fetch_envelopes(&mut session, &folder, &criteria, want, below).await;
                    let _ = mailbox::logout(session, self.limits.connect_timeout).await;
                    page
                })
                .await?;
            let full = batch.len() == want;
            below = batch.last().map(|oldest| oldest.uid);
            items.extend(batch);
            if !full {
                break;
            }
        }
        Ok(items)
    }

    /// `mail_thread`: computed from envelopes, zero bodies.
    pub async fn thread(
        &self,
        account: &str,
        message_id: &str,
        max: usize,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        let folder = self.folder_for(account, None)?;
        let cap = self.limits.clamp_messages(max);
        let scan = self.limits.max_messages;
        self.with_budget(async {
            let (mut session, _) = self.logged_in(account, Guard::Reads).await?;
            let outcome = match fetch_envelopes(&mut session, &folder, "ALL", scan, None).await {
                Ok(items) => Ok(group_thread(&items, message_id, cap)),
                Err(error) => Err(error),
            };
            let _ = mailbox::logout(session, self.limits.connect_timeout).await;
            outcome
        })
        .await
    }

    fn account(&self, id: &str) -> Result<&MailAccount, MailError> {
        self.accounts
            .iter()
            .find(|account| account.id == id)
            // A name this Mac does not have is a configuration mistake, not a
            // broken server: it never reads as one (DOC-COLLECT-1).
            .ok_or(MailError::Config { field: "account" })
    }

    /// Resolve a folder and enforce `only_folders` **before** any connection.
    fn folder_for(&self, id: &str, requested: Option<&str>) -> Result<String, MailError> {
        let account = self.account(id)?;
        let folder = requested.unwrap_or(&account.folders.inbox);
        if !account.reads_folder(folder) {
            return Err(MailError::FolderUnavailable {
                name: folder.to_string(),
                seen: account.only_folders.clone(),
            });
        }
        Ok(folder.to_string())
    }

    /// The configured Sent folder when `only_folders` allows reading it. A
    /// local trust check reads its To/Cc headers; it never widens the list.
    pub fn sent_folder(&self, id: &str) -> Option<String> {
        let account = self.account(id).ok()?;
        let sent = account.folders.sent.trim();
        (!sent.is_empty() && account.reads_folder(sent)).then_some(sent.to_string())
    }

    async fn logged_in(
        &self,
        id: &str,
        guard: Guard,
    ) -> Result<(Session<BoxedStream>, MailAccount), MailError> {
        let account = self.account(id)?.clone();
        let password = self.credentials.password(id).ok_or(MailError::Auth)?;
        let username = account.imap.username(&account.email).to_string();
        // Reads keep sealed MA2's single ceiling (`max_message_bytes` plus
        // framing, for both the total and the literal). Attachments bound the
        // connection by the per-call budget and accept a single literal no
        // larger than the per-part cap plus one (the partial the fetch asks).
        let (total_limit, literal_limit) = match guard {
            Guard::Reads => {
                let ceiling = self
                    .limits
                    .max_message_bytes
                    .saturating_add(crate::guard::READ_GUARD_OVERHEAD);
                (ceiling, ceiling)
            }
            Guard::Attachments => (
                self.limits
                    .max_call_attachment_bytes()
                    .saturating_add(crate::guard::READ_GUARD_OVERHEAD),
                self.limits.max_attachment_bytes().saturating_add(1),
            ),
        };
        let session = mailbox::login_with_caps(
            &account.imap,
            &username,
            &password,
            &self.dialer,
            &self.limits,
            total_limit,
            literal_limit,
        )
        .await?;
        Ok((session, account))
    }

    /// Bound the whole operation by [`Limits::call_timeout`].
    async fn with_budget<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, MailError>>,
    ) -> Result<T, MailError> {
        match tokio::time::timeout(self.limits.call_timeout, future).await {
            Err(_) => Err(MailError::Timeout {
                budget: self.limits.call_timeout,
            }),
            Ok(result) => result,
        }
    }

    fn search_criteria(&self, q: &SearchQuery) -> String {
        let days = self.limits.clamp_search_days(q.days.unwrap_or(0));
        let mut parts = vec![format!("SINCE {}", days_ago_date(days))];
        if !q.query.is_empty() {
            parts.push(format!("TEXT {}", imap_quote(&q.query)));
        }
        parts.join(" ")
    }
}

fn list_criteria(q: &ListQuery, since: Option<String>) -> String {
    let mut parts = vec![if q.unread == Some(true) {
        "UNSEEN"
    } else {
        "ALL"
    }
    .to_string()];
    if let Some(since) = since {
        parts.push(format!("SINCE {since}"));
    }
    parts.join(" ")
}

/// The newest `cap` envelopes matching `criteria`, below the `below` UID when
/// set (checked here too: a server may ignore a `UID` search key).
async fn fetch_envelopes(
    session: &mut Session<BoxedStream>,
    folder: &str,
    criteria: &str,
    cap: usize,
    below: Option<Uid>,
) -> Result<Vec<EnvelopeItem>, MailError> {
    session.select(folder).await.map_err(|error| match error {
        // NO to SELECT: the folder does not exist on this account.
        async_imap::error::Error::No(_) => MailError::FolderUnavailable {
            name: folder.to_string(),
            seen: Vec::new(),
        },
        error => map_imap_error(error),
    })?;
    let found = session.uid_search(criteria).await.map_err(map_imap_error)?;
    let mut uids: Vec<Uid> = found.into_iter().collect();
    uids.retain(|uid| below.is_none_or(|below| *uid < below));
    uids.sort_unstable_by(|a, b| b.cmp(a));
    uids.truncate(cap);
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let set = uids
        .iter()
        .map(Uid::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let stream = session
        .uid_fetch(set, "ENVELOPE FLAGS UID RFC822.SIZE")
        .await
        .map_err(map_imap_error)?;
    let fetches: Vec<Fetch> = stream.try_collect().await.map_err(map_imap_error)?;
    let mut items: Vec<EnvelopeItem> = fetches.iter().map(envelope_item).collect();
    // The server answers in UID order; callers expect the newest mail first.
    items.sort_unstable_by_key(|item| std::cmp::Reverse(item.uid));
    Ok(items)
}

/// One attachment-like part, discovered from `BODYSTRUCTURE` without a body.
struct PartInfo {
    part: String,
    file_name: String,
    mime: String,
    size: u32,
}

/// Enumerate the attachment-like parts and download the allowed ones.
async fn fetch_parts(
    session: &mut Session<BoxedStream>,
    uid: u32,
    folder: &str,
    per_attachment: usize,
    per_call: usize,
) -> Result<FetchedAttachments, MailError> {
    session.select(folder).await.map_err(map_imap_error)?;
    let stream = session
        .uid_fetch(uid.to_string(), "BODYSTRUCTURE ENVELOPE")
        .await
        .map_err(map_imap_error)?;
    let fetches: Vec<Fetch> = stream.try_collect().await.map_err(map_imap_error)?;
    let fetch = fetches.first().ok_or(MailError::Protocol)?;
    let message_id = fetch
        .envelope()
        .and_then(|envelope| envelope.message_id.as_ref())
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default();
    let parts = fetch
        .bodystructure()
        .map(enumerate_parts)
        .unwrap_or_default();

    let mut downloaded = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0usize;
    for info in parts {
        if !attachment_mime_allowed(&info.mime) {
            skipped.push(SkippedAttachment {
                part: info.part,
                file_name: info.file_name,
                mime: info.mime.clone(),
                reason: format!("mime type not allowed: {}", info.mime),
            });
            continue;
        }
        if info.size as usize > per_attachment {
            skipped.push(SkippedAttachment {
                part: info.part,
                file_name: info.file_name,
                mime: info.mime,
                reason: format!("attachment exceeds the {per_attachment}-byte cap"),
            });
            continue;
        }
        let remaining = per_call.saturating_sub(total);
        if remaining == 0 {
            skipped.push(SkippedAttachment {
                part: info.part,
                file_name: info.file_name,
                mime: info.mime,
                reason: format!("call attachment budget of {per_call} bytes is spent"),
            });
            break;
        }
        let Some(section) = section_path(&info.part) else {
            skipped.push(SkippedAttachment {
                part: info.part,
                file_name: info.file_name,
                mime: info.mime,
                reason: "unreadable part specifier".to_string(),
            });
            continue;
        };
        // The declared size is only a hint. Ask for one byte past the smaller
        // of the per-part cap and the remaining call budget: an honest server
        // can never send more, so the receive buffer stays bounded; a server
        // that ignores the partial is stopped by the connection's literal
        // guard, and one that overstates the part is caught by the length.
        let ceiling = per_attachment.min(remaining);
        let requested = ceiling.saturating_add(1);
        let stream = session
            .uid_fetch(
                uid.to_string(),
                format!("BODY.PEEK[{}]<0.{}>", info.part, requested),
            )
            .await
            .map_err(map_imap_error)?;
        let part_fetches: Vec<Fetch> = stream.try_collect().await.map_err(map_imap_error)?;
        let actual = part_fetches.iter().find_map(|part| part.section(&section));
        match actual {
            Some(actual) if actual.len() > ceiling => {
                let (reason, stop) = if per_attachment <= remaining {
                    (
                        format!("attachment exceeds the {per_attachment}-byte cap"),
                        false,
                    )
                } else {
                    (
                        format!("call attachment budget of {per_call} bytes is spent"),
                        true,
                    )
                };
                skipped.push(SkippedAttachment {
                    part: info.part,
                    file_name: info.file_name,
                    mime: info.mime,
                    reason,
                });
                if stop {
                    break;
                }
            }
            Some(actual) => {
                // Retain the bytes only here: a skipped part is never cloned.
                let bytes = actual.to_vec();
                let size = bytes.len();
                // An empty answer for a part the server declared as a file is
                // a broken answer, never a document: a 0-byte receipt would
                // reach the registry and the Documents page (DOC-COLLECT-1).
                if size == 0 && info.size > 0 {
                    skipped.push(SkippedAttachment {
                        part: info.part,
                        file_name: info.file_name,
                        mime: info.mime,
                        reason: "the server sent no bytes for a part it declared".to_string(),
                    });
                    continue;
                }
                total = total.saturating_add(size);
                let sha256 = Sha256::digest(&bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                downloaded.push(DownloadedAttachment {
                    size,
                    part: info.part,
                    file_name: info.file_name,
                    mime: info.mime,
                    sha256,
                    bytes,
                });
            }
            None => skipped.push(SkippedAttachment {
                part: info.part,
                file_name: info.file_name,
                mime: info.mime,
                reason: "the server returned no bytes for the part".to_string(),
            }),
        }
    }
    Ok(FetchedAttachments {
        message_id,
        downloaded,
        skipped,
    })
}

/// Walk a `BODYSTRUCTURE`, numbering parts the way RFC 3501 does.
fn enumerate_parts(root: &BodyStructure<'_>) -> Vec<PartInfo> {
    let mut out = Vec::new();
    walk_parts(root, &mut Vec::new(), &mut out);
    out
}

fn walk_parts(root: &BodyStructure<'_>, path: &mut Vec<u32>, out: &mut Vec<PartInfo>) {
    match root {
        BodyStructure::Multipart { bodies, .. } => {
            for (index, child) in bodies.iter().enumerate() {
                path.push(index as u32 + 1);
                walk_parts(child, path, out);
                path.pop();
            }
        }
        BodyStructure::Text { common, other, .. } | BodyStructure::Basic { common, other, .. } => {
            let file_name = part_filename(common);
            let attached = common
                .disposition
                .as_ref()
                .is_some_and(|disposition| disposition.ty.eq_ignore_ascii_case("attachment"));
            // The message's own text/plain body is not an attachment: only a
            // named part or an explicit attachment disposition is a candidate.
            if file_name.is_empty() && !attached {
                return;
            }
            out.push(PartInfo {
                part: path
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join("."),
                file_name,
                mime: format!("{}/{}", common.ty.ty, common.ty.subtype).to_ascii_lowercase(),
                size: other.octets,
            });
        }
        BodyStructure::Message { common, other, .. } => {
            // A nested message is a leaf: never recursed into.
            let file_name = part_filename(common);
            if file_name.is_empty() {
                return;
            }
            out.push(PartInfo {
                part: path
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join("."),
                file_name,
                mime: "message/rfc822".to_string(),
                size: other.octets,
            });
        }
    }
}

/// The sender-declared name: disposition `filename` first, then type `name`.
fn part_filename(common: &BodyContentCommon<'_>) -> String {
    common
        .disposition
        .as_ref()
        .and_then(|disposition| body_param(&disposition.params, "filename"))
        .or_else(|| body_param(&common.ty.params, "name"))
        .unwrap_or_default()
}

fn body_param(params: &BodyParams<'_>, key: &str) -> Option<String> {
    params
        .as_ref()?
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.to_string())
}

/// Parse `2.1` into the `SectionPath` the `Fetch` response is keyed by.
fn section_path(part: &str) -> Option<SectionPath> {
    if part.is_empty() {
        return None;
    }
    let mut numbers = Vec::new();
    for piece in part.split('.') {
        numbers.push(piece.parse::<u32>().ok()?);
    }
    Some(SectionPath::Part(numbers, None))
}

async fn read_body(
    session: &mut Session<BoxedStream>,
    uid: u32,
    folder: &str,
    limits: &Limits,
) -> Result<RawMail, MailError> {
    session.select(folder).await.map_err(map_imap_error)?;
    let declared = declared_size(session, uid).await?;
    if declared > limits.max_message_bytes {
        return Err(MailError::TooLarge {
            limit: limits.max_message_bytes,
            seen: declared,
        });
    }
    // Ask for one byte past the cap: an honest server can never send more, so
    // `body()` stays bounded; the read guard under the client covers a server
    // that ignores the partial range and declares a larger literal.
    let ceiling = limits.max_message_bytes.saturating_add(1);
    let stream = session
        .uid_fetch(uid.to_string(), format!("BODY.PEEK[]<0.{ceiling}>"))
        .await
        .map_err(map_imap_error)?;
    let fetches: Vec<Fetch> = stream.try_collect().await.map_err(map_imap_error)?;
    let bytes = fetches
        .iter()
        .find_map(|fetch| fetch.body())
        .map(|body| body.to_vec())
        .ok_or(MailError::Protocol)?;
    if bytes.len() > limits.max_message_bytes {
        return Err(MailError::TooLarge {
            limit: limits.max_message_bytes,
            seen: bytes.len(),
        });
    }
    Ok(RawMail {
        uid,
        folder: folder.to_string(),
        bytes,
    })
}

async fn declared_size(session: &mut Session<BoxedStream>, uid: u32) -> Result<usize, MailError> {
    let stream = session
        .uid_fetch(uid.to_string(), "RFC822.SIZE")
        .await
        .map_err(map_imap_error)?;
    let fetches: Vec<Fetch> = stream.try_collect().await.map_err(map_imap_error)?;
    Ok(fetches
        .iter()
        .find_map(|fetch| fetch.size)
        .map(|size| size as usize)
        .unwrap_or(0))
}

fn map_imap_error(error: async_imap::error::Error) -> MailError {
    match crate::guard::read_limit(&error) {
        Some((limit, seen)) => MailError::TooLarge { limit, seen },
        None => {
            // The kind only: an IMAP error can quote the server's bytes, and a
            // hostile server can echo the command (the password included)
            // back, so the text is never logged.
            let kind = match &error {
                async_imap::error::Error::No(_) => "no",
                async_imap::error::Error::Bad(_) => "bad",
                async_imap::error::Error::Parse(_) => "parse",
                _ => "other",
            };
            tracing::debug!(kind, "mail: the server's answer could not be read");
            MailError::Protocol
        }
    }
}
