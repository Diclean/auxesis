//! The B19 / B22 mail tools (`docs/mail.md` §3).
//!
//! Seven model-facing tools sit on top of [`MailApi`] (production:
//! [`crate::MailService`]). The four reads render sanitised, banner-wrapped,
//! bounded text. `mail_fetch_attachments` downloads allowed parts and hands
//! each to an [`EvidenceSink`] (the daemon writes the blob and the registry
//! rows); the model gets metadata only — `{sha256, file_name, mime, size,
//! duplicate}` — never bytes. `mail_draft` saves locally and never sends.
//!
//! Every argument struct is `deny_unknown_fields`, every string field is
//! bounded and rejects control characters, and every numeric bound is clamped
//! against [`Limits`] in code, not merely described in the schema.

use std::sync::Arc;

use async_trait::async_trait;
use kernel_broker::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, Trust};
use serde::Deserialize;
use serde_json::json;

use crate::direction::EnvelopeDirection;
use crate::error::MailError;
use crate::imap_read::{EnvelopeItem, FetchedAttachments, ListQuery, MailService, SearchQuery};
use crate::limits::Limits;
use crate::parse::MailItem;
use crate::sanitize::{render_envelopes, render_envelopes_counted, render_untrusted_capped};
use crate::send::{validate_address, OutgoingMail, SendOutcome};
use aux_runtime::executor::RecipientDirectory;

/// The mailbox a read names, shared with the skill runtime: the model is never
/// told an account slug, so a call that names one is a guess.
pub use aux_runtime::executor::resolve_account;

/// A draft's resolved `(to, to_display, question)`.
type DraftRecipients = (Vec<String>, Vec<String>, Option<String>);

/// The read side the tools call. Production is [`MailService`]; tests inject a
/// fake, so no tool test needs a socket.
#[async_trait]
pub trait MailApi: Send + Sync {
    /// `mail.list`.
    async fn list(&self, account: &str, query: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError>;
    /// Up to `max` headers of one folder (`None` = INBOX), newest first.
    /// Production pages past `max_messages`; a fake's one `list` is enough.
    async fn list_headers(
        &self,
        account: &str,
        folder: Option<&str>,
        max: usize,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        let folder = folder.map(str::to_string);
        let query = ListQuery {
            folder,
            limit: max,
            ..ListQuery::default()
        };
        self.list(account, &query).await
    }
    /// `mail.search`.
    async fn search(
        &self,
        account: &str,
        query: &SearchQuery,
    ) -> Result<Vec<EnvelopeItem>, MailError>;
    /// `mail.thread`.
    async fn thread(
        &self,
        account: &str,
        message_id: &str,
        max: usize,
    ) -> Result<Vec<EnvelopeItem>, MailError>;
    /// `mail.read`, already parsed into a [`MailItem`].
    async fn read(
        &self,
        account: &str,
        uid: u32,
        folder: &str,
        max_chars: usize,
    ) -> Result<MailItem, MailError>;
    /// The attachment download for `mail_fetch_attachments`.
    async fn fetch_attachments(
        &self,
        account: &str,
        folder: &str,
        uid: u32,
    ) -> Result<FetchedAttachments, MailError>;
    /// The one SMTP send for `mail_send` (B20).
    async fn send(&self, account: &str, mail: &OutgoingMail) -> Result<SendOutcome, MailError>;
    /// The configured account slugs, in owner order. A connector uses this to
    /// log only a real, validated account and to resolve the default account.
    fn account_ids(&self) -> Vec<String> {
        Vec::new()
    }
    /// The configured account addresses. A local lookup uses these to drop
    /// mail the owner sent to themself; the default is none.
    fn account_addresses(&self) -> Vec<String> {
        Vec::new()
    }
    /// The server-side Sent folder when the owner's `only_folders` read
    /// allowlist includes it. `None` means a local trust check cannot read it.
    fn sent_folder(&self, _account: &str) -> Option<String> {
        None
    }
    /// The effective bounds.
    fn limits(&self) -> &Limits;
}

#[async_trait]
impl MailApi for MailService {
    async fn list(&self, account: &str, query: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
        MailService::list(self, account, query).await
    }

    async fn list_headers(
        &self,
        account: &str,
        folder: Option<&str>,
        max: usize,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        MailService::list_headers(self, account, folder, max).await
    }

    async fn search(
        &self,
        account: &str,
        query: &SearchQuery,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        MailService::search(self, account, query).await
    }

    async fn thread(
        &self,
        account: &str,
        message_id: &str,
        max: usize,
    ) -> Result<Vec<EnvelopeItem>, MailError> {
        MailService::thread(self, account, message_id, max).await
    }

    async fn read(
        &self,
        account: &str,
        uid: u32,
        folder: &str,
        max_chars: usize,
    ) -> Result<MailItem, MailError> {
        let raw = MailService::read(self, account, uid, folder, max_chars).await?;
        crate::parse::parse_message(&raw)
    }

    async fn fetch_attachments(
        &self,
        account: &str,
        folder: &str,
        uid: u32,
    ) -> Result<FetchedAttachments, MailError> {
        MailService::fetch_attachments(self, account, folder, uid, 0).await
    }

    async fn send(&self, account: &str, mail: &OutgoingMail) -> Result<SendOutcome, MailError> {
        MailService::send(self, account, mail).await
    }

    fn account_ids(&self) -> Vec<String> {
        MailService::account_ids(self)
    }

    fn account_addresses(&self) -> Vec<String> {
        MailService::account_addresses(self)
    }

    fn sent_folder(&self, account: &str) -> Option<String> {
        MailService::sent_folder(self, account)
    }

    fn limits(&self) -> &Limits {
        MailService::limits(self)
    }
}

/// One attachment handed to the local evidence registry.
pub struct EvidenceAttachment {
    /// Lowercase SHA-256 of the bytes.
    pub sha256: String,
    /// Sender-declared file name.
    pub file_name: String,
    /// Declared MIME type.
    pub mime: String,
    /// Decoded length in bytes.
    pub size: usize,
    /// The decoded bytes; never part of a tool result.
    pub bytes: Vec<u8>,
    /// Account, as it appears in the source reference.
    pub account: String,
    /// Folder, as it appears in the source reference.
    pub folder: String,
    /// IMAP UID.
    pub uid: u32,
    /// `Message-ID` of the carrying message.
    pub message_id: String,
    /// IMAP part specifier.
    pub part: String,
}

/// What the registry remembers about one appended attachment.
pub struct EvidenceRef {
    /// Lowercase SHA-256, echoed back.
    pub sha256: String,
    /// True when the blob and `documents` row already existed.
    pub duplicate: bool,
}

/// The local write half: blob file plus registry rows (`docs/mail.md` §6).
pub trait EvidenceSink: Send + Sync {
    /// Append one attachment; bytes are consumed here, never returned.
    fn append(&self, attachment: EvidenceAttachment) -> Result<EvidenceRef, String>;
}

/// One composed message saved locally by `mail_draft`; never sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    /// The addresses the draft will be sent to; empty while unresolved.
    pub to: Vec<String>,
    /// The human line for each `to` address, e.g. `Northwind <camille@northwind.example>`.
    pub to_display: Vec<String>,
    pub subject: String,
    pub body: String,
}

/// The local draft store: production writes the encrypted store journal.
pub trait DraftSink: Send + Sync {
    /// Persist one draft and return its local id.
    fn save(&self, draft: &Draft) -> Result<i64, String>;
}

/// The seven tools over one [`MailApi`] plus the local sinks.
#[derive(Clone)]
pub struct MailToolset {
    api: Arc<dyn MailApi>,
    evidence: Option<Arc<dyn EvidenceSink>>,
    drafts: Option<Arc<dyn DraftSink>>,
    draft_contacts: Option<Arc<dyn RecipientDirectory>>,
    owner_input: Option<Arc<str>>,
}

impl MailToolset {
    /// An absent sink leaves the local tools registered but failing closed.
    pub fn new(api: Arc<dyn MailApi>, evidence: Option<Arc<dyn EvidenceSink>>) -> Self {
        Self {
            api,
            evidence,
            drafts: None,
            draft_contacts: None,
            owner_input: None,
        }
    }

    /// Wire the local draft store.
    pub fn with_drafts(mut self, sink: Arc<dyn DraftSink>) -> Self {
        self.drafts = Some(sink);
        self
    }

    /// Wire the send path's local contact directory: a draft name resolves
    /// exactly as a carded send resolves it.
    pub fn with_draft_contacts(mut self, contacts: Arc<dyn RecipientDirectory>) -> Self {
        self.draft_contacts = Some(contacts);
        self
    }

    /// The owner's own words: a draft recipient must appear there.
    pub fn with_owner_input(mut self, input: impl Into<Arc<str>>) -> Self {
        self.owner_input = Some(input.into());
        self
    }

    /// The mail API under the toolset, so a skill connector can call `send`
    /// directly and keep the typed error for the `mail.call` Ledger row.
    pub fn api(&self) -> Arc<dyn MailApi> {
        Arc::clone(&self.api)
    }

    /// The seven boxed native tools, ready for a
    /// [`kernel_broker::ToolRegistry::register_native`].
    pub fn tools(&self) -> Vec<Box<dyn NativeTool>> {
        vec![
            Box::new(MailListTool(self.clone())),
            Box::new(MailSearchTool(self.clone())),
            Box::new(MailThreadTool(self.clone())),
            Box::new(MailReadTool(self.clone())),
            Box::new(MailFetchAttachmentsTool(self.clone())),
            Box::new(MailSendTool(self.clone())),
            Box::new(MailDraftTool(self.clone())),
        ]
    }

    /// The account a read names. A call that names none uses the only configured
    /// account: the model is never told the slug, so requiring it only made it
    /// ask the owner. With several accounts the call must name one.
    fn account_or_only(&self, given: &str, tool: &str) -> Result<String, ToolError> {
        resolve_account(&self.api.account_ids(), Some(given))
            .map_err(|reason| bad_args(tool, &reason))
    }

    async fn list(&self, args: &serde_json::Value) -> Result<String, ToolError> {
        let args: ListArgs = deserialize(args, "mail_list")?;
        let account = self.account_or_only(&args.account, "mail_list")?;
        check_account(&account, "mail_list")?;
        check_folder(args.folder.as_deref(), "mail_list")?;
        let limits = self.api.limits();
        let max = limits.clamp_messages(0);
        let cap = limits.clamp_messages(args.limit.unwrap_or(0));
        // One row past the cap tells "exactly `cap` available" from "more".
        let query = ListQuery {
            folder: args.folder,
            limit: cap + 1,
            unread: args.unread,
            days: args.days,
        };
        let mut items = self.api.list(&account, &query).await.map_err(mail_error)?;
        let more = items.len() > cap;
        items.truncate(cap);
        let owner_addresses = self.api.account_addresses();
        let sent_folder = self.api.sent_folder(&account);
        let direction = EnvelopeDirection {
            owner_addresses: &owner_addresses,
            sent_folder: sent_folder.as_deref(),
            folder: query.folder.as_deref(),
        };
        let (rendered, shown) = render_envelopes_counted(&items, &direction);
        let unread = items[..shown].iter().filter(|item| item.unread).count();
        // At the backend's own bound a full window may hide more and the
        // backend cannot say; the byte budget can drop rows too.
        let cut = more || shown < items.len() || (cap == max && items.len() == cap);
        Ok(with_counts(rendered, unread, shown, cut.then_some(max)))
    }

    async fn search(&self, args: &serde_json::Value) -> Result<String, ToolError> {
        let args: SearchArgs = deserialize(args, "mail_search")?;
        let account = self.account_or_only(&args.account, "mail_search")?;
        check_account(&account, "mail_search")?;
        check_folder(args.folder.as_deref(), "mail_search")?;
        if args.query.is_empty() || args.query.len() > 512 || has_controls(&args.query) {
            return Err(bad_args(
                "mail_search",
                "query is empty, oversized or carries controls",
            ));
        }
        let query = SearchQuery {
            query: args.query,
            folder: args.folder,
            limit: args.limit.unwrap_or(0),
            days: args.days,
        };
        let items = self
            .api
            .search(&account, &query)
            .await
            .map_err(mail_error)?;
        let owner_addresses = self.api.account_addresses();
        let sent_folder = self.api.sent_folder(&account);
        let direction = EnvelopeDirection {
            owner_addresses: &owner_addresses,
            sent_folder: sent_folder.as_deref(),
            folder: query.folder.as_deref(),
        };
        Ok(render_envelopes(&items, &direction))
    }

    async fn thread(&self, args: &serde_json::Value) -> Result<String, ToolError> {
        let args: ThreadArgs = deserialize(args, "mail_thread")?;
        let account = self.account_or_only(&args.account, "mail_thread")?;
        check_account(&account, "mail_thread")?;
        if args.message_id.is_empty()
            || args.message_id.len() > 512
            || has_controls(&args.message_id)
        {
            return Err(bad_args(
                "mail_thread",
                "message_id is empty, oversized or carries controls",
            ));
        }
        let max = args.limit.unwrap_or(0);
        let items = self
            .api
            .thread(&account, &args.message_id, max)
            .await
            .map_err(mail_error)?;
        let owner_addresses = self.api.account_addresses();
        let sent_folder = self.api.sent_folder(&account);
        // `mail_thread` reads the inbox.
        let direction = EnvelopeDirection {
            owner_addresses: &owner_addresses,
            sent_folder: sent_folder.as_deref(),
            folder: Some("INBOX"),
        };
        Ok(render_envelopes(&items, &direction))
    }

    async fn read(&self, args: &serde_json::Value) -> Result<String, ToolError> {
        let args: ReadArgs = deserialize(args, "mail_read")?;
        let account = self.account_or_only(&args.account, "mail_read")?;
        check_account(&account, "mail_read")?;
        check_folder(args.folder.as_deref(), "mail_read")?;
        let folder = args.folder.as_deref().unwrap_or("INBOX");
        let max_chars = args.max_chars.unwrap_or(0);
        let item = self
            .api
            .read(&account, args.uid, folder, max_chars)
            .await
            .map_err(mail_error)?;
        // The cap is enforced here, whatever the implementation did with it.
        Ok(render_untrusted_capped(&item, self.api.limits(), max_chars))
    }

    async fn fetch_attachments(&self, args: &serde_json::Value) -> Result<String, ToolError> {
        let args: FetchAttachmentsArgs = deserialize(args, "mail_fetch_attachments")?;
        let account = self.account_or_only(&args.account, "mail_fetch_attachments")?;
        check_account(&account, "mail_fetch_attachments")?;
        check_folder(args.folder.as_deref(), "mail_fetch_attachments")?;
        let folder = args.folder.as_deref().unwrap_or("INBOX");
        let Some(sink) = &self.evidence else {
            return Err(ToolError::fetch(
                "this Mac has no evidence registry to append to",
            ));
        };
        let fetched = self
            .api
            .fetch_attachments(&account, folder, args.uid)
            .await
            .map_err(mail_error)?;
        let mut entries = Vec::new();
        for attachment in fetched.downloaded {
            let file_name = attachment.file_name.clone();
            let mime = attachment.mime.clone();
            let size = attachment.size;
            let reference = sink
                .append(EvidenceAttachment {
                    sha256: attachment.sha256,
                    file_name: attachment.file_name,
                    mime: attachment.mime,
                    size,
                    bytes: attachment.bytes,
                    account: account.clone(),
                    folder: folder.to_string(),
                    uid: args.uid,
                    message_id: fetched.message_id.clone(),
                    part: attachment.part,
                })
                .map_err(|reason| ToolError::fetch(format!("evidence registry: {reason}")))?;
            entries.push(json!({
                "sha256": reference.sha256,
                "file_name": file_name,
                "mime": mime,
                "size": size,
                "duplicate": reference.duplicate,
            }));
        }
        for skipped in fetched.skipped {
            entries.push(json!({
                "skipped": true,
                "file_name": skipped.file_name,
                "mime": skipped.mime,
                "reason": skipped.reason,
            }));
        }
        serde_json::to_string(&entries)
            .map_err(|error| ToolError::fetch(format!("rendering the attachment list: {error}")))
    }

    /// `mail_send`: exactly one SMTP submission through the API.
    async fn send(&self, args: &serde_json::Value) -> Result<String, ToolError> {
        let args: SendArgs = deserialize(args, "mail_send")?;
        if let Some(account) = args.account.as_deref() {
            // Only a canonical config slug names an account; anything else is
            // refused here, before the service and before any socket.
            if !account.is_empty() && !crate::config::is_account_slug(account) {
                return Err(bad_args("mail_send", "account is not a canonical slug"));
            }
            if !account.is_empty() && has_controls(account) {
                return Err(bad_args("mail_send", "account carries controls"));
            }
        }
        let mail = OutgoingMail {
            // The service replaces this with the account's own address.
            from: String::new(),
            to: args.to,
            cc: args.cc,
            subject: args.subject,
            body: args.body,
            ics: args.ics,
        };
        let has_ics = mail.ics.is_some();
        let outcome = self
            .api
            .send(args.account.as_deref().unwrap_or_default(), &mail)
            .await
            .map_err(mail_error)?;
        Ok(json!({
            "sent": true,
            "accepted": outcome.accepted,
            "bytes": outcome.bytes,
            "reply_class": outcome.reply_class,
            "ics": has_ics,
        })
        .to_string())
    }

    /// `mail_draft`: save locally; never a socket, never [`MailApi::send`].
    fn draft(&self, args: &serde_json::Value) -> Result<String, ToolError> {
        let args: DraftArgs = deserialize(args, "mail_draft")?;
        if args.body.trim().is_empty() {
            return Err(bad_args("mail_draft", "body is empty"));
        }
        if args.body.len() > crate::send::MAX_BODY_BYTES || args.body.contains('\0') {
            return Err(bad_args("mail_draft", "body is oversized"));
        }
        if args.subject.chars().count() > crate::send::MAX_SUBJECT_CHARS
            || has_controls(&args.subject)
        {
            return Err(bad_args(
                "mail_draft",
                "subject is oversized or carries controls",
            ));
        }
        let (to, to_display, question) = self.draft_recipients(args.to)?;
        let Some(sink) = &self.drafts else {
            return Err(ToolError::fetch(
                "this Mac has no local draft store to save to",
            ));
        };
        let draft = Draft {
            to: to.clone(),
            to_display: to_display.clone(),
            subject: args.subject.clone(),
            body: args.body,
        };
        let draft_id = sink
            .save(&draft)
            .map_err(|reason| ToolError::fetch(format!("draft store: {reason}")))?;
        let mut output = json!({
            "draft_id": draft_id,
            "saved": true,
            "sent": false,
            "to": to,
            "to_display": to_display,
            "subject": args.subject,
            "note": "saved on this Mac; nothing was sent",
        });
        if let Some(question) = question {
            output["question"] = json!(question);
        }
        Ok(output.to_string())
    }

    /// The draft's `to` comes from the owner's words plus the local contacts;
    /// mail is never read. Zero or several addresses save no recipient and
    /// ask one short question (fail closed: a later send picks nothing).
    fn draft_recipients(&self, raw: Vec<String>) -> Result<DraftRecipients, ToolError> {
        if raw.len() > crate::send::MAX_RECIPIENTS {
            return Err(bad_args("mail_draft", "too many recipients"));
        }
        let (mut to, mut display, mut question) = (Vec::new(), Vec::new(), None);
        for value in raw {
            let value = value.trim();
            if value.is_empty() || value.len() > 254 || has_controls(value) {
                return Err(bad_args(
                    "mail_draft",
                    "a recipient is empty, oversized or carries controls",
                ));
            }
            if let Some(owner) = &self.owner_input {
                let name = value.split_whitespace().next().unwrap_or(value);
                if !owner_says(owner, value) && !owner_says(owner, name) {
                    return Err(bad_args(
                        "mail_draft",
                        "a recipient must be named in the owner's message",
                    ));
                }
            }
            if value.contains('@') {
                validate_address(value, "to")
                    .map_err(|_| bad_args("mail_draft", "to is not a bare address"))?;
                to.push(value.to_string());
                display.push(value.to_string());
                continue;
            }
            match self.draft_matches(value).as_slice() {
                [address] => {
                    display.push(format!("{value} <{address}>"));
                    to.push(address.clone());
                }
                [] => {
                    question.get_or_insert(format!(
                        "Who at {value}? No contact matches: say their full name or address."
                    ));
                }
                _ => {
                    question.get_or_insert(format!(
                        "Who at {value}? Several contacts match: say the full name or address."
                    ));
                }
            }
        }
        // Fail closed: one unresolved name clears every recipient, so a later
        // "send it" can never send to part of what the owner asked.
        if question.is_some() {
            return Ok((Vec::new(), Vec::new(), question));
        }
        Ok((to, display, question))
    }

    /// The valid, de-duplicated local addresses for one name.
    fn draft_matches(&self, said: &str) -> Vec<String> {
        let Some(directory) = &self.draft_contacts else {
            return Vec::new();
        };
        let mut found: Vec<String> = Vec::new();
        for address in directory.addresses_for_name(said) {
            let address = address.trim();
            if validate_address(address, "to").is_ok()
                && !found
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(address))
            {
                found.push(address.to_string());
            }
        }
        found
    }
}

/// True when `owner` (the turn's trusted message) names `value`, case folded.
fn owner_says(owner: &str, value: &str) -> bool {
    owner.to_lowercase().contains(&value.to_lowercase())
}

/// Deserialize with a tool-named error message.
fn deserialize<T: for<'de> Deserialize<'de>>(
    args: &serde_json::Value,
    tool: &str,
) -> Result<T, ToolError> {
    serde_json::from_value(args.clone()).map_err(|error| ToolError::invalid_args(tool, error))
}

fn bad_args(tool: &str, message: &str) -> ToolError {
    ToolError::invalid_args(tool, message)
}

fn has_controls(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn check_account(account: &str, tool: &str) -> Result<(), ToolError> {
    if account.is_empty() || account.len() > 64 || has_controls(account) {
        return Err(bad_args(
            tool,
            "account is empty, oversized or carries controls",
        ));
    }
    Ok(())
}

fn check_folder(folder: Option<&str>, tool: &str) -> Result<(), ToolError> {
    if let Some(folder) = folder {
        if folder.is_empty() || folder.len() > 256 || has_controls(folder) {
            return Err(bad_args(
                tool,
                "folder is empty, oversized or carries controls",
            ));
        }
    }
    Ok(())
}

fn mail_error(error: MailError) -> ToolError {
    ToolError::fetch(error.to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    #[serde(default)]
    account: String,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    unread: Option<bool>,
    #[serde(default)]
    days: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    #[serde(default)]
    account: String,
    query: String,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    days: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadArgs {
    #[serde(default)]
    account: String,
    message_id: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    #[serde(default)]
    account: String,
    uid: u32,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    max_chars: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchAttachmentsArgs {
    #[serde(default)]
    account: String,
    #[serde(default)]
    folder: Option<String>,
    uid: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendArgs {
    #[serde(default)]
    account: Option<String>,
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    subject: String,
    body: String,
    /// The runtime-built `text/calendar` payload (an invite), never model text.
    #[serde(default)]
    ics: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftArgs {
    /// A bare address, or a contact name the owner typed. Empty is a valid
    /// draft: the owner may only want to read the words first.
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    subject: String,
    body: String,
}

/// One read tool: shared [`Tool`] plumbing, a distinct name, schema and method.
macro_rules! read_tool {
    ($wrapper:ident, $method:ident, $name:literal, $description:literal, $path:ident) => {
        pub struct $wrapper(MailToolset);

        impl NativeTool for $wrapper {
            fn native_name(&self) -> &'static str {
                $name
            }
            fn native_description(&self) -> &'static str {
                $description
            }
            fn native_schema(&self) -> &'static serde_json::Value {
                static SCHEMA: std::sync::LazyLock<serde_json::Value> =
                    std::sync::LazyLock::new(|| $crate::tools::schema_for(stringify!($method)));
                std::sync::LazyLock::force(&SCHEMA)
            }
        }

        #[async_trait]
        impl Tool for $wrapper {
            fn path_id(&self) -> kernel_core::privacy::PathId {
                kernel_core::privacy::PathId::$path
            }
            fn name(&self) -> &str {
                self.native_name()
            }
            fn schema(&self) -> serde_json::Value {
                self.native_schema().clone()
            }
            async fn run(
                &self,
                args: &serde_json::Value,
                _ctx: &ToolCtx,
            ) -> Result<ToolOutput, ToolError> {
                Ok(ToolOutput::ok(self.0.$method(args).await?))
            }
            fn risk(&self) -> Risk {
                Risk::Low
            }
            fn class(&self) -> ToolClass {
                ToolClass {
                    requires_explicit_rule: true,
                    output_trust: Trust::Untrusted,
                    returns_private_data: true,
                    ..ToolClass::default()
                }
            }
        }
    };
}

/// Put an explicit count line in front of a `mail_list` result, outside the
/// untrusted banner: no mail header can forge it, because position tells them
/// apart. The counts cover the rows shown, never the whole folder; the model
/// reads them instead of counting rows (it miscounted 8 as 7). When rows were
/// dropped (the caller's `limit`, the backend's `max` bound or the byte
/// budget) the line says the counts are a floor, so "1 unread" with `limit: 1`
/// is never reported as the folder's answer.
fn with_counts(rendered: String, unread: usize, total: usize, cut: Option<usize>) -> String {
    let mut line = format!(
        "unread_count={unread} total={total} (counts of the {total} messages listed below, \
         not of the whole folder)"
    );
    if let Some(max) = cut {
        line.push_str(&format!(
            "; the list is cut (limit, the {max}-message cap or the size budget), so the folder \
             may hold more: say \"at least {unread} unread\", never {unread} alone; \
             unread=true lists only unread mail, newest first"
        ));
    }
    format!("{line}\n{rendered}")
}

/// The read tools' JSON schemas, keyed by the toolset method name.
pub(crate) fn schema_for(method: &str) -> serde_json::Value {
    match method {
        "list" => json!({"type":"object","properties":{
            "account":{"type":"string","maxLength":64},
            "folder":{"type":"string","maxLength":256},
            "limit":{"type":"integer","minimum":1,"maximum":200},
            "unread":{"type":"boolean"},
            "days":{"type":"integer","minimum":1,"maximum":90}},
            "additionalProperties":false}),
        "search" => json!({"type":"object","properties":{
            "account":{"type":"string","maxLength":64},
            "query":{"type":"string","maxLength":512},
            "folder":{"type":"string","maxLength":256},
            "limit":{"type":"integer","minimum":1,"maximum":200},
            "days":{"type":"integer","minimum":1,"maximum":90}},
            "required":["query"],"additionalProperties":false}),
        "thread" => json!({"type":"object","properties":{
            "account":{"type":"string","maxLength":64},
            "message_id":{"type":"string","maxLength":512},
            "limit":{"type":"integer","minimum":1,"maximum":200}},
            "required":["message_id"],"additionalProperties":false}),
        "read" => json!({"type":"object","properties":{
            "account":{"type":"string","maxLength":64},
            "uid":{"type":"integer","minimum":1},
            "folder":{"type":"string","maxLength":256},
            "max_chars":{"type":"integer","minimum":1}},
            "required":["uid"],"additionalProperties":false}),
        "send" => json!({"type":"object","properties":{
            "account":{"type":"string","maxLength":64},
            "to":{"type":"array","items":{"type":"string","maxLength":254},"minItems":1,"maxItems":50},
            "cc":{"type":"array","items":{"type":"string","maxLength":254},"maxItems":50},
            "subject":{"type":"string","maxLength":998},
            "body":{"type":"string","maxLength":102400},
            "ics":{"type":"string"}},
            "required":["to","subject","body"],"additionalProperties":false}),
        "draft" => json!({"type":"object","properties":{
            "to":{"type":"array","items":{"type":"string","maxLength":254},"maxItems":50},
            "subject":{"type":"string","maxLength":998},
            "body":{"type":"string","maxLength":102400}},
            "required":["body"],"additionalProperties":false}),
        other => json!({"type":"object","additionalProperties":false, "note": other}),
    }
}

read_tool!(
    MailListTool,
    list,
    "mail_list",
    "List the newest messages of one folder as headers only (no body). The result \
     starts with unread_count and total, the counts of the listed window; to answer \
     how many are unread, call it with unread=true and no limit, then read those numbers, never count the rows.",
    B19
);
read_tool!(
    MailSearchTool,
    search,
    "mail_search",
    "Search one folder server-side for text; returns headers only.",
    B19
);
read_tool!(
    MailThreadTool,
    thread,
    "mail_thread",
    "Return the headers of the messages in one thread.",
    B19
);
read_tool!(
    MailReadTool,
    read,
    "mail_read",
    "Read one message body (plain text preferred), banner-wrapped and bounded.",
    B19
);

/// `mail_fetch_attachments` (B22): append allowed parts to the registry.
pub struct MailFetchAttachmentsTool(MailToolset);

impl NativeTool for MailFetchAttachmentsTool {
    fn native_name(&self) -> &'static str {
        "mail_fetch_attachments"
    }
    fn native_description(&self) -> &'static str {
        "Download the allowed attachments of one message into the local evidence \
         registry and return their hashes and names, never their bytes."
    }
    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            json!({"type":"object","properties":{
                "account":{"type":"string","maxLength":64},
                "folder":{"type":"string","maxLength":256},
                "uid":{"type":"integer","minimum":1}},
                "required":["uid"],"additionalProperties":false})
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for MailFetchAttachmentsTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B22
    }
    fn name(&self) -> &str {
        self.native_name()
    }
    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }
    async fn run(&self, args: &serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(self.0.fetch_attachments(args).await?))
    }
    fn risk(&self) -> Risk {
        Risk::Medium
    }
    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            output_trust: Trust::Untrusted,
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

/// `mail_send` (B20): exactly one SMTP submission. Skill-only: the broker's
/// floor refuses a plain-conversation call before the connector is reached.
pub struct MailSendTool(MailToolset);

impl NativeTool for MailSendTool {
    fn native_name(&self) -> &'static str {
        "mail_send"
    }
    fn native_description(&self) -> &'static str {
        "Send one plain-text email (optionally with a calendar invite) from the \
         owner's mailbox over SMTP. Skill-only: it can never run outside an \
         approved skill."
    }
    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> =
            std::sync::LazyLock::new(|| schema_for("send"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for MailSendTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B20
    }
    fn name(&self) -> &str {
        self.native_name()
    }
    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }
    async fn run(&self, args: &serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(self.0.send(args).await?))
    }
    fn risk(&self) -> Risk {
        Risk::High
    }
    fn class(&self) -> ToolClass {
        ToolClass {
            skill_only: true,
            requires_explicit_rule: true,
            output_trust: Trust::Trusted,
            // The acknowledgement carries only a count, no private data.
            returns_private_data: false,
            ..ToolClass::default()
        }
    }
}

/// `mail_draft` (B22, local journal): compose and save, never send, no card.
pub struct MailDraftTool(MailToolset);

impl NativeTool for MailDraftTool {
    fn native_name(&self) -> &'static str {
        "mail_draft"
    }
    fn native_description(&self) -> &'static str {
        "Write and save a draft of one plain-text email on this Mac. Call it at once \
         when the owner asks to draft or write a mail; do not read the mailbox first. \
         It NEVER sends and needs no approval. `to` may be empty, or a contact name or \
         address from the owner's own message; a recipient the owner did not write is \
         never used. A name resolves only from the owner's contacts: when the result \
         carries `question`, ask it to the owner in one short line and do not guess. A \
         later send keeps its own card."
    }
    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> =
            std::sync::LazyLock::new(|| schema_for("draft"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for MailDraftTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B22
    }
    fn name(&self) -> &str {
        self.native_name()
    }
    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }
    async fn run(&self, args: &serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(self.0.draft(args)?))
    }
    fn risk(&self) -> Risk {
        Risk::Medium
    }
    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            output_trust: Trust::Trusted,
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_broker::ToolClassExt;

    /// A mail API that never returns anything; only classification is read.
    struct NoopApi;

    #[async_trait]
    impl MailApi for NoopApi {
        async fn list(&self, _: &str, _: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
            Ok(Vec::new())
        }
        async fn search(&self, _: &str, _: &SearchQuery) -> Result<Vec<EnvelopeItem>, MailError> {
            Ok(Vec::new())
        }
        async fn thread(&self, _: &str, _: &str, _: usize) -> Result<Vec<EnvelopeItem>, MailError> {
            Ok(Vec::new())
        }
        async fn read(&self, _: &str, _: u32, _: &str, _: usize) -> Result<MailItem, MailError> {
            Err(MailError::Protocol)
        }
        async fn fetch_attachments(
            &self,
            _: &str,
            _: &str,
            _: u32,
        ) -> Result<FetchedAttachments, MailError> {
            Err(MailError::Protocol)
        }
        async fn send(&self, _: &str, _: &OutgoingMail) -> Result<SendOutcome, MailError> {
            Err(MailError::Protocol)
        }
        fn limits(&self) -> &Limits {
            static LIMITS: std::sync::LazyLock<Limits> = std::sync::LazyLock::new(Limits::default);
            std::sync::LazyLock::force(&LIMITS)
        }
    }

    /// Reports the accounts it is given and remembers the account `list` got.
    struct Accounts {
        ids: Vec<String>,
        listed: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl MailApi for Accounts {
        async fn list(&self, account: &str, q: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
            self.listed.lock().unwrap().push(account.to_string());
            NoopApi.list(account, q).await
        }
        async fn search(&self, a: &str, q: &SearchQuery) -> Result<Vec<EnvelopeItem>, MailError> {
            NoopApi.search(a, q).await
        }
        async fn thread(&self, a: &str, m: &str, n: usize) -> Result<Vec<EnvelopeItem>, MailError> {
            NoopApi.thread(a, m, n).await
        }
        async fn read(&self, a: &str, u: u32, f: &str, m: usize) -> Result<MailItem, MailError> {
            NoopApi.read(a, u, f, m).await
        }
        async fn fetch_attachments(
            &self,
            a: &str,
            f: &str,
            u: u32,
        ) -> Result<FetchedAttachments, MailError> {
            NoopApi.fetch_attachments(a, f, u).await
        }
        async fn send(&self, a: &str, m: &OutgoingMail) -> Result<SendOutcome, MailError> {
            NoopApi.send(a, m).await
        }
        fn account_ids(&self) -> Vec<String> {
            self.ids.clone()
        }
        fn limits(&self) -> &Limits {
            NoopApi.limits()
        }
    }

    fn toolset_with(ids: &[&str]) -> (MailToolset, Arc<Accounts>) {
        let api = Arc::new(Accounts {
            ids: ids.iter().map(|id| id.to_string()).collect(),
            listed: std::sync::Mutex::new(Vec::new()),
        });
        (MailToolset::new(api.clone(), None), api)
    }

    #[tokio::test]
    async fn a_read_without_an_account_uses_the_only_configured_one() {
        let (toolset, api) = toolset_with(&["personal"]);
        toolset.list(&json!({"unread": true})).await.unwrap();
        toolset
            .list(&json!({"account": "personal", "unread": true}))
            .await
            .unwrap();
        assert_eq!(*api.listed.lock().unwrap(), ["personal", "personal"]);
        // The schema no longer requires it.
        for method in ["list", "search", "thread", "read"] {
            let required = schema_for(method)["required"].clone();
            assert!(
                !required.to_string().contains("account"),
                "{method}: {required}"
            );
        }
    }

    #[tokio::test]
    async fn with_several_accounts_a_read_must_name_one() {
        let (toolset, api) = toolset_with(&["personal", "work"]);
        let error = toolset.list(&json!({})).await.unwrap_err().to_string();
        assert!(error.contains("personal, work"), "{error}");
        assert!(api.listed.lock().unwrap().is_empty());
        let (none, _) = toolset_with(&[]);
        assert!(none.list(&json!({})).await.is_err());
    }

    #[test]
    fn every_read_tool_is_untrusted_and_private_data() {
        let toolset = MailToolset::new(Arc::new(NoopApi), None);
        let names: Vec<String> = toolset
            .tools()
            .iter()
            .map(|tool| tool.name().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "mail_list",
                "mail_search",
                "mail_thread",
                "mail_read",
                "mail_fetch_attachments",
                "mail_send",
                "mail_draft"
            ]
        );
        for tool in toolset.tools() {
            assert!(tool.requires_explicit_rule(), "{}", tool.name());
            assert_eq!(
                tool.schema()["additionalProperties"],
                false,
                "{}",
                tool.name()
            );
            if tool.name() == "mail_send" {
                // The one network write is skill-only and its acknowledgement is trusted.
                assert!(tool.class().skill_only);
                assert!(!tool.returns_private_data());
                assert_eq!(tool.output_trust(), Trust::Trusted);
            } else if tool.name() == "mail_draft" {
                // A local compose: never skill-only, never a send.
                assert!(!tool.class().skill_only);
                assert!(tool.returns_private_data());
                assert_eq!(tool.output_trust(), Trust::Trusted);
            } else {
                assert!(tool.returns_private_data(), "{}", tool.name());
                assert_eq!(tool.output_trust(), Trust::Untrusted, "{}", tool.name());
            }
        }
    }

    /// Records saved drafts. The API is the existing `Accounts` fake, whose
    /// `send` fails, so a draft that tried to send could never pass.
    #[derive(Default)]
    struct DraftRecorder {
        drafts: std::sync::Mutex<Vec<Draft>>,
    }

    impl DraftSink for DraftRecorder {
        fn save(&self, draft: &Draft) -> Result<i64, String> {
            let mut drafts = self.drafts.lock().unwrap();
            drafts.push(draft.clone());
            Ok(drafts.len() as i64)
        }
    }

    fn draft_toolset(owner: &str) -> (MailToolset, Arc<DraftRecorder>, Arc<Accounts>) {
        draft_toolset_with(owner, vec![("Northwind", "camille@northwind.example")])
    }

    /// A local contact list, never the mailbox: `(said, address)`.
    struct DraftContacts(Vec<(&'static str, &'static str)>);

    impl RecipientDirectory for DraftContacts {
        fn is_known(&self, _: &str) -> bool {
            false
        }
        fn addresses_for_name(&self, said: &str) -> Vec<String> {
            self.0
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(said))
                .map(|(_, address)| address.to_string())
                .collect()
        }
    }

    fn draft_toolset_with(
        owner: &str,
        contacts: Vec<(&'static str, &'static str)>,
    ) -> (MailToolset, Arc<DraftRecorder>, Arc<Accounts>) {
        let (toolset, api) = toolset_with(&["personal"]);
        let drafts = Arc::new(DraftRecorder::default());
        let toolset = toolset
            .with_drafts(drafts.clone())
            .with_draft_contacts(Arc::new(DraftContacts(contacts)))
            .with_owner_input(owner);
        (toolset, drafts, api)
    }

    #[test]
    fn an_owner_ask_writes_a_local_draft_and_never_sends() {
        let (toolset, drafts, api) = draft_toolset("draft smth for northwind saying we're late");
        let output = toolset
            .draft(&json!({
                "to": ["Northwind"],
                "subject": "",
                "body": "We're late on the Northwind delivery.",
            }))
            .unwrap();
        let output: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(output["saved"], json!(true));
        assert_eq!(output["sent"], json!(false));
        assert_eq!(output["to"], json!(["camille@northwind.example"]));
        assert_eq!(
            output["to_display"],
            json!(["Northwind <camille@northwind.example>"])
        );
        let saved = drafts.drafts.lock().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].to, ["camille@northwind.example"]);
        drop(saved);
        assert!(
            api.listed.lock().unwrap().is_empty(),
            "a draft reads no mail"
        );

        // An address that only a mail body carries is never the recipient.
        drafts.drafts.lock().unwrap().clear();
        let error = toolset
            .draft(&json!({ "to": ["attacker@invented.example"], "body": "We're late." }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("owner's message"), "{error}");
        assert!(drafts.drafts.lock().unwrap().is_empty());
    }

    #[test]
    fn a_company_with_two_contacts_saves_no_recipient_and_asks_which() {
        let (toolset, drafts, _) = draft_toolset_with(
            "draft smth for northwind saying we're late",
            vec![
                ("Northwind", "camille@northwind.example"),
                ("Northwind", "lea@northwind.example"),
            ],
        );
        let output = toolset
            .draft(&json!({
                "to": ["Northwind"],
                "subject": "Late",
                "body": "We're late.",
            }))
            .unwrap();
        let output: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(output["saved"], json!(true));
        assert_eq!(output["to"], json!([]));
        assert_eq!(output["to_display"], json!([]));
        let question = output["question"].as_str().expect("one short question");
        assert!(question.contains("Northwind"), "{question}");
        let saved = drafts.drafts.lock().unwrap();
        assert_eq!(saved.len(), 1, "the draft is still saved");
        assert!(saved[0].to.is_empty());
    }
}
