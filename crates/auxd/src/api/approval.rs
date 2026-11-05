//! Interactive approvals (B-API v2).
//!
//! API turns cannot call a human through stdin, so an `ask` decision opens a
//! **pending approval**: the turn runner publishes `approval.new`, awaits the
//! answer with a bounded timeout (fail-closed deny), and the app answers
//! through `POST /v1/approvals/{id}`. The registry is in-memory: a daemon
//! restart drops every pending approval, and [`recover_stale_pending`] writes
//! one `approval.dropped` audit line per orphan at the next boot.
//!
//! Scheduled jobs never use this path: they keep their non-interactive
//! approver (`NonInteractiveApprover` in `agent_job.rs`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_notify::{Notification, Notifier};
use aux_store::Store;
use kernel_broker::{ApprovalDecision, ApprovalRequest, Approver, ApproverError, Risk};
use kernel_core::Lang;
use tokio::sync::{broadcast, oneshot};

pub(crate) use super::approval_preview;
use super::error;
use super::snapshot::clean_field;
use super::wire::{self, ApprovalFrame, ApprovalStateFrame};

/// Default bounded wait before an unanswered approval is denied.
///
/// This is the fallback when `config.toml` cannot be read; the live value
/// comes from `[approval] timeout_secs` (default
/// [`kernel_core::config::DEFAULT_APPROVAL_TIMEOUT_SECS`]), clamped strictly
/// below the turn timeout so the turn can report the approval's own expiry.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration =
    Duration::from_secs(kernel_core::config::DEFAULT_APPROVAL_TIMEOUT_SECS);

/// How long a `later` answer may be reopened by `POST /v1/approvals/{id}/undo`.
pub const APPROVAL_UNDO_WINDOW: Duration = Duration::from_secs(10);

/// What the phone is told about waiting approvals: a count and a pointer to
/// the app, never a tool, an argument, an address or a name. The
/// details stay on the approval card in the app. The local display gets the
/// same counts-only phrase when no gateway is paired.
pub fn phone_notice(waiting: usize, lang: Lang) -> Notification {
    let body = match (waiting <= 1, lang) {
        (true, Lang::En) => "1 approval is waiting. Open Auxesis to see it.".to_string(),
        (false, Lang::En) => {
            format!("{waiting} approvals are waiting. Open Auxesis to see them.")
        }
        (true, Lang::Fr) => {
            "1 approbation est en attente. Ouvrez Auxesis pour la voir.".to_string()
        }
        (false, Lang::Fr) => {
            format!("{waiting} approbations sont en attente. Ouvrez Auxesis pour les voir.")
        }
    };
    Notification::new("Auxesis", body)
}

/// Check a Gmail draft's fields. They are validated before an approval is
/// published so an unreadable destination never gets a card that could be
/// approved without showing where the draft goes.
fn gmail_draft_approval_check(arguments: &serde_json::Value) -> Result<(), ApproverError> {
    fn field<'a>(
        arguments: &'a serde_json::Value,
        name: &str,
        required: bool,
    ) -> Result<Option<&'a str>, ApproverError> {
        match arguments.get(name) {
            None if !required => Ok(None),
            Some(value) => value.as_str().map(Some).ok_or_else(|| {
                ApproverError(format!("Gmail draft has an unreadable {name} field"))
            }),
            None => Err(ApproverError(format!(
                "Gmail draft has no readable {name} field"
            ))),
        }
    }

    fn recipients(value: &str) -> Result<Vec<&str>, ApproverError> {
        let addresses = value.split(',').map(str::trim).collect::<Vec<_>>();
        if addresses.is_empty()
            || addresses.iter().any(|address| {
                let mut parts = address.split('@');
                let local = parts.next().unwrap_or_default();
                let domain = parts.next().unwrap_or_default();
                local.is_empty()
                    || domain.is_empty()
                    || address.len() > 254
                    || parts.next().is_some()
                    || address.chars().any(char::is_whitespace)
                    || address.chars().any(|character| {
                        character.is_control()
                            || matches!(
                                character,
                                '<' | '>'
                                    | ';'
                                    | ':'
                                    | '"'
                                    | '('
                                    | ')'
                                    | '['
                                    | ']'
                                    | '\\'
                                    | '\u{200b}'..='\u{200f}'
                                    | '\u{202a}'..='\u{202e}'
                                    | '\u{2060}'..='\u{2069}'
                                    | '\u{feff}'
                            )
                    })
                    || domain.starts_with('.')
                    || domain.ends_with('.')
                    || domain.contains("..")
                    || !domain.chars().all(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, '-' | '.')
                    })
            })
        {
            return Err(ApproverError(
                "Gmail draft has no readable recipient".to_string(),
            ));
        }
        Ok(addresses)
    }

    fn recipient_field<'a>(
        arguments: &'a serde_json::Value,
        name: &str,
        required: bool,
    ) -> Result<Option<Vec<&'a str>>, ApproverError> {
        let Some(value) = arguments.get(name) else {
            return if required {
                Err(ApproverError(
                    "Gmail draft has no readable recipient".to_string(),
                ))
            } else {
                Ok(None)
            };
        };
        let addresses = if let Some(value) = value.as_str() {
            recipients(value)?
        } else if let Some(values) = value.as_array() {
            let mut addresses = Vec::new();
            for value in values {
                let value = value.as_str().ok_or_else(|| {
                    ApproverError(format!("Gmail draft has an unreadable {name} field"))
                })?;
                addresses.extend(recipients(value)?);
            }
            addresses
        } else {
            return Err(ApproverError(format!(
                "Gmail draft has an unreadable {name} field"
            )));
        };
        Ok(Some(addresses))
    }

    let to = recipient_field(arguments, "to", true)?
        .ok_or_else(|| ApproverError("Gmail draft has no readable recipient".to_string()))?;
    // `to: []` (or a list of empty strings) passes the field check but leaves
    // no readable destination: the card must never be offered, since the
    // approval could not show where the draft goes.
    if to.is_empty() {
        return Err(ApproverError(
            "Gmail draft has no readable recipient".to_string(),
        ));
    }
    let cc = recipient_field(arguments, "cc", false)?;
    let bcc = recipient_field(arguments, "bcc", false)?;
    let count = to.len() + cc.as_ref().map_or(0, Vec::len) + bcc.as_ref().map_or(0, Vec::len);
    if count > 10 {
        return Err(ApproverError(
            "Gmail draft has too many recipients to show safely".to_string(),
        ));
    }
    let subject = field(arguments, "subject", true)?
        .ok_or_else(|| ApproverError("Gmail draft has no readable subject".to_string()))?;
    if subject.chars().count() > 998
        || subject.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{200b}'..='\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2060}'..='\u{2069}'
                        | '\u{feff}'
                )
        })
    {
        return Err(ApproverError(
            "Gmail draft has an unreadable subject".to_string(),
        ));
    }
    let recipient_bytes = to.iter().map(|address| address.len()).sum::<usize>()
        + cc.as_ref().map_or(0, |addresses| {
            addresses.iter().map(|address| address.len()).sum()
        })
        + bcc.as_ref().map_or(0, |addresses| {
            addresses.iter().map(|address| address.len()).sum()
        });
    if recipient_bytes > 4096 {
        return Err(ApproverError(
            "Gmail draft has an unreadable recipient".to_string(),
        ));
    }
    let body = field(arguments, "body", true)?
        .ok_or_else(|| ApproverError("Gmail draft has no readable body field".to_string()))?;
    // The body is shown whole on the card (the shared builder refuses a body
    // too big for a card), so it is only checked for the header shapes the
    // Gmail API would refuse.
    if body
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(ApproverError(
            "Gmail draft has an unreadable body field".to_string(),
        ));
    }
    Ok(())
}

/// The configured mail accounts, as `(id, address)`, for the card of `tool`.
///
/// The card must name the address a mail leaves from, so the accounts come
/// from the same `[connectors.mail]` table the mail tool sends with. No
/// config.toml, or no table, is no account: the card still asks, its From
/// unknown. A config.toml that is there but cannot be read safely or parsed
/// (a FIFO, a symlink, a broken table) refuses the card of a tool that
/// carries mail, never shows it without its sender. Another card names no
/// sender and still asks.
pub(crate) fn mail_accounts(home: &Path, tool: &str) -> Result<approval_preview::Accounts, String> {
    match configured_accounts(home) {
        None if approval_preview::carries_mail(tool) => Err(
            "config.toml cannot be read, so the card cannot name the sending account: refusing"
                .to_string(),
        ),
        read => Ok(read.unwrap_or_default()),
    }
}

/// The `[connectors.mail]` accounts, read once through the home's verified
/// directory fd; `None` when config.toml is there but cannot be read or parsed.
fn configured_accounts(home: &Path) -> Option<approval_preview::Accounts> {
    let read = kernel_core::SandboxHome::open_existing(home)
        .map_err(kernel_core::ConfigError::from)
        .and_then(|home| aux_engine::config::read_config_text(&home));
    let text = match read {
        Ok(text) => text,
        Err(kernel_core::ConfigError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return Some(Vec::new())
        }
        Err(_) => return None,
    };
    let value = toml::from_str::<toml::Value>(&text).ok()?;
    let Some(mail) = value.get("connectors").and_then(|c| c.get("mail")) else {
        return Some(Vec::new());
    };
    let config = aux_mail::MailConfig::from_toml(&toml::to_string(mail).ok()?).ok()?;
    let accounts = config.accounts.iter();
    Some(accounts.map(|a| (a.id.clone(), a.email.clone())).collect())
}

/// One pending approval: everything the app's `Approval` JSON needs, plus the
/// routing (agent, thread) for the audit trail.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    /// API id (`ap-<millis>-<seq>`), URL path segment and audit key.
    pub id: String,
    /// Id of the `approval.pending` journal row, or `0` when the audit row
    /// could not be written. `0` is never a real event id (SQLite ids start
    /// at 1) and keeps the frame decodable for the app's required `u64`.
    pub audit_id: u64,
    /// Agent that wants to run the tool.
    pub agent: String,
    /// Session the turn belongs to.
    pub thread_id: i64,
    /// The chief's session when a delegate asks: that turn waits on this card
    /// too. `None` for the chief's own asks.
    pub root_thread: Option<i64>,
    /// Tool name.
    pub tool: String,
    /// Risk classification of the tool.
    pub risk: Risk,
    /// The short title the card shows: a person reads this first.
    pub card_title: String,
    /// The human body the card shows: never JSON, never raw braces.
    pub card_body: String,
    /// The `label: value` lines the card shows as fields.
    pub card_detail: Vec<String>,
    /// The scrubbed arguments: the payload the owner edits as JSON. The card
    /// never shows it; only the edit form does.
    pub edit_args: String,
    /// Taint summary of the conversation that asked (`None` = clean): what
    /// introduced untrusted content. A tainted ask refuses "always allow".
    pub taint: Option<String>,
    /// True when the call will run unsandboxed (the `[shell]` escape hatch).
    /// Shown on the card; refuses "always allow" exactly like taint.
    pub unsandboxed: bool,
    /// True when the call runs sandboxed with every socket open
    /// (`[shell] network = true`). Shown on the card; refuses "always allow"
    /// exactly like taint.
    pub networked: bool,
    /// Creation time (unix milliseconds).
    pub created_ms: i64,
}

impl PendingApproval {
    /// True when the ask comes from a tainted conversation: "always allow"
    /// must be refused — taint can never widen permissions.
    pub fn is_tainted(&self) -> bool {
        self.taint.is_some()
    }

    /// The app-facing `Approval` shape (`state = pending`).
    pub fn frame(&self) -> ApprovalFrame {
        let tainted = self.is_tainted();
        let why = if self.unsandboxed {
            match self.taint.as_deref() {
                Some(source) => format!(
                    "unsandboxed call and tainted conversation: {source} is in context; every consequential call must be approved"
                ),
                None => "unsandboxed call: the shell will run without its sandbox; every call must be approved".to_string(),
            }
        } else if self.networked {
            match self.taint.as_deref() {
                Some(source) => format!(
                    "network-enabled shell and tainted conversation: {source} is in context; every call must be approved"
                ),
                None => "network-enabled shell: the sandbox has every socket open; every call must be approved".to_string(),
            }
        } else if tainted {
            format!(
                "tainted conversation: {} is in context, every consequential call must be approved",
                self.taint.as_deref().unwrap_or("untrusted content")
            )
        } else {
            "no matching rule: this tool always asks".to_string()
        };
        let scope_rule = if self.unsandboxed {
            "ask (unsandboxed call)".to_string()
        } else if self.networked {
            "ask (network-enabled shell)".to_string()
        } else if tainted {
            "ask (tainted conversation)".to_string()
        } else {
            "ask (no matching allow rule)".to_string()
        };
        ApprovalFrame {
            id: self.id.clone(),
            audit_id: self.audit_id,
            agent: clean_field(&self.agent),
            thread_id: self.thread_id.to_string(),
            ts: self.created_ms,
            action: format!("run {}", clean_field(&self.tool)),
            // The title is the human one the daemon built: never the
            // arguments.
            headline: clean_field(&self.card_title),
            preview: Some(self.card_body.clone()),
            full_preview: Some(self.card_body.clone()),
            edit_preview: Some(self.edit_args.clone()),
            detail: self.card_detail.clone(),
            why,
            verifier: None,
            taint: self.taint.clone(),
            unsandboxed: self.unsandboxed,
            clean_note: Some("arguments were sanitized and redacted by auxd".to_string()),
            scope_tool: clean_field(&self.tool),
            scope_resource: None,
            scope_rule,
            destructive: self.risk == Risk::High,
            state: ApprovalStateFrame::Pending,
        }
    }
}

/// What the API (or the timeout) decided for one pending approval.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    /// Approved or denied.
    pub allow: bool,
    /// The answer should apply to every future matching call.
    pub always: bool,
    /// Who answered (`you` for the API; `timeout` for the fail-closed deny).
    pub by: String,
    /// The edited draft (`edit` answer): the arguments the tool must run
    /// instead of the ones the model asked for. `None` runs the request
    /// unchanged, and is the only value for allow/deny/timeout.
    pub edited: Option<serde_json::Value>,
}

impl Resolution {
    /// Approve this call.
    pub fn allow_once() -> Self {
        Self {
            allow: true,
            always: false,
            by: "you".to_string(),
            edited: None,
        }
    }

    /// Approve this call with `arguments` substituted for the requested ones
    /// (the `edit` decision). Never persistent: an edit is allow-once only.
    pub fn edited_once(arguments: serde_json::Value) -> Self {
        Self {
            allow: true,
            always: false,
            by: "you".to_string(),
            edited: Some(arguments),
        }
    }

    /// Deny this call.
    pub fn deny() -> Self {
        Self {
            allow: false,
            always: false,
            by: "you".to_string(),
            edited: None,
        }
    }

    /// The fail-closed timeout decision.
    pub fn timeout() -> Self {
        Self {
            allow: false,
            always: false,
            by: "timeout".to_string(),
            edited: None,
        }
    }
}

/// In-memory registry of pending approvals and their waiters.
pub struct ApprovalRegistry {
    inner: Arc<Mutex<Inner>>,
    timeout: Duration,
    next: AtomicU64,
    /// Where the fixed [`phone_notice`] goes when an approval opens; the
    /// gateway router in production. `None` keeps the phone silent.
    phone: Mutex<Option<Arc<dyn Notifier>>>,
    /// The local macOS sink used when no gateway is paired
    /// (APPROVAL-NO-GATEWAY). `None` sends no local notice.
    local: Mutex<Option<Arc<dyn Notifier>>>,
    /// The owner's UI language for that fixed phrase.
    lang: Mutex<Lang>,
    /// When the phone was last told, so a burst of approvals sends one text.
    phone_last: Mutex<Option<std::time::Instant>>,
}

/// The shortest gap between two approval texts to the phone.
const PHONE_NOTICE_GAP: Duration = Duration::from_secs(600);

struct Inner {
    pending: HashMap<String, PendingApproval>,
    waiters: HashMap<String, oneshot::Sender<Resolution>>,
    /// Ids whose claim outlived the turn: the timeout grace expiry marked
    /// them, so a late [`ClaimedApproval::complete_with`] must not wake the
    /// turn or publish an `allowed` frame. A turn that ends also
    /// marks its own claimed ids.
    abandoned: HashSet<String>,
    /// Ids currently claimed by an in-flight answer, mapped to their session
    /// (thread). A turn ends -> every claimed approval of that session is
    /// abandoned too, so a completion that lands after the turn gave up
    /// cannot wake it.
    claimed: HashMap<String, i64>,
    /// Opaque callback nonces (Telegram inline buttons) mapped to the approval
    /// they answer. A nonce is single-use and is retired with its approval, so
    /// a leaked or replayed nonce is dead and the raw approval id is never
    /// exposed on the wire.
    nonces: HashMap<String, String>,
    /// `later` answers, kept only for the bounded undo window so the same id
    /// can be re-opened in every view.
    deferred: HashMap<String, (PendingApproval, Instant)>,
    /// The turn (`run_id`) that waits on each card, so a turn that ends
    /// retires its own cards only (CARD-NEVER-BLOCKS).
    runs: HashMap<String, String>,
}

impl ApprovalRegistry {
    /// A registry whose waits are bounded by `timeout`.
    pub fn new(timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(Inner {
                pending: HashMap::new(),
                waiters: HashMap::new(),
                abandoned: HashSet::new(),
                claimed: HashMap::new(),
                nonces: HashMap::new(),
                deferred: HashMap::new(),
                runs: HashMap::new(),
            })),
            timeout,
            next: AtomicU64::new(0),
            phone: Mutex::new(None),
            local: Mutex::new(None),
            lang: Mutex::new(Lang::En),
            phone_last: Mutex::new(None),
        })
    }

    /// Tell the owner's phone, with a fixed phrase, when an approval opens.
    pub fn set_phone_notifier(&self, notifier: Arc<dyn Notifier>) {
        *kernel_core::lock_recover(&self.phone) = Some(notifier);
    }

    /// Raise the fixed phrase on the local macOS display when no gateway is
    /// paired. It uses the same `aux_notify` sink as the local gateway, and the
    /// fixed text carries no mail or client content.
    pub fn set_local_notifier(&self, notifier: Arc<dyn Notifier>) {
        *kernel_core::lock_recover(&self.local) = Some(notifier);
    }

    /// The owner's UI language for the fixed phrase.
    pub fn set_language(&self, lang: Lang) {
        *kernel_core::lock_recover(&self.lang) = lang;
    }

    /// Send the fixed phrase for the approvals now waiting (best effort), at
    /// most once per [`PHONE_NOTICE_GAP`]: the owner opens the app for all of
    /// them. With no paired gateway the local display is the channel; with one,
    /// the phone.
    fn notify_phone(&self) {
        let notifier = kernel_core::lock_recover(&self.local)
            .clone()
            .or_else(|| kernel_core::lock_recover(&self.phone).clone());
        let Some(notifier) = notifier else {
            return;
        };
        let waiting = self.list_pending().len();
        if waiting == 0 {
            return;
        }
        {
            let mut last = kernel_core::lock_recover(&self.phone_last);
            let now = std::time::Instant::now();
            if last.is_some_and(|at| now.duration_since(at) < PHONE_NOTICE_GAP) {
                return;
            }
            *last = Some(now);
        }
        let lang = *kernel_core::lock_recover(&self.lang);
        if let Err(err) = notifier.notify(&phone_notice(waiting, lang)) {
            tracing::warn!(error = %err, "approval notice not sent");
        }
    }

    /// How long an approval may wait before the fail-closed deny.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Register `pending` under a fresh id and return the waiter the turn
    /// blocks on. The id in the returned entry is the final one.
    pub fn begin(
        &self,
        mut pending: PendingApproval,
    ) -> (oneshot::Receiver<Resolution>, PendingApproval) {
        if pending.id.is_empty() {
            pending.id = self.next_id();
        }
        let receiver = self.register(pending.clone());
        (receiver, pending)
    }

    /// Generate the next approval id without registering anything.
    ///
    /// The audit row is written with this id *before* [`Self::register`], so
    /// a listed approval always carries its `audit_id`.
    pub fn next_id(&self) -> String {
        let seq = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let millis = chrono::Utc::now().timestamp_millis();
        format!("ap-{millis}-{seq}")
    }

    /// Issue an opaque, single-use callback nonce for a pending approval, or
    /// `None` when the id is unknown.
    ///
    /// The nonce is 128 CSPRNG bits rendered as hex, prefixed so it can never
    /// be confused with an approval id, and well under Telegram's 64-byte
    /// `callback_data` cap. It is retired with its approval (claim, expiry or
    /// turn end) and redeemed at most once.
    pub fn issue_callback_nonce(&self, id: &str) -> Option<String> {
        let nonce = random_nonce()?;
        let mut inner = kernel_core::lock_recover(&self.inner);
        if !inner.pending.contains_key(id) {
            return None;
        }
        inner.nonces.insert(nonce.clone(), id.to_string());
        Some(nonce)
    }

    /// Redeem a callback nonce to the approval it answers. Exactly one caller
    /// wins: an unknown, already-used or retired nonce gets `None`.
    pub fn redeem_callback_nonce(&self, nonce: &str) -> Option<String> {
        kernel_core::lock_recover(&self.inner).nonces.remove(nonce)
    }

    /// Look up a nonce without consuming it; transport callers retire it only
    /// after the approval route confirms a successful decision.
    pub fn callback_nonce_target(&self, nonce: &str) -> Option<String> {
        kernel_core::lock_recover(&self.inner)
            .nonces
            .get(nonce)
            .cloned()
    }

    /// Forget every nonce pointing at `id`.
    fn retire_nonces(inner: &mut Inner, id: &str) {
        inner.nonces.retain(|_, target| target.as_str() != id);
    }

    /// Make `pending` visible and return the waiter the turn blocks on.
    pub fn register(&self, pending: PendingApproval) -> oneshot::Receiver<Resolution> {
        self.register_run(pending, None)
    }

    /// [`Self::register`] for the turn `run_id`, stamped under the same lock.
    pub fn register_run(
        &self,
        pending: PendingApproval,
        run_id: Option<&str>,
    ) -> oneshot::Receiver<Resolution> {
        let (sender, receiver) = oneshot::channel();
        let id = pending.id.clone();
        debug_assert!(!id.is_empty(), "approval ids are assigned before register");
        let mut inner = kernel_core::lock_recover(&self.inner);
        if let Some(run_id) = run_id {
            inner.runs.insert(id.clone(), run_id.to_string());
        }
        inner.pending.insert(id.clone(), pending);
        inner.waiters.insert(id, sender);
        receiver
    }

    /// Remember `id` as deferred and return it, so a `later` answer can be
    /// reopened within [`APPROVAL_UNDO_WINDOW`].
    pub fn defer(&self, id: &str) -> Option<PendingApproval> {
        let mut inner = kernel_core::lock_recover(&self.inner);
        let pending = inner.pending.get(id).cloned()?;
        let now = Instant::now();
        inner
            .deferred
            .retain(|_, (_, at)| now.duration_since(*at) < APPROVAL_UNDO_WINDOW);
        inner
            .deferred
            .insert(id.to_string(), (pending.clone(), now));
        Some(pending)
    }

    /// Re-open a deferred approval within the undo window, or `None`.
    pub fn undo(&self, id: &str) -> Option<PendingApproval> {
        let mut inner = kernel_core::lock_recover(&self.inner);
        let (pending, at) = inner.deferred.remove(id)?;
        if at.elapsed() > APPROVAL_UNDO_WINDOW {
            return None;
        }
        inner.abandoned.remove(id);
        let (sender, _receiver) = oneshot::channel();
        inner.pending.insert(id.to_string(), pending.clone());
        inner.waiters.insert(id.to_string(), sender);
        Some(pending)
    }

    /// Pending approvals, oldest first.
    pub fn list_pending(&self) -> Vec<PendingApproval> {
        let inner = kernel_core::lock_recover(&self.inner);
        let mut pending: Vec<PendingApproval> = inner.pending.values().cloned().collect();
        pending.sort_by_key(|entry| (entry.created_ms, entry.id.clone()));
        pending
    }

    /// One pending approval by id.
    pub fn get(&self, id: &str) -> Option<PendingApproval> {
        kernel_core::lock_recover(&self.inner)
            .pending
            .get(id)
            .cloned()
    }

    /// True when a card asked by `thread_id`'s turn, or by an agent it
    /// delegated to, still waits for the owner.
    pub fn holds_thread(&self, thread_id: i64) -> bool {
        self.cards_holding(thread_id) > 0
    }

    /// How many cards asked by `thread_id`'s turns, or by agents they
    /// delegated to, wait for the owner: each parks one turn of the thread.
    pub fn cards_holding(&self, thread_id: i64) -> usize {
        kernel_core::lock_recover(&self.inner)
            .pending
            .values()
            .filter(|entry| entry.thread_id == thread_id || entry.root_thread == Some(thread_id))
            .count()
    }

    /// Snapshot pending approvals for a trusted in-process channel notifier.
    pub fn pending(&self) -> Vec<PendingApproval> {
        kernel_core::lock_recover(&self.inner)
            .pending
            .values()
            .cloned()
            .collect()
    }

    /// Answer a pending approval. `None` = unknown or already answered.
    ///
    /// This wakes the waiter immediately; the answer route uses
    /// [`Self::claim`] instead so side effects (audit, rule write, broadcast)
    /// happen **before** the turn resumes.
    pub fn resolve(&self, id: &str, resolution: Resolution) -> Option<PendingApproval> {
        let claimed = self.claim(id)?;
        let pending = claimed.pending().clone();
        claimed.complete(resolution);
        Some(pending)
    }

    /// Atomically take a pending approval out of the registry **without**
    /// waking its waiter yet.
    ///
    /// Exactly one caller can claim an id: a late or duplicate answer gets
    /// `None` (a clean 404) before it can write anything. The caller owns the
    /// claimed waiter and must eventually call [`ClaimedApproval::complete`];
    /// until then the turn keeps waiting.
    pub fn claim(&self, id: &str) -> Option<ClaimedApproval> {
        let mut inner = kernel_core::lock_recover(&self.inner);
        let pending = inner.pending.remove(id)?;
        let waiter = inner.waiters.remove(id);
        inner.claimed.insert(id.to_string(), pending.thread_id);
        Self::retire_nonces(&mut inner, id);
        Some(ClaimedApproval {
            registry: Arc::clone(&self.inner),
            pending,
            waiter,
        })
    }

    /// True when `id` was abandoned: its turn already gave up (cancellation,
    /// timeout or normal end) and a late answer must be rejected, not
    /// applied.
    pub fn is_abandoned(&self, id: &str) -> bool {
        kernel_core::lock_recover(&self.inner)
            .abandoned
            .contains(id)
    }

    /// Retire every approval of one session.
    ///
    /// Called by the turn runner when a turn ends — in particular when a
    /// cancelled or timed-out turn stopped waiting on an answer. Still-pending
    /// ids are removed (the app's card disappears) and marked abandoned; ids
    /// an answer already claimed are marked abandoned too, so a completion
    /// that lands after the turn gave up cannot wake it or publish `allowed`.
    /// Returns the retired ids (tests/diagnostics).
    pub fn abandon_thread(&self, thread_id: i64) -> Vec<String> {
        let retired = self.abandon_where(thread_id, None);
        retired.into_iter().map(|(id, _)| id).collect()
    }

    /// [`Self::abandon_thread`] for the turn `run_id` alone: a card another
    /// turn of the session waits on stays answerable (CARD-NEVER-BLOCKS). A
    /// card with no turn recorded is retired too (fail closed). Each id says
    /// whether it was still pending (`true`) or claimed by an answer.
    pub fn abandon_run(&self, thread_id: i64, run_id: &str) -> Vec<(String, bool)> {
        self.abandon_where(thread_id, Some(run_id))
    }

    fn abandon_where(&self, thread_id: i64, run_id: Option<&str>) -> Vec<(String, bool)> {
        let mut inner = kernel_core::lock_recover(&self.inner);
        let runs = std::mem::take(&mut inner.runs);
        let ours = |id: &str| run_id.is_none_or(|run| runs.get(id).is_none_or(|own| own == run));
        let mut retired = Vec::new();
        let pending_ids: Vec<String> = inner
            .pending
            .iter()
            .filter(|(id, pending)| pending.thread_id == thread_id && ours(id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in pending_ids {
            inner.pending.remove(&id);
            inner.waiters.remove(&id);
            inner.abandoned.insert(id.clone());
            Self::retire_nonces(&mut inner, &id);
            retired.push((id, true));
        }
        let claimed_ids: Vec<String> = inner
            .claimed
            .iter()
            .filter(|(id, owner)| **owner == thread_id && ours(id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in claimed_ids {
            if inner.abandoned.insert(id.clone()) {
                retired.push((id, false));
            }
        }
        inner.runs = runs;
        for (id, _) in &retired {
            inner.runs.remove(id);
        }
        retired
    }

    /// Mark a claimed approval as abandoned: the turn already gave up (the
    /// timeout grace expired) and was denied. A later
    /// [`ClaimedApproval::complete_with`] then returns
    /// [`Completion::Abandoned`] instead of waking a turn that no longer
    /// waits, so the answer can be reported truthfully.
    ///
    /// No-op when the id was never claimed (the timeout path only calls this
    /// after `expire` returned `None`).
    pub fn abandon(&self, id: &str) {
        let mut inner = kernel_core::lock_recover(&self.inner);
        inner.abandoned.insert(id.to_string());
    }

    /// Drop a pending approval without answering (timeout path). `None` when
    /// the id is unknown or was answered concurrently.
    pub fn expire(&self, id: &str) -> Option<PendingApproval> {
        let mut inner = kernel_core::lock_recover(&self.inner);
        let pending = inner.pending.remove(id)?;
        inner.waiters.remove(id);
        inner.runs.remove(id);
        Self::retire_nonces(&mut inner, id);
        Some(pending)
    }
}

/// How a claimed approval finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// The resolution woke the turn.
    Delivered,
    /// The turn already gave up (timeout grace expired): nothing was sent and
    /// no `allowed` frame may be published for this answer.
    Abandoned,
}

/// A pending approval claimed by exactly one answer, with its waiter still
/// unsent. Dropping the claim without [`Self::complete`] leaves the turn
/// waiting for its timeout (fail closed).
pub struct ClaimedApproval {
    registry: Arc<Mutex<Inner>>,
    pending: PendingApproval,
    waiter: Option<oneshot::Sender<Resolution>>,
}

impl ClaimedApproval {
    /// The claimed pending approval.
    pub fn pending(&self) -> &PendingApproval {
        &self.pending
    }

    /// Wake the turn with `resolution`. The answer route calls this last, so
    /// the audit row and the `approval.resolved` frame are already out when
    /// the turn resumes.
    pub fn complete(self, resolution: Resolution) {
        let _ = self.complete_with(resolution, || {});
    }

    /// Complete the claim atomically with its side effects:
    /// under the registry lock, `before_wake` runs (the audit row and the
    /// `approval.resolved` broadcast) and only then is the waiter woken — so
    /// the frame always precedes the turn it authorized.
    ///
    /// If the turn already gave up ([`ApprovalRegistry::abandon`] or
    /// [`ApprovalRegistry::abandon_thread`] ran first), `before_wake` does
    /// **not** run and [`Completion::Abandoned`] is returned: the caller must
    /// report the real outcome, never `allowed`.
    pub fn complete_with<F: FnOnce()>(
        mut self,
        resolution: Resolution,
        before_wake: F,
    ) -> Completion {
        let mut inner = kernel_core::lock_recover(&self.registry);
        inner.claimed.remove(&self.pending.id);
        if inner.abandoned.contains(&self.pending.id) {
            return Completion::Abandoned;
        }
        before_wake();
        if let Some(waiter) = self.waiter.take() {
            let _ = waiter.send(resolution);
        }
        Completion::Delivered
    }
}

impl Drop for ClaimedApproval {
    fn drop(&mut self) {
        // A claim that was dropped without completion (panic, early error)
        // must not stay "in flight" forever; a finished claim needs no turn.
        let mut inner = kernel_core::lock_recover(&self.registry);
        inner.claimed.remove(&self.pending.id);
        inner.runs.remove(&self.pending.id);
    }
}

/// The API's approver: publish the ask, then wait for the app's answer.
pub struct ApiApprover {
    registry: Arc<ApprovalRegistry>,
    home: PathBuf,
    events: broadcast::Sender<String>,
    thread_id: i64,
    /// Identity of the turn this approver serves. Stamped on every
    /// `approval.pending` row it writes, so a receipt attributes the ask by
    /// identity rather than by a row-id window shared with other turns of the
    /// same thread. `None` for callers that keep no per-turn receipt.
    run_id: Option<String>,
    /// The chief's session this approver's turn was delegated from.
    root_thread: Option<i64>,
    /// Counts the cards that expired unanswered, for the engine (MEM-FORGET-HANG).
    expired: Option<Arc<std::sync::atomic::AtomicUsize>>,
    /// The turn's cards stop waiting here (MEM-FORGET-HANG).
    deadline: Option<Instant>,
}

impl ApiApprover {
    /// An approver for one turn in session `thread_id`.
    pub fn new(
        registry: Arc<ApprovalRegistry>,
        home: PathBuf,
        events: broadcast::Sender<String>,
        thread_id: i64,
    ) -> Self {
        Self {
            registry,
            home,
            events,
            thread_id,
            run_id: None,
            root_thread: None,
            expired: None,
            deadline: None,
        }
    }

    /// MEM-FORGET-HANG: every card of the turn starting now stops waiting at
    /// 9/10 of the approval timeout, so a client that waits as long as one
    /// card (600 s each by default) still gets the turn's reply.
    pub fn with_turn_deadline(mut self) -> Self {
        self.deadline = Some(Instant::now() + self.registry.timeout() * 9 / 10);
        self
    }

    /// Count each card that expires unanswered in `counter`.
    pub fn with_expiry_count(mut self, counter: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.expired = Some(counter);
        self
    }

    fn count_expiry(&self) {
        if let Some(counter) = &self.expired {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Stamp every card with the chief's session `root` (a delegate's turn).
    pub fn with_root_thread(mut self, root: Option<i64>) -> Self {
        self.root_thread = root;
        self
    }

    /// Attribute every approval row this approver writes to `run_id`.
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    /// Log one journal row, returning its id (`None` when the store is
    /// unwritable; the frame then carries the `0` sentinel.
    fn audit(&self, kind: &str, payload: serde_json::Value) -> Option<u64> {
        let path = kernel_core::store_path(&self.home);
        match Store::open(&path).and_then(|store| store.log_event_id(kind, &payload.to_string())) {
            Ok(id) => Some(id as u64),
            Err(err) => {
                tracing::warn!(error = %err, "approval audit could not be written");
                None
            }
        }
    }

    fn publish(&self, value: serde_json::Value) {
        wire::send_bounded(&self.events, &value);
    }
}

#[async_trait]
impl Approver for ApiApprover {
    /// Answer an ask, carrying an edited draft when the app sent one.
    ///
    /// The broker calls this (not `approve`); the returned decision's
    /// `arguments` is the payload the tool must run.
    async fn decide(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApproverError> {
        let raw_args =
            serde_json::to_string(&request.arguments).unwrap_or_else(|_| "null".to_string());
        // A card never hides part of what it approves. Arguments too long
        // to show whole are refused before any card, so what runs (a skill's
        // mail or `.ics` text included) is what was shown. A mail body is
        // shown whole and scrolls in the app, so it has its own cap.
        let preview = error::scrub_preview(&self.home, &raw_args, usize::MAX);
        // Measured on what runs too: a masked secret shortens the preview,
        // never the payload.
        let longest = preview.len().max(raw_args.len());
        let limit = if approval_preview::carries_mail(&request.tool) {
            wire::MAX_MAIL_ARGS_BYTES
        } else {
            wire::MAX_TOOL_ARGS_BYTES
        };
        if longest > limit {
            return Err(ApproverError(format!(
                "too long to show for approval: {} bytes, a card shows {}",
                longest, limit
            )));
        }
        // A send's card shows exactly what leaves: when the preview differs
        // from the payload (a masked secret, a home path, a cleaned
        // character), the send is refused before any card. MCP tools count
        // as sends: their reach is unknown.
        let sends = request.tool == "mail_send"
            || request.tool == "google_gmail_send"
            || request.tool.starts_with("skill__")
            || request.tool.starts_with("mcp__");
        if sends && preview != raw_args {
            return Err(ApproverError(send_not_showable(&raw_args)));
        }
        // A Gmail draft refuses an unreadable recipient or subject before any
        // card: the owner would approve a destination nobody can read.
        if request.tool == "google_gmail_create_draft" {
            gmail_draft_approval_check(&request.arguments)?;
        }
        // The card the owner reads: a short title, the fields of the action
        // and the text it carries, built here, in the daemon, once. A case
        // that cannot be shown whole is refused, never shortened.
        let accounts = mail_accounts(&self.home, &request.tool).map_err(ApproverError)?;
        let card = approval_preview::build_checked(
            &request.tool,
            &request.arguments,
            &accounts,
            &|text| error::scrub_preview(&self.home, text, usize::MAX),
        )
        .map_err(ApproverError)?;
        let title = error::scrub_preview(&self.home, &card.title, usize::MAX);
        let body = error::scrub_preview(&self.home, &card.body, usize::MAX);
        let detail: Vec<String> = card
            .detail
            .iter()
            .map(|line| error::scrub_preview(&self.home, line, usize::MAX))
            .collect();
        // A send that cannot be shown exactly as it would leave is refused
        // before any card: the owner must see the whole text.
        if sends && (title != card.title || body != card.body || detail != card.detail) {
            return Err(ApproverError(send_not_showable(&raw_args)));
        }
        // Taint rides along with the ask: the card shows the source, the app
        // greys "always allow", and the answer route refuses it server-side.
        let taint = request.taint_source.clone().or_else(|| {
            request
                .tainted
                .then(|| "untrusted content in context (source unknown)".to_string())
        });
        let pending = PendingApproval {
            id: self.registry.next_id(),
            audit_id: 0,
            agent: request.agent.clone(),
            thread_id: self.thread_id,
            root_thread: self.root_thread,
            tool: request.tool.clone(),
            risk: request.risk,
            card_title: title,
            card_body: body,
            card_detail: detail,
            edit_args: preview,
            taint,
            unsandboxed: request.unsandboxed,
            networked: request.networked,
            created_ms: chrono::Utc::now().timestamp_millis(),
        };
        // The audit row is attempted before the approval becomes visible, so
        // a listed approval carries its real `audit_id` whenever the store is
        // writable; otherwise it carries the documented `0` sentinel (the
        // app's model requires a number. The turn's `run_id` rides on
        // the row so a receipt can attribute the ask by identity.
        let mut audit_payload = serde_json::json!({
            "id": pending.id,
            "agent": pending.agent,
            "tool": pending.tool,
            "risk": pending.risk,
            "thread_id": pending.thread_id,
            "tainted": pending.is_tainted(),
            "taint_source": pending.taint.clone(),
            "unsandboxed": pending.unsandboxed,
            "networked": pending.networked,
        });
        if let Some(run_id) = &self.run_id {
            audit_payload["run_id"] = serde_json::Value::String(run_id.clone());
        }
        let audit_id = self.audit("approval.pending", audit_payload).unwrap_or(0);
        let pending = PendingApproval {
            audit_id,
            ..pending
        };
        let mut receiver = self
            .registry
            .register_run(pending.clone(), self.run_id.as_deref());
        self.publish(wire::approval_new(&pending.frame()));
        self.registry.notify_phone();

        let wait = self.deadline.map_or(self.registry.timeout(), |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        match tokio::time::timeout(wait, &mut receiver).await {
            Ok(Ok(resolution)) => Ok(decision_of(resolution)),
            Ok(Err(_dropped)) => {
                // The registry dropped the sender without an answer; fail
                // closed (the broker audits the denial).
                Ok(ApprovalDecision::new(false))
            }
            Err(_elapsed) => {
                match self.registry.expire(&pending.id) {
                    Some(pending) => {
                        self.audit(
                            "approval.answered",
                            serde_json::json!({
                                "id": pending.id,
                                "decision": "timeout",
                                "by": "timeout",
                                "always": false,
                            }),
                        );
                        self.publish(wire::approval_resolved(
                            &pending.id,
                            ApprovalStateFrame::Expired,
                        ));
                        self.publish(wire::approval_updated(
                            &pending.id,
                            ApprovalStateFrame::Expired,
                        ));
                        self.count_expiry();
                        Ok(ApprovalDecision::new(false))
                    }
                    None => {
                        // The answer path claimed this pending just before
                        // the deadline (claim happens before its audit,
                        // broadcast and — for allow-always — the rule write).
                        // Give it a short bounded grace to finish instead of
                        // denying an answer that arrived in time.
                        match tokio::time::timeout(Duration::from_millis(500), &mut receiver).await
                        {
                            Ok(Ok(resolution)) => Ok(decision_of(resolution)),
                            _ => {
                                // The grace expired: the turn is denied now.
                                // Mark the claim abandoned so a completion
                                // that lands later cannot wake the turn or
                                // publish an `allowed` frame, then
                                // re-check the channel: `complete_with` and
                                // `abandon` are serialized by the registry
                                // lock, so a resolution found here really was
                                // delivered before the abandon mark.
                                self.registry.abandon(&pending.id);
                                match receiver.try_recv() {
                                    Ok(resolution) => Ok(decision_of(resolution)),
                                    Err(_) => {
                                        self.audit(
                                            "approval.answered",
                                            serde_json::json!({
                                                "id": pending.id,
                                                "decision": "timeout",
                                                "by": "timeout",
                                                "always": false,
                                                "late_claim": true,
                                            }),
                                        );
                                        // Same order as the plain timeout: the
                                        // expired frame is out before the
                                        // turn resumes, so it precedes
                                        // `tool.end`/`message.done`.
                                        self.publish(wire::approval_resolved(
                                            &pending.id,
                                            ApprovalStateFrame::Expired,
                                        ));
                                        self.publish(wire::approval_updated(
                                            &pending.id,
                                            ApprovalStateFrame::Expired,
                                        ));
                                        self.count_expiry();
                                        Ok(ApprovalDecision::new(false))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// The plain approve/deny view of [`Self::decide`], for callers that keep
    /// the older `bool` contract.
    async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(self.decide(request).await?.allow)
    }
}

/// Adapt a registry [`Resolution`] to the broker's [`ApprovalDecision`]: the
/// `edit` draft, when present, is the payload the broker authorizes.
fn decision_of(resolution: Resolution) -> ApprovalDecision {
    ApprovalDecision {
        allow: resolution.allow,
        arguments: resolution.edited,
    }
}

/// Why a send is not shown for approval: the card must show exactly what
/// leaves the Mac, so a payload that cannot be shown whole is refused.
fn send_not_showable(raw_args: &str) -> String {
    if kernel_broker::redact_secrets(raw_args) != raw_args {
        "holds a secret: a send never carries one, so it is not shown for approval".to_string()
    } else {
        "cannot be shown exactly as it would be sent, so it is not shown for approval".to_string()
    }
}

/// 128 bits from the OS CSPRNG, prefixed and hex-encoded: an opaque callback
/// nonce that never resembles an approval id. `None` when the OS source is
/// unavailable, so a nonce is never guessed or fabricated.
fn random_nonce() -> Option<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .ok()?;
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Some(format!("n{hex}"))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Drop orphaned pending approvals (in-memory registry lost to a restart) and
/// audit one `approval.dropped` line each. Best effort: failures are logged.
pub fn recover_stale_pending(db_path: &Path) {
    match stale_pending_ids(db_path) {
        Ok(ids) => {
            let Ok(store) = Store::open(db_path) else {
                return;
            };
            for id in ids {
                if let Err(err) = store.log_event(
                    "approval.dropped",
                    &serde_json::json!({
                        "id": id,
                        "reason": "daemon restart",
                        "outcome": "abandoned",
                    })
                    .to_string(),
                ) {
                    tracing::warn!(error = %err, "approval recovery audit failed");
                }
            }
        }
        Err(err) => tracing::warn!(error = %err, "approval recovery read failed"),
    }
    if let Err(err) = recover_unfinished_runs(db_path) {
        tracing::warn!(error = %err, "skill run recovery failed");
    }
}

/// Close each skill run the daemon died inside: a `skill.approval` row with no
/// `skill.run` row for its run. Written as an `abandoned` run, once.
fn recover_unfinished_runs(db_path: &Path) -> anyhow::Result<()> {
    if !db_path.exists() {
        return Ok(());
    }
    let conn = aux_store::open_keyed_readonly(db_path)?;
    let mut approvals: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    let mut finished: HashSet<String> = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT kind, payload FROM events WHERE kind IN ('skill.approval', 'skill.run')",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (kind, payload) = row?;
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&payload) else {
            continue;
        };
        let Some(run_id) = value.get("run_id").and_then(|id| id.as_str()) else {
            continue;
        };
        if kind == "skill.run" {
            finished.insert(run_id.to_string());
        } else {
            approvals
                .entry(run_id.to_string())
                .or_insert_with(|| value.clone());
        }
    }
    drop(stmt);
    drop(conn);
    if approvals.keys().all(|run_id| finished.contains(run_id)) {
        return Ok(());
    }
    let store = Store::open(db_path)?;
    for (run_id, value) in &approvals {
        if finished.contains(run_id) {
            continue;
        }
        let payload = serde_json::json!({
            "agent": value.get("agent"),
            "skill_name": value.get("skill_name"),
            "skill_version": value.get("skill_version"),
            "skill_hash": value.get("skill_hash"),
            "run_id": run_id,
            "outcome": "abandoned",
            "reason": "daemon restart",
        });
        store.log_event("skill.run", &payload.to_string())?;
    }
    Ok(())
}

/// Ids of `approval.pending` rows with no matching `approval.answered` or
/// `approval.dropped` row.
fn stale_pending_ids(db_path: &Path) -> anyhow::Result<Vec<String>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = aux_store::open_keyed_readonly(db_path)?;
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'events'",
        [],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(Vec::new());
    }
    let ids_in = |kind: &str| -> anyhow::Result<HashSet<String>> {
        let mut stmt = conn.prepare("SELECT payload FROM events WHERE kind = ?1")?;
        let rows = stmt.query_map([kind], |row| row.get::<_, String>(0))?;
        let mut ids = HashSet::new();
        for payload in rows {
            let payload = payload?;
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&payload) {
                if let Some(id) = value.get("id").and_then(|id| id.as_str()) {
                    ids.insert(id.to_string());
                }
            }
        }
        Ok(ids)
    };
    let pending = ids_in("approval.pending")?;
    let mut answered = ids_in("approval.answered")?;
    answered.extend(ids_in("approval.dropped")?);
    let mut stale: Vec<String> = pending.difference(&answered).cloned().collect();
    stale.sort();
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn pending() -> PendingApproval {
        PendingApproval {
            id: "ap-1-1".to_string(),
            audit_id: 7,
            agent: "main".to_string(),
            thread_id: 3,
            root_thread: None,
            tool: "shell".to_string(),
            risk: Risk::High,
            card_title: "Run ls".to_string(),
            card_body: "command: ls".to_string(),
            card_detail: vec!["command: ls".to_string()],
            edit_args: "{\"command\":\"ls\"}".to_string(),
            taint: None,
            unsandboxed: false,
            networked: false,
            created_ms: 1_791_106_200_000,
        }
    }

    /// A home with one mail account: the card names the address a mail
    /// leaves from, so a send can be shown whole.
    fn mail_home(home: &std::path::Path) {
        std::fs::write(
            kernel_core::config_path(home),
            "[connectors.mail]\n[[connectors.mail.accounts]]\nid = \"work\"\nemail = \"owner@example.test\"\n",
        )
        .unwrap();
    }

    fn pending_with_id(id: &str) -> PendingApproval {
        let mut entry = pending();
        entry.id = id.to_string();
        entry
    }

    #[test]
    fn callback_nonces_are_opaque_single_use_and_reject_the_raw_id() {
        let registry = ApprovalRegistry::new(Duration::from_secs(60));
        let entry = pending();
        let _receiver = registry.register(entry.clone());
        let nonce = registry.issue_callback_nonce(&entry.id).expect("nonce");
        assert_ne!(nonce, entry.id);
        assert!(nonce.starts_with('n'));
        assert!(nonce.len() <= 64);
        // The predictable approval id is not a valid callback token.
        assert!(registry.redeem_callback_nonce(&entry.id).is_none());
        // Nor is an unknown nonce.
        assert!(registry.redeem_callback_nonce("n00").is_none());
        // The first use wins and yields the approval id it answers.
        assert_eq!(
            registry.redeem_callback_nonce(&nonce).as_deref(),
            Some(entry.id.as_str())
        );
        // A replay is refused.
        assert!(registry.redeem_callback_nonce(&nonce).is_none());
        // A nonce for an unknown approval is never issued.
        assert!(registry.issue_callback_nonce("ap-unknown").is_none());
    }

    #[test]
    fn callback_nonce_is_retired_when_the_approval_is_claimed_or_expired() {
        let registry = ApprovalRegistry::new(Duration::from_secs(60));
        let entry = pending_with_id("ap-claim");
        let _receiver = registry.register(entry.clone());
        let nonce = registry.issue_callback_nonce(&entry.id).unwrap();
        let claimed = registry.claim(&entry.id).expect("claim");
        claimed.complete(Resolution::deny());
        assert!(registry.redeem_callback_nonce(&nonce).is_none());

        let entry = pending_with_id("ap-expire");
        let _receiver = registry.register(entry.clone());
        let nonce = registry.issue_callback_nonce(&entry.id).unwrap();
        assert!(registry.expire(&entry.id).is_some());
        assert!(registry.redeem_callback_nonce(&nonce).is_none());
    }

    /// The draft's fields are checked before any card: an unreadable
    /// destination never gets one.
    #[test]
    fn a_gmail_draft_with_readable_fields_is_accepted() {
        assert!(gmail_draft_approval_check(&serde_json::json!({
            "to": "one@example.test, two@example.test",
            "cc": "copy@example.test",
            "bcc": "hidden@example.test",
            "subject": "A subject that must remain visible",
            "body": "The body, whole.",
        }))
        .is_ok());
    }

    #[test]
    fn gmail_preview_refuses_missing_or_unreadable_recipients() {
        for arguments in [
            serde_json::json!({"subject":"hi", "body":"body"}),
            serde_json::json!({"to":"", "subject":"hi", "body":"body"}),
            serde_json::json!({"to":17, "subject":"hi", "body":"body"}),
            // An empty recipient list has no readable destination.
            serde_json::json!({"to":[], "subject":"hi", "body":"body"}),
            serde_json::json!({"to":[], "cc":"copy@example.test", "subject":"hi", "body":"body"}),
            serde_json::json!({"to":["   "], "subject":"hi", "body":"body"}),
        ] {
            assert!(gmail_draft_approval_check(&arguments).is_err());
        }
    }

    /// A send whose text does not fit on a card is refused before any
    /// card; one that fits is shown whole.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_too_long_for_the_card_is_refused_and_a_short_one_shown_whole() {
        // The card stays open until the test answers it: no timer can close
        // it before the test looks.
        let registry = ApprovalRegistry::new(DEFAULT_APPROVAL_TIMEOUT);
        let (events, _keep) = broadcast::channel(16);
        let directory = tempfile::tempdir().unwrap();
        mail_home(directory.path());
        let approver = Arc::new(ApiApprover::new(
            registry.clone(),
            directory.path().into(),
            events,
            1,
        ));
        let send = |body: String| ApprovalRequest {
            agent: "clients".to_string(),
            tool: "mail_send".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({ "to": ["a@example.test"], "body": body }),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        let long = format!("{}CANARY", "x".repeat(wire::MAX_MAIL_ARGS_BYTES));
        let err = approver.decide(&send(long)).await.unwrap_err();
        assert!(
            err.0.starts_with("too long to show for approval"),
            "{err:?}"
        );
        assert!(registry.list_pending().is_empty());
        // A masked secret shortens the preview, not the payload: the send is
        // refused, never shown cut.
        let masked = format!("password={}", "FICTIONAL".repeat(800));
        let err = approver.decide(&send(masked)).await.unwrap_err();
        assert!(err.0.starts_with("holds a secret"), "{err:?}");
        let err = approver
            .decide(&send("password=Fict1onal-Pw-42".to_string()))
            .await
            .unwrap_err();
        assert!(err.0.starts_with("holds a secret"), "{err:?}");
        // A home path would read `<home>/…` on the card but leave whole.
        let home = directory.path().join("meeting.txt");
        let err = approver
            .decide(&send(format!("notes at {}", home.display())))
            .await
            .unwrap_err();
        assert!(err.0.starts_with("cannot be shown exactly"), "{err:?}");
        assert!(registry.list_pending().is_empty());

        let body = "y".repeat(wire::MAX_MAIL_ARGS_BYTES - 64);
        let waiting = {
            let (approver, body) = (Arc::clone(&approver), body.clone());
            tokio::spawn(async move { approver.decide(&send(body)).await })
        };
        let card = wait_for_pending(&registry).await;
        // The card shows the text that leaves the Mac, whole: never the JSON.
        assert_eq!(card.card_body, body);
        assert_eq!(card.card_title, "Send mail to a@example.test");
        // The card names the sender it will leave from.
        assert!(
            card.card_detail
                .contains(&"From: owner@example.test (account work)".to_string()),
            "{:?}",
            card.card_detail
        );
        // The edit payload is always valid JSON: the editor's own text.
        let edit: serde_json::Value =
            serde_json::from_str(&card.frame().edit_preview.unwrap()).expect("valid JSON");
        assert_eq!(edit["body"], body.as_str());
        assert!(card.card_body.contains("yyy"));
        assert!(!card.card_body.contains("{\""));
        // The owner says no: nothing is sent.
        registry.resolve(&card.id, Resolution::deny());
        assert!(!waiting.await.unwrap().unwrap().allow);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_phone_gets_only_the_fixed_phrase_for_a_waiting_approval() {
        // The card stays open until the test answers it.
        let registry = ApprovalRegistry::new(DEFAULT_APPROVAL_TIMEOUT);
        let phone = Arc::new(aux_notify::FakeNotifier::new());
        registry.set_phone_notifier(phone.clone());
        let (events, _keep) = broadcast::channel(16);
        let directory = tempfile::tempdir().unwrap();
        let approver = ApiApprover::new(registry.clone(), directory.path().into(), events, 1);
        let request = ApprovalRequest {
            agent: "Camille Durand".to_string(),
            tool: "google_gmail_create_draft".to_string(),
            risk: Risk::Medium,
            arguments: serde_json::json!({
                "to": "camille@example.test",
                "subject": "Invoice for Camille Durand",
                "body": "Please pay by Friday."
            }),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        let waiting = tokio::spawn(async move { approver.decide(&request).await });
        wait_until("no phone notice was sent", || phone.count() > 0).await;
        let sent = phone.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].title, "Auxesis");
        assert_eq!(
            sent[0].body,
            "1 approval is waiting. Open Auxesis to see it."
        );
        let text = format!("{}\n{}", sent[0].title, sent[0].body);
        for leaked in [
            "camille@example.test",
            "Invoice",
            "Camille",
            "Durand",
            "google_gmail_create_draft",
            "Friday",
        ] {
            assert!(!text.contains(leaked), "{leaked:?} reached the phone");
        }
        // The details stay in the app: the pending card still carries them.
        let card = wait_for_pending(&registry).await;
        let frame = card.frame();
        assert!(
            frame
                .detail
                .iter()
                .any(|line| line.contains("camille@example.test")),
            "{:?}",
            frame.detail
        );
        assert_eq!(frame.preview.as_deref(), Some("Please pay by Friday."));
        registry.resolve(&card.id, Resolution::deny());
        let _ = waiting.await;
    }

    /// APPROVAL-NO-GATEWAY: with no paired remote the fixed phrase must reach
    /// the local macOS sink now, through the same `aux_notify` path the local
    /// gateway uses. The phone notifier stays installed but is not chosen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn with_no_gateway_a_waiting_approval_raises_one_local_notice() {
        let directory = tempfile::tempdir().unwrap();
        let local = Arc::new(aux_notify::FakeNotifier::new());
        let phone = Arc::new(aux_notify::FakeNotifier::new());
        let registry = ApprovalRegistry::new(Duration::from_millis(200));
        registry.set_phone_notifier(phone.clone());
        registry.set_local_notifier(local.clone());
        let (events, _keep) = broadcast::channel(16);
        let approver = ApiApprover::new(registry.clone(), directory.path().into(), events, 1);
        let request = ApprovalRequest {
            agent: "Camille Durand".to_string(),
            tool: "google_gmail_create_draft".to_string(),
            risk: Risk::Medium,
            arguments: serde_json::json!({
                "to": "camille@example.test",
                "subject": "Invoice for Camille Durand",
                "body": "Please pay by Friday."
            }),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        let waiting = tokio::spawn(async move { approver.decide(&request).await });

        wait_until("no local approval notice was raised", || local.count() > 0).await;
        let sent = local.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(phone.count(), 0, "the phone is not the local channel");
        assert_eq!(sent[0].title, "Auxesis");
        assert_eq!(
            sent[0].body,
            "1 approval is waiting. Open Auxesis to see it."
        );
        let text = format!("{}\n{}", sent[0].title, sent[0].body);
        for leaked in [
            "camille@example.test",
            "Invoice",
            "Camille",
            "Durand",
            "google_gmail_create_draft",
            "Friday",
        ] {
            assert!(
                !text.contains(leaked),
                "{leaked:?} reached the local notice"
            );
        }

        let _ = waiting.await;
    }

    /// A value that goes out must be showable whole: a draft whose
    /// recipient would be shown redacted is refused, never approved while the
    /// raw address goes to `drafts.create`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gmail_draft_whose_recipient_would_be_redacted_is_refused() {
        let registry = ApprovalRegistry::new(Duration::from_millis(500));
        let (events, _keep) = broadcast::channel(16);
        let directory = tempfile::tempdir().unwrap();
        let approver = ApiApprover::new(registry.clone(), directory.path().into(), events, 1);
        let request = ApprovalRequest {
            agent: "mail".to_string(),
            tool: "google_gmail_create_draft".to_string(),
            risk: Risk::Medium,
            arguments: serde_json::json!({
                "to": "xoxb-123456789012-abcdefghijklmnopqrstuvwx@example.test",
                "subject": "Invoice",
                "body": "Please pay by Friday."
            }),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        let err = approver.decide(&request).await.unwrap_err();
        assert!(err.0.contains("would be shown redacted"), "{err:?}");
        assert!(
            registry.list_pending().is_empty(),
            "no card for a redacted value"
        );
    }

    /// The same rule for a body: a secret in the text is refused, never shown
    /// redacted while the raw text leaves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_whose_body_would_be_redacted_is_refused() {
        let registry = ApprovalRegistry::new(Duration::from_millis(500));
        let (events, _keep) = broadcast::channel(16);
        let directory = tempfile::tempdir().unwrap();
        mail_home(directory.path());
        let approver = ApiApprover::new(registry.clone(), directory.path().into(), events, 1);
        let request = ApprovalRequest {
            agent: "clients".to_string(),
            tool: "mail_send".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({
                "to": ["a@example.test"],
                "subject": "Hello",
                "body": "password=Fict1onal-Pw-42"
            }),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        let err = approver.decide(&request).await.unwrap_err();
        assert!(
            err.0.contains("would be shown redacted") || err.0.contains("holds a secret"),
            "{err:?}"
        );
        assert!(
            registry.list_pending().is_empty(),
            "no card for a redacted value"
        );
    }

    /// A long mail body is shown whole: the card scrolls, it never cuts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_long_mail_body_is_shown_whole() {
        // The card stays open until the test answers it.
        let registry = ApprovalRegistry::new(DEFAULT_APPROVAL_TIMEOUT);
        let (events, _keep) = broadcast::channel(16);
        let directory = tempfile::tempdir().unwrap();
        mail_home(directory.path());
        let approver = ApiApprover::new(registry.clone(), directory.path().into(), events, 1);
        let body = "y".repeat(20 * 1024);
        let request = ApprovalRequest {
            agent: "clients".to_string(),
            tool: "mail_send".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({ "to": ["a@example.test"], "subject": "Hi", "body": body }),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        let waiting = tokio::spawn(async move { approver.decide(&request).await });
        let card = wait_for_pending(&registry).await;
        assert_eq!(card.card_body.len(), body.len());
        assert_eq!(card.card_body, body);
        registry.resolve(&card.id, Resolution::deny());
        let _ = waiting.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burst_of_approvals_sends_one_phone_text() {
        // All five cards must be open at once: none may close on a timer
        // while a slow runner is still opening the others.
        let registry = ApprovalRegistry::new(DEFAULT_APPROVAL_TIMEOUT);
        let phone = Arc::new(aux_notify::FakeNotifier::new());
        registry.set_phone_notifier(phone.clone());
        let (events, _keep) = broadcast::channel(64);
        let directory = tempfile::tempdir().unwrap();
        mail_home(directory.path());
        let mut waiting = Vec::new();
        for _ in 0..5 {
            let approver =
                ApiApprover::new(registry.clone(), directory.path().into(), events.clone(), 1);
            let request = ApprovalRequest {
                agent: "mail".to_string(),
                tool: "mail_send".to_string(),
                risk: Risk::Medium,
                arguments: serde_json::json!({}),
                tainted: false,
                taint_source: None,
                web_approval: None,
                unsandboxed: false,
                networked: false,
            };
            waiting.push(tokio::spawn(async move { approver.decide(&request).await }));
        }
        wait_until("approvals never opened", || {
            registry.list_pending().len() >= 5
        })
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(phone.count(), 1, "{:?}", phone.sent());
        for task in waiting {
            task.abort();
        }
    }

    #[test]
    fn the_phone_notice_counts_and_names_nothing_else() {
        assert_eq!(
            phone_notice(1, Lang::En).body,
            "1 approval is waiting. Open Auxesis to see it."
        );
        assert_eq!(
            phone_notice(3, Lang::En).body,
            "3 approvals are waiting. Open Auxesis to see them."
        );
        assert_eq!(
            phone_notice(1, Lang::Fr).body,
            "1 approbation est en attente. Ouvrez Auxesis pour la voir."
        );
        assert_eq!(
            phone_notice(3, Lang::Fr).body,
            "3 approbations sont en attente. Ouvrez Auxesis pour les voir."
        );
    }

    #[tokio::test]
    async fn unreadable_gmail_recipient_is_refused_before_approval_is_registered() {
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let (events, _) = broadcast::channel(8);
        let directory = tempfile::tempdir().unwrap();
        let approver = ApiApprover::new(registry.clone(), directory.path().into(), events, 1);
        let request = ApprovalRequest {
            agent: "main".to_string(),
            tool: "google_gmail_create_draft".to_string(),
            risk: Risk::Medium,
            arguments: serde_json::json!({"to":"", "subject":"hi", "body":"body"}),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        assert!(approver.decide(&request).await.is_err());
        assert!(registry.list_pending().is_empty());
    }

    /// A config.toml that is there but cannot be read safely (a FIFO nobody
    /// writes to, a symlink) refuses a send's card at once: the card could not
    /// name the account the mail leaves from. A card that names no sender
    /// still asks, and the other `[connectors.mail]` readers mount nothing,
    /// at once too.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreadable_config_refuses_a_send_card_at_once() {
        let registry = ApprovalRegistry::new(Duration::from_millis(500));
        let (events, _keep) = broadcast::channel(16);
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().to_path_buf();
        let (config, mailed) = (kernel_core::config_path(&home), home.join("mail.toml"));
        mail_home(&home);
        std::fs::rename(&config, &mailed).unwrap();
        let approver = Arc::new(ApiApprover::new(registry.clone(), home.clone(), events, 1));
        let send = ApprovalRequest {
            agent: "clients".to_string(),
            tool: "mail_send".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({ "to": ["a@example.test"], "subject": "Hi", "body": "Hello" }),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        for kind in ["fifo", "symlink"] {
            if kind == "fifo" {
                let made = std::process::Command::new("mkfifo").arg(&config).status();
                assert!(made.unwrap().success());
            } else {
                std::os::unix::fs::symlink(&mailed, &config).unwrap();
            }
            let (approver, send) = (Arc::clone(&approver), send.clone());
            let decided = tokio::spawn(async move { approver.decide(&send).await });
            let decided = tokio::time::timeout(Duration::from_secs(10), decided).await;
            let err = decided.expect("the card blocked").unwrap().unwrap_err();
            assert!(err.0.contains("cannot be read"), "{kind}: {err:?}");
            assert!(registry.list_pending().is_empty(), "{kind}: no card");
            let (moved, (sent, got)) = (home.clone(), std::sync::mpsc::channel());
            std::thread::spawn(move || {
                let none = crate::crm::mail_config(&moved).is_none()
                    && crate::local_brief::mail_config(&moved).is_none()
                    && super::super::turn::load_mail_config(&moved).is_none();
                sent.send((none, mail_accounts(&moved, "shell")))
            });
            let (none, shell) = got.recv_timeout(Duration::from_secs(10)).expect("blocked");
            assert!(none, "{kind}: no mail config");
            assert_eq!(shell, Ok(Vec::new()), "{kind}: no sender to name, it asks");
            std::fs::remove_file(&config).unwrap();
        }
        // No config, or no table, is no account: the card asks, From unknown.
        assert_eq!(mail_accounts(&home, "mail_send"), Ok(Vec::new()));
        for broken in [
            "not = [toml",
            "[[connectors.mail.accounts]]\nid = \"Bad\"\n",
        ] {
            std::fs::write(&config, broken).unwrap();
            assert!(mail_accounts(&home, "skill__x").is_err(), "{broken}");
        }
        std::fs::rename(&mailed, &config).unwrap();
        let work = ("work".to_string(), "owner@example.test".to_string());
        assert_eq!(mail_accounts(&home, "mail_send"), Ok(vec![work]));
        assert!(crate::crm::mail_config(&home).is_some());
    }

    #[test]
    fn a_poisoned_registry_lock_recovers_instead_of_panicking() {
        // E-8: a panic in the audit path poisons the registry; every later
        // approval request must recover instead of aborting the daemon.
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let poisoner = Arc::clone(&registry.inner);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the approval registry");
        }));
        assert!(registry.inner.is_poisoned());

        assert!(registry.list_pending().is_empty());
        assert!(registry.get("ap-x").is_none());
        let entry = pending();
        let mut receiver = registry.register(entry.clone());
        assert_eq!(registry.list_pending().len(), 1);
        let claimed = registry.claim(&entry.id).expect("claim after poison");
        claimed.complete(Resolution::deny());
        assert_eq!(receiver.try_recv(), Ok(Resolution::deny()));
        registry.abandon("ap-y");
        assert!(registry.expire("ap-y").is_none());
    }

    /// The app's `Approval` shape, copied from `model.rs` (contract).
    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct AppApproval {
        id: String,
        audit_id: u64,
        agent: String,
        thread_id: String,
        ts: i64,
        action: String,
        headline: String,
        #[serde(default)]
        preview: Option<String>,
        #[serde(default)]
        full_preview: Option<String>,
        #[serde(default)]
        detail: Vec<String>,
        why: String,
        #[serde(default)]
        scope_resource: Option<String>,
        scope_tool: String,
        scope_rule: String,
        #[serde(default)]
        destructive: bool,
        #[serde(default)]
        state: AppApprovalState,
    }

    #[allow(dead_code)]
    #[derive(Debug, Default, Deserialize)]
    #[serde(tag = "state", rename_all = "snake_case")]
    enum AppApprovalState {
        #[default]
        Pending,
        Allowed {
            by: String,
            always: bool,
        },
        Denied {
            by: String,
        },
        Expired,
    }

    #[test]
    fn pending_frame_deserializes_as_the_app_approval() {
        let value = serde_json::to_value(pending().frame()).unwrap();
        let approval: AppApproval = serde_json::from_value(value).unwrap();
        assert_eq!(approval.id, "ap-1-1");
        assert_eq!(approval.audit_id, 7);
        assert_eq!(approval.thread_id, "3");
        assert_eq!(approval.scope_tool, "shell");
        // The title and the body are the human ones: never the arguments.
        assert_eq!(approval.headline, "Run ls");
        assert_eq!(approval.preview.as_deref(), Some("command: ls"));
        assert!(!approval.headline.contains("{\""));
        assert!(approval.destructive, "shell is high risk");
    }

    #[test]
    fn an_unsandboxed_frame_says_so_and_still_decodes() {
        // The card carries `unsandboxed: true` and the
        // why/scope strings the owner reads; the app model ignores the new
        // field (no `deny_unknown_fields`) and keeps decoding.
        let value = serde_json::to_value(
            PendingApproval {
                unsandboxed: true,
                networked: false,
                ..pending()
            }
            .frame(),
        )
        .unwrap();
        assert_eq!(value["unsandboxed"], serde_json::json!(true));
        assert!(
            value["why"].as_str().unwrap().contains("unsandboxed"),
            "{}",
            value["why"]
        );
        assert!(
            value["scope_rule"]
                .as_str()
                .unwrap()
                .contains("unsandboxed"),
            "{}",
            value["scope_rule"]
        );
        let _: AppApproval = serde_json::from_value(value).unwrap();
    }

    #[tokio::test]
    async fn resolve_answers_the_waiter_and_removes_the_pending() {
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let (receiver, entry) = registry.begin(pending());
        assert_eq!(registry.list_pending().len(), 1);
        assert!(entry.id.starts_with("ap-"));

        let resolved = registry
            .resolve(&entry.id, Resolution::allow_once())
            .unwrap();
        assert_eq!(resolved.id, entry.id);
        assert_eq!(receiver.await.unwrap(), Resolution::allow_once());
        assert!(registry.list_pending().is_empty());
        assert!(registry.resolve(&entry.id, Resolution::deny()).is_none());
    }

    #[tokio::test]
    async fn claim_is_exclusive_and_completion_wakes_the_waiter() {
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let (mut receiver, entry) = registry.begin(pending());

        // Exactly one claim wins, and claiming removes the pending at once.
        let claimed = registry.claim(&entry.id).unwrap();
        assert_eq!(claimed.pending().id, entry.id);
        assert!(registry.claim(&entry.id).is_none());
        assert!(registry.resolve(&entry.id, Resolution::deny()).is_none());
        assert!(registry.list_pending().is_empty());
        // Side effects can happen while the turn is still waiting…
        assert!(receiver.try_recv().is_err(), "claim must not wake the turn");

        // …and `complete` is what hands the answer over, last.
        claimed.complete(Resolution::allow_once());
        assert_eq!(receiver.await.unwrap(), Resolution::allow_once());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_failure_emits_the_zero_sentinel_not_an_undecodable_frame() {
        let dir = tempfile::tempdir().unwrap();
        // `home` is a file, so the store under it cannot be opened: every
        // audit write fails.
        let home = dir.path().join("home");
        std::fs::write(&home, "not a directory").unwrap();
        let registry = ApprovalRegistry::new(Duration::from_millis(30));
        let (events, mut ws) = broadcast::channel(16);
        let approver = ApiApprover::new(Arc::clone(&registry), home, events, 3);
        let request = ApprovalRequest {
            agent: "main".to_string(),
            tool: "shell".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({"command": "ls"}),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };

        let waiting = tokio::spawn(async move { approver.approve(&request).await });
        // The card closes on its 30 ms timer, so read the frame it emitted:
        // the channel keeps it, a slow runner cannot miss it.
        let frame = next_frame(&mut ws).await;
        assert_eq!(frame["type"], "approval.new");
        let value = frame["approval"].clone();
        assert_eq!(
            value["audit_id"], 0,
            "an unwritable audit is the documented 0 sentinel: {value}"
        );
        // The app's `Approval` requires a `u64`: the degraded frame must
        // still deserialize.
        let approval: AppApproval = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(approval.audit_id, 0);
        assert!(
            !waiting.await.unwrap().unwrap(),
            "timeout still fails closed"
        );
        // The expiry names the same card.
        let resolved = next_frame(&mut ws).await;
        assert_eq!(resolved["type"], "approval.resolved");
        assert_eq!(resolved["id"], value["id"]);
    }

    #[tokio::test]
    async fn an_abandoned_claim_cannot_wake_the_turn_or_deliver_effects() {
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let (mut receiver, entry) = registry.begin(pending());

        // The timeout path marks the in-flight claim abandoned…
        let claimed = registry.claim(&entry.id).unwrap();
        registry.abandon(&entry.id);
        // …and a completion that lands afterwards must not run its
        // side effects nor hand the (stale) answer to the turn.
        let mut effects_ran = false;
        let outcome = claimed.complete_with(Resolution::allow_once(), || effects_ran = true);
        assert_eq!(outcome, Completion::Abandoned);
        assert!(!effects_ran, "abandoned answers publish nothing");
        assert!(
            receiver.try_recv().is_err(),
            "the turn must not be woken after it gave up"
        );
    }

    #[tokio::test]
    async fn expire_drops_without_answering() {
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let (receiver, entry) = registry.begin(pending());
        let expired = registry.expire(&entry.id).unwrap();
        assert_eq!(expired.id, entry.id);
        assert!(receiver.await.is_err(), "no answer was sent");
        assert!(registry.list_pending().is_empty());
    }

    #[test]
    fn a_turn_that_ends_retires_its_own_cards_and_never_another_turns() {
        // CARD-NEVER-BLOCKS: two turns of thread 3; the second one ends.
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let mut parked = pending();
        parked.id = "ap-parked".to_string();
        let mut receiver = registry.register_run(parked, Some("run-1"));
        let mut other = pending();
        other.id = "ap-other".to_string();
        let _other = registry.register_run(other, Some("run-2"));
        let mut legacy = pending();
        legacy.id = "ap-legacy".to_string();
        let _legacy = registry.register(legacy);
        assert_eq!(registry.cards_holding(3), 3);

        let mut retired = registry.abandon_run(3, "run-2");
        retired.sort();
        let ids: Vec<&str> = retired.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["ap-legacy", "ap-other"], "no turn = fail closed");
        assert!(retired.iter().all(|(_, pending)| *pending));
        assert_eq!(registry.cards_holding(3), 1);
        assert!(!registry.is_abandoned("ap-parked"));
        registry
            .resolve("ap-parked", Resolution::allow_once())
            .expect("the parked turn's card is still answerable");
        assert_eq!(receiver.try_recv(), Ok(Resolution::allow_once()));
        assert!(registry
            .resolve("ap-parked", Resolution::allow_once())
            .is_none());
    }

    #[test]
    fn abandon_thread_retires_pending_and_claimed_ids_of_one_session() {
        // When a turn ends (cancel, timeout or normal), its session's
        // approvals are retired — pending ones disappear, claimed ones become
        // unabandonable answers.
        let registry = ApprovalRegistry::new(Duration::from_secs(1));
        let (mut receiver_a, entry_a) = registry.begin(pending()); // thread 3
        let mut other = pending();
        other.id = "ap-other".to_string();
        other.thread_id = 9;
        let (mut receiver_b, entry_b) = registry.begin(other);
        let claimed_a = registry.claim(&entry_a.id).expect("claim a");

        let retired = registry.abandon_thread(3);
        assert_eq!(retired, vec![entry_a.id.clone()]);
        assert!(registry.is_abandoned(&entry_a.id));
        assert!(
            !registry.is_abandoned(&entry_b.id),
            "another session's approval is untouched"
        );
        assert_eq!(registry.list_pending().len(), 1);
        assert!(receiver_a.try_recv().is_err(), "a is not woken");

        // A completion that lands after the turn gave up runs no effects.
        let mut effects_ran = false;
        assert_eq!(
            claimed_a.complete_with(Resolution::allow_once(), || effects_ran = true),
            Completion::Abandoned
        );
        assert!(!effects_ran);

        // The other session's pending approval still works.
        registry
            .resolve(&entry_b.id, Resolution::allow_once())
            .expect("b is still answerable");
        assert_eq!(receiver_b.try_recv(), Ok(Resolution::allow_once()));

        // A pending id of the retired thread is dropped too.
        let (mut receiver_c, entry_c) = registry.begin(pending());
        let retired = registry.abandon_thread(3);
        assert_eq!(retired, vec![entry_c.id.clone()]);
        assert!(registry.is_abandoned(&entry_c.id));
        assert!(registry.list_pending().is_empty());
        assert!(receiver_c.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn api_approver_allows_on_an_api_answer() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::open(&kernel_core::store_path(&home)).unwrap();
        drop(store);
        let registry = ApprovalRegistry::new(Duration::from_secs(30));
        let (events, mut ws) = broadcast::channel(16);
        let approver = ApiApprover::new(Arc::clone(&registry), home, events, 3);
        let request = ApprovalRequest {
            agent: "main".to_string(),
            tool: "shell".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({"command": "ls"}),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };

        let waiting = tokio::spawn(async move { approver.approve(&request).await });
        let pending = wait_for_pending(&registry).await;
        assert!(pending.id.starts_with("ap-"));
        // approval.new was published with the app shape. The pending becomes
        // visible shortly before the broadcast, so wait for the frame under a
        // short timeout instead of racing the publish with `try_recv`.
        let text = tokio::time::timeout(Duration::from_secs(5), ws.recv())
            .await
            .expect("approval.new must be published")
            .expect("the event channel must still be open");
        let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(frame["type"], "approval.new");
        assert_eq!(frame["approval"]["id"], pending.id);

        registry.resolve(&pending.id, Resolution::allow_once());
        assert!(waiting.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn api_approver_times_out_fail_closed_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::open(&kernel_core::store_path(&home)).unwrap();
        drop(store);
        let registry = ApprovalRegistry::new(Duration::from_millis(30));
        let (events, mut ws) = broadcast::channel(16);
        let approver = ApiApprover::new(Arc::clone(&registry), home.clone(), events, 3);
        let request = ApprovalRequest {
            agent: "main".to_string(),
            tool: "shell".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({"command": "ls"}),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };

        assert!(!approver.approve(&request).await.unwrap(), "timeout denies");
        assert!(registry.list_pending().is_empty());

        let mut kinds = Vec::new();
        while let Ok(text) = ws.try_recv() {
            let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
            kinds.push((frame["type"].to_string(), frame));
        }
        assert_eq!(kinds[0].0, "\"approval.new\"");
        assert_eq!(kinds[1].0, "\"approval.resolved\"");
        assert_eq!(kinds[1].1["state"], serde_json::json!({"state": "expired"}));

        // The journal carries pending + timeout answered rows.
        let store = Store::open(&kernel_core::store_path(&home)).unwrap();
        assert_eq!(store.event_count("approval.pending").unwrap(), 1);
        assert_eq!(store.event_count("approval.answered").unwrap(), 1);
    }

    /// A turn's card stops waiting at 9/10 of the approval timeout, counted
    /// from the turn's start, so a client that waits as long as one card
    /// still gets the reply. On a paused clock the wait is exact, whatever
    /// the runner's load.
    #[tokio::test(start_paused = true)]
    async fn a_turn_card_stops_waiting_at_nine_tenths_of_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let registry = ApprovalRegistry::new(DEFAULT_APPROVAL_TIMEOUT);
        let (events, _ws) = broadcast::channel(16);
        let approver = ApiApprover::new(Arc::clone(&registry), dir.path().into(), events, 3)
            .with_turn_deadline();
        let request = ApprovalRequest {
            agent: "main".to_string(),
            tool: "shell".to_string(),
            risk: Risk::High,
            arguments: serde_json::json!({"command": "ls"}),
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };

        let started = tokio::time::Instant::now();
        assert!(
            !approver.approve(&request).await.unwrap(),
            "no answer denies"
        );
        let waited = started.elapsed();
        // The timer rounds its deadline up to the next millisecond.
        let limit = DEFAULT_APPROVAL_TIMEOUT * 9 / 10 + Duration::from_millis(1);
        assert!(waited <= limit, "the card waited {waited:?}, past 9/10");
        assert!(
            waited >= DEFAULT_APPROVAL_TIMEOUT / 2,
            "the card waited only {waited:?}"
        );
        assert!(registry.list_pending().is_empty(), "the card is closed");
    }

    /// The longest a test waits for a card to open. Opening one scrubs its
    /// text and writes its first audit row, which creates and migrates the
    /// test's store: under a second on an idle machine, past 10 s on a busy
    /// CI runner, close to a minute under heavy CPU load. It only bounds a
    /// broken test.
    const CARD_OPENS_WITHIN: Duration = Duration::from_secs(120);

    async fn wait_for_pending(registry: &ApprovalRegistry) -> PendingApproval {
        // The approval is registered by a task spawned on *this* test's
        // runtime, so the wait must yield to that runtime: a blocking
        // `std::thread::sleep` poll starves the very task being waited for on
        // a many-test, many-core run (reproduced 100% with 16 libtest threads,
        // green with 4). Yield and keep a generous deadline so a loaded
        // machine cannot turn scheduling latency into a failure.
        let deadline = tokio::time::Instant::now() + CARD_OPENS_WITHIN;
        loop {
            if let Some(pending) = registry.list_pending().into_iter().next() {
                return pending;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no pending approval appeared"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Poll `done` every 10 ms, yielding to the runtime, until it holds or
    /// [`CARD_OPENS_WITHIN`] is over; `missing` names what never came.
    async fn wait_until(missing: &str, done: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + CARD_OPENS_WITHIN;
        while !done() {
            assert!(tokio::time::Instant::now() < deadline, "{missing}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The next live-event frame, within [`CARD_OPENS_WITHIN`].
    async fn next_frame(ws: &mut broadcast::Receiver<String>) -> serde_json::Value {
        let text = tokio::time::timeout(CARD_OPENS_WITHIN, ws.recv())
            .await
            .expect("no frame was published")
            .expect("the event channel must still be open");
        serde_json::from_str(&text).unwrap()
    }

    /// F6: a daemon that dies with a card pending, or mid-run, leaves its
    /// Ledger open. The boot recovery closes both with an `abandoned` row.
    #[test]
    fn a_restart_closes_a_pending_card_and_an_unfinished_run_as_abandoned() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = Store::open(&db).unwrap();
        let run = |run_id: &str, outcome: Option<&str>| {
            let mut payload = serde_json::json!({
                "agent": "main",
                "skill_name": "send-invite",
                "skill_version": "1",
                "skill_hash": "abc",
                "run_id": run_id,
            });
            if let Some(outcome) = outcome {
                payload["outcome"] = serde_json::Value::String(outcome.to_string());
            } else {
                payload["decision"] = serde_json::Value::String("approved".to_string());
            }
            payload.to_string()
        };
        store
            .log_event("approval.pending", r#"{"id":"ap-1-1"}"#)
            .unwrap();
        store
            .log_event("skill.approval", &run("run-1", None))
            .unwrap();
        store
            .log_event("skill.approval", &run("run-2", None))
            .unwrap();
        store
            .log_event("skill.run", &run("run-2", Some("done")))
            .unwrap();
        drop(store);

        recover_stale_pending(&db);

        let store = Store::open(&db).unwrap();
        let dropped = store.event_payloads("approval.dropped").unwrap();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert!(
            dropped[0].contains(r#""outcome":"abandoned""#),
            "{}",
            dropped[0]
        );
        let runs = store.event_payloads("skill.run").unwrap();
        let abandoned: Vec<&String> = runs
            .iter()
            .filter(|payload| payload.contains(r#""outcome":"abandoned""#))
            .collect();
        assert_eq!(abandoned.len(), 1, "{runs:?}");
        assert!(
            abandoned[0].contains(r#""run_id":"run-1""#),
            "{}",
            abandoned[0]
        );
    }
}
