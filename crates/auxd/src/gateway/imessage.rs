//! The Messages (iMessage) gateway behind G1's [`Gateway`] trait (D34, G2).
//!
//! Inbound rows are read from `chat.db` through an [`InboundSource`] that is
//! already locked to the configured owner handle(s) and pinned chat GUID, and
//! queued as tainted [`InboundText`] only. Outbound text arrives as an
//! [`OutboundText`] that the router admitted on this gateway's kernel egress
//! path, and is passed to the [`Sender`] after the pacing gate opens. The
//! gateway never sends an approval card (there are no buttons over Messages);
//! the call fails closed.
//!
//! **Egress binding.** The kernel has no iMessage row yet (`PathId` is
//! `#[non_exhaustive]` and lives in the pinned kernel crate). Outbound is
//! admitted on [`PathId::C5`], the existing outbound-channel row whose policy
//! is identical to the intended C-row: `NotCovered`, `Disabled` in Private,
//! `Allow` in Open. The kernel needs a dedicated row (`C11`, "iMessage in and
//! out", Private `Disabled`, Open `Allow`); until it lands, this binding cannot
//! widen anything and Private mode holds every model-derived send. The one
//! Private send is [`PRIVATE_NOTICE`], a constant admitted on C11 (and, for
//! the morning brief, [`BRIEF_NOTICE`]).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aux_imessage::config::ImessageConfig;
use aux_imessage::cursor::CursorStore;
use aux_imessage::pacing::Pacer;
use aux_imessage::reader::{ChatSpec, InboundSource, ReadReceipt, ReaderError};
use aux_imessage::sender::{SendError, Sender};
use aux_store::Store;
use kernel_core::privacy::{PathId, PrivacyMode, Refused};
use tokio::sync::mpsc;

use super::{
    ApprovalCard, Capabilities, ChatId, Gateway, GatewayError, InboundText, Level, OutboundText,
    OwnerId, SendCause,
};
use crate::api::{PrivateAnswers, TurnError, TurnRecord};

/// The channel id.
pub const CHANNEL: &str = "imessage";

/// Kind of the throwaway session a private owner text runs in. It is not
/// `chat`, so it never becomes an agent's current thread, even when a crash
/// leaves it behind with the rows its turn stored (PRIVATE-TRANSCRIPT).
pub const PRIVATE_SESSION_KIND: &str = "imessage-private";

/// The interim kernel egress row; see the module note.
pub const EGRESS_PATH: PathId = PathId::C5;

/// The row for the one text Messages may send in Private mode (C11).
pub const NOTICE_PATH: PathId = PathId::C11;

/// The only text sent over Messages in Private mode. A constant: the answer
/// holds real names after local rehydration, so it stays in the app.
pub const PRIVATE_NOTICE: &str = "Answered in Auxesis (private mode). Open the app to read it.";

/// The fixed Private-mode reply, admitted on [`NOTICE_PATH`]. It takes no
/// text, so no session, model or owner text can reach it.
pub fn private_notice(mode: PrivacyMode) -> Result<OutboundText, Refused> {
    OutboundText::admitted(NOTICE_PATH, mode, Level::Normal, PRIVATE_NOTICE)
}

/// The only other text sent over Messages in Private mode: a private turn
/// gave no answer. A constant, so no error detail or count can reach it.
pub const PRIVATE_FAILURE_NOTICE: &str = "Couldn't answer in private mode. Open Auxesis.";

/// The fixed Private-mode failure reply, admitted on [`NOTICE_PATH`].
pub fn private_failure_notice(mode: PrivacyMode) -> Result<OutboundText, Refused> {
    OutboundText::admitted(NOTICE_PATH, mode, Level::Normal, PRIVATE_FAILURE_NOTICE)
}

/// Sent in Open mode instead of a reply whose scrub failed (IMSG-SCRUB-1). A
/// constant, so nothing of the held text can reach it.
pub const REPLY_HELD_NOTICE: &str = "Reply held on your Mac, open Auxesis to read it.";

/// The only text sent over Messages for the morning brief in Private mode. A
/// constant: no mail content, name or count; the full brief stays in the app.
pub const BRIEF_NOTICE: &str = "Your morning brief is ready in Auxesis.";

/// The single paired owner (there is exactly one pinned chat).
pub const OWNER: OwnerId = OwnerId(0);

/// The single pinned chat.
pub const CHAT: ChatId = ChatId(0);

/// How many tainted inbound messages may wait for a turn.
pub const INBOUND_CAPACITY: usize = 16;

/// Rows read per poll.
pub const POLL_LIMIT: usize = 20;

/// Read receipts read per poll.
pub const RECEIPT_LIMIT: usize = 20;

/// Longest a send waits for the pacing gate before it gives up and reports a
/// failure. The rule is 15 s; 30 s leaves one retry of headroom.
pub const PACING_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why the gateway could not be built. Carries no handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// The section is disabled or invalid.
    #[error("the [imessage] section is disabled or invalid")]
    Config,
    /// The pinned-chat binding is malformed.
    #[error("the [imessage] binding is invalid")]
    Binding,
}

/// Why a poll failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PollError {
    /// The read-only query failed.
    #[error("the chat.db read failed")]
    Read(#[from] ReaderError),
    /// The persisted cursor is unreadable.
    #[error("the persisted iMessage cursor is unreadable")]
    Cursor,
    /// The blocking read task failed.
    #[error("the iMessage read task failed")]
    Join,
}

/// What one poll did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PollReport {
    /// Inbound messages queued for a turn.
    pub accepted: usize,
    /// Inbound messages dropped on a full queue.
    pub dropped: usize,
    /// Rows skipped because their content would not decode.
    pub skipped: usize,
    /// The cursor after the poll.
    pub cursor: i64,
}

/// The Messages implementation of [`Gateway`].
pub struct MessagesGateway {
    spec: ChatSpec,
    target: String,
    source: Arc<dyn InboundSource>,
    sender: Arc<dyn Sender>,
    pacer: Pacer,
    cursor: Mutex<Option<i64>>,
    cursor_store: Option<CursorStore>,
    receipt_cursor: Mutex<i64>,
    unread: Mutex<Vec<ReadReceipt>>,
    inbound_tx: mpsc::Sender<InboundText>,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<InboundText>>,
}

impl MessagesGateway {
    /// Build a gateway from an **enabled, valid** section. Anything else is a
    /// [`BuildError::Config`], so a misconfigured channel is never constructed.
    pub fn new(
        config: &ImessageConfig,
        source: Arc<dyn InboundSource>,
        sender: Arc<dyn Sender>,
        pacer: Pacer,
        cursor_store: Option<CursorStore>,
    ) -> Result<Self, BuildError> {
        if !config.enabled || config.validate().is_err() {
            return Err(BuildError::Config);
        }
        let spec = ChatSpec::new(config.owner_handles.clone(), config.chat_guid.clone())
            .map_err(|_| BuildError::Binding)?;
        let target = spec
            .owner_handles()
            .first()
            .cloned()
            .ok_or(BuildError::Config)?;
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CAPACITY);
        Ok(Self {
            spec,
            target,
            source,
            sender,
            pacer,
            cursor: Mutex::new(None),
            cursor_store,
            receipt_cursor: Mutex::new(0),
            unread: Mutex::new(Vec::new()),
            inbound_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        })
    }

    /// The pinned binding (tests and diagnostics).
    pub fn spec(&self) -> &ChatSpec {
        &self.spec
    }

    /// The owner handle a send targets.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Read new rows, queue the tainted ones, advance and persist the cursor.
    /// A failed cursor read stops the poll (fail closed); skipped content is
    /// counted, never logged.
    ///
    /// A full queue stops the loop and leaves the cursor at the **last
    /// delivered** rowid, so the rows that did not fit are read again next
    /// poll instead of being lost. Every examined row counts for pacing before
    /// its queue attempt, so a dropped inbound still paces the next send.
    pub fn poll_once(&self, limit: usize) -> Result<PollReport, PollError> {
        let cursor = self.ensure_cursor()?;
        let batch = self.source.read_since(&self.spec, cursor, limit)?;
        let mut report = PollReport {
            skipped: batch.skipped,
            cursor,
            ..PollReport::default()
        };
        let mut last_delivered = cursor;
        let mut queue_full = false;
        for message in &batch.messages {
            self.pacer.record_inbound_now();
            let inbound = InboundText::tainted(CHAT, message.rowid, &message.text);
            match self.inbound_tx.try_send(inbound) {
                Ok(()) => {
                    report.accepted += 1;
                    last_delivered = message.rowid;
                }
                Err(_) => {
                    queue_full = true;
                    break;
                }
            }
        }
        if queue_full {
            report.dropped = batch.messages.len().saturating_sub(report.accepted);
        }
        let new_cursor = if queue_full {
            last_delivered
        } else {
            batch.max_seen_rowid.max(cursor)
        };
        *lock(&self.cursor) = Some(new_cursor);
        if let Some(store) = &self.cursor_store {
            if let Err(err) = store.save(new_cursor) {
                tracing::warn!(error = %err, "imessage cursor not persisted");
            }
        }
        report.cursor = new_cursor;
        if report.skipped > 0 {
            tracing::warn!(
                skipped = report.skipped,
                "imessage rows skipped: content would not decode"
            );
        }
        Ok(report)
    }

    /// Read new read receipts for the agent's own outgoing messages and keep
    /// the unread ones. Returns how many are currently unread.
    pub fn refresh_receipts(&self, limit: usize) -> Result<usize, ReaderError> {
        let cursor = *lock(&self.receipt_cursor);
        let receipts = self.source.read_receipts_since(&self.spec, cursor, limit)?;
        if receipts.is_empty() {
            return Ok(self.unread_count());
        }
        let newest = receipts
            .iter()
            .map(|receipt| receipt.rowid)
            .max()
            .unwrap_or(cursor)
            .max(cursor);
        {
            let mut unread = lock(&self.unread);
            for receipt in receipts.iter().filter(|receipt| receipt.is_unread()) {
                if !unread.iter().any(|known| known.rowid == receipt.rowid) {
                    unread.push(receipt.clone());
                }
            }
            unread.retain(|known| {
                !receipts
                    .iter()
                    .any(|receipt| receipt.rowid == known.rowid && receipt.is_read)
            });
        }
        *lock(&self.receipt_cursor) = newest;
        Ok(self.unread_count())
    }

    /// The unread outgoing messages seen so far.
    pub fn unread(&self) -> Vec<ReadReceipt> {
        lock(&self.unread).clone()
    }

    /// How many unread outgoing messages are tracked.
    pub fn unread_count(&self) -> usize {
        lock(&self.unread).len()
    }

    /// The persisted cursor, or a fresh cursor at the current max ROWID (so a
    /// first run never replays old history). A corrupt cursor is an error.
    fn ensure_cursor(&self) -> Result<i64, PollError> {
        if let Some(cursor) = *lock(&self.cursor) {
            return Ok(cursor);
        }
        let loaded = match &self.cursor_store {
            Some(store) => store.load().map_err(|_| PollError::Cursor)?,
            None => None,
        };
        let cursor = match loaded {
            Some(cursor) => cursor,
            None => self.source.max_rowid()?,
        };
        *lock(&self.cursor) = Some(cursor);
        if let Some(store) = &self.cursor_store {
            if let Err(err) = store.save(cursor) {
                tracing::warn!(error = %err, "imessage cursor not persisted");
            }
        }
        Ok(cursor)
    }

    /// Wait until the pacing gate opens, at most [`PACING_MAX_WAIT`]. A wait
    /// that would run past the bound is a failure, logged without content.
    async fn wait_for_pacing(&self) -> Result<(), GatewayError> {
        let deadline = tokio::time::Instant::now() + PACING_MAX_WAIT;
        loop {
            match self.pacer.try_acquire() {
                Ok(()) => return Ok(()),
                Err(err) => {
                    let now = tokio::time::Instant::now();
                    if now >= deadline {
                        tracing::warn!(
                            wait_secs = err.wait_secs(),
                            "imessage send still held after the bounded pacing wait"
                        );
                        return Err(GatewayError::Send(SendCause::Paced));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    let wait = std::time::Duration::from_secs(err.wait_secs().max(1) as u64)
                        .min(remaining);
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}

/// Run one `chat.db` poll on a blocking thread, so the SQLite read never
/// stalls the async runtime.
pub async fn poll_offloaded(
    gateway: Arc<MessagesGateway>,
    limit: usize,
) -> Result<PollReport, PollError> {
    tokio::task::spawn_blocking(move || gateway.poll_once(limit))
        .await
        .map_err(|_| PollError::Join)?
}

/// Run one read-receipt query on a blocking thread.
pub async fn receipts_offloaded(
    gateway: Arc<MessagesGateway>,
    limit: usize,
) -> Result<usize, PollError> {
    tokio::task::spawn_blocking(move || gateway.refresh_receipts(limit))
        .await
        .map_err(|_| PollError::Join)?
        .map_err(PollError::Read)
}

#[async_trait]
impl Gateway for MessagesGateway {
    fn id(&self) -> &'static str {
        CHANNEL
    }

    fn egress_path(&self) -> PathId {
        EGRESS_PATH
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            text: true,
            // No buttons over Messages: a card would wait forever, so refuse.
            approvals: false,
            brief: true,
            read_receipts: true,
            calls: false,
        }
    }

    fn owner(&self) -> Option<OwnerId> {
        Some(OWNER)
    }

    fn is_paired_owner(&self, sender: OwnerId, chat: ChatId) -> bool {
        sender == OWNER && chat == CHAT
    }

    fn is_paired(&self) -> bool {
        true
    }

    fn brief_notice_path(&self) -> Option<PathId> {
        Some(NOTICE_PATH)
    }

    async fn send(&self, outbound: &OutboundText) -> Result<(), GatewayError> {
        self.wait_for_pacing().await?;
        self.sender
            .send_text(&self.target, outbound.text())
            .map_err(map_send_error)
    }

    async fn deliver_approval(&self, _card: &ApprovalCard) -> Result<(), GatewayError> {
        // A Messages reply cannot carry the single-use nonce, so the card is
        // refused rather than sent as an unusable question.
        Err(GatewayError::Disabled)
    }

    async fn deliver_brief(&self, brief: &OutboundText) -> Result<(), GatewayError> {
        self.send(brief).await
    }

    async fn next_inbound(&self) -> Option<InboundText> {
        self.inbound_rx.lock().await.recv().await
    }
}

/// Map a sender failure without ever carrying the text or a handle.
fn map_send_error(error: SendError) -> GatewayError {
    match error {
        SendError::NotConfigured => GatewayError::Unpaired,
        SendError::NotOwner | SendError::SelfSend => GatewayError::OwnerIdentifierHeld,
        SendError::Timeout => GatewayError::Send(SendCause::Timeout),
        SendError::NotAuthorized => GatewayError::Send(SendCause::NotAuthorized),
        SendError::MessagesUnavailable => GatewayError::Send(SendCause::MessagesUnavailable),
        SendError::Empty | SendError::Transport => GatewayError::Send(SendCause::Transport),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A channel-session key that does not store the owner's raw chat GUID.
fn chat_key(home: &std::path::Path, guid: &str, agent: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(home.as_os_str().to_string_lossy().as_bytes());
    hasher.update(guid.as_bytes());
    // The legacy `main` keeps its old key; another agent gets its own thread.
    if agent != crate::agent::LEGACY_DEFAULT_AGENT {
        hasher.update(agent.as_bytes());
    }
    format!("chat#{}", hasher.finalize().to_hex())
}

/// The session one owner text runs in. Outside Private mode it is the pinned
/// chat's channel session, created tainted on first use. In Private mode it is
/// a throwaway: no channel binding, tainted, and deleted (with its taint mark)
/// when this value drops, so the turn leaves no chat metadata (G1).
pub struct TurnSession {
    /// The session id the turn runs in.
    pub id: i64,
    /// Whether the session is a Private-mode throwaway.
    pub private: bool,
    store: Arc<Mutex<Store>>,
}

impl Drop for TurnSession {
    fn drop(&mut self) {
        if self.private {
            let _ = kernel_core::lock_recover(&self.store).delete_session(self.id);
        }
    }
}

/// The session for the next owner text, by the mode read now.
pub fn session_for(
    home: &std::path::Path,
    store: &Arc<Mutex<Store>>,
    gateway: &MessagesGateway,
) -> Option<TurnSession> {
    let private = crate::privacy_wiring::private_now(home);
    let agent = crate::agent::default_chat_agent(home);
    let db = kernel_core::lock_recover(store);
    let id = if private {
        let session = db
            .create_session_of_kind(&agent, None, PRIVATE_SESSION_KIND)
            .ok()?;
        let _ = db.mark_session_tainted(session.id, CHANNEL, None);
        session.id
    } else {
        let key = chat_key(home, gateway.spec().chat_guid(), &agent);
        match db.channel_session(CHANNEL, &key).ok().flatten() {
            Some(id) => id,
            None => {
                let session = db
                    .create_session_of_kind(&agent, Some("iMessage"), "chat")
                    .ok()?;
                let effective = db.bind_channel_session(CHANNEL, &key, session.id).ok()?;
                let _ = db.mark_session_tainted(effective, CHANNEL, None);
                effective
            }
        }
    };
    Some(TurnSession {
        id,
        private,
        store: Arc::clone(store),
    })
}

/// Run one owner text as a turn of `session`, then reply over Messages.
/// Outside Private mode the reply is the assistant text. In Private mode the
/// turn runs quiet (`run_turn`'s last argument), the answer is held in memory
/// for the app ([`PrivateAnswers`], C12) and the reply is only
/// [`PRIVATE_NOTICE`], or [`PRIVATE_FAILURE_NOTICE`] when there is no answer.
/// The mode is read again after the turn, so a switch to Private mid-turn is
/// honoured.
pub async fn answer_inbound<F>(
    home: &std::path::Path,
    gateway: &MessagesGateway,
    held: &PrivateAnswers,
    session: TurnSession,
    content: String,
    run_turn: F,
) where
    F: FnOnce(i64, &str, bool) -> Result<TurnRecord, TurnError> + Send + 'static,
{
    let (id, quiet) = (session.id, session.private);
    let turn = tokio::task::spawn_blocking(move || run_turn(id, &content, quiet)).await;
    let mode = crate::privacy_wiring::current_mode(home);
    let private = quiet || mode == PrivacyMode::Private;
    let reply = match turn {
        Ok(Ok(record)) => record
            .messages
            .iter()
            .rev()
            .find(|message| message.role == "assistant" && !message.content.trim().is_empty())
            .map(|message| message.content.clone()),
        Ok(Err(err)) if !private => {
            tracing::warn!(error = %err, "imessage turn failed");
            None
        }
        _ => None,
    };
    let outbound = match (private, reply) {
        (true, Some(reply)) => {
            held.hold_local(home, id, &reply);
            private_notice(mode)
        }
        (true, None) => {
            tracing::warn!("imessage private turn gave no answer");
            private_failure_notice(mode)
        }
        // IMSG-SCRUB-1: the stored answer can hold real values (rehydrated
        // tokens, or what an injected mail made the model echo); mask them,
        // and send the fixed notice when the scrub itself fails.
        (false, Some(reply)) => {
            let text = super::scrub_for_owner(home, &reply).unwrap_or_else(|| {
                tracing::warn!("imessage reply scrub failed; notice sent instead");
                REPLY_HELD_NOTICE.to_string()
            });
            OutboundText::admitted(gateway.egress_path(), mode, Level::Normal, text)
        }
        (false, None) => return,
    };
    match outbound {
        Ok(outbound) => {
            if let Err(err) = gateway.send(&outbound).await {
                tracing::warn!(cause = %err.cause(), "imessage reply not delivered");
            }
        }
        Err(refused) => tracing::info!(path = refused.path.as_str(), "imessage reply held"),
    }
}
