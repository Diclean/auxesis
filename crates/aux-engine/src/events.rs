//! Live turn events for embedding frontends (B-API v2).
//!
//! The engine persists every message as it happens; a [`TurnEvents`] sink
//! additionally observes the same stream so a UI can follow a turn without
//! polling. Implementations must be cheap, non-blocking and infallible: a
//! failed event must never fail the turn.

use aux_providers::{ChatRequest, SafeMessage, ToolCall};
use aux_store::Message;

/// The value-free outcome summary for one finished tool call.
#[derive(Debug, Clone, Copy)]
pub struct ToolEndOutcome<'a> {
    /// Engine outcome label (`ok`, `denied`, `failed`, `unknown_tool`, `capped`).
    pub status: &'a str,
    /// Text returned as the tool result.
    pub result: &'a str,
    /// Stable, value-free failure category for owner-facing receipts.
    pub error_kind: Option<&'a str>,
}

/// Sink for one turn's live events, in insertion order.
pub trait TurnEvents: Send + Sync {
    /// The gated conversation about to go to the model, once per round, just
    /// before the request (SHELL-JUDGE reads the owner's messages from it).
    /// The default ignores it.
    fn sent(&self, messages: &[SafeMessage]) {
        let _ = messages;
    }

    /// The full, gated request about to go to the provider, including tools.
    /// Sinks that only need message context can use the default forwarding.
    fn request(&self, request: &ChatRequest) {
        self.sent(&request.messages);
    }

    /// A message was persisted (user echo, assistant text/tool call, or tool
    /// result). System prompts are not reported.
    fn message(&self, message: &Message);

    /// Transient text for an assistant message that is still streaming,
    /// reported before the message is persisted.
    ///
    /// `draft` identifies one provider call's stream within the turn (1-based,
    /// one per round); `seq` is 1-based and monotonic within that draft.
    /// Deltas are advisory: the persisted message ([`Self::message`]) remains
    /// the single source of truth, and a consumer may drop or coalesce these
    /// frames. The default implementation ignores them, so existing sinks
    /// keep working unchanged.
    fn message_delta(&self, session_id: i64, draft: u64, seq: u64, text: &str) {
        let _ = (session_id, draft, seq, text);
    }

    /// The `(token, value)` pairs one of this session's outbound gates minted,
    /// reported before any text that holds those tokens can stream. The values
    /// are for the local display side only: a sink keeps them in memory and
    /// never logs, stores or sends them. The default ignores them.
    fn session_tokens(&self, session_id: i64, pairs: &[(String, String)]) {
        let _ = (session_id, pairs);
    }

    /// A tool call is about to be authorized/run.
    fn tool_start(&self, session_id: i64, message_id: i64, index: usize, call: &ToolCall);

    /// A tool call ended with this value-free outcome summary.
    fn tool_end(
        &self,
        session_id: i64,
        message_id: i64,
        index: usize,
        call: &ToolCall,
        outcome: ToolEndOutcome<'_>,
    );

    /// CAL-NO-TOOL-GUESS: an answer about `domain` came back with no tool
    /// call this turn. `retried` is true when the model is asked once to
    /// check, false when its second guess is replaced by the honest line.
    /// The default ignores it.
    fn read_check(&self, session_id: i64, domain: &str, retried: bool) {
        let _ = (session_id, domain, retried);
    }

    /// The turn is over. `message_id` is the last persisted message of the
    /// turn (the final assistant answer, or the last tool result when the
    /// round cap was hit).
    fn done(&self, session_id: i64, message_id: i64);
}
