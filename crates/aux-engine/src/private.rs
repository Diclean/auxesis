//! The memory-only conversation of a private turn (`README.md`, "The two modes").
//!
//! The chat input and event feed (C7) is Disabled in private mode, so the feed
//! sees only the gated copy and no session title or system row is written. The
//! chat history store (G1) is allowed: the local SQLCipher store keeps each row
//! as the gated copy the provider saw, and the session's token table beside it
//! (PRIVATE-TRANSCRIPT), so the owner's page shows the values and a restart
//! re-sends the same tokens. Within the process a private conversation goes on
//! from the gated messages it sent (with its taint and private-data flag), kept
//! here, keyed by home and session id.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use aux_providers::SafeMessage;
use kernel_broker::Taint;
use kernel_core::privacy::{admit_call, Destination, PathId, PrivacyMode};

/// Conversations kept at once. The oldest session id goes first.
const MAX_CONVERSATIONS: usize = 256;

/// What a private conversation keeps between turns.
#[derive(Clone)]
pub(crate) struct Conversation {
    /// The gated messages, system prompt first, bounded like the store window.
    pub(crate) messages: Vec<SafeMessage>,
    pub(crate) taint: Taint,
    pub(crate) carries_private_data: bool,
}

type Table = BTreeMap<(PathBuf, i64), Conversation>;

fn table() -> MutexGuard<'static, Table> {
    static TABLE: OnceLock<Mutex<Table>> = OnceLock::new();
    match TABLE.get_or_init(|| Mutex::new(BTreeMap::new())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Whether this conversation's text may reach the store and the event feed in
/// `mode`: chat history (G1) and the chat input and event feed (C7) must both be
/// allowed. In private mode C7 is Disabled, so the feed sees the gated copy.
pub(crate) fn raw_text_allowed(mode: PrivacyMode) -> bool {
    history_allowed(mode) && admit_call(PathId::C7, mode, Destination::LocalDisplay).is_ok()
}

/// Whether the local store may keep this conversation's rows in `mode` (G1).
pub(crate) fn history_allowed(mode: PrivacyMode) -> bool {
    admit_call(PathId::G1, mode, Destination::LocalDisplay).is_ok()
}

/// The conversation kept for `session_id` under `home`, if any.
pub(crate) fn recall(home: &Path, session_id: i64) -> Option<Conversation> {
    table().get(&(home.to_path_buf(), session_id)).cloned()
}

/// Keep `conversation` for `session_id` under `home`, evicting the oldest.
pub(crate) fn remember(home: &Path, session_id: i64, conversation: Conversation) {
    let mut table = table();
    table.insert((home.to_path_buf(), session_id), conversation);
    while table.len() > MAX_CONVERSATIONS {
        let oldest = table.keys().next().cloned();
        match oldest {
            Some(key) => {
                table.remove(&key);
            }
            None => break,
        }
    }
}
