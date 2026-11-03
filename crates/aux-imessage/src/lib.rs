//! `aux-imessage` — the Messages (iMessage) transport for the Auxesis gateway
//! (the Messages contract is `docs/imessage.md`).
//!
//! Three pieces, each behind a trait so the daemon never touches the real
//! `chat.db` or the real Messages app in a test:
//!
//! * [`reader`]: a **read-only** connection to `chat.db`, with the query
//!   locked to the configured owner handle(s) and the pinned chat GUID. Both
//!   are bound parameters; no SQL is ever built from a value. `text` is
//!   preferred, and a NULL `text` falls back to [`attributed`]'s bounded,
//!   panic-free typedstream decoder. Read receipts come from the agent's own
//!   outgoing rows (`is_from_me = 1`, `is_read`, `date_read`).
//! * [`sender`]: the [`sender::Sender`] trait and the production AppleScript
//!   implementation. The text travels through `on run argv`, never
//!   interpolated into the script, and a send to the agent's own handle or to
//!   anyone but the pinned owner is refused before `osascript` runs. A send is
//!   never retried.
//! * [`pacing`]: an injectable clock and the 15 s rule (wait after the owner's
//!   last inbound; keep 15 s between sends) that stops the owner's iPhone from
//!   jumping threads.
//!
//! [`config`] reads the `[imessage]` section of `gateways.toml`; it is
//! disabled by default and any invalid enabled section disables it.

pub mod attributed;
pub mod config;
pub mod cursor;
pub mod pacing;
pub mod reader;
pub mod sender;

pub use attributed::{decode_attributed_body, AttributedError};
pub use config::{GatewaysConfig, ImessageConfig, Mode};
pub use cursor::{CursorError, CursorStore};
pub use pacing::{Clock, Pacer, PacingError, SystemClock};
pub use reader::{
    ChatDbReader, ChatSpec, InboundBatch, InboundMessage, InboundSource, ReadReceipt, ReaderError,
};
pub use sender::{
    AppleScriptSender, CommandOutput, CommandRunner, ProcessRunner, SendError, Sender,
};
