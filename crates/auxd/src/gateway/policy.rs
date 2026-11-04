//! The pure notify policy: levels, batching, quiet hours and the daily cap
//! (D34, G1).
//!
//! Nothing here reads the clock or touches I/O: the caller passes `now` as
//! seconds since the Unix epoch, so every rule is deterministic and testable.

/// Most messages a day may carry, unless a real emergency adds one.
pub const DEFAULT_DAILY_CAP: u32 = 20;
/// The dropped-notice ledger is bounded; a flood cannot grow it without limit.
pub const MAX_DROPPED: usize = 64;
/// A batch is bounded even during quiet hours or a sustained notification flood.
pub const MAX_BATCHED: usize = 256;
/// Maximum retained bytes for one notice.
pub const MAX_NOTICE_BYTES: usize = 4096;

use serde::{Deserialize, Serialize};

use super::truncate_utf8;

/// How urgent a notice is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    /// Goes in the brief.
    Info,
    /// Batched, at most one message per window.
    Normal,
    /// Delivered immediately, quiet hours and daily cap included.
    Urgent,
}

/// One message offered to the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// The notice level.
    pub level: Level,
    /// The message text; never logged here.
    pub text: String,
}

impl Notice {
    /// A notice of `level` carrying `text`.
    pub fn new(level: Level, text: impl Into<String>) -> Self {
        Self {
            level,
            text: text.into(),
        }
    }
}

/// The tunables, all explicit so tests are deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Info/normal notices inside one window leave as a single message.
    pub window_secs: i64,
    /// Quiet hours start, in local hours (0-23); urgent passes.
    pub quiet_start_hour: u8,
    /// Quiet hours end, in local hours (0-23).
    pub quiet_end_hour: u8,
    /// Most messages per day; urgent counts but is never dropped.
    pub daily_cap: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            window_secs: 30 * 60,
            quiet_start_hour: 22,
            quiet_end_hour: 7,
            daily_cap: DEFAULT_DAILY_CAP,
        }
    }
}

/// What the caller may do with an offered notice right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Deliver immediately (urgent).
    SendNow,
    /// Held for the current batch window; `flush` combines them.
    Batched,
    /// Held by quiet hours; it leaves when quiet ends.
    Quiet,
}

/// The policy's accumulated state, one per channel.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PolicyState {
    window_start: Option<i64>,
    batched: Vec<Notice>,
    day: i64,
    sent_today: u32,
    dropped: Vec<Notice>,
}

impl PolicyState {
    /// A state that already spent the day's cap: info/normal are held until
    /// the next day; urgent still passes. Used when the persisted state cannot
    /// be read, so a corrupt file fails closed.
    pub(crate) fn cap_reached(now: i64, cap: u32) -> Self {
        Self {
            day: now.div_euclid(86_400),
            sent_today: cap,
            ..Self::default()
        }
    }
}

/// The notify policy. Stateless itself; the state lives in [`PolicyState`].
#[derive(Debug, Clone, Copy)]
pub struct NotifyPolicy {
    config: PolicyConfig,
}

impl NotifyPolicy {
    /// A policy with `config`.
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// The tunables.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Offer one notice. The returned [`Action`] says what may happen now;
    /// held and dropped notices stay in `state`.
    pub fn offer(&self, state: &mut PolicyState, now: i64, notice: Notice) -> Action {
        roll_day(state, now);
        if notice.level == Level::Urgent {
            state.sent_today = state.sent_today.saturating_add(1);
            return Action::SendNow;
        }
        if self.is_quiet(now) {
            hold(state, now, notice);
            return Action::Quiet;
        }
        hold(state, now, notice);
        Action::Batched
    }

    /// Emit the pending batch as one message once the window elapsed and it is
    /// not quiet. Returns `None` while holding.
    pub fn flush(&self, state: &mut PolicyState, now: i64) -> Option<Notice> {
        if state.batched.is_empty() {
            return None;
        }
        if self.is_quiet(now) {
            return None;
        }
        let start = state.window_start.unwrap_or(now);
        if now - start < self.config.window_secs {
            return None;
        }
        let level = state
            .batched
            .iter()
            .map(|notice| notice.level)
            .max()
            .unwrap_or(Level::Info);
        let text = state
            .batched
            .iter()
            .map(|notice| notice.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        state.batched.clear();
        state.window_start = None;
        let batch = Notice { level, text };
        if state.sent_today >= self.config.daily_cap {
            if state.dropped.len() < MAX_DROPPED {
                state.dropped.push(batch);
            }
            return None;
        }
        state.sent_today = state.sent_today.saturating_add(1);
        Some(batch)
    }

    /// The notices the daily cap dropped, reported in the next brief. Clears
    /// the ledger.
    pub fn take_dropped(&self, state: &mut PolicyState) -> Vec<Notice> {
        std::mem::take(&mut state.dropped)
    }

    /// Whether `now`'s local hour is inside quiet hours.
    pub fn is_quiet(&self, now: i64) -> bool {
        let hour = now.div_euclid(3600).rem_euclid(24) as u8;
        let start = self.config.quiet_start_hour % 24;
        let end = self.config.quiet_end_hour % 24;
        if start == end {
            return false;
        }
        if start < end {
            hour >= start && hour < end
        } else {
            hour >= start || hour < end
        }
    }
}

fn hold(state: &mut PolicyState, now: i64, notice: Notice) {
    let notice = Notice {
        level: notice.level,
        text: truncate_utf8(&notice.text, MAX_NOTICE_BYTES),
    };
    if state.batched.len() >= MAX_BATCHED {
        if state.dropped.len() < MAX_DROPPED {
            state.dropped.push(notice);
        }
        return;
    }
    if state.batched.is_empty() {
        state.window_start = Some(now);
    }
    state.batched.push(notice);
}

fn roll_day(state: &mut PolicyState, now: i64) {
    let day = now.div_euclid(86_400);
    if day != state.day {
        state.day = day;
        state.sent_today = 0;
    }
}
