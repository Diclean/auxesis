//! The outbound pacing gate (G2).
//!
//! Live testing showed the owner's iPhone jumps threads when replies arrive too
//! fast, so a send is allowed only when **both** hold:
//!
//! * at least `min_gap` seconds have passed since the owner's last inbound
//!   message, and
//! * at least `min_gap` seconds have passed since the previous send.
//!
//! The clock is injected ([`Clock`]), so the rule is tested deterministically.
//! A refused send is refused — the caller never retries it.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The time source, in whole seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_secs(&self) -> i64;
}

/// The production clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs() as i64,
            Err(_) => 0,
        }
    }
}

/// Why a send is not allowed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacingError {
    /// The next allowed second; the caller must not retry before it.
    #[error("the iMessage pacing gate is closed for {wait_secs}s")]
    TooSoon {
        /// Whole seconds still to wait.
        wait_secs: i64,
    },
}

impl PacingError {
    /// Whole seconds still to wait.
    pub fn wait_secs(self) -> i64 {
        match self {
            Self::TooSoon { wait_secs } => wait_secs,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PaceState {
    last_inbound: Option<i64>,
    last_send: Option<i64>,
}

/// The pacing gate. Cheap to share; all state is behind one mutex.
pub struct Pacer {
    clock: Arc<dyn Clock>,
    min_gap_secs: i64,
    state: Mutex<PaceState>,
}

impl Pacer {
    /// A gate with `min_gap_secs` between events.
    pub fn new(clock: Arc<dyn Clock>, min_gap_secs: i64) -> Self {
        Self {
            clock,
            min_gap_secs,
            state: Mutex::new(PaceState::default()),
        }
    }

    /// The configured gap.
    pub fn min_gap_secs(&self) -> i64 {
        self.min_gap_secs
    }

    /// Record an inbound from the owner observed now.
    pub fn record_inbound_now(&self) {
        self.record_inbound_at(self.clock.now_secs());
    }

    /// Record an inbound from the owner at `at`.
    pub fn record_inbound_at(&self, at: i64) {
        let mut state = self.lock();
        state.last_inbound = Some(state.last_inbound.map_or(at, |previous| previous.max(at)));
    }

    /// Try to claim the send slot at the current clock time.
    pub fn try_acquire(&self) -> Result<(), PacingError> {
        self.try_acquire_at(self.clock.now_secs())
    }

    /// Try to claim the send slot at `now`. On success the slot is consumed.
    pub fn try_acquire_at(&self, now: i64) -> Result<(), PacingError> {
        let mut state = self.lock();
        let after_inbound = state
            .last_inbound
            .map(|last| last.saturating_add(self.min_gap_secs));
        let after_send = state
            .last_send
            .map(|last| last.saturating_add(self.min_gap_secs));
        let ready_at = match (after_inbound, after_send) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        if let Some(ready_at) = ready_at {
            if now < ready_at {
                return Err(PacingError::TooSoon {
                    wait_secs: ready_at - now,
                });
            }
        }
        state.last_send = Some(now);
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PaceState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct FakeClock(AtomicI64);

    impl FakeClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }
        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl Clock for FakeClock {
        fn now_secs(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn pacer(now: i64) -> (Arc<FakeClock>, Pacer) {
        let clock = Arc::new(FakeClock::new(now));
        let pacer = Pacer::new(clock.clone(), 15);
        (clock, pacer)
    }

    #[test]
    fn the_first_send_is_allowed() {
        let (_, pacer) = pacer(1_000);
        pacer.try_acquire().unwrap();
    }

    #[test]
    fn two_sends_keep_fifteen_seconds_apart() {
        let (clock, pacer) = pacer(1_000);
        pacer.try_acquire().unwrap();
        clock.set(1_010);
        assert_eq!(
            pacer.try_acquire(),
            Err(PacingError::TooSoon { wait_secs: 5 })
        );
        clock.set(1_015);
        pacer.try_acquire().unwrap();
        clock.set(1_020);
        assert_eq!(
            pacer.try_acquire(),
            Err(PacingError::TooSoon { wait_secs: 10 })
        );
        clock.set(1_030);
        pacer.try_acquire().unwrap();
    }

    #[test]
    fn a_reply_waits_fifteen_seconds_after_the_owners_last_inbound() {
        let (clock, pacer) = pacer(2_000);
        pacer.record_inbound_at(2_000);
        clock.set(2_014);
        assert_eq!(
            pacer.try_acquire(),
            Err(PacingError::TooSoon { wait_secs: 1 })
        );
        clock.set(2_015);
        pacer.try_acquire().unwrap();
    }

    #[test]
    fn a_later_inbound_reopens_the_wait() {
        let (clock, pacer) = pacer(3_000);
        pacer.record_inbound_at(3_000);
        clock.set(3_015);
        pacer.try_acquire().unwrap();
        // The owner writes again; the next reply waits a full gap.
        clock.set(3_016);
        pacer.record_inbound_now();
        clock.set(3_026);
        assert_eq!(
            pacer.try_acquire(),
            Err(PacingError::TooSoon { wait_secs: 5 })
        );
        clock.set(3_031);
        pacer.try_acquire().unwrap();
    }

    #[test]
    fn an_earlier_inbound_does_not_move_the_wait_backwards() {
        let pacer = Pacer::new(Arc::new(SystemClock), 15);
        pacer.record_inbound_at(5_000);
        pacer.record_inbound_at(4_000);
        // The later inbound still governs: 5_000 + 15.
        assert_eq!(
            pacer.try_acquire_at(4_014),
            Err(PacingError::TooSoon { wait_secs: 1001 })
        );
        pacer.try_acquire_at(5_015).unwrap();
    }
}
