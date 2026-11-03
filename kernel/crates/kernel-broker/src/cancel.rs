//! Cooperative cancellation token for one turn (E-18).
//!
//! The token lives in `kernel-broker` (not the engine) so tool implementations
//! can observe it through [`ToolCtx::cancel`](crate::ToolCtx): the engine
//! fires it on client disconnect or the configured turn timeout, and a
//! long-running tool can then run its own cleanup (the `shell` tool kills
//! its whole process tree) instead of relying only on being dropped.
//!
//! Cancelling never rolls back persisted state — the WS-C write-ahead taint
//! marks written before an untrusted dispatch must survive exactly as they do
//! for a crash or a timeout.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

/// A one-way cancellation signal shared between the route and one turn.
#[derive(Debug, Default)]
pub struct CancelToken {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancelToken {
    /// Create a fresh token.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Cancel the turn. Idempotent; wakes every waiter.
    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    /// True once [`Self::cancel`] has run.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Resolve when the token is cancelled (immediately when it already is).
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Register before the second check so a cancel between the check and
        // the first poll can never be missed.
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancel_wakes_a_waiter_and_sticks() {
        let cancel = CancelToken::new();
        assert!(!cancel.is_cancelled());
        let waiter = {
            let cancel = Arc::clone(&cancel);
            tokio::spawn(async move { cancel.cancelled().await })
        };
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("the waiter must wake")
            .unwrap();
        assert!(cancel.is_cancelled());
        // Waiting on an already-cancelled token returns immediately.
        tokio::time::timeout(std::time::Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("cancelled() must not block");
        // cancel() is idempotent.
        cancel.cancel();
    }
}
