//! In-memory notifier for tests and offline development.

use crate::{Notification, Notifier, NotifyError};
use std::sync::Mutex;

/// Records every notification it is asked to deliver.
///
/// By default delivery succeeds; [`FakeNotifier::failing`] returns an
/// osascript-style error instead (while still recording the attempt), so
/// error paths can be exercised without a real notification.
#[derive(Debug, Default)]
pub struct FakeNotifier {
    sent: Mutex<Vec<Notification>>,
    failure: Option<String>,
}

impl FakeNotifier {
    /// A fake that always succeeds.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fake that records the attempt then fails with `stderr`.
    pub fn failing(stderr: impl Into<String>) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            failure: Some(stderr.into()),
        }
    }

    /// Snapshot of everything passed to [`Notifier::notify`], in order.
    pub fn sent(&self) -> Vec<Notification> {
        self.sent.lock().expect("fake notifier lock").clone()
    }

    /// The most recent notification, if any.
    pub fn last(&self) -> Option<Notification> {
        self.sent
            .lock()
            .expect("fake notifier lock")
            .last()
            .cloned()
    }

    /// How many notifications were passed to `notify` (successful or not).
    pub fn count(&self) -> usize {
        self.sent.lock().expect("fake notifier lock").len()
    }

    /// Forget everything recorded so far.
    pub fn clear(&self) {
        self.sent.lock().expect("fake notifier lock").clear();
    }
}

impl Notifier for FakeNotifier {
    fn notify(&self, notification: &Notification) -> Result<(), NotifyError> {
        self.sent
            .lock()
            .expect("fake notifier lock")
            .push(notification.clone());
        match &self.failure {
            Some(stderr) => Err(NotifyError::Osascript {
                status: "1".to_string(),
                stderr: stderr.clone(),
            }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_succeeds_by_default() {
        let fake = FakeNotifier::new();
        let notification = Notification::new("Build", "done");
        assert!(fake.notify(&notification).is_ok());
        assert_eq!(fake.count(), 1);
        assert_eq!(fake.last(), Some(notification.clone()));
        assert_eq!(fake.sent(), vec![notification]);
    }

    #[test]
    fn failing_records_the_attempt_then_errors() {
        let fake = FakeNotifier::failing("script editor not allowed");
        let err = fake
            .notify(&Notification::new("Build", "failed"))
            .unwrap_err();
        assert!(matches!(
            err,
            NotifyError::Osascript { ref status, ref stderr }
                if status == "1" && stderr == "script editor not allowed"
        ));
        assert_eq!(fake.count(), 1);
        fake.clear();
        assert_eq!(fake.count(), 0);
        assert!(fake.last().is_none());
    }
}
