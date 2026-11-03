//! Kill-switch decorator: refuse delivery while the `STOP` marker exists.
//!
//! Slice B owns `aux stop` / `aux resume` and the marker
//! (`~/.auxesis/STOP`). This wrapper is the notification half of that
//! contract: the marker path is injected, so the daemon can pass the real
//! one while tests use a temp file.
//!
//! Engagement is fail-safe and matches `kernel_core::killswitch`: **any**
//! filesystem entry at the marker path — a file, a directory, or a dangling
//! symlink — reads as stopped.

use crate::{Notification, Notifier, NotifyError};
use std::path::{Path, PathBuf};

/// Blocks a wrapped notifier while `stop_marker` exists on disk.
#[derive(Debug)]
pub struct StopSwitchNotifier<N> {
    inner: N,
    stop_marker: PathBuf,
}

impl<N> StopSwitchNotifier<N> {
    /// Wrap `inner`; delivery is refused while `stop_marker` exists.
    pub fn new(inner: N, stop_marker: impl Into<PathBuf>) -> Self {
        Self {
            inner,
            stop_marker: stop_marker.into(),
        }
    }

    /// Path of the `STOP` marker this notifier checks.
    pub fn stop_marker(&self) -> &Path {
        &self.stop_marker
    }

    /// Whether the kill switch is currently engaged.
    ///
    /// Mirrors `kernel_core::killswitch::is_stopped`: *any* filesystem entry
    /// at the marker path counts, including a dangling symlink, so a
    /// malicious or broken marker can never leave notifications running
    /// while the daemon pauses. `Path::exists()` would follow the link and
    /// read a dangling symlink as "not stopped".
    pub fn is_stopped(&self) -> bool {
        std::fs::symlink_metadata(&self.stop_marker).is_ok()
    }
}

impl<N: Notifier> Notifier for StopSwitchNotifier<N> {
    fn notify(&self, notification: &Notification) -> Result<(), NotifyError> {
        if self.is_stopped() {
            return Err(NotifyError::Stopped);
        }
        self.inner.notify(notification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeNotifier;

    #[test]
    fn delivers_while_the_marker_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeNotifier::new();
        let notifier = StopSwitchNotifier::new(&fake, dir.path().join("STOP"));
        assert!(!notifier.is_stopped());
        notifier.notify(&Notification::new("t", "b")).unwrap();
        assert_eq!(fake.count(), 1);
    }

    #[test]
    fn suppresses_and_leaves_inner_untouched_while_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("STOP");
        std::fs::write(&marker, b"").unwrap();
        let fake = FakeNotifier::new();
        let notifier = StopSwitchNotifier::new(&fake, &marker);
        assert!(notifier.is_stopped());
        let err = notifier.notify(&Notification::new("t", "b")).unwrap_err();
        assert!(matches!(err, NotifyError::Stopped));
        assert_eq!(fake.count(), 0);
        assert_eq!(notifier.stop_marker(), marker);
    }

    /// Regression for the M2 security-review C-01 finding: a dangling `STOP`
    /// symlink must read as engaged, exactly like
    /// `kernel_core::killswitch::is_stopped`.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_counts_as_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("STOP");
        std::os::unix::fs::symlink(dir.path().join("missing-target"), &marker).unwrap();
        let fake = FakeNotifier::new();
        let notifier = StopSwitchNotifier::new(&fake, &marker);

        assert!(notifier.is_stopped(), "any entry at STOP must read stopped");
        let err = notifier.notify(&Notification::new("t", "b")).unwrap_err();
        assert!(matches!(err, NotifyError::Stopped));
        assert_eq!(fake.count(), 0);
    }

    #[test]
    fn resumes_after_the_marker_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("STOP");
        std::fs::write(&marker, b"stop").unwrap();
        let fake = FakeNotifier::new();
        let notifier = StopSwitchNotifier::new(&fake, &marker);
        assert!(notifier.notify(&Notification::new("t", "b")).is_err());
        std::fs::remove_file(&marker).unwrap();
        notifier.notify(&Notification::new("t", "b")).unwrap();
        assert_eq!(fake.count(), 1);
    }
}
