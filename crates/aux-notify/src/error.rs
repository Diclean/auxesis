//! Errors a notification transport can return.

use thiserror::Error;

/// Why a notification could not be delivered.
#[derive(Debug, Error)]
pub enum NotifyError {
    /// The platform has no `osascript` (notifications are macOS-only).
    #[error("notifications are not supported on this platform")]
    Unsupported,

    /// `osascript` could not be started (missing binary, permission denied).
    #[error("failed to run osascript: {0}")]
    Spawn(#[source] std::io::Error),

    /// `osascript` ran but exited non-zero; `stderr` is sanitized and capped.
    #[error("osascript failed (status {status}): {stderr}")]
    Osascript {
        /// Exit code as text, or `"signal"` when killed by a signal.
        status: String,
        /// Sanitized stderr, or `"(no stderr)"` when empty.
        stderr: String,
    },

    /// `osascript` did not finish within the hard timeout and was killed.
    #[error("osascript timed out and was killed")]
    Timeout,

    /// The `STOP` kill switch is engaged; nothing is delivered.
    #[error("notification suppressed by the STOP kill switch")]
    Stopped,
}

impl NotifyError {
    /// Map an I/O failure from the osascript runner to the right variant.
    pub(crate) fn from_io(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::Unsupported => Self::Unsupported,
            std::io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Spawn(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_actionable() {
        assert_eq!(
            NotifyError::Unsupported.to_string(),
            "notifications are not supported on this platform"
        );
        assert_eq!(
            NotifyError::Stopped.to_string(),
            "notification suppressed by the STOP kill switch"
        );
        assert_eq!(
            NotifyError::Osascript {
                status: "1".into(),
                stderr: "boom".into(),
            }
            .to_string(),
            "osascript failed (status 1): boom"
        );
        assert!(NotifyError::Spawn(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no osascript"
        ))
        .to_string()
        .starts_with("failed to run osascript:"));
    }

    #[test]
    fn timeout_has_its_own_message() {
        assert_eq!(
            NotifyError::Timeout.to_string(),
            "osascript timed out and was killed"
        );
    }

    #[test]
    fn timed_out_io_kind_becomes_the_timeout_variant() {
        let err = NotifyError::from_io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "osascript did not finish",
        ));
        assert!(matches!(err, NotifyError::Timeout));
    }

    #[test]
    fn spawn_keeps_the_io_error_as_source() {
        let err = NotifyError::Spawn(std::io::Error::new(std::io::ErrorKind::NotFound, "nope"));
        let source = std::error::Error::source(&err).expect("io source");
        assert_eq!(source.to_string(), "nope");
    }

    #[test]
    fn unsupported_io_kind_becomes_the_unsupported_variant() {
        let err = NotifyError::from_io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not macos",
        ));
        assert!(matches!(err, NotifyError::Unsupported));
    }
}
