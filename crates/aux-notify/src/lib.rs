//! macOS notifications for Auxesis.
//!
//! [`Notifier`] is the contract the engine and scheduler program against.
//! [`MacNotifier`] delivers through `osascript display notification` (no
//! extra installs); [`FakeNotifier`] records calls so tests never show a
//! real notification.
//!
//! Titles and bodies are untrusted input (model output, job summaries,
//! provider errors): [`MacNotifier`] runs them through
//! [`kernel_broker::sanitize_text`], encodes them as AppleScript string literals,
//! and writes the source to `osascript`'s **stdin** (executed at the fixed
//! absolute path `/usr/bin/osascript`, with a cleared environment), so
//! quotes and backslashes cannot inject AppleScript and no notification
//! text — one-time trust codes included — ever reaches `argv` or the process
//! table.
//!
//! [`StopSwitchNotifier`] wraps any notifier with the `STOP` kill-switch
//! marker contract (Slice B): while the marker exists, delivery is refused
//! with [`NotifyError::Stopped`] and the inner notifier is untouched.
//!
//! ```
//! use aux_notify::{FakeNotifier, Notification, Notifier};
//!
//! let notifier = FakeNotifier::new();
//! notifier.notify(&Notification::new("Build", "done")).unwrap();
//! assert_eq!(notifier.last().unwrap().title, "Build");
//! ```

// The test seam can only exist in a debug build. A release build that enables
// `test-notify` (for example `--release --features auxd/test-notify`) fails
// here instead of compiling a sandbox bypass.
#[cfg(all(feature = "test-notify", not(debug_assertions)))]
compile_error!("aux-notify's test-notify seam is debug-only: release builds must not enable it");

mod error;
mod fake;
mod mac;
mod notification;
mod stop;

pub use error::NotifyError;
pub use fake::FakeNotifier;
pub use mac::MacNotifier;
pub use notification::Notification;
pub use stop::StopSwitchNotifier;

use mac::OSASCRIPT_PATH;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Transport for user-visible notifications.
///
/// Implementations are `Send + Sync` so the daemon can share one behind an
/// `Arc`. [`Notifier::notify`] takes `&self`; implementations that record
/// calls use interior mutability (see [`FakeNotifier`]).
pub trait Notifier: Send + Sync {
    /// Deliver `notification`, or explain why it could not be delivered.
    ///
    /// Callers may treat [`NotifyError::Stopped`] as a benign no-op: the
    /// kill switch is engaged, so nothing was sent and nothing failed.
    fn notify(&self, notification: &Notification) -> Result<(), NotifyError>;
}

impl<T: Notifier + ?Sized> Notifier for &T {
    fn notify(&self, notification: &Notification) -> Result<(), NotifyError> {
        (**self).notify(notification)
    }
}

impl<T: Notifier + ?Sized> Notifier for Arc<T> {
    fn notify(&self, notification: &Notification) -> Result<(), NotifyError> {
        (**self).notify(notification)
    }
}

/// The notifier every binary delivers through; the one place that decides
/// between a real banner and a sandbox sink.
///
/// `sandboxed` is `kernel_core::sandbox_guard_active()` at the call site, so
/// this crate never reads the sandbox guard itself. While it is set,
/// notifications are recorded in memory by a [`FakeNotifier`] and
/// [`MacNotifier`] (and so `osascript`) is not reached, unless the
/// non-default `test-notify` seam is active (see [`transport`]). When the seam
/// is active, the program is the stand-in and nothing else.
pub fn system_notifier(sandboxed: bool) -> Arc<dyn Notifier> {
    // Read once, here: the program that runs is the one the selector saw.
    let stand_in = test_seam_stand_in();
    match transport(sandboxed, stand_in.is_some()) {
        Transport::Sink => Arc::new(FakeNotifier::new()),
        Transport::Mac => Arc::new(MacNotifier::with_program(
            stand_in.unwrap_or_else(|| PathBuf::from(OSASCRIPT_PATH)),
        )),
    }
}

/// Which delivery path [`system_notifier`] builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// Records in memory; never spawns a process.
    Sink,
    /// The real `osascript` transport.
    Mac,
}

/// The sandbox decision. The sink is used in a sandbox, except when the test
/// seam redirects `osascript` to a stand-in, so the daemon's shutdown tests
/// can still observe a real child process. Production builds never enable the
/// seam, so a sandboxed production run always records.
fn transport(sandboxed: bool, test_seam: bool) -> Transport {
    if sandboxed && !test_seam {
        Transport::Sink
    } else {
        Transport::Mac
    }
}

/// The stand-in `osascript` that the `test-notify` seam selects, if any.
///
/// Only a build compiled with the feature in debug mode can select one, and
/// the real system binary is never a stand-in. So with the seam active the
/// transport runs the stand-in and nothing else, even in a sandbox.
fn seam_stand_in(compiled: bool, env: Option<OsString>) -> Option<PathBuf> {
    let path = PathBuf::from(env?);
    (compiled && path.as_path() != Path::new(OSASCRIPT_PATH)).then_some(path)
}

/// [`seam_stand_in`] with this build's compile-time gate and the environment.
fn test_seam_stand_in() -> Option<PathBuf> {
    seam_stand_in(
        cfg!(all(feature = "test-notify", debug_assertions)),
        std::env::var_os("AUXESIS_NOTIFY_OSASCRIPT"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sandbox_records_unless_the_test_seam_is_active() {
        assert_eq!(transport(true, false), Transport::Sink);
        assert_eq!(transport(true, true), Transport::Mac);
        assert_eq!(transport(false, false), Transport::Mac);
        assert_eq!(transport(false, true), Transport::Mac);
    }

    #[test]
    fn the_seam_selects_a_stand_in_and_never_the_system_osascript() {
        assert_eq!(
            seam_stand_in(true, Some(OsString::from("/tmp/stand-in"))),
            Some(PathBuf::from("/tmp/stand-in"))
        );
        assert_eq!(
            seam_stand_in(true, Some(OsString::from(OSASCRIPT_PATH))),
            None,
            "the real osascript is never a stand-in"
        );
        assert_eq!(seam_stand_in(true, None), None);
    }

    #[test]
    fn a_build_without_the_feature_or_debug_assertions_ignores_the_seam() {
        assert_eq!(
            seam_stand_in(false, Some(OsString::from("/tmp/stand-in"))),
            None,
            "release and default builds never honour the override"
        );
    }

    #[cfg(not(feature = "test-notify"))]
    #[test]
    fn a_default_build_ignores_the_override_variable() {
        std::env::set_var("AUXESIS_NOTIFY_OSASCRIPT", "/tmp/planted-osascript");
        let stand_in = test_seam_stand_in();
        std::env::remove_var("AUXESIS_NOTIFY_OSASCRIPT");
        assert_eq!(stand_in, None);
    }
}
