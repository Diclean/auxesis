//! Kill-switch gates: a cheap predicate the engine checks between steps.
//!
//! The marker itself belongs to `kernel_core::killswitch`; this module only
//! adapts it to an injectable [`StopCheck`] so the chat loop never depends on
//! a global path and tests control the gate directly.

use std::path::PathBuf;

/// Consulted between steps of a run.
///
/// When a check reads engaged, the run aborts at the next step boundary: no
/// further provider call, no further tool call, no notification.
pub trait StopCheck: Send + Sync {
    /// True when the kill switch is engaged.
    fn is_stopped(&self) -> bool;
}

impl<T: StopCheck + ?Sized> StopCheck for std::sync::Arc<T> {
    fn is_stopped(&self) -> bool {
        (**self).is_stopped()
    }
}

/// A [`StopCheck`] backed by the `<home>/STOP` marker.
#[derive(Debug, Clone)]
pub struct MarkerStop {
    home: PathBuf,
}

impl MarkerStop {
    /// Check the marker at `home`.
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    /// The home whose `STOP` marker this gate reads.
    pub fn home(&self) -> &std::path::Path {
        &self.home
    }
}

impl StopCheck for MarkerStop {
    fn is_stopped(&self) -> bool {
        marker_engaged(&self.home)
    }
}

/// The kill switch, failing safe: engaged when the kernel reads it engaged
/// or when the marker path cannot be read for any reason other than "absent"
/// (EACCES, EIO, ...). The kernel's own path fallback reads such an error as
/// off; this never does.
pub fn marker_engaged(home: &std::path::Path) -> bool {
    kernel_core::killswitch::is_stopped(home)
        || match std::fs::symlink_metadata(kernel_core::killswitch::stop_path(home)) {
            Ok(_) => true,
            Err(err) => err.kind() != std::io::ErrorKind::NotFound,
        }
}

/// A [`StopCheck`] that engages when the privacy mode is no longer the one a run
/// started under, in either direction, at any step. A run that starts in private
/// keeps going: only a change stops it.
#[derive(Clone)]
pub struct ModeChangeStop {
    started: kernel_core::privacy::PrivacyMode,
    live: kernel_core::privacy::ModeFn,
}

impl ModeChangeStop {
    /// Stop when `live` stops returning `started`.
    pub fn new(
        started: kernel_core::privacy::PrivacyMode,
        live: kernel_core::privacy::ModeFn,
    ) -> Self {
        Self { started, live }
    }
}

impl StopCheck for ModeChangeStop {
    fn is_stopped(&self) -> bool {
        (self.live)() != self.started
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn marker_stop_tracks_engage_and_release() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let stop = MarkerStop::new(&home);

        assert!(!stop.is_stopped());
        kernel_core::killswitch::engage(&home).unwrap();
        assert!(stop.is_stopped());
        kernel_core::killswitch::release(&home).unwrap();
        assert!(!stop.is_stopped());
        assert_eq!(stop.home(), home);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_marker_path_reads_engaged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        assert!(!marker_engaged(&home));
        // A home whose entries cannot be looked up (EACCES): never "off".
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::symlink_metadata(home.join("STOP"))
            .err()
            .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound);
        let engaged = marker_engaged(&home);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root bypasses the mode bits; the check is only meaningful otherwise.
        if !readable {
            assert!(engaged, "a read error must read as engaged");
        }
    }

    #[test]
    fn arc_stop_check_delegates() {
        use std::sync::Arc;
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let stop: Arc<dyn StopCheck> = Arc::new(MarkerStop::new(&home));
        assert!(!stop.is_stopped());
        kernel_core::killswitch::engage(&home).unwrap();
        assert!(stop.is_stopped());
    }
}
