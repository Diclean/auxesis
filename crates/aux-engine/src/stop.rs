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
        kernel_core::killswitch::is_stopped(&self.home)
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
