//! Kill switch: the `STOP` marker that halts all proactive work.
//!
//! The marker is a plain file at `<home>/STOP`. Its *existence* is the
//! signal — never its contents — so any process can check it cheaply and
//! there is nothing to parse or corrupt. `aux stop` creates it, `aux resume`
//! removes it, and every always-on component (the daemon, scheduled jobs,
//! notifications) is expected to check [`is_stopped`] before each step.
//!
//! Engagement is fail-safe: if *anything* occupies the marker path —
//! including a dangling symlink — the switch reads as engaged. Engaging
//! never follows a symlink (`create_new`), so it cannot be tricked into
//! truncating another file.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Name of the kill-switch marker inside the Auxesis home.
pub const STOP_FILE: &str = "STOP";

/// Path of the kill-switch marker for `home`.
pub fn stop_path(home: &Path) -> PathBuf {
    home.join(STOP_FILE)
}

/// True when the switch is engaged.
///
/// Uses `symlink_metadata` so a dangling symlink at the marker path still
/// counts as engaged (fail safe).
pub fn is_stopped(home: &Path) -> bool {
    // J-02 round 5: read the marker through the verified home handle when
    // this process has one (fail-safe on any error: a home we cannot verify
    // reads as stopped). The path fallback serves library/tests.
    if let Ok(handle) = crate::paths::verified_home_for(home) {
        return handle
            .exists_no_follow(Path::new(STOP_FILE))
            .unwrap_or(true);
    }
    std::fs::symlink_metadata(stop_path(home)).is_ok()
}

/// Engage the kill switch, creating the home directory when needed.
///
/// Idempotent: a marker that already exists (for any reason) is left
/// untouched, and the call succeeds.
pub fn engage(home: &Path) -> std::io::Result<()> {
    // J-02 write gateway: the marker is created relative to the verified
    // home directory fd, never through the home path string.
    // Production uses the process-wide verified home (re-verified on every
    // use); libraries/tests without one open the explicit path.
    let handle = aux_core_verified(home)?;
    let data = format!("stopped at unix {}\n", now_unix());
    handle.write_new(Path::new(STOP_FILE), data.as_bytes(), 0o600)?;
    Ok(())
}

/// The verified home handle for this process, or a fresh one for `home`
/// when the process never ran `ensure_home` (library/tests).
fn aux_core_verified(home: &Path) -> std::io::Result<crate::paths::SandboxHome> {
    crate::paths::verified_home_or_verify(home)
}

/// Release the kill switch.
///
/// Returns `true` when a marker was removed and `false` when the switch was
/// already off. Other errors are reported so a directory squatting on the
/// path is never silently ignored.
pub fn release(home: &Path) -> std::io::Result<bool> {
    // J-02 round 4: fd-relative delete on the verified home handle.
    let handle = match crate::paths::SandboxHome::open_existing(home) {
        Ok(handle) => handle,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    handle.remove_file(Path::new(STOP_FILE))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn engage_and_release_round_trip() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");

        assert!(!is_stopped(&home));
        engage(&home).unwrap();
        assert!(is_stopped(&home));
        assert_eq!(stop_path(&home), home.join("STOP"));
        assert!(stop_path(&home).is_file());

        assert!(release(&home).unwrap());
        assert!(!is_stopped(&home));
        assert!(!stop_path(&home).exists());
    }

    #[test]
    fn engage_is_idempotent_and_never_overwrites() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        engage(&home).unwrap();
        let first = std::fs::read_to_string(stop_path(&home)).unwrap();

        engage(&home).unwrap();
        let second = std::fs::read_to_string(stop_path(&home)).unwrap();
        assert_eq!(first, second);
        assert!(is_stopped(&home));
    }

    #[test]
    fn release_on_a_clean_home_reports_false() {
        let dir = tempdir().unwrap();
        assert!(!release(&dir.path().join("home")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_still_reads_as_stopped() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink(home.join("missing-target"), stop_path(&home)).unwrap();

        assert!(is_stopped(&home), "fail safe: any entry means engaged");
        // Releasing removes the link itself, never the target.
        assert!(release(&home).unwrap());
        assert!(!is_stopped(&home));
    }

    #[test]
    fn engage_creates_the_home_directory() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("nested/home");
        engage(&home).unwrap();
        assert!(home.is_dir());
        assert!(is_stopped(&home));
    }

    #[test]
    fn release_reports_a_directory_in_the_way() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(stop_path(&home)).unwrap();

        assert!(is_stopped(&home));
        assert!(release(&home).is_err(), "a directory cannot be removed");
    }
}
