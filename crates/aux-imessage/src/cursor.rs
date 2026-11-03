//! The persisted ROWID cursor (G2).
//!
//! One small JSON file under the verified home, mode 0600, written through the
//! [`SandboxHome`] gateway. A missing file is a fresh install (`None`, and the
//! caller starts at the current max ROWID so it never replays history); a file
//! that cannot be read or parsed is an error, so the caller stops polling
//! rather than silently re-reading or skipping.

use std::path::PathBuf;

use kernel_core::SandboxHome;
use serde::{Deserialize, Serialize};

/// Why the cursor could not be read or written. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CursorError {
    /// The file did not parse.
    #[error("the iMessage cursor file is corrupt")]
    Corrupt,
    /// The file could not be read or written.
    #[error("the iMessage cursor file is unreadable")]
    Io,
}

#[derive(Debug, Serialize, Deserialize)]
struct CursorFile {
    last_rowid: i64,
}

/// A cursor file under the verified home.
#[derive(Debug, Clone)]
pub struct CursorStore {
    home: SandboxHome,
    relative: PathBuf,
}

impl CursorStore {
    /// A store for `relative` under `home`. The file name is a plain relative
    /// name; the gateway refuses traversal and the config refuses anything
    /// that is not one normal component.
    pub fn new(home: SandboxHome, relative: impl Into<PathBuf>) -> Self {
        Self {
            home,
            relative: relative.into(),
        }
    }

    /// The absolute file this store reads and writes.
    pub fn path(&self) -> PathBuf {
        self.home.path().join(&self.relative)
    }

    /// The persisted ROWID, or `None` when the file does not exist yet.
    pub fn load(&self) -> Result<Option<i64>, CursorError> {
        let bytes = match std::fs::read(self.path()) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CursorError::Io),
        };
        let file: CursorFile = serde_json::from_slice(&bytes).map_err(|_| CursorError::Corrupt)?;
        if file.last_rowid < 0 {
            return Err(CursorError::Corrupt);
        }
        Ok(Some(file.last_rowid))
    }

    /// Persist `last_rowid` through the sandbox home gateway, mode 0600.
    pub fn save(&self, last_rowid: i64) -> Result<(), CursorError> {
        if last_rowid < 0 {
            return Err(CursorError::Corrupt);
        }
        let raw = serde_json::to_vec(&CursorFile { last_rowid }).map_err(|_| CursorError::Io)?;
        self.home
            .write_atomic(&self.relative, &raw, 0o600)
            .map_err(|_| CursorError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &std::path::Path) -> CursorStore {
        CursorStore::new(SandboxHome::open(dir).expect("sandbox home"), "cursor.json")
    }

    #[test]
    fn a_missing_file_is_a_fresh_install() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(store(dir.path()).load(), Ok(None));
    }

    #[test]
    fn a_saved_cursor_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        store.save(4321).unwrap();
        assert_eq!(store.load(), Ok(Some(4321)));
        store.save(9999).unwrap();
        assert_eq!(store.load(), Ok(Some(9999)));
    }

    #[test]
    fn a_corrupt_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        std::fs::write(store.path(), b"{not json").unwrap();
        assert_eq!(
            store.load().unwrap_err().to_string(),
            "the iMessage cursor file is corrupt"
        );
    }

    #[test]
    #[cfg(unix)]
    fn the_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        store.save(1).unwrap();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
