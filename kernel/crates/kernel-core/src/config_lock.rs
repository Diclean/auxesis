//! Inter-process advisory lock for the home configuration files.
//!
//! `config.toml` and `.env` are read-modify-write files: the daemon (API
//! routes, provider settings) and the CLI (`aux secret set`) each read the
//! current contents, change one entry and rewrite the whole file. Two writers
//! that interleave lose the other's change — most visibly, a CLI
//! `aux secret set` running while the daemon saves an API key used to rewrite
//! `.env` from a stale read and erase that key (security review P2).
//!
//! This module is the single serialization point: an exclusive `flock` on
//! `<home>/.config.lock`, an OS primitive the kernel releases on process
//! death, so a crashed writer never wedges the home. The daemon still holds
//! its in-process `config_write` mutex *around* the same critical sections;
//! the file lock extends that mutual exclusion across processes (and across
//! threads, since every caller opens its own descriptor).
//!
//! The wait is bounded ([`CONFIG_LOCK_TIMEOUT`]): a writer that cannot make
//! progress returns a clear error instead of blocking forever behind a stuck
//! process.
//!
//! The lock file goes through the verified-home write gateway
//! ([`SandboxHome`]): created atomically `0600` (`O_CREAT | O_EXCL`),
//! fd-relative and `O_NOFOLLOW`, so a symlink planted at `.config.lock` is
//! refused rather than followed.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::paths::SandboxHome;

/// Lock file that every `config.toml` / `.env` read-modify-write shares.
pub const CONFIG_LOCK_FILE: &str = ".config.lock";

/// How long a writer waits for a contended lock before failing.
pub const CONFIG_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval between non-blocking `flock` attempts.
const RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// Errors opening or acquiring the configuration lock.
#[derive(Debug, thiserror::Error)]
pub enum ConfigLockError {
    /// The verified home could not be opened for the lock file.
    #[error("cannot verify the Auxesis home for the configuration lock {}: {source}", path.display())]
    Home {
        /// Home path (diagnostic only).
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The lock file could not be opened through the verified-home gateway.
    #[error("cannot open the configuration lock {}: {source}", path.display())]
    Open {
        /// Lock file path (diagnostic only).
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The lock is still held by another process after the whole wait budget.
    #[error(
        "the configuration lock {} is still held after {} s — another aux process is writing \
         the configuration; retry in a moment",
        path.display(),
        wait.as_secs()
    )]
    Timeout {
        /// Lock file path.
        path: PathBuf,
        /// Total wait budget that elapsed.
        wait: Duration,
    },
    /// `flock` failed with an unexpected errno.
    #[error("cannot lock {}: {source}", path.display())]
    Flock {
        /// Lock file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Run `f` while holding the inter-process configuration lock for `home`.
///
/// Every read-modify-write of `config.toml` or `.env` goes through here. The
/// closure must be synchronous and must not await: it runs on the caller's
/// thread with the lock held, so daemon callers enter it from
/// `spawn_blocking` (never across an `await`).
pub fn with_config_lock<T>(home: &Path, f: impl FnOnce() -> T) -> Result<T, ConfigLockError> {
    let _guard = ConfigLockGuard::acquire(home, CONFIG_LOCK_TIMEOUT)?;
    Ok(f())
}

/// A held configuration lock; dropping it releases the `flock`.
#[derive(Debug)]
struct ConfigLockGuard {
    file: std::fs::File,
}

impl ConfigLockGuard {
    fn acquire(home: &Path, timeout: Duration) -> Result<Self, ConfigLockError> {
        let path = home.join(CONFIG_LOCK_FILE);
        let handle = SandboxHome::open(home).map_err(|source| ConfigLockError::Home {
            path: home.to_path_buf(),
            source,
        })?;
        // Ensure the lock file exists through the gateway's atomic exclusive
        // create (`O_CREAT | O_EXCL`, `O_NOFOLLOW`, `0600`). A plain
        // `O_CREAT` open of a *missing* file is not race-free on Darwin: two
        // concurrent creators can both see `ENOENT` instead of one creating
        // and the other getting `EEXIST`. `write_new` maps `EEXIST` to
        // `false` and never writes when the file already exists.
        handle
            .write_new(Path::new(CONFIG_LOCK_FILE), b"", 0o600)
            .map_err(|source| ConfigLockError::Open {
                path: path.clone(),
                source,
            })?;
        // The file now exists, so this is a plain open: the append flag is
        // irrelevant to `flock` and the file is never written.
        let file = handle
            .open_append(Path::new(CONFIG_LOCK_FILE), 0o600)
            .map_err(|source| ConfigLockError::Open {
                path: path.clone(),
                source,
            })?;

        let start = Instant::now();
        let deadline = start + timeout;
        loop {
            #[cfg(unix)]
            match try_flock(&file) {
                Ok(true) => break,
                Ok(false) => {
                    if Instant::now() >= deadline {
                        return Err(ConfigLockError::Timeout {
                            path: path.clone(),
                            wait: start.elapsed(),
                        });
                    }
                    std::thread::sleep(RETRY_INTERVAL);
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(ConfigLockError::Flock {
                        path: path.clone(),
                        source,
                    })
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (&deadline, &start);
                break;
            }
        }
        Ok(Self { file })
    }
}

/// One non-blocking exclusive `flock` attempt: `true` when acquired.
#[cfg(unix)]
fn try_flock(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    Err(err)
}

impl Drop for ConfigLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // Closing the fd releases the flock; the explicit unlock keeps
            // the intent obvious and ignores errors (the close does it too).
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_times_out_with_a_clear_error_and_is_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        let first = ConfigLockGuard::acquire(home, CONFIG_LOCK_TIMEOUT).unwrap();

        let err = ConfigLockGuard::acquire(home, Duration::from_millis(60)).unwrap_err();
        assert!(
            matches!(err, ConfigLockError::Timeout { .. }),
            "a contended lock must time out, got {err:?}"
        );
        assert!(
            err.to_string().contains(CONFIG_LOCK_FILE),
            "the error must name the lock file: {err}"
        );

        // Dropping the holder releases the kernel lock.
        drop(first);
        let third = ConfigLockGuard::acquire(home, Duration::from_millis(60)).unwrap();
        drop(third);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_acquires_are_serialized() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let home = home.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let guard = ConfigLockGuard::acquire(&home, CONFIG_LOCK_TIMEOUT).unwrap();
                    drop(guard);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _guard = ConfigLockGuard::acquire(dir.path(), CONFIG_LOCK_TIMEOUT).unwrap();
        let mode = std::fs::metadata(dir.path().join(CONFIG_LOCK_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the lock file must be 0600");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_lock_file_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"not a lock").unwrap();
        std::os::unix::fs::symlink(&victim, home.join(CONFIG_LOCK_FILE)).unwrap();

        let err = with_config_lock(home, || ()).unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "a symlinked lock must be refused with an error"
        );
        // The victim was never opened or truncated by the lock path.
        assert_eq!(std::fs::read(&victim).unwrap(), b"not a lock");
    }
}
