//! Single-instance lock for `auxd`.
//!
//! A daemon holds a non-blocking `flock` on `<home>/auxd.lock` for its whole
//! lifetime. A second daemon pointed at the same home exits with a clear
//! error instead of sharing the scheduler (which would double-run jobs and
//! fight over leases).
//!
//! `flock` is released by the kernel when the process exits, so a lock file
//! left behind by a crashed process is stale by construction: the next
//! daemon acquires it and overwrites the recorded pid. The file itself is
//! 0600 and only ever contains a pid.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors returned when acquiring the daemon lock.
#[derive(Debug, Error)]
pub enum LockError {
    /// The lock file could not be created or opened.
    #[error("cannot open lock file {}: {source}", path.display())]
    Open {
        /// Lock file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Another live daemon already holds the lock.
    #[error("another auxd{} is already running on this home (lock {})", held_pid_suffix(.pid), path.display())]
    Held {
        /// Lock file path.
        path: PathBuf,
        /// Pid recorded in the lock file; `None` when the winner has not
        /// written it yet (startup race) or the file is unreadable.
        pid: Option<u32>,
    },
    /// `flock` itself failed with an unexpected errno.
    #[error("cannot lock {}: {message}", path.display())]
    Flock {
        /// Lock file path.
        path: PathBuf,
        /// Human-readable error.
        message: String,
    },
}

/// A held daemon lock; releasing it is dropping the value (or process exit).
#[derive(Debug)]
pub struct InstanceLock {
    file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// Acquire the lock at `path` without blocking.
    ///
    /// A stale file from a dead process is not an obstacle: `flock` only
    /// conflicts with a live holder.
    pub fn acquire(path: &Path) -> Result<Self, LockError> {
        // The flock instance lock; the lock is an OS primitive and must be path-based.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Never truncate before the lock is held: the current holder's
            // pid must survive so the refusal can name it.
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|source| LockError::Open {
                path: path.to_path_buf(),
                source,
            })?;

        // Non-blocking exclusive lock: the kernel releases it on process
        // death, so there is no stale-lock pid logic to get wrong.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(LockError::Held {
                    path: path.to_path_buf(),
                    pid: read_pid(&mut file),
                });
            }
            return Err(LockError::Flock {
                path: path.to_path_buf(),
                message: error.to_string(),
            });
        }

        // Record our pid for diagnostics; the lock is what enforces
        // exclusivity, never this content.
        let pid = std::process::id();
        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = writeln!(file, "{pid}");
        let _ = file.flush();

        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    /// Path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Closing the file releases the flock; explicit unlock keeps the
        // intent obvious and ignores errors (the drop does it anyway).
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Read the pid recorded in a lock file, or `None` when it is unreadable or
/// the holder has not written it yet (the startup race must never be
/// reported as `pid 0`).
fn read_pid(file: &mut File) -> Option<u32> {
    let mut raw = String::new();
    if file.seek(SeekFrom::Start(0)).is_err() || file.read_to_string(&mut raw).is_err() {
        return None;
    }
    raw.trim().parse().ok()
}

/// `" (pid N)"` when the holder's pid is known, `""` otherwise.
fn held_pid_suffix(pid: &Option<u32>) -> String {
    match pid {
        Some(pid) => format!(" (pid {pid})"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn second_acquisition_is_refused_and_release_frees_the_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("auxd.lock");

        let first = InstanceLock::acquire(&path).unwrap();
        assert_eq!(first.path(), path.as_path());

        let second = InstanceLock::acquire(&path).unwrap_err();
        match second {
            LockError::Held { pid, .. } => {
                assert_eq!(pid, Some(std::process::id()), "our own pid is recorded");
            }
            other => panic!("expected LockError::Held, got {other:?}"),
        }

        // Released on drop: the next daemon can take over.
        drop(first);
        let third = InstanceLock::acquire(&path).unwrap();
        drop(third);
    }

    #[test]
    fn a_held_lock_without_a_recorded_pid_never_says_pid_0() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("auxd.lock");
        let first = InstanceLock::acquire(&path).unwrap();

        // Model the startup race: the winner holds the flock but has not
        // written its pid yet.
        let empty = OpenOptions::new().write(true).open(&path).unwrap();
        empty.set_len(0).unwrap();

        let err = InstanceLock::acquire(&path).unwrap_err();
        match err {
            LockError::Held { pid, .. } => assert_eq!(pid, None, "nothing was recorded yet"),
            other => panic!("expected LockError::Held, got {other:?}"),
        }
        let message = err.to_string();
        assert!(!message.contains("pid 0"), "{message}");
        assert!(
            message.contains("another auxd is already running"),
            "{message}"
        );

        // Once the winner records its pid, the refusal names it.
        drop(first);
        let second = InstanceLock::acquire(&path).unwrap();
        let err = InstanceLock::acquire(&path).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(&format!("(pid {})", std::process::id())),
            "{message}"
        );
        drop(second);
    }

    #[test]
    fn stale_lock_file_from_a_dead_pid_is_acquirable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("auxd.lock");
        // A crashed process left the file behind; there is no live flock.
        std::fs::write(&path, "999999\n").unwrap();

        let lock = InstanceLock::acquire(&path).unwrap();

        // The stale pid was replaced by ours.
        let recorded: u32 = std::fs::read_to_string(lock.path())
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(recorded, std::process::id());
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("auxd.lock");

        let _lock = InstanceLock::acquire(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "lock file must be 0600");
    }
}
