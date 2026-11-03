//! `RLIMIT_CORE=0` for private mode. A core dump is a copy of process memory,
//! so it must never hold private values. Wave 1b calls
//! [`disable_core_dumps`] once, at daemon start.

/// Sets the core-dump limit, soft and hard, to zero.
///
/// The hard limit cannot be raised again by an unprivileged process, so this
/// is a one-way change for the process that calls it.
#[cfg(unix)]
pub fn disable_core_dumps() -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is an initialised `rlimit` that lives for the whole call.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Whether both core-dump limits are zero.
#[cfg(unix)]
pub fn core_dumps_disabled() -> std::io::Result<bool> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` that lives for the whole call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(limit.rlim_cur == 0 && limit.rlim_max == 0)
}

/// Core dumps cannot be turned off on this platform.
#[cfg(not(unix))]
pub fn disable_core_dumps() -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Core dumps cannot be inspected on this platform.
#[cfg(not(unix))]
pub fn core_dumps_disabled() -> std::io::Result<bool> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const CHILD_ENV: &str = "AUX_CORE_DUMPS_TEST_CHILD";

    #[test]
    fn core_dumps_are_disabled_in_a_child_process() {
        if std::env::var_os(CHILD_ENV).is_none() {
            // Lowering the hard limit is one-way, so run the check in a fresh
            // copy of this test binary and leave the test runner alone.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "privacy::core_dumps::tests::core_dumps_are_disabled_in_a_child_process",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .status()
                .expect("spawn the test binary as a child");
            assert!(status.success(), "child exited with {status}");
            return;
        }
        disable_core_dumps().expect("setrlimit(RLIMIT_CORE, 0)");
        assert!(core_dumps_disabled().expect("getrlimit(RLIMIT_CORE)"));
    }
}
