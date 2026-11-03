//! WF-1 round 8 P3: pin metadata must not grow with the number of live
//! drafts. Process-isolated so the RSS measurement is not polluted by other
//! tests' allocations.

use std::path::PathBuf;

use auxd::api::{DeltaStream, StreamSinks};
use tokio::sync::broadcast;

/// Current resident set size of this process, in bytes.
fn rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        // SAFETY: `info` is a valid, correctly sized buffer.
        let written = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        assert!(written > 0, "proc_pidinfo failed");
        info.pti_resident_size
    }
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").expect("statm");
        let pages: u64 = statm
            .split_whitespace()
            .nth(1)
            .expect("rss field")
            .parse()
            .expect("pages");
        pages * 4096
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `usage` is a valid pointer for the duration of the call.
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        usage.ru_maxrss as u64
    }
}

/// R8 P3: 2,000 empty live streams pinned to 128 values must not add
/// per-value pin metadata per stream. The pin table is two `u64`s per live
/// stream, shared in the registry.
#[test]
fn pin_metadata_does_not_grow_with_stream_count() {
    for index in 0..kernel_broker::scrub::MAX_KNOWN_SECRETS {
        kernel_broker::scrub::register_known_secret(&format!(
            "CANARY_KS_PINMEM_{index:04}_7f3a9c2e1b5d"
        ));
    }
    let before = rss_bytes();
    let mut streams = Vec::with_capacity(2000);
    for _ in 0..2000 {
        let (sender, receiver) = broadcast::channel(4);
        streams.push(DeltaStream::new(
            StreamSinks::loopback(sender),
            PathBuf::from("/Users/secret/.auxesis"),
            "main",
            3,
            "draft-3-1",
        ));
        drop(receiver);
    }
    let after = rss_bytes();
    let growth = after.saturating_sub(before);
    // The shared pin table adds two `u64`s per live stream; the per-value
    // BTreeSet model this replaced grew ~7 MiB for this loop (R8 bite proof).
    assert!(
        growth < 4 * 1024 * 1024,
        "pin metadata grew {growth} bytes for 2000 live streams"
    );
    drop(streams);
}
