//! Performance budgets, process-isolated from the `auxd` unit tests.
//!
//! The unit-test binary accumulates every test's registered canaries in the
//! process-global known-secret registry, so a 1 MiB scrub there searches an
//! automaton no production stream would have; these probes measure the
//! streaming design itself (one 1 MiB delta, and a 3000-delta run), on a
//! dedicated process.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use auxd::api::{DeltaStream, StreamSinks};
use tokio::sync::broadcast;

const HOME: &str = "/Users/secret/.auxesis";
/// Mirrors `MAX_RELEASE_BYTES` in the delta stream.
const MAX_RELEASE_BYTES: usize = 32 * 1024;

fn stream() -> (Arc<DeltaStream>, broadcast::Receiver<String>) {
    let (sender, receiver) = broadcast::channel(128);
    let stream = DeltaStream::new(
        StreamSinks::loopback(sender),
        PathBuf::from(HOME),
        "main",
        3,
        "draft-3-1",
    );
    (stream, receiver)
}

fn drained(receiver: &mut broadcast::Receiver<String>) -> Vec<serde_json::Value> {
    let mut frames = Vec::new();
    while let Ok(text) = receiver.try_recv() {
        frames.push(serde_json::from_str(&text).unwrap());
    }
    frames
}

fn joined(frames: &[serde_json::Value]) -> String {
    frames
        .iter()
        .map(|frame| frame["text"].as_str().unwrap())
        .collect()
}

fn whole(text: &str) -> String {
    kernel_broker::scrub_external_preview(Path::new(HOME), text, usize::MAX)
}

/// Floor `at` onto a UTF-8 char boundary of `text` (test-side copy).
fn floor_char_boundary(text: &str, at: usize) -> usize {
    let bytes = text.as_bytes();
    let mut at = at.min(bytes.len());
    while at > 0 && at < bytes.len() && (bytes[at] & 0xC0) == 0x80 {
        at -= 1;
    }
    at
}

/// CPU time of the calling thread, not wall time: a shared CI runner
/// schedules these probes against other work, and the budgets must measure
/// the work the implementation does.
fn thread_cpu_time() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid pointer for the duration of the call.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(result, 0, "clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed");
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// One 1 MiB provider delta must stream out whole and fast — and
/// equal the whole-buffer scrub.
#[test]
fn a_one_mib_delta_streams_out_fully_and_fast() {
    // Whitespace-free on purpose: the whole-buffer scrub then skips the
    // condensed-copy pass, so the budget below measures the streaming
    // design, not the shared scrubber's largest allocation.
    let body = "x".repeat(1 << 20);
    assert_eq!(body.len(), 1 << 20);
    // Best of three attempts, on CPU time: wall time under contention is
    // reported in the failure message, but the contract is the work the
    // implementation does.
    let mut best_cpu = Duration::MAX;
    let mut best_wall = Duration::MAX;
    for attempt in 0..3 {
        let (stream, mut receiver) = stream();
        let wall = std::time::Instant::now();
        let cpu_start = thread_cpu_time();
        stream.push(&body, 1);
        stream.finish();
        let cpu = thread_cpu_time() - cpu_start;
        let wall = wall.elapsed();
        let frames = drained(&mut receiver);
        let text = joined(&frames);
        assert_eq!(text.len(), body.len(), "attempt {attempt} dropped bytes");
        assert_eq!(text, body, "attempt {attempt} changed the text");
        for frame in &frames {
            assert!(
                frame["text"].as_str().unwrap().len() <= MAX_RELEASE_BYTES,
                "a frame exceeded the release bound"
            );
        }
        best_cpu = best_cpu.min(cpu);
        best_wall = best_wall.min(wall);
    }
    assert_eq!(body, whole(&body), "diverged from the whole-buffer scrub");
    assert!(
        best_cpu < Duration::from_secs(2),
        "a 1 MiB delta took {best_cpu:?} CPU ({best_wall:?} wall) at best"
    );
}

/// A 3000-delta run with a flush after every delta must stay fast (the
/// whole-buffer rescans are stepped, not per push) and byte-exact.
#[test]
fn three_thousand_deltas_stream_within_budget() {
    let body = "Le streaming par deltas doit rester rapide et exact. ".repeat(430);
    let (stream, mut receiver) = stream();
    let cpu_start = thread_cpu_time();
    let start = std::time::Instant::now();
    let step = (body.len() / 3000).max(1);
    let mut position = 0usize;
    let mut seq = 0u64;
    while position < body.len() {
        let mut end = (position + step).min(body.len());
        end = floor_char_boundary(&body, end);
        if end == position {
            end = body.len();
        }
        seq += 1;
        stream.push(&body[position..end], seq);
        stream.flush();
        position = end;
    }
    stream.finish();
    let cpu = thread_cpu_time() - cpu_start;
    let wall = start.elapsed();
    assert!(seq >= 3000, "expected at least 3000 pushes, got {seq}");
    let text = joined(&drained(&mut receiver));
    assert_eq!(text, body, "the 3000-delta run changed the text");
    assert_eq!(text, whole(&body));
    assert!(
        cpu < Duration::from_secs(2),
        "3000 deltas took {cpu:?} CPU ({wall:?} wall)"
    );
}
