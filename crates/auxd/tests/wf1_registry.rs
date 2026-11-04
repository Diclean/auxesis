//! Registry changes while a delta stream is live.
//!
//! Process-isolated from the `auxd` unit tests so the LRU-cap probes can fill
//! the known-secret registry without racing another test's canaries. The
//! unit-level pin behaviour lives in `aux-tools` (`scrub.rs`); this file
//! proves the end-to-end guarantees: a value a live stream started with
//! cannot be evicted out from under it, and a saturated registry fails
//! closed with a visible placeholder instead of leaking.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use auxd::api::{DeltaStream, StreamSinks};
use tokio::sync::broadcast;

const HOME: &str = "/Users/secret/.auxesis";
const MASK: &str = "<redacted>";

/// The registry is process-global; these probes fill and trim it, so they
/// run one at a time.
static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

fn stream() -> (Arc<DeltaStream>, broadcast::Receiver<String>) {
    let (sender, receiver) = broadcast::channel(256);
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

/// A value registered before the stream starts is pinned by it: filling the
/// registry past `MAX_KNOWN_SECRETS` evicts unpinned fillers, never the live
/// value, and the frames the stream emits still carry the mask.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_stream_pins_its_values_against_lru_eviction() {
    let _guard = lock();
    let canary = format!("CNR7LRU{}", 5_130_421_987u64);
    assert!(kernel_broker::scrub::register_known_secret(&canary));
    let (stream, mut receiver) = stream();

    // Fill the registry well past its cap while the stream is live.
    for index in 0..kernel_broker::scrub::MAX_KNOWN_SECRETS + 16 {
        kernel_broker::scrub::register_known_secret(&format!(
            "CANARY_KS_LRUPROBE_{index:04}_7f3a9c2e1b5d"
        ));
    }
    assert!(
        kernel_broker::scrub::redact_known_secrets(&format!("use {canary} now")).is_some(),
        "the live stream's pinned value was evicted"
    );

    stream.push(&format!("token={canary}"), 1);
    stream.finish();
    let text = joined(&drained(&mut receiver));
    assert!(
        !text.contains(&canary),
        "a pinned value reached the frames: {text:?}"
    );
    assert!(text.contains(MASK), "{text:?}");
}

/// The same, for a value registered *by the stream itself* after it started:
/// the value is not pinned (it was not there at start), but the frames still
/// mask it because the whole-buffer scrub is consulted on every emit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_value_registered_mid_stream_is_masked_from_its_registration_on() {
    let _guard = lock();
    let canary = format!("CNR7MID{}", 9_814_072_635u64);
    let (stream, mut receiver) = stream();
    stream.push(&format!("before {canary} "), 1);
    // The registration happens between two pushes; the pending tail is
    // scrubbed with the new registry at `finish`.
    assert!(kernel_broker::scrub::register_known_secret(&canary));
    stream.push("after", 2);
    stream.finish();
    let text = joined(&drained(&mut receiver));
    assert!(
        !text.contains(&canary),
        "the mid-stream registered value leaked: {text:?}"
    );
    assert!(text.contains(MASK), "{text:?}");
}

/// An oversized value's closure cannot cover every spelling; the value
/// is still registered (its raw form matches) but live streams fail closed
/// with the visible placeholder instead of publishing it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_registry_masks_the_whole_message() {
    let _guard = lock();
    kernel_broker::scrub::clear_known_secrets();
    let value = "K".repeat(1024);
    assert!(kernel_broker::scrub::register_known_secret(&value));
    assert!(
        kernel_broker::scrub::registry_oversized(),
        "the closure must exceed the budget"
    );
    let (stream, mut receiver) = stream();
    stream.push(&format!("ordinary text {value} ordinary tail"), 1);
    stream.finish();
    let text = joined(&drained(&mut receiver));
    assert!(text.contains(MASK), "expected the placeholder: {text:?}");
    assert!(
        !text.contains(&value),
        "the oversized value leaked: {text:?}"
    );
    drop(stream);
    kernel_broker::scrub::clear_known_secrets();
}

/// R8 (3), the security review's repro: with every value pinned the registry grows to its
/// hard ceiling and then refuses new values; the pinned target is never
/// evicted, and a live stream fails closed with a visible placeholder
/// instead of publishing the target verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_registry_masks_the_whole_message() {
    let _guard = lock();
    let target = format!("PINNED_TARGET_CNR8_{}", 492_817_365u64);
    assert!(kernel_broker::scrub::register_known_secret(&target));
    for index in 0..kernel_broker::scrub::MAX_KNOWN_SECRETS - 1 {
        kernel_broker::scrub::register_known_secret(&format!(
            "CANARY_KS_SAT_{index:04}_7f3a9c2e1b5d"
        ));
    }
    // The original stream pins all 128 values.
    let (main_stream, mut receiver) = stream();
    // Register one value at a time and immediately pin it with a new stream:
    // every value stays pinned, so the registry grows to the hard ceiling.
    let mut extra: Vec<Arc<DeltaStream>> = Vec::new();
    for index in 0..kernel_broker::scrub::MAX_KNOWN_SECRETS_HARD {
        if kernel_broker::scrub::registry_saturated() {
            break;
        }
        kernel_broker::scrub::register_known_secret(&format!(
            "CANARY_KS_SATGROW_{index:04}_7f3a9c2e1b5d"
        ));
        extra.push(stream().0);
    }
    assert!(
        kernel_broker::scrub::registry_saturated(),
        "the registry must report saturation at its hard ceiling"
    );
    // The pinned target is still registered, and a new value is refused.
    assert!(
        kernel_broker::scrub::redact_known_secrets(&format!("use {target} now")).is_some(),
        "a pinned value was evicted at the hard ceiling"
    );
    assert!(
        !kernel_broker::scrub::register_known_secret("CANARY_KS_SATOVER_7f3a9c2e1b5d"),
        "a new value must be refused at the hard ceiling"
    );

    // A live stream fails closed: the placeholder, never the raw target.
    main_stream.push(&format!("ordinary text {target} ordinary tail"), 1);
    main_stream.finish();
    let text = joined(&drained(&mut receiver));
    assert!(text.contains(MASK), "expected the placeholder: {text:?}");
    assert!(
        !text.contains(&target),
        "the pinned target leaked through a saturated stream: {text:?}"
    );
    drop(extra);
    drop(main_stream);
}
