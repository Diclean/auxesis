// K-REGISTRY-PERF r1 regression binary for NO SEAL P2.
//
// A scan inside a non-main thread's thread-local `Drop` used to abort with
// `AccessError` because the `SHARED` cache was reached through `LocalKey::with`.
// The fix replaced every cache touch with `try_with`, so a scan that runs
// while thread-local storage is being torn down falls back to a fresh build
// whose output is byte-identical to the cached one.
//
// Two paths are exercised:
//   1. the `Drop` of another thread-local invokes the registry, and
//   2. an immediate follow-up scan on the freshly joined thread.
//
// Both must produce zero spans on `"x"` (no recogniser matches a single
// lowercase letter) and exit 0. The repro lives outside `tests/` so `cargo
// test` runs it as a forked process and never poisons the test runner's
// thread-locals on a failure.
use kernel_privacy::Registry;

struct DropScan;

impl Drop for DropScan {
    fn drop(&mut self) {
        // First call site: inside the `Drop` of a thread-local, after that
        // thread-local's storage is being torn down.
        let spans = Registry::new().analyze("x");
        assert!(spans.is_empty(), "drop scan: {spans:?}");
    }
}

thread_local! {
    static T: DropScan = const { DropScan };
}

fn main() {
    let handle = std::thread::spawn(|| {
        T.with(|_| ());
        // Second call site: immediately after the local has been touched.
        let spans = Registry::new().analyze("x");
        assert!(spans.is_empty(), "thread scan: {spans:?}");
    });
    handle.join().expect("child thread");
    let spans = Registry::new().analyze("x");
    assert!(spans.is_empty(), "main scan: {spans:?}");
    println!("ok");
}
