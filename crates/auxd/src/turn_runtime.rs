//! One current-thread runtime per worker thread, reused across turns (E-11).
//!
//! The engine's futures are `!Send`-friendly by design (the broker is
//! authenticated through a store handle, and one turn stays one task), so
//! each turn runs on a current-thread runtime from inside a blocking task.
//! Building that runtime per turn was measurable overhead (a reactor, a
//! timer driver and a blocking-pool handle each time); a `thread_local` slot
//! gives every blocking worker one long-lived runtime and keeps concurrency
//! (one worker thread, one turn at a time).
//!
//! Not re-entrant: a future passed to [`block_on`] must not call [`block_on`]
//! again on the same thread.

use std::cell::RefCell;
use std::future::Future;

thread_local! {
    static RUNTIME: RefCell<Option<tokio::runtime::Runtime>> = const { RefCell::new(None) };
}

/// Stack for the runtime's blocking pool, which runs delegated turns: the
/// std default on macOS/Linux. Pinned so a lowered `RUST_MIN_STACK` cannot
/// shrink it under a delegated turn (CROSS-AGENT-SIGSEGV: 256 KiB overflowed
/// 20/20 runs in a `tokio-rt-worker`, while 2 MiB always passed).
const BLOCKING_STACK: usize = 2 * 1024 * 1024;

/// Builds counted in tests, to prove the runtime is reused.
#[cfg(test)]
pub(crate) static RUNTIME_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Run `future` to completion on this thread's cached current-thread runtime.
pub fn block_on<F: Future>(future: F) -> std::io::Result<F::Output> {
    RUNTIME.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            #[cfg(test)]
            RUNTIME_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *slot = Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .thread_stack_size(BLOCKING_STACK)
                    .build()?,
            );
        }
        let runtime = slot.as_ref().expect("the runtime was built above");
        Ok(runtime.block_on(future))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn the_runtime_is_built_once_per_thread() {
        assert_eq!(block_on(async { 1 }).unwrap(), 1);
        let builds = RUNTIME_BUILDS.load(Ordering::SeqCst);
        // A second turn on the same thread reuses it, whatever earlier tests
        // on this thread already built.
        assert_eq!(block_on(async { 2 }).unwrap(), 2);
        assert_eq!(RUNTIME_BUILDS.load(Ordering::SeqCst), builds);
    }
}
