//! Poison-tolerant lock helpers.
//!
//! A panic while a mutex is held poisons it; every later `.unwrap()` on that
//! lock panics again, turning one transient bug into a repeated-abort loop.
//! Recovery (`into_inner()`) with a logged error is the policy for daemon
//! state: a panic elsewhere is never a reason to abandon the daemon.

use std::sync::{Mutex, MutexGuard};

/// Lock `mutex`, recovering from a poisoned lock with a logged error.
pub fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!("a mutex was poisoned by a panic; recovering the guard");
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_poisoned_lock_recovers_instead_of_panicking() {
        let mutex = Arc::new(Mutex::new(7i32));
        let poisoner = Arc::clone(&mutex);
        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the lock");
        });
        assert!(mutex.is_poisoned());
        assert_eq!(*lock_recover(&mutex), 7);
    }
}
