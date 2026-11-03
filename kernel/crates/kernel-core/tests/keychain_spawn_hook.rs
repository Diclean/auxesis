//! Security review r11: a `PATH` shim cannot observe an absolute `/usr/bin/security`
//! launch, so this test injects a launcher into the single spawn site and
//! proves that a clean environment (no `AUXESIS_ALLOW_KEYCHAIN=1`) never
//! reaches it. `/usr/bin/security` is never executed here.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn the_single_spawn_site_is_unreachable_without_the_opt_in() {
    // A clean environment: no opt-in, no sandbox flag. The check is
    // default-deny, so it refuses whatever HOME says.
    std::env::remove_var("AUXESIS_ALLOW_KEYCHAIN");
    std::env::remove_var("AUXESIS_SANDBOX");

    let attempts = Arc::new(AtomicUsize::new(0));
    let recorder = Arc::clone(&attempts);
    kernel_core::keychain::set_security_test_launcher(Some(Box::new(move |_args| {
        recorder.fetch_add(1, Ordering::SeqCst);
        Err("the single spawn site must not be reached without the opt-in".to_string())
    })));

    let error = kernel_core::keychain::run_security(&[
        "find-generic-password",
        "-s",
        "auxesis",
        "-a",
        "nobody",
    ])
    .expect_err("a clean environment must refuse without spawning");
    assert!(error.contains("not queried"), "{error}");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "the spawn site was reached without AUXESIS_ALLOW_KEYCHAIN=1"
    );

    kernel_core::keychain::set_security_test_launcher(None);
}
