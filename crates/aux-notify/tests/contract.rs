//! Public-API contract tests for `aux-notify`: trait objects, sharing across
//! threads, and the `STOP` kill-switch decorator. Nothing here touches a
//! real notification.

use aux_notify::{FakeNotifier, Notification, Notifier, NotifyError, StopSwitchNotifier};
use std::sync::Arc;

fn send(notifier: &dyn Notifier, title: &str) -> Result<(), NotifyError> {
    notifier.notify(&Notification::new(title, "body"))
}

#[test]
fn trait_objects_deliver_to_the_fake() {
    let fake = FakeNotifier::new();
    let notifier: &dyn Notifier = &fake;
    send(notifier, "one").unwrap();
    assert_eq!(fake.count(), 1);
    assert_eq!(fake.last().unwrap().title, "one");
}

#[test]
fn arc_notifier_is_shareable_across_threads() {
    let fake = Arc::new(FakeNotifier::new());
    let mut handles = Vec::new();
    for index in 0..4 {
        let fake = Arc::clone(&fake);
        handles.push(std::thread::spawn(move || {
            assert!(fake
                .notify(&Notification::new(format!("t{index}"), "b"))
                .is_ok());
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(fake.count(), 4);
}

#[test]
fn stop_switch_suppresses_while_marker_exists() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("STOP");
    let fake = FakeNotifier::new();
    let notifier = StopSwitchNotifier::new(&fake, &marker);

    send(&notifier, "before").unwrap();
    assert_eq!(fake.count(), 1);

    std::fs::write(&marker, b"").unwrap();
    assert!(matches!(
        send(&notifier, "during"),
        Err(NotifyError::Stopped)
    ));
    assert_eq!(fake.count(), 1, "inner notifier must be untouched");

    std::fs::remove_file(&marker).unwrap();
    send(&notifier, "after").unwrap();
    assert_eq!(fake.count(), 2);
}
