use aux_brief::{run_once, BriefResult, FakeBriefSource};
use aux_notify::FakeNotifier;
use aux_store::Store;
use chrono::{Local, TimeZone};
use kernel_core::Config;
use tempfile::tempdir;

#[test]
fn offline_run_writes_one_inbox_message_and_one_test_notification() {
    let home = tempdir().unwrap();
    let store = Store::open(&home.path().join("store.sqlite")).unwrap();
    let notifier = FakeNotifier::new();
    let now = Local
        .with_ymd_and_hms(2026, 10, 7, 8, 0, 0)
        .single()
        .unwrap();

    let first = run_once(
        &store,
        &FakeBriefSource::default(),
        &notifier,
        &Config::default(),
        now,
        3,
        || false,
    )
    .unwrap();
    let restarted = run_once(
        &store,
        &FakeBriefSource::default(),
        &notifier,
        &Config::default(),
        now,
        3,
        || false,
    )
    .unwrap();

    assert!(matches!(first, BriefResult::Sent { .. }));
    assert!(matches!(restarted, BriefResult::AlreadySent { .. }));
    assert_eq!(notifier.count(), 1);
    let sessions = store.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    let messages = store.list_messages(sessions[0].id).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].role, "assistant");
    assert!(messages[0].content.contains("For your information"));
    store.create_session("main", Some("nouveau fil")).unwrap();
    assert!(store
        .append_daily_brief_once("main", "2026-10-07", "duplicate", &serde_json::Value::Null)
        .unwrap()
        .is_none());
}
