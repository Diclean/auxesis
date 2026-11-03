//! The notify policy: levels, batching, quiet hours and the daily cap. Pure
//! and clock-injected, so every case is deterministic.

use auxd::gateway::policy::{
    Action, Level, Notice, NotifyPolicy, PolicyConfig, PolicyState, DEFAULT_DAILY_CAP, MAX_BATCHED,
    MAX_DROPPED, MAX_NOTICE_BYTES,
};

const DAY: i64 = 86_400;

fn at(day: i64, hour: i64) -> i64 {
    day * DAY + hour * 3600
}

fn policy(quiet_start: u8, quiet_end: u8) -> NotifyPolicy {
    NotifyPolicy::new(PolicyConfig {
        window_secs: 1800,
        quiet_start_hour: quiet_start,
        quiet_end_hour: quiet_end,
        daily_cap: DEFAULT_DAILY_CAP,
    })
}

#[test]
fn three_info_inside_one_window_leave_as_one_message() {
    let policy = policy(0, 0);
    let mut state = PolicyState::default();
    let start = at(10, 9);
    assert_eq!(
        policy.offer(&mut state, start, Notice::new(Level::Info, "one")),
        Action::Batched
    );
    assert_eq!(
        policy.offer(&mut state, start + 10, Notice::new(Level::Info, "two")),
        Action::Batched
    );
    assert_eq!(
        policy.offer(&mut state, start + 20, Notice::new(Level::Normal, "three")),
        Action::Batched
    );
    assert!(
        policy.flush(&mut state, start + 100).is_none(),
        "window still open"
    );
    let batch = policy
        .flush(&mut state, start + 1800)
        .expect("one batched message");
    assert_eq!(batch.level, Level::Normal);
    assert_eq!(batch.text, "one\ntwo\nthree");
    assert!(policy.flush(&mut state, start + 3600).is_none());
}

#[test]
fn quiet_hours_hold_info_but_let_urgent_pass() {
    let policy = NotifyPolicy::new(PolicyConfig::default());
    let mut state = PolicyState::default();
    let night = at(10, 23);
    assert!(policy.is_quiet(night));
    assert_eq!(
        policy.offer(&mut state, night, Notice::new(Level::Info, "brief")),
        Action::Quiet
    );
    assert!(
        policy.flush(&mut state, night + 1800).is_none(),
        "quiet holds the batch"
    );
    assert_eq!(
        policy.offer(&mut state, night, Notice::new(Level::Urgent, "fire")),
        Action::SendNow
    );
    assert!(!policy.is_quiet(at(11, 7)), "07:00 ends the quiet window");
    let batch = policy
        .flush(&mut state, at(11, 7))
        .expect("leaves when quiet ends");
    assert_eq!(batch.text, "brief");
}

#[test]
fn the_daily_cap_drops_and_reports_the_overflow() {
    let policy = NotifyPolicy::new(PolicyConfig {
        window_secs: 0,
        quiet_start_hour: 0,
        quiet_end_hour: 0,
        daily_cap: 2,
    });
    let mut state = PolicyState::default();
    let start = at(10, 10);
    for i in 0..2 {
        assert_eq!(
            policy.offer(
                &mut state,
                start + i,
                Notice::new(Level::Normal, format!("n{i}"))
            ),
            Action::Batched
        );
        let sent = policy.flush(&mut state, start + i).expect("under the cap");
        assert_eq!(sent.text, format!("n{i}"));
    }
    assert_eq!(
        policy.offer(&mut state, start + 5, Notice::new(Level::Normal, "over")),
        Action::Batched
    );
    assert!(
        policy.flush(&mut state, start + 5).is_none(),
        "over the cap: dropped"
    );
    let dropped = policy.take_dropped(&mut state);
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].text, "over");
    assert!(policy.take_dropped(&mut state).is_empty());

    // Urgent still leaves, and it counts against the cap.
    assert_eq!(
        policy.offer(&mut state, start + 6, Notice::new(Level::Urgent, "now")),
        Action::SendNow
    );
    assert_eq!(
        policy.offer(&mut state, start + 7, Notice::new(Level::Normal, "after")),
        Action::Batched
    );
    assert!(policy.flush(&mut state, start + 7).is_none());
}

#[test]
fn the_daily_cap_defaults_to_twenty() {
    assert_eq!(PolicyConfig::default().daily_cap, DEFAULT_DAILY_CAP);
    assert_eq!(DEFAULT_DAILY_CAP, 20);
}

#[test]
fn a_notification_flood_cannot_grow_the_batch_or_retained_text_without_limit() {
    let policy = policy(22, 7);
    let mut state = PolicyState::default();
    let huge = "é".repeat(MAX_NOTICE_BYTES);
    for _ in 0..10_000 {
        policy.offer(&mut state, at(10, 23), Notice::new(Level::Normal, &huge));
    }

    let state = serde_json::to_value(state).unwrap();
    let batched = state["batched"].as_array().unwrap();
    let dropped = state["dropped"].as_array().unwrap();
    assert_eq!(batched.len(), MAX_BATCHED);
    assert_eq!(dropped.len(), MAX_DROPPED);
    assert!(batched
        .iter()
        .all(|notice| { notice["text"].as_str().unwrap().len() <= MAX_NOTICE_BYTES }));
    assert!(dropped
        .iter()
        .all(|notice| { notice["text"].as_str().unwrap().len() <= MAX_NOTICE_BYTES }));
}
