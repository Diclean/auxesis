//! The daemon's outbound router: policy first, gateway second, with a
//! persisted counter. Pure and clock-injected, so no daemon or network runs.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use auxd::gateway::policy::{Action, Level, NotifyPolicy, PolicyConfig};
use auxd::gateway::router::{Clock, NotifyRouter, Pending, QueueFull, Sink};

const DAY: i64 = 86_400;

/// A clock the test can move.
#[derive(Clone)]
struct FixedClock(Arc<AtomicI64>);

impl FixedClock {
    fn new(secs: i64) -> Self {
        Self(Arc::new(AtomicI64::new(secs)))
    }

    fn set(&self, secs: i64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_local_secs(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Records every message the router queued.
#[derive(Default)]
struct RecordingSink {
    items: Mutex<Vec<Pending>>,
}

impl Sink for RecordingSink {
    fn try_enqueue(&self, pending: Pending) -> Result<(), QueueFull> {
        self.items.lock().unwrap().push(pending);
        Ok(())
    }
}

impl RecordingSink {
    fn alerts(&self) -> Vec<String> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter_map(|pending| match pending {
                Pending::Alert { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    fn briefs(&self) -> Vec<String> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter_map(|pending| match pending {
                Pending::Brief { text } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }
}

fn build(
    sink: &Arc<RecordingSink>,
    clock: &FixedClock,
    home: kernel_core::SandboxHome,
    config: PolicyConfig,
) -> NotifyRouter {
    NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(config),
        home,
        Arc::new(clock.clone()),
    )
}

fn open_home(dir: &std::path::Path) -> kernel_core::SandboxHome {
    kernel_core::SandboxHome::open(dir).expect("open test home")
}

fn no_quiet() -> PolicyConfig {
    PolicyConfig {
        window_secs: 0,
        quiet_start_hour: 0,
        quiet_end_hour: 0,
        daily_cap: 20,
    }
}

#[tokio::test]
async fn a_brief_inside_quiet_hours_waits_for_the_quiet_window_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(RecordingSink::default());
    let clock = FixedClock::new(3 * 3600);
    let router = build(
        &sink,
        &clock,
        open_home(dir.path()),
        PolicyConfig::default(),
    );

    assert_eq!(router.brief("good morning"), Action::Quiet);
    assert!(sink.briefs().is_empty(), "quiet hours hold the brief");
    assert!(router.flush().is_none());

    clock.set(7 * 3600);
    router.flush();
    assert_eq!(sink.briefs(), vec!["good morning".to_string()]);
    assert_eq!(router.brief("tomorrow"), Action::SendNow);
}

#[tokio::test]
async fn the_daily_cap_sends_twenty_and_reports_the_rest_in_the_next_brief() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(RecordingSink::default());
    let clock = FixedClock::new(10 * DAY + 10 * 3600);
    let router = build(&sink, &clock, open_home(dir.path()), no_quiet());

    for i in 0..25 {
        assert_eq!(
            router.alert(Level::Info, &format!("alert {i}")).await,
            Action::Batched
        );
        router.flush();
    }
    assert_eq!(sink.alerts().len(), 20, "twenty leave, five are dropped");

    // Urgent is never dropped, even at the cap; it still counts.
    assert_eq!(router.alert(Level::Urgent, "fire").await, Action::SendNow);
    assert_eq!(sink.alerts().len(), 21);

    router.brief("brief");
    let briefs = sink.briefs();
    assert_eq!(briefs.len(), 1);
    assert!(briefs[0].contains("5 notification(s) not delivered"));
    for i in 20..25 {
        assert!(briefs[0].contains(&format!("alert {i}")), "{}", briefs[0]);
    }
}

#[tokio::test]
async fn a_restart_keeps_the_daily_counter() {
    let dir = tempfile::tempdir().unwrap();
    let home = open_home(dir.path());
    let clock = FixedClock::new(10 * DAY + 10 * 3600);
    let config = no_quiet();
    let first = Arc::new(RecordingSink::default());
    let router = build(&first, &clock, home.clone(), config);
    for i in 0..20 {
        router.alert(Level::Info, &format!("a{i}")).await;
        router.flush();
    }
    assert_eq!(first.alerts().len(), 20);
    drop(router);

    let second = Arc::new(RecordingSink::default());
    let restarted = build(&second, &clock, home, config);
    assert_eq!(restarted.alert(Level::Info, "over").await, Action::Batched);
    restarted.flush();
    assert!(second.alerts().is_empty(), "the cap survived the restart");
    restarted.brief("brief");
    assert!(second.briefs()[0].contains("over"));
}

#[cfg(unix)]
#[tokio::test]
async fn the_state_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(RecordingSink::default());
    let clock = FixedClock::new(10 * DAY + 10 * 3600);
    let router = build(
        &sink,
        &clock,
        open_home(dir.path()),
        PolicyConfig::default(),
    );
    router.alert(Level::Urgent, "one").await;
    let mode = std::fs::metadata(router.state_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[tokio::test]
async fn a_corrupt_state_file_fails_closed_and_is_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let home = open_home(dir.path());
    std::fs::write(
        home.path().join("notify_policy.json"),
        b"{ this is not json",
    )
    .unwrap();
    let sink = Arc::new(RecordingSink::default());
    let clock = FixedClock::new(10 * DAY + 10 * 3600);
    let router = build(&sink, &clock, home.clone(), no_quiet());

    // The cap is spent: an info notice is held and then dropped.
    assert_eq!(router.alert(Level::Info, "held").await, Action::Batched);
    assert!(router.flush().is_none());
    assert_eq!(router.alert(Level::Urgent, "fire").await, Action::SendNow);
    router.brief("brief");
    assert!(sink.briefs()[0].contains("held"), "{:?}", sink.briefs());

    let quarantined = std::fs::read_dir(home.path())
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("notify_policy.json.corrupt-")
        });
    assert!(quarantined, "the corrupt file is quarantined");
}

#[tokio::test]
async fn a_missing_state_file_starts_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(RecordingSink::default());
    let clock = FixedClock::new(10 * DAY + 10 * 3600);
    let router = build(&sink, &clock, open_home(dir.path()), no_quiet());

    assert_eq!(router.alert(Level::Info, "first").await, Action::Batched);
    assert!(router.flush().is_some(), "a fresh state still sends");
}
