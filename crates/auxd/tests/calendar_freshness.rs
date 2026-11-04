//! The calendar copy says how old it is.
//!
//! Only the app reads EventKit; it publishes a snapshot every 30 minutes and
//! keeps the old copy when it cannot. The snapshot carries its own capture
//! facts (`captured_at`, `covers_from`, `covers_to`), the status route exposes
//! them, and every calendar read a model gets carries an engine-written line
//! once the copy is not fresh. Sandbox homes only, ephemeral API port.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aux_store::Store;
use auxd::apple_eventkit::{
    save_snapshot, snapshot_age, snapshot_covers, EventItem, EventKitSnapshot,
};
use chrono::{DateTime, TimeZone, Utc};
use common::{get, post, KillOnDrop};
use kernel_broker::{ToolCtx, ToolRegistry};
use kernel_core::{config_path, store_path};

const STALE_LINE: &str = "it may be out of date — open Auxesis to refresh.";

fn home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        config_path(&home),
        "version = 1\ndefault_agent = \"main\"\n\n[privacy]\nmode = \"open\"\n\n\
         [[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
         model = \"fake-model\"\nkind = \"fake\"\n",
    )
    .unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    (dir, home)
}

fn utc(at: DateTime<Utc>) -> Option<String> {
    Some(at.to_rfc3339())
}

/// A snapshot the app read at `captured`, covering `captured - 1 h` out 8 days.
fn snapshot(captured: DateTime<Utc>) -> EventKitSnapshot {
    let start = Utc::now() + chrono::Duration::hours(3);
    EventKitSnapshot {
        authorized: true,
        events: vec![EventItem {
            id: Some("evt-1".into()),
            title: "Design review with Lumen Studio".into(),
            start: start.to_rfc3339(),
            end: (start + chrono::Duration::hours(1)).to_rfc3339(),
            all_day: None,
            calendar: "Work".into(),
            location: None,
            attendees: Some(vec!["mailto:ines@lumen.test".into()]),
            calendar_id: None,
            recurring: None,
        }],
        reminders: vec![],
        captured_at: utc(captured),
        covers_from: utc(captured - chrono::Duration::hours(1)),
        covers_to: utc(captured + chrono::Duration::days(8)),
        default_calendar_id: None,
        events_truncated: false,
        reminders_truncated: false,
    }
}

fn start_daemon(dir: &Path, home: &Path) -> (KillOnDrop, SocketAddr, String) {
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir, home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut daemon = KillOnDrop::new(child);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = sender.send(line);
        }
    });
    let deadline = Instant::now() + common::LOADED_RUNNER_WAIT;
    let port = loop {
        assert!(Instant::now() < deadline, "the daemon announces its API");
        assert!(daemon.try_wait().unwrap().is_none(), "the daemon exited");
        let Ok(line) = receiver.recv_timeout(Duration::from_millis(200)) else {
            continue;
        };
        if let Some(port) = line.strip_prefix("auxd api on http://127.0.0.1:") {
            break port.trim().parse::<u16>().unwrap();
        }
    };
    let token = std::fs::read_to_string(auxd::api::token_path(home)).unwrap();
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    (daemon, addr, token.trim().to_string())
}

#[test]
fn the_status_route_says_how_fresh_the_calendar_copy_is() {
    let (dir, home) = home();
    let (_daemon, addr, token) = start_daemon(dir.path(), &home);
    let status = || get(addr, "/v1/apple-eventkit/status", Some(&token));
    let publish = |snapshot: &EventKitSnapshot| {
        let body = serde_json::to_string(snapshot).unwrap();
        let saved = post(addr, "/v1/apple-eventkit/snapshot", Some(&token), &body);
        assert_eq!(saved.status, 204, "body: {}", saved.body);
    };

    let none = status();
    assert_eq!(none.status, 200, "body: {}", none.body);
    let none = none.json();
    assert_eq!(none["shared"], false);
    assert_eq!(none["fresh"], false);
    assert!(none["updated_at"].is_null());

    let captured = Utc::now() - chrono::Duration::minutes(2);
    publish(&snapshot(captured));
    let fresh = status().json();
    assert_eq!(fresh["shared"], true);
    assert_eq!(fresh["fresh"], true, "{fresh}");
    let at = |value: &serde_json::Value| {
        DateTime::parse_from_rfc3339(value.as_str().unwrap())
            .unwrap()
            .to_utc()
    };
    assert_eq!(at(&fresh["updated_at"]).timestamp(), captured.timestamp());
    assert_eq!(
        at(&fresh["covers_to"]).timestamp(),
        (captured + chrono::Duration::days(8)).timestamp()
    );

    // The app was closed four days ago: the capture time says so, whatever
    // the file's write time.
    let old = Utc::now() - chrono::Duration::days(4);
    publish(&snapshot(old));
    let stale = status().json();
    assert_eq!(stale["shared"], true);
    assert_eq!(stale["fresh"], false, "a four-day-old copy is not fresh");
    assert_eq!(at(&stale["updated_at"]).timestamp(), old.timestamp());

    // A snapshot with no capture facts: still accepted,
    // never fresh, its age unknown.
    publish(&EventKitSnapshot {
        captured_at: None,
        covers_from: None,
        covers_to: None,
        ..snapshot(Utc::now())
    });
    let legacy = status().json();
    assert_eq!(legacy["shared"], true);
    assert_eq!(legacy["fresh"], false);
    assert!(legacy["updated_at"].is_null(), "{legacy}");

    let anonymous = get(addr, "/v1/apple-eventkit/status", None);
    assert_eq!(anonymous.status, 401, "the route needs the bearer token");
}

#[test]
fn coverage_fails_closed_on_every_unknown() {
    let max_age = chrono::Duration::hours(2);
    let oct = |d: u32, h: u32, m: u32| Utc.with_ymd_and_hms(2026, 10, d, h, m, 0).unwrap();
    // Read at 23:59 on the 16th, its window the 16th 00:00 out 8 days;
    // published, and asked, two minutes later on the 17th.
    let late = EventKitSnapshot {
        captured_at: utc(oct(16, 23, 59)),
        covers_from: utc(oct(16, 0, 0)),
        covers_to: utc(oct(24, 0, 0)),
        ..EventKitSnapshot::default()
    };
    let now = oct(17, 0, 1);
    assert!(snapshot_covers(
        &late,
        oct(17, 9, 0),
        oct(23, 18, 0),
        now,
        max_age
    ));
    assert!(
        !snapshot_covers(&late, oct(17, 9, 0), oct(24, 10, 0), now, max_age),
        "the 24th was never read, though a mtime-based guess would say so"
    );

    // A clock change: captured more than 5 minutes ahead of now.
    let ahead = EventKitSnapshot {
        captured_at: utc(now + chrono::Duration::minutes(6)),
        ..late.clone()
    };
    assert!(!snapshot_covers(&ahead, now, now, now, max_age));
    assert!(!snapshot_age(&ahead, now).fresh);

    // An old file: no capture facts at all.
    let legacy = EventKitSnapshot {
        captured_at: None,
        covers_from: None,
        covers_to: None,
        ..late.clone()
    };
    assert!(!snapshot_covers(&legacy, now, now, now, max_age));
    let age = snapshot_age(&legacy, now);
    assert!(!age.fresh);
    assert_eq!(age.updated_at, None);

    // The window ends before the asked end.
    let short = EventKitSnapshot {
        covers_to: utc(oct(20, 0, 0)),
        ..late.clone()
    };
    assert!(!snapshot_covers(
        &short,
        oct(17, 9, 0),
        oct(21, 9, 0),
        now,
        max_age
    ));
    // Too old, too early a start.
    assert!(!snapshot_covers(
        &late,
        oct(17, 9, 0),
        oct(17, 10, 0),
        oct(17, 3, 0),
        max_age
    ));
    assert!(!snapshot_covers(
        &late,
        oct(15, 9, 0),
        oct(17, 10, 0),
        now,
        max_age
    ));
}

/// The free-times read asks for its search window, whole local
/// days as UTC bounds (`free_times::search_span`, pinned for Budapest in its
/// own tests), and only the copy's capture facts decide whether it is held.
#[test]
fn the_free_times_window_is_held_only_by_the_copy_s_own_coverage() {
    let max_age = chrono::Duration::hours(2);
    let at = |text: &str| DateTime::parse_from_rfc3339(text).unwrap().to_utc();
    let copy = |captured: &str, from: &str, to: &str| EventKitSnapshot {
        captured_at: Some(captured.into()),
        covers_from: Some(from.into()),
        covers_to: Some(to.into()),
        ..EventKitSnapshot::default()
    };
    // Budapest: read Oct 19 23:59:59 CEST, its window that day out 8 days
    // (to Oct 27 00:00 CET); published, and asked, at 00:00:01 / 00:01 on
    // Oct 20, whose search runs Oct 21 00:00 CEST to Oct 28 00:00 CET.
    let late = copy(
        "2026-10-19T21:59:59Z",
        "2026-10-18T22:00:00Z",
        "2026-10-26T23:00:00Z",
    );
    let now = at("2026-10-19T22:01:00Z");
    let (from, to) = (at("2026-10-20T22:00:00Z"), at("2026-10-27T23:00:00Z"));
    assert!(!snapshot_covers(&late, from, to, now, max_age));
    // The same search, from a copy read at 00:00:01: held, to the edge.
    let fresh = copy(
        "2026-10-19T22:00:01Z",
        "2026-10-19T22:00:00Z",
        "2026-10-27T23:00:00Z",
    );
    assert!(snapshot_covers(&fresh, from, to, now, max_age));
    // Its window one second short of either end of the search: not held.
    let short = copy(
        "2026-10-19T22:00:01Z",
        "2026-10-19T22:00:00Z",
        "2026-10-27T22:59:59Z",
    );
    assert!(!snapshot_covers(&short, from, to, now, max_age));
    let late_start = copy(
        "2026-10-19T22:00:01Z",
        "2026-10-20T22:00:01Z",
        "2026-10-27T23:00:00Z",
    );
    assert!(!snapshot_covers(&late_start, from, to, now, max_age));
    // App in Budapest, daemon in Tokyo: Oct 20 00:01 JST asks Oct 21 00:00
    // to Oct 28 00:00 JST, past the app's Oct 27 00:00 CET.
    let budapest = copy(
        "2026-10-19T15:01:00Z",
        "2026-10-18T22:00:00Z",
        "2026-10-26T23:00:00Z",
    );
    let tokyo = (at("2026-10-20T15:00:00Z"), at("2026-10-27T15:00:00Z"));
    let now = at("2026-10-19T15:01:00Z");
    assert!(!snapshot_covers(&budapest, tokyo.0, tokyo.1, now, max_age));
    // An old-format copy holds nothing; a reversed query is never held.
    let legacy = EventKitSnapshot::default();
    assert!(!snapshot_covers(
        &legacy,
        from,
        to,
        at("2026-10-19T22:01:00Z"),
        max_age
    ));
    assert!(!snapshot_covers(
        &fresh,
        to,
        from,
        at("2026-10-19T22:01:00Z"),
        max_age
    ));
}

async fn run(registry: &ToolRegistry, name: &str, home: &Path) -> String {
    let output = registry
        .get(name)
        .unwrap_or_else(|| panic!("{name} is registered"))
        .run(&serde_json::json!({}), &ToolCtx::new("test", home))
        .await
        .unwrap();
    assert!(!output.is_error, "{}", output.content);
    output.content
}

#[tokio::test]
async fn every_calendar_read_says_when_the_copy_is_out_of_date() {
    let (_dir, home) = home();
    let store = Arc::new(Mutex::new(Store::open(&store_path(&home)).unwrap()));
    let mut registry = ToolRegistry::new();
    auxd::apple_eventkit::register_tools(&home, &mut registry);
    auxd::crm::register_tools(&home, Arc::clone(&store), &mut registry);
    let reads = ["apple_calendar_list_events", "crm_today"];

    // A fresh copy is served as it is.
    save_snapshot(&home, &snapshot(Utc::now())).unwrap();
    for name in reads {
        let content = run(&registry, name, &home).await;
        assert!(!content.contains(STALE_LINE), "{name}: {content}");
    }
    let events = run(&registry, "apple_calendar_list_events", &home).await;
    assert!(events.contains("Design review with Lumen Studio"));

    // The app was closed four days ago: every read says so, from the engine.
    save_snapshot(&home, &snapshot(Utc::now() - chrono::Duration::days(4))).unwrap();
    for name in reads {
        let content = run(&registry, name, &home).await;
        assert!(
            content.contains("Calendar last updated "),
            "{name}: {content}"
        );
        assert!(content.contains(STALE_LINE), "{name}: {content}");
    }
    let events = run(&registry, "apple_calendar_list_events", &home).await;
    assert!(
        events.starts_with("Calendar last updated "),
        "the line comes before the events: {events}"
    );
    assert!(events.contains("Design review with Lumen Studio"));

    // The owner's current file: written by a build with no capture facts.
    let legacy = EventKitSnapshot {
        captured_at: None,
        covers_from: None,
        covers_to: None,
        ..snapshot(Utc::now())
    };
    save_snapshot(&home, &legacy).unwrap();
    for name in reads {
        let content = run(&registry, name, &home).await;
        assert!(
            content.contains("Calendar last updated at an unknown time"),
            "{name}: {content}"
        );
        assert!(content.contains(STALE_LINE), "{name}: {content}");
    }
}
