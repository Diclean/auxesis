//! `POST /v1/brief/run` runs the daemon's morning brief on
//! demand, through the same inner path as the scheduled 08:00 job.
//!
//! Sandbox only: a temp home, a loopback `aux-fakemail` simulator with a
//! pinned self-signed certificate, fictional `*.test` data and a fictional
//! EventKit snapshot. The real home, the real daemon port and the network are
//! never touched.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use aux_fakemail::{serve, SimConfig, StoredMail};
use auxd::api::{self, ApiOptions};
use auxd::apple_eventkit::{save_snapshot, EventItem, EventKitSnapshot};
use auxd::gateway::policy::{NotifyPolicy, PolicyConfig};
use auxd::gateway::router::{NotifyRouter, Pending, QueueFull, Sink, SystemClock};
use auxd::local_brief::LocalBriefSource;
use chrono::{Local, NaiveDate, SecondsFormat};
use common::{http, HttpResponse};
use kernel_core::{config_path, store_path, SandboxHome};

const UNREAD_A: &str = "Fictional unread: kickoff agenda";
const UNREAD_B: &str = "Fictional unread: signed quote";
const READ_SUBJECT: &str = "Fictional read: weekly digest";
const EVENT_TODAY_A: &str = "Fictional standup";
const EVENT_TODAY_B: &str = "Fictional design review";
const EVENT_TOMORROW: &str = "Fictional retro tomorrow";
const SENDER: &str = "camille@northwind.example";
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Start the loopback simulator on its own runtime/thread and keep it alive
/// for the rest of the test process. Returns the bound IMAP port and the CA
/// file the account pins.
fn start_mailbox(dir: &Path, mailbox: &[StoredMail]) -> (u16, std::path::PathBuf) {
    let sim_dir = dir.join("sim");
    std::fs::create_dir_all(&sim_dir).unwrap();
    std::fs::write(
        sim_dir.join("mailbox.json"),
        serde_json::to_vec(mailbox).unwrap(),
    )
    .unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("simulator runtime");
        let server = runtime
            .block_on(serve(SimConfig {
                dir: sim_dir,
                imap_port: 0,
                smtp_port: 0,
            }))
            .expect("start the simulator");
        tx.send((server.imap_port, server.ca_file.clone()))
            .expect("publish the simulator port");
        loop {
            std::thread::park();
        }
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("the simulator started")
}

fn stored(uid: u32, subject: &str, unread: bool, date: &str) -> StoredMail {
    StoredMail {
        uid,
        message_id: format!("<brief-{uid}@mailsim.test>"),
        subject: subject.to_string(),
        from: format!("Camille Example <{SENDER}>"),
        to: vec!["Owner <owner@mailsim.test>".to_string()],
        cc: Vec::new(),
        date: date.to_string(),
        body: format!(
            "From: Camille Example <{SENDER}>\r\n\
             To: Owner <owner@mailsim.test>\r\n\
             Subject: {subject}\r\n\
             Date: {date}\r\n\
             Message-ID: <brief-{uid}@mailsim.test>\r\n\
             \r\n\
             Fictional body for {subject}.\r\n"
        ),
        flags: if unread {
            Vec::new()
        } else {
            vec!["\\Seen".to_string()]
        },
        in_reply_to: None,
        ..StoredMail::default()
    }
}

/// Write the sandbox config: open privacy mode, a disabled quiet window
/// (`start == end`, so the run is deterministic at any test hour), and one
/// mailbox account that pins the simulator's certificate.
fn write_config(home: &Path, imap_port: u16, ca_file: &Path, quiet_start: &str, quiet_end: &str) {
    let config = format!(
        "version = 1\n\n[privacy]\nmode = \"open\"\n\n\
         [quiet]\nstart = \"{quiet_start}\"\nend = \"{quiet_end}\"\n\n\
         [connectors.mail]\n\n\
         [[connectors.mail.accounts]]\n\
         id = \"briefsim\"\n\
         email = \"owner@mailsim.test\"\n\n\
         [connectors.mail.accounts.imap]\n\
         host = \"127.0.0.1\"\n\
         port = {imap_port}\n\
         security = \"tls\"\n\
         ca_file = \"{}\"\n",
        ca_file.display()
    );
    std::fs::write(config_path(home), config).unwrap();
    let env = home.join(".env");
    std::fs::write(&env, "AUX_MAIL_BRIEFSIM=fictional-password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn local_instant(date: NaiveDate, hour: u32) -> String {
    date.and_hms_opt(hour, 0, 0)
        .unwrap()
        .and_local_timezone(Local)
        .single()
        .unwrap()
        .to_utc()
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn event(title: &str, start: String, end: String, all_day: Option<bool>) -> EventItem {
    EventItem {
        id: None,
        title: title.to_string(),
        start,
        end,
        all_day,
        calendar: "Work".to_string(),
        location: None,
        attendees: None,
        calendar_id: None,
        recurring: None,
    }
}

/// Records what the router queued, so the test needs no gateway.
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

async fn call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> HttpResponse {
    let method = method.to_string();
    let path = path.to_string();
    let token = token.map(str::to_string);
    let body = body.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        http(addr, &method, &path, token.as_deref(), body.as_deref())
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brief_run_api_writes_once_and_notifies_counts_only() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let today = Local::now().date_naive();
    let tomorrow = today.succ_opt().unwrap();
    let date = Local::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
    let mailbox = vec![
        stored(1, UNREAD_A, true, &date),
        stored(2, READ_SUBJECT, false, &date),
        stored(3, UNREAD_B, true, &date),
    ];
    let (imap_port, ca_file) = start_mailbox(dir.path(), &mailbox);

    write_config(&home, imap_port, &ca_file, "00:00", "00:00");

    let snapshot = EventKitSnapshot {
        authorized: true,
        events: vec![
            // Deliberately out of order: the stored brief must list them by start.
            event(
                EVENT_TODAY_B,
                local_instant(today, 14),
                local_instant(today, 15),
                None,
            ),
            event(
                EVENT_TODAY_A,
                local_instant(today, 0),
                local_instant(tomorrow, 0),
                Some(true),
            ),
            event(
                EVENT_TOMORROW,
                local_instant(tomorrow, 10),
                local_instant(tomorrow, 11),
                None,
            ),
        ],
        reminders: Vec::new(),
        ..Default::default()
    };
    // The store is created first: the snapshot is encrypted with the home's
    // store key, which `Store::open` establishes.
    let _ = aux_store::Store::open(&store_path(&home)).unwrap();
    save_snapshot(&home, &snapshot).unwrap();

    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();

    // The router records the brief; its own quiet window is disabled
    // (`start == end`) so the run's quiet-hours rule is the only one that can
    // hold it.
    let sink = Arc::new(RecordingSink::default());
    let handle = SandboxHome::open(&home).expect("open the test home");
    let policy = PolicyConfig {
        quiet_start_hour: 0,
        quiet_end_hour: 0,
        ..PolicyConfig::default()
    };
    let router = Arc::new(NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(policy),
        handle,
        Arc::new(SystemClock),
    ));

    let api_handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            brief_source: Some(Arc::new(LocalBriefSource::new(home.clone()))),
            notify_router: Some(Arc::clone(&router)),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let addr = api_handle.addr();

    // (a) no bearer token never reaches the run.
    let missing = call(addr, "POST", "/v1/brief/run", None, Some("{}")).await;
    assert_eq!(missing.status, 401, "body: {}", missing.body);
    assert!(
        sink.briefs().is_empty(),
        "an unauthenticated call must not run the brief"
    );

    // (e) the Today read: unauthenticated is 401; before any run there is no
    // brief for today.
    let unauthenticated = call(addr, "GET", "/v1/brief/today", None, None).await;
    assert_eq!(
        unauthenticated.status, 401,
        "body: {}",
        unauthenticated.body
    );
    let absent = call(addr, "GET", "/v1/brief/today", Some(TOKEN), None).await;
    assert_eq!(absent.status, 404, "body: {}", absent.body);
    assert_eq!(
        absent.json()["error"]["code"],
        "no_brief",
        "{}",
        absent.body
    );

    // (b) the first POST writes today's brief from the fixture snapshot and
    // mailbox.
    let first = call(addr, "POST", "/v1/brief/run", Some(TOKEN), Some("{}")).await;
    assert_eq!(first.status, 200, "body: {}", first.body);
    let value = first.json();
    assert_eq!(value["status"], "written", "{value}");
    let brief = value["brief"]
        .as_str()
        .expect("a written brief carries its text");
    assert!(!brief.contains("00:00–00:00"), "{brief}");
    assert!(brief.contains(EVENT_TODAY_B), "{brief}");
    assert!(!brief.contains(EVENT_TOMORROW), "{brief}");
    assert!(brief.contains(UNREAD_A), "{brief}");
    assert!(brief.contains(UNREAD_B), "{brief}");
    assert!(!brief.contains(READ_SUBJECT), "{brief}");

    // (e) the stored brief reads back in the app's DailyBrief shape: events by
    // start, unread headers only, and the degraded source named once.
    let today = call(addr, "GET", "/v1/brief/today", Some(TOKEN), None).await;
    assert_eq!(today.status, 200, "body: {}", today.body);
    let body = today.json();
    assert_eq!(body["day"], Local::now().format("%Y-%m-%d").to_string());
    assert!(body["written_at"].is_string(), "{body}");
    let events = body["events"].as_array().expect("events are listed");
    let titles: Vec<&str> = events
        .iter()
        .map(|e| e["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, [EVENT_TODAY_A, EVENT_TODAY_B], "{body}");
    assert_eq!(events[0]["all_day"], true, "{body}");
    let mail = body["mail"].as_array().expect("unread mail is listed");
    let subjects: Vec<&str> = mail
        .iter()
        .map(|m| m["subject"].as_str().unwrap())
        .collect();
    // Newest first: UID 3 before UID 1.
    assert_eq!(subjects, [UNREAD_B, UNREAD_A], "{body}");
    assert!(
        mail[0]["sender"].as_str().unwrap().contains(SENDER),
        "{body}"
    );
    let notes = body["notes"].as_array().expect("notes are listed");
    assert_eq!(
        notes.len(),
        1,
        "no city is set, so only weather degrades: {body}"
    );

    // (d) the routed notification is counts-only: no title, sender or subject.
    let briefs = sink.briefs();
    assert_eq!(briefs.len(), 1, "{briefs:?}");
    let notification = &briefs[0];
    for secret in [
        UNREAD_A,
        UNREAD_B,
        READ_SUBJECT,
        EVENT_TODAY_A,
        EVENT_TODAY_B,
        EVENT_TOMORROW,
        SENDER,
    ] {
        assert!(
            !notification.contains(secret),
            "{secret} leaked into the notification: {notification}"
        );
    }
    assert!(notification.contains("2 event(s) today"), "{notification}");
    assert!(notification.contains("2 unread"), "{notification}");
    assert!(!notification.contains("new message"), "{notification}");

    // (c) a second run the same day is idempotent.
    let second = call(addr, "POST", "/v1/brief/run", Some(TOKEN), Some("{}")).await;
    assert_eq!(second.status, 200, "body: {}", second.body);
    assert_eq!(second.json()["status"], "already_today");
    assert_eq!(sink.briefs().len(), 1, "no second notification");

    api_handle.shutdown();
}

/// `GET /v1/brief/status` says whether today's brief ran,
/// when, how and what happened to the delivery, and never carries content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brief_status_reports_the_run_and_delivery_without_content() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let today = Local::now().date_naive();
    let date = Local::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
    let (imap_port, ca_file) = start_mailbox(dir.path(), &[stored(1, UNREAD_A, true, &date)]);
    write_config(&home, imap_port, &ca_file, "00:00", "00:00");
    let _ = aux_store::Store::open(&store_path(&home)).unwrap();
    save_snapshot(
        &home,
        &EventKitSnapshot {
            authorized: true,
            events: vec![event(
                EVENT_TODAY_A,
                local_instant(today, 9),
                local_instant(today, 9),
                None,
            )],
            reminders: Vec::new(),
            ..Default::default()
        },
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let sink = Arc::new(RecordingSink::default());
    let router = Arc::new(NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(PolicyConfig {
            quiet_start_hour: 0,
            quiet_end_hour: 0,
            ..PolicyConfig::default()
        }),
        SandboxHome::open(&home).expect("open the test home"),
        Arc::new(SystemClock),
    ));
    let api_handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            brief_source: Some(Arc::new(LocalBriefSource::new(home.clone()))),
            notify_router: Some(router),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let addr = api_handle.addr();

    // (d) no bearer token, no status.
    let denied = call(addr, "GET", "/v1/brief/status", None, None).await;
    assert_eq!(denied.status, 401, "body: {}", denied.body);

    // Rows a crash or an older build could leave behind must not break the read.
    {
        let store = aux_store::Store::open(&store_path(&home)).unwrap();
        for payload in ["not json", "{\"day\": 5}", "null", "[]"] {
            store.log_event("brief.run", payload).unwrap();
        }
        // Same-day rows with one foreign word (a name, lowercase and short)
        // in a field that must hold a closed value: each is dropped, never
        // echoed.
        let day = Local::now().format("%Y-%m-%d").to_string();
        for (field, path) in [
            ("trigger", "/trigger"),
            ("result", "/result"),
            ("section", "/sections/mail"),
            ("outcome", "/delivery/outcome"),
            ("reason", "/delivery/reason"),
        ] {
            let mut row = serde_json::json!({
                "day": day, "at": "2026-10-14T08:00:00+02:00", "trigger": "scheduled",
                "result": "written",
                "sections": {"calendar": "built", "weather": "no_city", "mail": "built"},
                "delivery": {"outcome": "sent", "reason": null},
            });
            *row.pointer_mut(path).unwrap() = "camille".into();
            store
                .log_event("brief.run", &row.to_string())
                .unwrap_or_else(|_| panic!("{field}"));
        }
    }

    // (a) nothing ran today: "not run" and the next scheduled time.
    let before = call(addr, "GET", "/v1/brief/status", Some(TOKEN), None).await;
    assert_eq!(before.status, 200, "body: {}", before.body);
    let before = before.json();
    assert_eq!(before["runs_today"], 0, "{before}");
    assert_eq!(before["status"], "not_run", "{before}");
    assert!(before["last_run"].is_null(), "{before}");
    assert!(before["next_scheduled"].is_string(), "{before}");
    assert!(before["scheduled_time"].is_string(), "{before}");

    // (b) after a manual run: when, trigger, sections and delivery.
    let run = call(addr, "POST", "/v1/brief/run", Some(TOKEN), Some("{}")).await;
    assert_eq!(run.json()["status"], "written", "{}", run.body);
    let after = call(addr, "GET", "/v1/brief/status", Some(TOKEN), None).await;
    assert_eq!(after.status, 200, "body: {}", after.body);
    let value = after.json();
    assert_eq!(value["status"], "written", "{value}");
    let last = &value["last_run"];
    assert_eq!(last["trigger"], "manual", "{value}");
    assert_eq!(last["result"], "written", "{value}");
    assert!(
        last["at"].as_str().is_some_and(|at| at.contains('T')),
        "{value}"
    );
    // The recording sink cannot report delivery, so the run never claims "sent".
    assert_eq!(last["delivery"]["outcome"], "queued", "{value}");
    assert_eq!(
        last["sections"],
        serde_json::json!({"calendar": "built", "weather": "no_city", "mail": "built"}),
        "{value}"
    );

    // A second run the same day does not hide the run that wrote the brief.
    let again = call(addr, "POST", "/v1/brief/run", Some(TOKEN), Some("{}")).await;
    assert_eq!(again.json()["status"], "already_today", "{}", again.body);
    let value = call(addr, "GET", "/v1/brief/status", Some(TOKEN), None)
        .await
        .json();
    assert_eq!(value["last_run"]["result"], "written", "{value}");
    assert_eq!(value["runs_today"], 2, "{value}");

    // (c) the payload carries no brief text, subject, sender, title or handle.
    let raw = call(addr, "GET", "/v1/brief/status", Some(TOKEN), None)
        .await
        .body;
    for secret in [
        UNREAD_A,
        EVENT_TODAY_A,
        SENDER,
        "mailsim.test",
        "Fictional",
        "owner@",
        "Camille",
        "camille",
    ] {
        assert!(
            !raw.contains(secret),
            "{secret} leaked into the status: {raw}"
        );
    }
    api_handle.shutdown();
}

/// The brief reads the mailbox, suggests one unknown sender asking for a
/// quote (not the newsletter or the auto-reply), and the add / ignore routes act.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brief_suggests_a_possible_client_and_add_and_ignore_act() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let date = Local::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
    let lead = |uid: u32, from: &str, header: &str, text: &str| {
        let mut mail = stored(uid, "Hello", true, &date);
        mail.from = from.to_string();
        mail.body = format!(
            "From: {from}\r\nTo: Owner <owner@mailsim.test>\r\nSubject: Hello\r\nDate: {date}\r\n\
             {header}\r\n{text}\r\n"
        );
        mail
    };
    let mailbox = vec![
        lead(
            1,
            "Mira Fictive <mira@client.example>",
            "",
            "Could you send me a quote?",
        ),
        lead(
            2,
            "Shop <deals@shop.example>",
            "List-Unsubscribe: <mailto:u@shop.example>\r\n",
            "Book now",
        ),
        lead(
            3,
            "Out <away@away.example>",
            "Auto-Submitted: auto-replied\r\n",
            "A quote follows",
        ),
    ];
    let (imap_port, ca_file) = start_mailbox(dir.path(), &mailbox);
    write_config(&home, imap_port, &ca_file, "00:00", "00:00");
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let router = Arc::new(NotifyRouter::new(
        Arc::new(RecordingSink::default()),
        NotifyPolicy::new(PolicyConfig {
            quiet_start_hour: 0,
            quiet_end_hour: 0,
            ..PolicyConfig::default()
        }),
        SandboxHome::open(&home).expect("open the test home"),
        Arc::new(SystemClock),
    ));
    let api_handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            brief_source: Some(Arc::new(LocalBriefSource::new(home.clone()))),
            notify_router: Some(router),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let addr = api_handle.addr();

    let run = call(addr, "POST", "/v1/brief/run", Some(TOKEN), Some("{}")).await;
    assert!(
        run.json()["brief"]
            .as_str()
            .unwrap()
            .contains("mira@client.example"),
        "{}",
        run.body
    );
    let today = call(addr, "GET", "/v1/brief/today", Some(TOKEN), None)
        .await
        .json();
    assert_eq!(today["prospects"].as_array().unwrap().len(), 1, "{today}");
    assert_eq!(today["prospects"][0]["reason"], "quote", "{today}");

    let body = r#"{"account":"briefsim","name":"Mira Fictive","email":"mira@client.example"}"#;
    let added = call(
        addr,
        "POST",
        "/v1/brief/prospects/add",
        Some(TOKEN),
        Some(body),
    )
    .await;
    assert_eq!(added.status, 200, "{}", added.body);
    let store = aux_store::Store::open(&store_path(&home)).unwrap();
    assert_eq!(
        store.parties().unwrap()[0].tags,
        vec!["prospect".to_string()]
    );
    let today = call(addr, "GET", "/v1/brief/today", Some(TOKEN), None)
        .await
        .json();
    assert!(today["prospects"].as_array().unwrap().is_empty(), "{today}");

    // A sender today's brief never suggested: no write, whatever the caller
    // sends (the name of a suggestion comes from the brief, not the request).
    let other = r#"{"account":"briefsim","name":"Unexpected","email":"Other@Client.example"}"#;
    for route in ["/v1/brief/prospects/add", "/v1/brief/prospects/ignore"] {
        let refused = call(addr, "POST", route, Some(TOKEN), Some(other)).await;
        assert_eq!(refused.status, 404, "{route}: {}", refused.body);
    }
    assert_eq!(store.parties().unwrap().len(), 1);
    assert!(store.ignored_senders().unwrap().is_empty());
    // Added already: no longer suggested, so a second add writes nothing.
    let again = call(
        addr,
        "POST",
        "/v1/brief/prospects/add",
        Some(TOKEN),
        Some(body),
    )
    .await;
    assert_eq!(again.status, 404, "{}", again.body);
    let denied = call(addr, "POST", "/v1/brief/prospects/add", None, Some(body)).await;
    assert_eq!(denied.status, 401);
}
