//! One brief run reads the local EventKit snapshot and the
//! configured mailbox, writes the full brief, and sends a counts-only
//! notification that carries no title, sender or subject.
//!
//! Everything is sandboxed: a temp home, a loopback `aux-fakemail` simulator
//! with a pinned self-signed certificate, and fictional `*.test` data. The
//! real home, the real macOS Keychain and the network are never touched.

use std::net::TcpListener;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use aux_brief::{run_once, BriefResult, BriefSource, BriefSourceError, MAX_SOURCE_READS};
use aux_fakemail::{serve, SimConfig, StoredMail};
use aux_notify::FakeNotifier;
use auxd::api::brief::run_brief_now;
use auxd::apple_eventkit::{save_snapshot, EventItem, EventKitSnapshot};
use auxd::gateway::policy::{NotifyPolicy, PolicyConfig};
use auxd::gateway::router::{NotifyRouter, Pending, QueueFull, Sink, SystemClock};
use auxd::local_brief::LocalBriefSource;
use chrono::{Local, NaiveDate, SecondsFormat};
use kernel_core::{Config, Lang};

const UNREAD_A: &str = "Fictional unread: kickoff agenda";
const UNREAD_B: &str = "Fictional unread: signed quote";
const READ_SUBJECT: &str = "Fictional read: weekly digest";
const EVENT_TODAY_A: &str = "Fictional standup";
const EVENT_TODAY_B: &str = "Fictional design review";
const EVENT_TOMORROW: &str = "Fictional retro tomorrow";
const SENDER: &str = "camille@northwind.example";

/// Start the loopback simulator on its own runtime/thread and keep it alive for
/// the rest of the test process. Returns the bound IMAP port and the CA file
/// the account pins.
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

/// Write the sandbox config: open privacy mode plus one mailbox account that
/// pins the simulator's certificate.
fn write_config(home: &Path, imap_port: u16, ca_file: &Path) {
    write_config_in(home, "open", "127.0.0.1", imap_port, Some(ca_file));
}

/// The same sandbox config with the privacy mode, the IMAP host and an
/// optional pinned certificate chosen by the test (a pinned certificate is
/// refused on a non-loopback host, so those tests pass none).
fn write_config_in(home: &Path, mode: &str, host: &str, imap_port: u16, ca_file: Option<&Path>) {
    let ca_line = ca_file
        .map(|path| format!("ca_file = \"{}\"\n", path.display()))
        .unwrap_or_default();
    let config = format!(
        "version = 1\n\n[privacy]\nmode = \"{mode}\"\n\n\
         [connectors.mail]\n\n\
         [[connectors.mail.accounts]]\n\
         id = \"briefsim\"\n\
         email = \"owner@mailsim.test\"\n\n\
         [connectors.mail.accounts.imap]\n\
         host = \"{host}\"\n\
         port = {imap_port}\n\
         security = \"tls\"\n\
         {ca_line}"
    );
    std::fs::write(kernel_core::config_path(home), config).unwrap();
    // The password comes from `<home>/.env`, never the Keychain; the simulator
    // accepts any value.
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

fn event(title: &str, start: String, end: String) -> EventItem {
    EventItem {
        id: None,
        title: title.to_string(),
        start,
        end,
        all_day: None,
        calendar: "Work".to_string(),
        location: None,
        attendees: None,
        calendar_id: None,
        recurring: None,
    }
}

fn stored_brief(store: &aux_store::Store) -> String {
    let session = store.list_sessions().unwrap().remove(0);
    store.list_messages(session.id).unwrap().remove(0).content
}

#[test]
fn local_brief_reads_snapshot_and_mailbox_but_notifies_counts_only() {
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
    write_config(&home, imap_port, &ca_file);

    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
    let snapshot = EventKitSnapshot {
        authorized: true,
        events: vec![
            event(
                EVENT_TODAY_A,
                local_instant(today, 9),
                local_instant(today, 9),
            ),
            event(
                EVENT_TODAY_B,
                local_instant(today, 14),
                local_instant(today, 15),
            ),
            event(
                EVENT_TOMORROW,
                local_instant(tomorrow, 10),
                local_instant(tomorrow, 11),
            ),
        ],
        reminders: Vec::new(),
        ..Default::default()
    };
    save_snapshot(&home, &snapshot).unwrap();

    let source = LocalBriefSource::new(home.clone());
    let notifier = FakeNotifier::new();
    let mut config = Config::default();
    config.ui.language = Lang::En;
    let now = today
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_local_timezone(Local)
        .single()
        .unwrap();
    let result = run_once(
        &store,
        &source,
        &notifier,
        &config,
        now,
        MAX_SOURCE_READS,
        || false,
    )
    .unwrap();
    assert!(matches!(result, BriefResult::Sent { .. }));

    // The stored brief keeps the full text: both of today's titles and both
    // unread subjects, and never tomorrow's event.
    let brief = stored_brief(&store);
    assert!(brief.contains(EVENT_TODAY_A), "{brief}");
    assert!(brief.contains(EVENT_TODAY_B), "{brief}");
    assert!(!brief.contains(EVENT_TOMORROW), "{brief}");
    assert!(brief.contains(UNREAD_A), "{brief}");
    assert!(brief.contains(UNREAD_B), "{brief}");
    assert!(!brief.contains(READ_SUBJECT), "{brief}");

    // The notification carries counts only: no title, sender or subject.
    let notification = notifier.last().unwrap().body.clone();
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
}

#[test]
fn no_snapshot_and_no_account_keep_the_not_connected_lines() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();

    let source = LocalBriefSource::new(home.clone());
    let notifier = FakeNotifier::new();
    let mut config = Config::default();
    config.ui.language = Lang::En;
    // Noon, not `Local::now()`: after 22:00 the default quiet hours hold the
    // brief and nothing is stored, so the test failed on evening runs.
    let now = Local::now()
        .date_naive()
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_local_timezone(Local)
        .single()
        .unwrap();
    run_once(
        &store,
        &source,
        &notifier,
        &config,
        now,
        MAX_SOURCE_READS,
        || false,
    )
    .unwrap();

    let brief = stored_brief(&store);
    // No snapshot means calendar is NotConnected; no account means mail is.
    assert!(brief.contains("Calendar: not available."), "{brief}");
    assert!(brief.contains("Mail: not available."), "{brief}");
    assert!(!brief.contains("Google"), "{brief}");
}

/// Three of today's messages, one with a hostile Subject: the mail section
/// must stay available, list all three, and carry no control character.
fn assert_bad_subject_keeps_the_mail_section(bad: &str) {
    use aux_brief::BriefSource;

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let date = Local::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
    let mailbox = vec![
        stored(1, UNREAD_A, true, &date),
        stored(2, bad, true, &date),
        stored(3, UNREAD_B, true, &date),
    ];
    let (imap_port, ca_file) = start_mailbox(dir.path(), &mailbox);
    write_config(&home, imap_port, &ca_file);

    let source = LocalBriefSource::new(home.clone());
    let today = Local::now().format("%Y-%m-%d").to_string();
    let headers = source
        .mail_headers(&today)
        .unwrap_or_else(|error| panic!("mail section failed for {bad:?}: {error:?}"));
    assert_eq!(headers.len(), 3, "{bad:?}: {headers:?}");
    for header in &headers {
        assert!(
            !header.subject.chars().any(char::is_control),
            "{bad:?}: control character in {:?}",
            header.subject
        );
    }
    assert!(headers.iter().any(|h| h.subject == UNREAD_A));
    assert!(headers.iter().any(|h| h.subject == UNREAD_B));
}

#[test]
fn today_mail_count_uses_unread_inbox_without_a_day_window() {
    use aux_brief::BriefSource;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let old_date = "Mon, 05 Oct 2026 09:00:00 +0000";
    let today = Local::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
    let mailbox = vec![
        stored(1, UNREAD_A, true, old_date),
        stored(2, UNREAD_B, true, old_date),
        stored(3, READ_SUBJECT, false, &today),
    ];
    let (imap_port, ca_file) = start_mailbox(dir.path(), &mailbox);
    write_config(&home, imap_port, &ca_file);
    let source = LocalBriefSource::new(home);
    let headers = source.mail_headers("2026-10-24").unwrap();
    assert_eq!(headers.len(), 2);
    assert!(headers.iter().all(|header| header.unread));
}

#[test]
fn a_subject_with_bell_and_soh_does_not_fail_the_mail_section() {
    assert_bad_subject_keeps_the_mail_section("Fictional \u{1}quote\u{7} reminder");
}

#[test]
fn a_subject_with_a_bare_cr_does_not_fail_the_mail_section() {
    assert_bad_subject_keeps_the_mail_section("Fictional split\rsubject");
}

/// Regression guard, not a reproduction: envelope subjects are not RFC 2047
/// decoded on read, so this encoded word stays literal text and already
/// passed before the fix. It pins that behaviour: if decoding is ever added,
/// the decoded controls must still be cleaned.
#[test]
fn an_encoded_word_subject_decoding_to_controls_does_not_fail_the_mail_section() {
    assert_bad_subject_keeps_the_mail_section("Fictional =?UTF-8?Q?bell=07_and=01_soh?= subject");
}

/// Records what the router queued, so these tests need no gateway.
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

/// Run `run_brief_now` once against the home. A test that wants a calendar
/// writes the snapshot first; without one the calendar line is "not
/// available". Returns the result, the store and what the router queued.
fn run_now(
    home: &Path,
) -> (
    Result<BriefResult, auxd::api::brief::BriefNowError>,
    aux_store::Store,
    Vec<String>,
) {
    let today = Local::now().date_naive();
    let store = aux_store::Store::open(&kernel_core::store_path(home)).unwrap();
    let sink = Arc::new(RecordingSink::default());
    let policy = PolicyConfig {
        quiet_start_hour: 0,
        quiet_end_hour: 0,
        ..PolicyConfig::default()
    };
    let router = NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(policy),
        kernel_core::SandboxHome::open(home).expect("open the test home"),
        Arc::new(SystemClock),
    );
    let mut config = Config::default();
    config.ui.language = Lang::En;
    let now = today
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_local_timezone(Local)
        .single()
        .unwrap();
    let result = run_brief_now(
        home,
        &config,
        &LocalBriefSource::new(home.to_path_buf()),
        &router,
        &store,
        now,
        || false,
    );
    let queued = sink
        .items
        .lock()
        .unwrap()
        .iter()
        .filter_map(|pending| match pending {
            Pending::Brief { text } => Some(text.clone()),
            _ => None,
        })
        .collect();
    (result, store, queued)
}

#[test]
fn private_mode_builds_the_brief_from_a_loopback_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let date = Local::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
    let mailbox = vec![
        stored(1, UNREAD_A, true, &date),
        stored(2, READ_SUBJECT, false, &date),
    ];
    let (imap_port, ca_file) = start_mailbox(dir.path(), &mailbox);
    write_config_in(&home, "private", "127.0.0.1", imap_port, Some(&ca_file));

    let (result, store, queued) = run_now(&home);

    assert!(matches!(result, Ok(BriefResult::Sent { .. })), "{result:?}");
    let brief = stored_brief(&store);
    assert!(brief.contains("Calendar: not available."), "{brief}");
    assert!(brief.contains(UNREAD_A), "{brief}");
    assert!(!brief.contains(READ_SUBJECT), "{brief}");
    // The notification stays counts-only.
    for text in queued {
        for secret in [UNREAD_A, SENDER] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
    }
}

#[test]
fn private_mode_never_dials_a_non_loopback_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    // `0.0.0.0` is not a loopback spelling, yet a connect to it lands on this
    // listener: a dial would be counted.
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    write_config_in(&home, "private", "0.0.0.0", port, None);

    let (result, store, _queued) = run_now(&home);

    assert!(matches!(result, Ok(BriefResult::Sent { .. })), "{result:?}");
    assert!(listener.accept().is_err(), "the remote host was dialled");
    let brief = stored_brief(&store);
    // The brief is still written; the mail section is skipped, not failed, and
    // the line says why.
    assert!(
        brief.contains("Mail: not available in private mode."),
        "{brief}"
    );
}

#[test]
fn private_mode_treats_an_unparsable_mail_config_as_not_local() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    // An unknown field: the table does not parse.
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"private\"\n\n\
         [connectors.mail]\n\n[[connectors.mail.accounts]]\n\
         id = \"briefsim\"\nemail = \"owner@mailsim.test\"\nsurprise = 1\n",
    )
    .unwrap();

    let (result, store, _queued) = run_now(&home);

    assert!(matches!(result, Ok(BriefResult::Sent { .. })), "{result:?}");
    let brief = stored_brief(&store);
    assert!(brief.contains("Mail: not available."), "{brief}");
}

#[test]
fn an_empty_imap_host_is_not_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    write_config_in(&home, "private", "", 993, None);

    let (result, store, _queued) = run_now(&home);

    assert!(matches!(result, Ok(BriefResult::Sent { .. })), "{result:?}");
    assert!(stored_brief(&store).contains("Mail: not available in private mode."));
}

/// The mode is open for the up-front check and private from the next read on,
/// as when the owner switches between the check and the dial. The remote
/// account gets no password at the last step, so the host is never dialled.
#[test]
fn a_switch_to_private_between_the_check_and_the_dial_opens_no_connection() {
    use kernel_core::privacy::{ModeFn, PrivacyMode};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    // `0.0.0.0` is not a loopback spelling, yet a connect to it lands on this
    // listener: a dial would be counted.
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    write_config_in(&home, "open", "0.0.0.0", port, None);

    let reads = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reads);
    let mode: ModeFn = Arc::new(move || {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            PrivacyMode::Open
        } else {
            PrivacyMode::Private
        }
    });
    let source = LocalBriefSource::new(home.clone()).with_mode(mode);

    let result = source.mail_headers("2026-10-14");

    assert_eq!(result, Err(BriefSourceError::Unavailable));
    assert!(
        reads.load(Ordering::SeqCst) >= 2,
        "the dial gate read the mode"
    );
    assert!(listener.accept().is_err(), "the remote host was dialled");
}

#[test]
fn private_mode_brief_shows_the_stored_calendar_event_and_keeps_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    write_config_in(&home, "private", "mail.remote.example", 993, None);
    let today = Local::now().date_naive();
    // The store exists (so does the key) before the snapshot is written.
    drop(aux_store::Store::open(&kernel_core::store_path(&home)).unwrap());
    let snapshot = EventKitSnapshot {
        authorized: true,
        events: vec![event(
            EVENT_TODAY_A,
            local_instant(today, 9),
            local_instant(today, 10),
        )],
        reminders: Vec::new(),
        ..Default::default()
    };
    save_snapshot(&home, &snapshot).unwrap();
    // A legacy plaintext copy is still swept in private mode.
    let legacy = home.join("apple-eventkit.json");
    std::fs::write(&legacy, b"{}").unwrap();

    let (result, store, _queued) = run_now(&home);
    auxd::apple_eventkit::sweep_stored(&home).unwrap();

    assert!(matches!(result, Ok(BriefResult::Sent { .. })), "{result:?}");
    let brief = stored_brief(&store);
    assert!(brief.contains(EVENT_TODAY_A), "{brief}");
    assert!(
        brief.contains("Mail: not available in private mode."),
        "{brief}"
    );
    assert!(auxd::apple_eventkit::snapshot_path(&home).exists());
    assert!(!legacy.exists(), "the plaintext copy goes");
}
