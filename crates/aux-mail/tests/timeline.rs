//! B3 acceptance: a fixture mailbox produces the CRM timeline (`docs/mail.md` §4).
//!
//! Lives in aux-mail's own tests so the offline TLS seam may be named by this
//! crate's dev-dependency self-reference (`scripts/check-egress.sh`), exactly
//! as the C1 collector test does. The fake binds `127.0.0.1:0`; no socket
//! leaves the machine. People and companies are fictional.
//!
//! What this proves:
//! * a fake IMAP mailbox with mails between the owner and three fixture parties
//!   (plus one unknown sender) produces the right timeline for each party:
//!   right count, right order, right kinds;
//! * the unknown sender gets nothing;
//! * a unique body canary planted in every message is absent from every table
//!   — only a reference and a header-built summary are stored;
//! * running the whole refresh twice produces the same rows.

use std::path::Path;
use std::sync::Arc;

use aux_crm::{CalendarEvent, Crm, MailThread};
use aux_fakemail::{FakeImap, RawMessage, StaticCredentials};
use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security};
use aux_mail::dial::Dialer;
use aux_mail::imap_read::MailService;
use aux_mail::limits::Limits;
use aux_mail::EnvelopeItem;

/// Planted in every message body. Nothing may persist it.
const BODY_CANARY: &str = "CANARY-BODY-B3-NORTHWIND";

const BODY: &str =
    "From: fixture\r\nSubject: body\r\n\r\nCANARY-BODY-B3-NORTHWIND the invoice is attached.\r\n";

fn message(
    uid: u32,
    message_id: &str,
    subject: &str,
    from: &str,
    to: &[&str],
    cc: &[&str],
    date: &str,
) -> RawMessage {
    RawMessage {
        uid,
        message_id: message_id.to_string(),
        subject: subject.to_string(),
        from: from.to_string(),
        to: to.iter().map(|value| value.to_string()).collect(),
        cc: cc.iter().map(|value| value.to_string()).collect(),
        date: date.to_string(),
        body: BODY,
        flags: Vec::new(),
        bodystructure: None,
        parts: Vec::new(),
        in_reply_to: None,
    }
}

/// Three threads between the owner and three parties, plus one stranger.
fn fixtures() -> Vec<RawMessage> {
    vec![
        message(
            1,
            "<t0@fixture.test>",
            "Thread zero",
            "Person Zero <person0@fixture.test>",
            &["owner@fixture.test"],
            &[],
            "2025-10-01T09:00:00Z",
        ),
        message(
            2,
            "<t1@fixture.test>",
            "Thread one",
            "owner@fixture.test",
            &["person1@fixture.test"],
            &[],
            "2025-10-02T09:00:00Z",
        ),
        message(
            3,
            "<t2@fixture.test>",
            "Thread two",
            "Person Two <person2@fixture.test>",
            &["owner@fixture.test"],
            &["person0@fixture.test"],
            "2025-10-03T09:00:00Z",
        ),
        message(
            4,
            "<t9@fixture.test>",
            "Unknown sender",
            "unknown@unknown.test",
            &["owner@fixture.test"],
            &[],
            "2025-10-04T09:00:00Z",
        ),
    ]
}

const ROOTS: [&str; 4] = [
    "<t0@fixture.test>",
    "<t1@fixture.test>",
    "<t2@fixture.test>",
    "<t9@fixture.test>",
];

fn events() -> Vec<CalendarEvent> {
    vec![
        CalendarEvent {
            id: "evt-p0".to_string(),
            title: "Kick-off".to_string(),
            start: "2025-10-05T10:00:00Z".to_string(),
            attendees: vec![
                "mailto:person0@fixture.test".to_string(),
                "owner@fixture.test".to_string(),
            ],
        },
        CalendarEvent {
            id: "evt-p1p2".to_string(),
            title: "Review".to_string(),
            start: "2025-10-06T10:00:00Z".to_string(),
            attendees: vec![
                "person1@fixture.test".to_string(),
                "Person Two <person2@fixture.test>".to_string(),
            ],
        },
        CalendarEvent {
            id: "evt-unknown".to_string(),
            title: "Spam".to_string(),
            start: "2025-10-07T10:00:00Z".to_string(),
            attendees: vec!["unknown@unknown.test".to_string()],
        },
    ]
}

fn account(fake: &FakeImap) -> MailAccount {
    MailAccount {
        id: "personal".to_string(),
        email: "owner@fixture.test".to_string(),
        display: None,
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: fake.port,
            security: Security::Tls,
            username: None,
            ca_file: None,
        },
        smtp: None,
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    }
}

fn service(fake: &FakeImap) -> MailService {
    let cert = fake.cert().expect("the TLS fake has a cert");
    let limits = Limits::default();
    MailService::new(
        Dialer::with_client_config(cert.client_config(), limits.connect_timeout),
        limits,
        vec![account(fake)],
        Arc::new(StaticCredentials::new("personal", "secret")),
    )
}

/// Fold one grouped thread's headers into a builder input. Addresses accumulate;
/// the builder normalises and de-duplicates them.
fn thread_input(items: &[EnvelopeItem]) -> MailThread {
    let root = items
        .iter()
        .min_by_key(|item| item.uid)
        .expect("one message");
    let mut from = Vec::new();
    let mut to = Vec::new();
    let mut cc = Vec::new();
    for item in items {
        from.push(item.from.clone());
        to.extend(item.to.clone());
        cc.extend(item.cc.clone());
    }
    MailThread {
        account: "personal".to_string(),
        mailbox: "INBOX".to_string(),
        uid: root.uid,
        message_id: root.message_id.clone(),
        subject: root.subject.clone(),
        at: items
            .iter()
            .map(|item| item.date.clone())
            .max()
            .unwrap_or_default(),
        owner: vec!["owner@fixture.test".to_string()],
        last_from: items
            .iter()
            .max_by_key(|item| item.uid)
            .map(|item| item.from.clone())
            .unwrap_or_default(),
        from,
        to,
        cc,
    }
}

/// One full refresh: every fixture thread, then every fixture event.
async fn refresh(crm: &Crm<'_>, service: &MailService) -> usize {
    let mut inserted = 0;
    for root in ROOTS {
        let items = service.thread("personal", root, 100).await.expect("thread");
        inserted += crm.attach_mail_thread(&thread_input(&items)).unwrap().len();
    }
    for event in events() {
        inserted += crm.attach_calendar_event(&event).unwrap().len();
    }
    inserted
}

fn home_with_store() -> (tempfile::TempDir, std::path::PathBuf, aux_store::Store) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
    (dir, home, store)
}

fn party(display: &str, email: &str) -> aux_store::NewParty {
    aux_store::NewParty {
        kind: aux_store::PartyKind::Person,
        display_name: display.to_string(),
        name_variants: vec![display.to_string()],
        emails: vec![email.to_string()],
        phones: Vec::new(),
        addresses: Vec::new(),
        tags: Vec::new(),
        notes: String::new(),
        time_zone: None,
        origin: "owner".to_string(),
    }
}

fn kinds(store: &aux_store::Store, party: i64) -> Vec<String> {
    store
        .interactions_for_party(party)
        .unwrap()
        .into_iter()
        .map(|row| row.kind)
        .collect()
}

/// Every text value in every user table, for the body-canary check.
fn all_store_text(home: &Path) -> String {
    let conn = aux_store::open_keyed_readonly(&kernel_core::store_path(home)).unwrap();
    let mut tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables.sort();
    let mut out = String::new();
    for table in tables {
        let mut statement = match conn.prepare(&format!("SELECT * FROM \"{table}\"")) {
            Ok(statement) => statement,
            Err(_) => continue,
        };
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                let mut line = String::new();
                for index in 0..columns {
                    if let Ok(text) = row.get::<_, String>(index) {
                        line.push_str(&text);
                    }
                }
                Ok(line)
            })
            .unwrap();
        for row in rows {
            out.push_str(&row.unwrap());
        }
    }
    out
}

#[tokio::test]
async fn a_fixture_mailbox_and_events_produce_the_right_timeline() {
    let (_dir, home, store) = home_with_store();
    let crm = Crm::new(&store);
    let p0 = crm
        .create(party("Person Zero", "person0@fixture.test"))
        .unwrap();
    let p1 = crm
        .create(party("Person One", "person1@fixture.test"))
        .unwrap();
    let p2 = crm
        .create(party("Person Two", "person2@fixture.test"))
        .unwrap();

    let fake = FakeImap::spawn_tls(fixtures()).await;
    let service = service(&fake);

    let inserted = refresh(&crm, &service).await;
    assert_eq!(
        inserted, 7,
        "2 for p0 + 1 for p1 + 1 for p2 + 1 + 2 for the events"
    );

    assert_eq!(
        kinds(&store, p0.id),
        vec!["mail", "mail", "meeting"],
        "p0: the thread it sent to the owner, the stranger's copy, then the meeting"
    );
    assert_eq!(kinds(&store, p1.id), vec!["mail", "meeting"]);
    assert_eq!(kinds(&store, p2.id), vec!["mail", "meeting"]);

    let p0_rows = store.interactions_for_party(p0.id).unwrap();
    assert!(p0_rows[0].summary.starts_with("received: "));
    assert!(p0_rows[0].summary.contains("Thread zero"));
    // The stranger sent Thread two; the owner did not, so the party was copied.
    assert!(p0_rows[1].summary.starts_with("copied: "));
    assert!(p0_rows[1].summary.contains("Thread two"));
    assert_eq!(p0_rows[2].summary, "Kick-off");
    assert!(p0_rows[0].source_ref.contains("<t0@fixture.test>"));

    let p1_rows = store.interactions_for_party(p1.id).unwrap();
    assert!(p1_rows[0].summary.starts_with("sent: "));
    assert!(p1_rows[0].summary.contains("Thread one"));
    assert!(p1_rows[1].source_ref.contains("evt-p1p2"));

    // Order is the stored `at`, oldest first.
    let times: Vec<&str> = p0_rows.iter().map(|row| row.at.as_str()).collect();
    assert_eq!(
        times,
        vec![
            "2025-10-01T09:00:00Z",
            "2025-10-03T09:00:00Z",
            "2025-10-05T10:00:00Z"
        ]
    );

    // Positive control: the fixture body really is readable through the mail
    // path, so the canary's absence below is a property of the builder and not
    // of the fixture.
    let raw = service
        .read("personal", 1, "INBOX", 4096)
        .await
        .expect("the fixture body reads");
    assert!(
        String::from_utf8_lossy(&raw.bytes).contains(BODY_CANARY),
        "the fake server must serve the body for the canary to mean anything"
    );

    // The body canary is in no table; the subject summaries are.
    let text = all_store_text(&home);
    assert!(!text.contains(BODY_CANARY), "a mail body reached the store");
    assert!(text.contains("Thread zero"));
    assert!(text.contains("Kick-off"));

    // Running the whole refresh again changes nothing.
    assert_eq!(refresh(&crm, &service).await, 0, "a re-run inserts no row");
    assert_eq!(store.interactions_for_party(p0.id).unwrap().len(), 3);
    assert_eq!(store.interactions_for_party(p1.id).unwrap().len(), 2);
    assert_eq!(store.interactions_for_party(p2.id).unwrap().len(), 2);
    assert!(!all_store_text(&home).contains(BODY_CANARY));
}

#[tokio::test]
async fn the_unknown_sender_gets_nothing() {
    let (_dir, _home, store) = home_with_store();
    let crm = Crm::new(&store);
    let _p0 = crm
        .create(party("Person Zero", "person0@fixture.test"))
        .unwrap();

    let fake = FakeImap::spawn_tls(fixtures()).await;
    let service = service(&fake);
    let items = service
        .thread("personal", "<t9@fixture.test>", 100)
        .await
        .expect("thread");

    assert!(crm
        .attach_mail_thread(&thread_input(&items))
        .unwrap()
        .is_empty());
    assert!(store.interactions_for_party(1).unwrap().is_empty());
}
