//! The daily-use demo mailbox (`aux-fakemail demo`) served
//! over loopback, one brief run through `LocalBriefSource`.
//!
//! The brief lists three possible new clients (two requests and a referral),
//! flags neither the newsletter nor the auto-reply nor the two clients, and
//! the notification carries counts only. Sandboxed: temp home, ephemeral
//! port, fictional `*.example` data.

use std::sync::mpsc;
use std::time::Duration;

use aux_brief::{run_once, BriefResult, MAX_SOURCE_READS};
use aux_fakemail::{demo_mailbox, serve, SimConfig, StoredMail};
use aux_notify::FakeNotifier;
use auxd::local_brief::LocalBriefSource;
use chrono::Local;
use kernel_core::{Config, Lang};

const LEADS: [&str; 3] = [
    "mira@lumenworks.example",
    "owen@quaystone.example",
    "lena@harborline.example",
];
const NOT_LEADS: [&str; 4] = [
    "news@studioweekly.example",
    "priya@verdant.example",
    "camille@northwind.example",
    "jonas@brightpath.example",
];

#[test]
fn the_demo_mailbox_gives_three_possible_new_clients_and_a_counts_only_text() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let sim_dir = dir.path().join("fakemail");
    std::fs::create_dir_all(&home).unwrap();
    // The brief runs at today's noon, so the demo mails are dated from that
    // same noon: dated from the real clock, a run after midnight saw a window
    // ten hours off and counted fewer new mails.
    let now = Local::now()
        .date_naive()
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_local_timezone(Local)
        .single()
        .unwrap();
    std::fs::create_dir_all(&sim_dir).unwrap();
    std::fs::write(
        sim_dir.join("mailbox.json"),
        serde_json::to_vec_pretty(&demo_mailbox(now.timestamp())).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Same mode as the install path (`write_demo`).
        std::fs::set_permissions(
            sim_dir.join("mailbox.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let mails: Vec<StoredMail> =
        serde_json::from_slice(&std::fs::read(sim_dir.join("mailbox.json")).unwrap()).unwrap();
    assert_eq!(mails.len(), 12, "the install set is twelve mails");

    let (tx, rx) = mpsc::channel();
    let sim = sim_dir.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let server = runtime
            .block_on(serve(SimConfig {
                dir: sim,
                imap_port: 0,
                smtp_port: 0,
            }))
            .expect("start the simulator");
        tx.send((server.imap_port, server.ca_file.clone())).unwrap();
        loop {
            std::thread::park();
        }
    });
    let (imap_port, ca_file) = rx.recv_timeout(Duration::from_secs(30)).unwrap();

    // A loopback demo account: id `demo`, key AUX_MAIL_DEMO.
    std::fs::write(
        kernel_core::config_path(&home),
        format!(
            "version = 1\n\n[privacy]\nmode = \"open\"\n\n[connectors.mail]\n\n\
             [[connectors.mail.accounts]]\nid = \"demo\"\nemail = \"owner@mailsim.test\"\n\n\
             [connectors.mail.accounts.imap]\nhost = \"127.0.0.1\"\nport = {imap_port}\n\
             security = \"tls\"\nca_file = \"{}\"\n",
            ca_file.display()
        ),
    )
    .unwrap();
    std::fs::write(home.join(".env"), "AUX_MAIL_DEMO=fictional-password\n").unwrap();

    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
    let notifier = FakeNotifier::new();
    let mut config = Config::default();
    config.ui.language = Lang::En;
    let result = run_once(
        &store,
        &LocalBriefSource::new(home.clone()),
        &notifier,
        &config,
        now,
        MAX_SOURCE_READS,
        || false,
    )
    .unwrap();
    assert!(matches!(result, BriefResult::Sent { .. }));

    let session = store.list_sessions().unwrap().remove(0);
    let brief = store.list_messages(session.id).unwrap().remove(0).content;
    assert!(!brief.contains("Mail: not available"), "{brief}");
    // Eight of the twelve are unread; the section shows the six newest, so the
    // oldest unread mail is the one left out.
    assert!(brief.contains("8 unread"), "{brief}");
    assert!(brief.contains("Thanks, looks good"), "{brief}");
    assert!(!brief.contains("Re: Notes from Friday's call"), "{brief}");
    let (_, section) = brief
        .split_once("Possible new clients")
        .unwrap_or_else(|| panic!("no new-client section: {brief}"));
    assert_eq!(
        section.lines().filter(|l| l.starts_with('•')).count(),
        3,
        "{section}"
    );
    for address in LEADS {
        assert!(section.contains(address), "{address} missing: {section}");
    }
    for address in NOT_LEADS {
        assert!(!section.contains(address), "{address} flagged: {section}");
    }
    for (address, reason) in [
        (LEADS[0], "quote"),
        (LEADS[1], "availability"),
        (LEADS[2], "referral"),
    ] {
        let line = section.lines().find(|l| l.contains(address)).unwrap();
        assert!(line.contains(reason), "{line}");
    }

    let notification = notifier.last().unwrap().body;
    assert!(
        notification.contains("3 possible new clients"),
        "{notification}"
    );
    for mail in &mails {
        assert!(!notification.contains(&mail.subject), "{notification}");
    }
    for address in LEADS.iter().chain(NOT_LEADS.iter()) {
        assert!(!notification.contains(address), "{notification}");
    }
}
