//! BRIEF-SINCE-CLOCK acceptance: the morning brief's mail window follows the
//! brief's own local day, not the system clock in UTC.
//!
//! The brief runs at 2026-10-15 21:30 at -04:00, which is already 2026-10-16
//! in UTC. Today follows the all-unread INBOX list used by `mail_list`, so all
//! three messages are included regardless of date. Sandboxed: temp home,
//! ephemeral port, fictional `*.example` data.

use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::Duration;

use aux_brief::BriefSource;
use aux_fakemail::{serve, SimConfig, StoredMail};
use auxd::local_brief::LocalBriefSource;

const OWNER: &str = "owner@mailsim.test";

/// A fictional unread INBOX mail whose `Date` header is `date`.
fn mail(uid: u32, subject: &str, date: &str) -> StoredMail {
    let id = format!("<since-{uid}@mailsim.test>");
    StoredMail {
        uid,
        message_id: id.clone(),
        subject: subject.to_string(),
        from: "Ana <ana@studio.example>".to_string(),
        to: vec![OWNER.to_string()],
        date: date.to_string(),
        body: format!(
            "From: Ana <ana@studio.example>\r\nTo: {OWNER}\r\nSubject: {subject}\r\n\
             Date: {date}\r\nMessage-ID: {id}\r\n\r\nHello.\r\n"
        ),
        ..StoredMail::default()
    }
}

#[test]
fn today_mail_includes_all_unread_inbox_messages_without_a_day_window() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let sim_dir = dir.path().join("fakemail");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&sim_dir).unwrap();
    let mails = vec![
        mail(
            1,
            "Old mail from the 12th",
            "Mon, 12 Oct 2026 10:00:00 -0400",
        ),
        mail(2, "Last night's mail", "Wed, 14 Oct 2026 21:00:00 -0400"),
        mail(3, "This morning's mail", "Thu, 15 Oct 2026 08:00:00 -0400"),
    ];
    let path = sim_dir.join("mailbox.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&mails).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

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
             [[connectors.mail.accounts]]\nid = \"demo\"\nemail = \"{OWNER}\"\n\n\
             [connectors.mail.accounts.imap]\nhost = \"127.0.0.1\"\nport = {imap_port}\n\
             security = \"tls\"\nca_file = \"{}\"\n",
            ca_file.display()
        ),
    )
    .unwrap();
    std::fs::write(home.join(".env"), "AUX_MAIL_DEMO=fictional-password\n").unwrap();

    // The brief's own local day, as `run_once` passes it down.
    let headers = LocalBriefSource::new(home.clone())
        .mail_headers("2026-10-15")
        .unwrap();
    let subjects: BTreeSet<&str> = headers.iter().map(|h| h.subject.as_str()).collect();
    assert_eq!(
        subjects,
        BTreeSet::from([
            "Old mail from the 12th",
            "Last night's mail",
            "This morning's mail",
        ]),
        "Today follows the all-unread inbox list semantics, without a date window"
    );
}
