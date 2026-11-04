//! Simulator acceptance: a real aux-mail client over the local fake.
//!
//! Everything here is loopback and fictional. The client pins the simulator's
//! self-signed `cert.pem` through the new `ca_file` setting; no webpki root is
//! involved and no socket leaves the machine.

use std::sync::Arc;
use std::time::Duration;

use aux_fakemail::{default_mailbox, serve, SimConfig, StaticCredentials};
use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security, SmtpSettings};
use aux_mail::dial::Dialer;
use aux_mail::error::MailError;
use aux_mail::imap_read::{ListQuery, MailService};
use aux_mail::limits::Limits;
use aux_mail::mailbox;
use aux_mail::send::OutgoingMail;

fn account(imap_host: &str, imap_port: u16, smtp_port: u16, ca: &str) -> MailAccount {
    MailAccount {
        id: "mailsim".to_string(),
        email: "owner@mailsim.test".to_string(),
        display: None,
        imap: ImapSettings {
            host: imap_host.to_string(),
            port: imap_port,
            security: Security::Tls,
            username: None,
            ca_file: Some(ca.to_string()),
        },
        smtp: Some(SmtpSettings {
            host: "127.0.0.1".to_string(),
            port: smtp_port,
            security: Security::Tls,
            username: None,
            ca_file: Some(ca.to_string()),
        }),
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string(), "Sent".to_string()],
    }
}

#[tokio::test]
async fn lists_inbox_and_mirrors_a_send_to_sent_and_outbox() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = serve(SimConfig {
        dir: dir.path().to_path_buf(),
        imap_port: 0,
        smtp_port: 0,
    })
    .await
    .expect("start the simulator");
    let ca = server.ca_file.to_string_lossy().into_owned();
    let limits = Limits::default();
    let service = MailService::new(
        Dialer::new(limits.connect_timeout),
        limits,
        vec![account(
            "127.0.0.1",
            server.imap_port,
            server.smtp_port,
            &ca,
        )],
        Arc::new(StaticCredentials::new("mailsim", "any-password")),
    );

    let inbox = service
        .list("mailsim", &ListQuery::default())
        .await
        .expect("list INBOX over pinned TLS");
    assert_eq!(inbox.len(), 12, "the default fixture is twelve messages");
    let expected_unread = default_mailbox()
        .iter()
        .filter(|mail| !mail.flags.iter().any(|flag| flag == "\\Seen"))
        .count();
    assert_eq!(
        inbox.iter().filter(|item| item.unread).count(),
        expected_unread,
        "the unread count matches the fixture"
    );

    let outcome = service
        .send(
            "mailsim",
            &OutgoingMail {
                from: String::new(),
                to: vec!["me@example.org".to_string()],
                cc: Vec::new(),
                subject: "Hello from the simulator test".to_string(),
                body: "A fictional message body.".to_string(),
                ics: None,
            },
        )
        .await
        .expect("send over pinned TLS");
    assert_eq!(outcome.accepted, 1);

    let sent = service
        .list(
            "mailsim",
            &ListQuery {
                folder: Some("Sent".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("list Sent");
    assert_eq!(sent.len(), 1, "the sent message appears in Sent");
    assert_eq!(sent[0].subject, "Hello from the simulator test");

    assert!(
        server.outbox.join("1.eml").exists(),
        "the accepted message is written to outbox/"
    );
}

#[tokio::test]
async fn ca_file_on_a_non_loopback_host_is_refused_before_any_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = serve(SimConfig {
        dir: dir.path().to_path_buf(),
        imap_port: 0,
        smtp_port: 0,
    })
    .await
    .expect("start the simulator");
    let ca = server.ca_file.to_string_lossy().into_owned();

    // A canary on every interface: a dial to `127.0.0.2` (loopback range, but
    // not one of the three allowed spellings) would land here. It must not.
    let canary = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("canary listener");
    let port = canary.local_addr().expect("canary addr").port();
    let limits = Limits::default();
    let dialer = Dialer::new(limits.connect_timeout);

    for host in ["mail.example.com", "127.0.0.2"] {
        let settings = account(host, port, server.smtp_port, &ca).imap;
        let error = mailbox::login(&settings, "owner@mailsim.test", "any", &dialer, &limits)
            .await
            .expect_err("a non-loopback ca_file must be refused");
        assert!(
            matches!(error, MailError::Config { field } if field == "ca_file"),
            "{error:?}"
        );
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(150), canary.accept())
            .await
            .is_err(),
        "the refusal must happen before any socket is opened"
    );
}
