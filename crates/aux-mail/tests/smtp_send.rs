//! MA4: the SMTP send path against the in-process fake. Offline only.
//!
//! Every test asserts the no-retry rule: the fake's `mail_from_count` is one on
//! success and stays one on a `421`.

use std::sync::Arc;
use std::time::Duration;

use aux_fakemail::{FakeSmtp, StaticCredentials};
use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security, SmtpSettings};
use aux_mail::dial::Dialer;
use aux_mail::error::MailError;
use aux_mail::ics::{build_request_ics, Invite};
use aux_mail::imap_read::MailService;
use aux_mail::limits::Limits;
use aux_mail::send::OutgoingMail;

fn account(fake: &FakeSmtp, security: Security) -> MailAccount {
    MailAccount {
        id: "personal".to_string(),
        email: "me@example.org".to_string(),
        display: None,
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: 1,
            security: Security::Tls,
            username: None,
            ca_file: None,
        },
        smtp: Some(SmtpSettings {
            host: "127.0.0.1".to_string(),
            port: fake.port,
            security,
            username: None,
            ca_file: None,
        }),
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    }
}

fn service(fake: &FakeSmtp, security: Security, limits: Limits) -> MailService {
    // The fake's self-signed cert is trusted only through the test seam.
    let dialer = match (security, fake.cert()) {
        (Security::Plain, _) => Dialer::new(Duration::from_secs(2)),
        (_, Some(cert)) => Dialer::with_client_config(cert.client_config(), limits.connect_timeout),
        (_, None) => Dialer::new(limits.connect_timeout),
    };
    MailService::new(
        dialer,
        limits,
        vec![account(fake, security)],
        Arc::new(StaticCredentials::new("personal", "secret-canary")),
    )
}

fn mail() -> OutgoingMail {
    OutgoingMail {
        from: String::new(),
        to: vec!["camille@exemple.fr".to_string()],
        cc: Vec::new(),
        subject: "Invitation".to_string(),
        body: "Bonjour, invitation confirmée.".to_string(),
        ics: None,
    }
}

#[tokio::test]
async fn implicit_tls_sends_exactly_one_message() {
    let fake = FakeSmtp::spawn_tls().await;
    let service = service(&fake, Security::Tls, Limits::default());
    let outcome = service.send("personal", &mail()).await.expect("send");
    assert_eq!(outcome.accepted, 1);
    assert_eq!(fake.mail_from_count(), 1, "exactly one MAIL FROM");
    let accepted = fake.accepted();
    assert_eq!(accepted.len(), 1);
    assert!(accepted[0].contains("Subject: Invitation"), "{accepted:?}");
    assert!(
        accepted[0].contains("Content-Type: text/plain"),
        "{accepted:?}"
    );
    // The password never appears in the recorded commands.
    let commands = fake.commands();
    assert!(
        !commands
            .iter()
            .any(|line| line.contains("secret-canary") || line.contains("c2VjcmV0")),
        "{commands:?}"
    );
    assert!(
        commands.iter().any(|line| line.starts_with("AUTH")),
        "{commands:?}"
    );
}

#[tokio::test]
async fn starttls_upgrades_and_sends_one_message() {
    let fake = FakeSmtp::spawn_starttls().await;
    let service = service(&fake, Security::StartTls, Limits::default());
    let outcome = service.send("personal", &mail()).await.expect("send");
    assert_eq!(outcome.accepted, 1);
    assert_eq!(fake.mail_from_count(), 1);
    let commands = fake.commands();
    assert!(
        commands
            .iter()
            .any(|line| line.to_ascii_uppercase().contains("STARTTLS")),
        "{commands:?}"
    );
}

#[tokio::test]
async fn plain_security_is_refused_before_any_socket() {
    let fake = FakeSmtp::spawn().await;
    let service = service(&fake, Security::Plain, Limits::default());
    let error = service
        .send("personal", &mail())
        .await
        .expect_err("refused");
    assert!(
        matches!(error, MailError::InsecurePassword { .. }),
        "{error:?}"
    );
    assert_eq!(fake.connections(), 0, "no socket may open");
}

#[tokio::test]
async fn a_421_on_mail_from_is_not_retried() {
    let fake = FakeSmtp::spawn_throttle_mail_from().await;
    let service = service(&fake, Security::Tls, Limits::default());
    let error = service
        .send("personal", &mail())
        .await
        .expect_err("throttled");
    assert!(matches!(error, MailError::RateLimited), "{error:?}");
    assert_eq!(fake.mail_from_count(), 1, "the send must not be retried");
    assert!(fake.accepted().is_empty());
}

#[tokio::test]
async fn a_timeout_after_data_is_typed_uncertain() {
    let fake = FakeSmtp::spawn_stall_after_data().await;
    let limits = Limits::new(
        256,
        512 * 1024,
        5,
        Duration::from_millis(150),
        Duration::from_secs(2),
        1,
        1,
    );
    let service = service(&fake, Security::Tls, limits);
    let error = service
        .send("personal", &mail())
        .await
        .expect_err("the final reply never came");
    assert!(matches!(error, MailError::Uncertain), "{error:?}");
    assert_eq!(fake.mail_from_count(), 1, "one attempt");
}

#[tokio::test]
async fn a_drop_after_data_is_typed_uncertain() {
    let fake = FakeSmtp::spawn_drop_after_data().await;
    let service = service(&fake, Security::Tls, Limits::default());
    let error = service
        .send("personal", &mail())
        .await
        .expect_err("the final reply never came");
    assert!(matches!(error, MailError::Uncertain), "{error:?}");
    assert_eq!(fake.mail_from_count(), 1, "one attempt");
    assert_eq!(
        fake.accepted().len(),
        1,
        "the server saw the whole message before the drop"
    );
}

#[tokio::test]
async fn an_oversized_message_is_refused_before_any_socket() {
    let fake = FakeSmtp::spawn_tls().await;
    let limits = Limits::new(
        256,
        512 * 1024,
        5,
        Duration::from_secs(5),
        Duration::from_secs(2),
        1,
        1,
    );
    let service = service(&fake, Security::Tls, limits);
    let mut mail = mail();
    mail.body = "x".repeat(4096);
    let error = service
        .send("personal", &mail)
        .await
        .expect_err("too large");
    assert!(matches!(error, MailError::TooLarge { .. }), "{error:?}");
    assert_eq!(fake.connections(), 0, "no socket may open");
}

#[tokio::test]
async fn header_injection_is_refused_before_any_socket() {
    let fake = FakeSmtp::spawn_tls().await;
    let service = service(&fake, Security::Tls, Limits::default());
    let mut mail = mail();
    mail.subject = "hi\r\nBcc: leak@exemple.fr".to_string();
    let error = service.send("personal", &mail).await.expect_err("refused");
    assert!(
        matches!(error, MailError::InvalidField("subject")),
        "{error:?}"
    );
    assert_eq!(fake.connections(), 0, "no socket may open");
}

#[tokio::test]
async fn a_recipient_the_fake_refuses_is_typed_and_not_retried() {
    let fake = FakeSmtp::spawn_tls().await;
    let service = service(&fake, Security::Tls, Limits::default());
    let mut mail = mail();
    mail.to = vec!["nobody@example.net".to_string()];
    let error = service.send("personal", &mail).await.expect_err("refused");
    assert!(
        matches!(error, MailError::RecipientDenied { .. }),
        "{error:?}"
    );
    assert_eq!(fake.mail_from_count(), 1);
}

#[tokio::test]
async fn an_invite_goes_out_as_a_calendar_part_with_the_real_attendee() {
    let fake = FakeSmtp::spawn_tls().await;
    let service = service(&fake, Security::Tls, Limits::default());
    let ics = build_request_ics(&Invite {
        uid: "evt-1@auxesis.local".to_string(),
        summary: "Meeting with Camille Exemple".to_string(),
        start_utc: "20261011T080000Z".to_string(),
        end_utc: "20261011T083000Z".to_string(),
        dtstamp_utc: "20261010T120000Z".to_string(),
        organizer_email: "me@example.org".to_string(),
        organizer_name: Some("Owner".to_string()),
        attendee_email: "camille@exemple.fr".to_string(),
        attendee_name: Some("Camille Exemple".to_string()),
        location: None,
        description: None,
    })
    .unwrap();
    let mut mail = mail();
    mail.ics = Some(ics);
    let outcome = service.send("personal", &mail).await.expect("send");
    assert_eq!(outcome.accepted, 1);
    let accepted = fake.accepted();
    assert!(accepted[0].contains("Content-Type: text/calendar; method=REQUEST"));
    assert!(accepted[0].contains("filename=\"invite.ics\""));
    // The raw base64 of the calendar carries no visible token delimiters; the
    // decoded message is asserted in the hero test.
    assert!(!accepted[0].contains('\u{27e6}'));
    assert!(!accepted[0].contains('\u{27e7}'));
}
