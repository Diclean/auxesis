//! The receipts collector's mail path.
//!
//! Four shapes are pinned here, with fictional data only: a call that names a
//! mailbox account this Mac does not have — the model is never told the slug,
//! so it guesses — is a configuration error, never "the mail server sent
//! something we couldn't read"; a refused part is skipped; an empty answer is
//! never filed; and the exact bytes of a refusal are pinned. Loopback only.

use std::sync::Arc;

use aux_fakemail::{read_line, read_until_tag, send_line, FakeImap, RawMessage, StaticCredentials};
use aux_mail::config::{ImapSettings, MailAccount, Security};
use aux_mail::dial::Dialer;
use aux_mail::error::MailError;
use aux_mail::imap_read::MailService;
use aux_mail::limits::Limits;
use tokio::net::TcpStream;

/// The account this Mac has.
const ACCOUNT: &str = "sim";
/// The slug the model guesses: it is never told the real one.
const GUESSED: &str = "personal";
/// The bytes of the fictional receipt every part carries.
const PDF: &str = "%PDF-1.4 fictional receipt\r\n";

/// One message with three PDF parts; the server has bytes for two of them.
fn message() -> RawMessage {
    let mut message = aux_fakemail::fixture_understated_parts(PDF, PDF.len());
    message.parts.retain(|(name, _)| *name != "3");
    message
}

fn service(fake: &FakeImap) -> MailService {
    let cert = fake.cert().expect("the TLS fake has a cert");
    let limits = Limits::default();
    let account = MailAccount {
        id: ACCOUNT.to_string(),
        email: "owner@mailsim.test".to_string(),
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: fake.port,
            security: Security::Tls,
            ..Default::default()
        },
        ..Default::default()
    };
    MailService::new(
        Dialer::with_client_config(cert.client_config(), limits.connect_timeout),
        limits,
        vec![account],
        Arc::new(StaticCredentials::new(ACCOUNT, "secret")),
    )
}

/// The account this Mac does not have is a configuration mistake, and it says
/// so: never "the mail server sent something we couldn't read".
#[tokio::test]
async fn an_account_this_mac_does_not_have_is_a_configuration_error() {
    let fake = FakeImap::spawn_tls(vec![message()]).await;
    let error = service(&fake)
        .fetch_attachments(GUESSED, "INBOX", 44, 0)
        .await
        .expect_err("the guessed account reads nothing");

    let MailError::Config { field } = &error else {
        panic!("the guessed account must be a configuration error: {error:?}");
    };
    assert_eq!(*field, "account", "the account name is the wrong part");
    let message = error.user_message(aux_mail::error::Lang::En);
    assert!(
        !message.title.contains("we couldn't read"),
        "a wrong account is not a broken server: {}",
        message.title
    );
    // No socket was opened for an account that does not exist.
    assert!(fake.commands().is_empty(), "{:?}", fake.commands());
}

/// A part the server refuses is skipped with a reason, and the parts it does
/// have still arrive. A part it answers with no bytes at all, while declaring
/// it as a file, is never filed as a document.
#[tokio::test]
async fn a_part_the_server_cannot_give_is_skipped_and_the_others_still_arrive() {
    let fake = FakeImap::spawn_tls(vec![message()]).await;
    let fetched = service(&fake)
        .fetch_attachments(ACCOUNT, "INBOX", 44, 0)
        .await
        .expect("the message reads");
    assert_eq!(fetched.downloaded.len(), 2, "{fetched:?}");
    assert_eq!(fetched.downloaded[0].mime, "application/pdf");
    assert_eq!(fetched.downloaded[0].bytes, PDF.as_bytes());
    assert_eq!(fetched.skipped.len(), 1, "{fetched:?}");
    assert!(
        fetched.skipped[0].reason.contains("no bytes"),
        "{fetched:?}"
    );

    let empty = aux_fakemail::fixture_understated_parts("", PDF.len());
    let fake = FakeImap::spawn_tls(vec![empty]).await;
    let fetched = service(&fake)
        .fetch_attachments(ACCOUNT, "INBOX", 44, 0)
        .await
        .expect("the message reads");
    assert!(fetched.downloaded.is_empty(), "{fetched:?}");
    assert_eq!(fetched.skipped.len(), 3, "{fetched:?}");
    assert!(
        fetched.skipped[0].reason.contains("declared"),
        "{fetched:?}"
    );
}

/// The exact bytes a server sends when it refuses a part it does not have: a
/// tagged `NO`, never an empty literal.
#[tokio::test]
async fn a_part_the_server_does_not_have_is_refused_with_a_tagged_no() {
    let fake = FakeImap::spawn(vec![message()]).await;
    let mut stream = TcpStream::connect(("127.0.0.1", fake.port))
        .await
        .expect("connect to the fake");
    assert!(read_line(&mut stream).await.starts_with("* OK"));
    send_line(&mut stream, "a1 LOGIN owner@mailsim.test secret").await;
    assert!(read_until_tag(&mut stream, "a1").await.contains("a1 OK"));
    send_line(&mut stream, "a2 SELECT INBOX").await;
    assert!(read_until_tag(&mut stream, "a2").await.contains("a2 OK"));
    send_line(&mut stream, "a3 UID FETCH 44 BODY.PEEK[3]").await;
    let answer = read_until_tag(&mut stream, "a3").await;
    assert_eq!(answer, "a3 NO [NONEXISTENT] unknown part\r\n");
    assert!(!answer.contains('{'), "no literal is sent: {answer}");
}
