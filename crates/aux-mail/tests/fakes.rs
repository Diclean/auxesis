//! M2 + M2b: the fakes testing the fakes. Offline only.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use aux_mail::config::Security;
use aux_mail::dial::Dialer;
use aux_mail::error::MailError;

use aux_fakemail::{
    fixture_mailbox, fixture_multipart_with_pdf, read_line, read_until, read_until_tag, send_line,
    FakeImap, FakeSmtp,
};

async fn connect_plain(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect the fake")
}

async fn refuses_after_drop(port: u16) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn full_imap_round_trip_records_commands_and_never_sets_seen() {
    let fake = FakeImap::spawn(fixture_mailbox(3)).await;
    let mut stream = connect_plain(fake.port).await;
    assert!(read_line(&mut stream).await.starts_with("* OK"));

    send_line(&mut stream, "a1 LOGIN me@example.org secret").await;
    assert!(read_until_tag(&mut stream, "a1").await.contains("a1 OK"));

    send_line(&mut stream, "a2 LIST \"\" *").await;
    assert!(read_until_tag(&mut stream, "a2").await.contains("INBOX"));

    send_line(&mut stream, "a3 SELECT INBOX").await;
    assert!(read_until_tag(&mut stream, "a3").await.contains("a3 OK"));

    send_line(&mut stream, "a4 UID SEARCH ALL").await;
    assert!(read_until_tag(&mut stream, "a4")
        .await
        .contains("* SEARCH 1 2 3"));

    send_line(
        &mut stream,
        "a5 UID FETCH 1 (ENVELOPE FLAGS UID RFC822.SIZE)",
    )
    .await;
    let envelopes = read_until_tag(&mut stream, "a5").await;
    assert!(envelopes.contains("ENVELOPE"), "{envelopes}");
    assert!(envelopes.contains("RFC822.SIZE"), "{envelopes}");

    send_line(&mut stream, "a6 UID FETCH 1 BODY.PEEK[]").await;
    let body = read_until_tag(&mut stream, "a6").await;
    assert!(body.contains("BODY[]"), "{body}");
    assert!(body.contains("Hello fixture body."), "{body}");

    let commands = fake.commands();
    assert!(
        commands.iter().any(|line| line.contains("BODY.PEEK[]")),
        "{commands:?}"
    );
    assert!(
        !commands.iter().any(|line| {
            let upper = line.to_ascii_uppercase();
            upper.contains("STORE") && line.contains("\\Seen")
        }),
        "no command may set \\Seen: {commands:?}"
    );
}

#[tokio::test]
async fn append_stores_the_exact_bytes() {
    let fake = FakeImap::spawn(fixture_mailbox(1)).await;
    let mut stream = connect_plain(fake.port).await;
    let _ = read_line(&mut stream).await;
    let body = "From: me@example.org\r\nSubject: draft\r\n\r\nDraft body.\r\n";
    send_line(
        &mut stream,
        &format!("a1 APPEND Drafts (\\Draft) {{{}}}", body.len()),
    )
    .await;
    assert!(read_line(&mut stream).await.starts_with('+'));
    stream.write_all(body.as_bytes()).await.expect("literal");
    stream.write_all(b"\r\n").await.expect("terminator");
    stream.flush().await.expect("flush");
    assert!(read_line(&mut stream).await.contains("a1 OK"));
    assert_eq!(fake.appended(), vec![body.to_string()]);
}

#[tokio::test]
async fn multipart_bodystructure_and_part_are_served() {
    let fake = FakeImap::spawn(vec![fixture_multipart_with_pdf()]).await;
    let mut stream = connect_plain(fake.port).await;
    let _ = read_line(&mut stream).await;

    send_line(&mut stream, "a1 UID FETCH 42 BODYSTRUCTURE").await;
    let structure = read_until_tag(&mut stream, "a1").await;
    assert!(structure.contains("BODYSTRUCTURE"), "{structure}");
    assert!(structure.contains("\"APPLICATION\" \"PDF\""), "{structure}");

    send_line(&mut stream, "a2 UID FETCH 42 BODY.PEEK[2]").await;
    let part = read_until_tag(&mut stream, "a2").await;
    assert!(part.contains("BODY[2]"), "{part}");
    assert!(part.contains("%PDF-1.4 fake invoice"), "{part}");

    let commands = fake.commands();
    assert!(commands.iter().any(|line| line.contains("BODYSTRUCTURE")));
    assert!(commands.iter().any(|line| line.contains("BODY.PEEK[2]")));
}

#[tokio::test]
async fn the_tls_cert_is_accepted_by_the_test_verifier_and_not_the_default_one() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let cert = fake.cert().expect("tls cert");

    let connector = TlsConnector::from(cert.client_config());
    let tcp = connect_plain(fake.port).await;
    let name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector
        .connect(name, tcp)
        .await
        .expect("the test verifier accepts");
    let mut greeting = vec![0u8; 64];
    let read = tls.read(&mut greeting).await.expect("greeting");
    assert!(String::from_utf8_lossy(&greeting[..read]).contains("* OK"));

    let production = TlsConnector::from(aux_mail::tlsutil::client_config());
    let tcp = connect_plain(fake.port).await;
    let name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let rejected = production.connect(name, tcp).await;
    assert!(rejected.is_err(), "the default verifier must reject");

    // And the dialer types the refusal as `CertRejected`, not a bare error.
    let dialer = Dialer::new(Duration::from_secs(2));
    let error = dialer
        .connect(&fake.endpoint(Security::Tls))
        .await
        .expect_err("the production verifier must reject the self-signed cert");
    assert!(matches!(error, MailError::CertRejected { .. }), "{error:?}");
}

#[tokio::test]
async fn fakes_bind_loopback_only_and_shut_down_when_dropped() {
    let fake = FakeImap::spawn(fixture_mailbox(1)).await;
    assert!(fake.addr().ip().is_loopback());
    assert_ne!(fake.port, 0);
    let imap_port = fake.port;
    // Hold a live connection across the drop: its serving task must be aborted
    // too, so the client sees EOF rather than a parked socket.
    let mut held = connect_plain(imap_port).await;
    assert!(read_line(&mut held).await.starts_with("* OK"));
    drop(fake);
    assert!(
        refuses_after_drop(imap_port).await,
        "the IMAP listener must close on drop"
    );
    let closed = tokio::time::timeout(Duration::from_secs(1), async {
        let mut byte = [0u8; 1];
        held.read(&mut byte).await
    })
    .await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "a held connection must close when the fake is dropped: {closed:?}"
    );

    let smtp = FakeSmtp::spawn().await;
    assert!(smtp.addr().ip().is_loopback());
    assert_ne!(smtp.port, 0);
    let smtp_port = smtp.port;
    drop(smtp);
    assert!(
        refuses_after_drop(smtp_port).await,
        "the SMTP listener must close on drop"
    );
}

#[tokio::test]
async fn fake_smtp_advertises_auth_and_relays_a_message() {
    let fake = FakeSmtp::spawn().await;
    let mut stream = connect_plain(fake.port).await;
    assert!(read_line(&mut stream).await.starts_with("220"));

    send_line(&mut stream, "EHLO tester").await;
    let ehlo = read_until(&mut stream, "250 8BITMIME\r\n").await;
    assert!(ehlo.contains("AUTH PLAIN LOGIN"), "{ehlo}");

    send_line(&mut stream, "AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=").await;
    assert!(read_line(&mut stream).await.starts_with("235"));

    send_line(&mut stream, "MAIL FROM:<me@example.org>").await;
    assert!(read_line(&mut stream).await.starts_with("250"));
    send_line(&mut stream, "RCPT TO:<ok@example.org>").await;
    assert!(read_line(&mut stream).await.starts_with("250"));

    send_line(&mut stream, "DATA").await;
    assert!(read_line(&mut stream).await.starts_with("354"));
    send_line(&mut stream, "Subject: hi").await;
    send_line(&mut stream, "Hello.").await;
    send_line(&mut stream, ".").await;
    assert!(read_line(&mut stream).await.starts_with("250"));

    send_line(&mut stream, "QUIT").await;
    assert!(read_line(&mut stream).await.starts_with("221"));

    let accepted = fake.accepted();
    assert_eq!(accepted.len(), 1);
    assert!(accepted[0].contains("Subject: hi"), "{accepted:?}");
    assert!(accepted[0].contains("Hello."), "{accepted:?}");
    let commands = fake.commands();
    assert!(
        !commands
            .iter()
            .any(|line| line.contains("dGVzdAB0ZXN0AHRlc3Q=")),
        "credentials must never be recorded: {commands:?}"
    );
}

#[tokio::test]
async fn fake_smtp_rejects_an_unknown_recipient_with_550() {
    let fake = FakeSmtp::spawn().await;
    let mut stream = connect_plain(fake.port).await;
    let _ = read_line(&mut stream).await;
    send_line(&mut stream, "EHLO tester").await;
    let _ = read_until(&mut stream, "250 8BITMIME\r\n").await;
    send_line(&mut stream, "MAIL FROM:<me@example.org>").await;
    assert!(read_line(&mut stream).await.starts_with("250"));
    send_line(&mut stream, "RCPT TO:<nobody@example.net>").await;
    let response = read_line(&mut stream).await;
    assert!(response.starts_with("550"), "{response}");
    assert!(fake.commands().iter().any(|line| line.contains("RCPT TO")));
}

#[tokio::test]
async fn fake_smtp_rejects_an_unknown_sender_with_550() {
    // The relay rule: `MAIL FROM` from an address the fake does not relay for
    // is refused with 550, so a wrong sender is visible before any RCPT.
    let fake = FakeSmtp::spawn().await;
    let mut stream = connect_plain(fake.port).await;
    let _ = read_line(&mut stream).await;
    send_line(&mut stream, "EHLO tester").await;
    let _ = read_until(&mut stream, "250 8BITMIME\r\n").await;
    send_line(&mut stream, "MAIL FROM:<stranger@example.net>").await;
    let response = read_line(&mut stream).await;
    assert!(response.starts_with("550"), "{response}");
    assert!(fake
        .commands()
        .iter()
        .any(|line| line.contains("MAIL FROM")));
}
