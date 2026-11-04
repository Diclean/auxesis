//! Dial + TLS against the in-process fake. Offline only.

use std::time::Duration;

use aux_fakemail::{fixture_mailbox, FakeImap};
use aux_mail::config::{ImapSettings, Security};
use aux_mail::dial::Dialer;
use aux_mail::error::{Lang, MailError};
use aux_mail::limits::Limits;
use aux_mail::mailbox;

const CONNECT: Duration = Duration::from_secs(2);

fn settings(fake: &FakeImap, security: Security) -> ImapSettings {
    ImapSettings {
        host: "127.0.0.1".to_string(),
        port: fake.port,
        security,
        username: None,
        ca_file: None,
    }
}

#[tokio::test]
async fn implicit_tls_succeeds_with_the_test_verifier() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(2)).await;
    let cert = fake.cert().expect("tls fake has a cert");
    let dialer = Dialer::with_client_config(cert.client_config(), CONNECT);
    let stream = dialer
        .connect(&fake.endpoint(Security::Tls))
        .await
        .expect("the test verifier accepts the fake cert");
    drop(stream);
    assert!(fake
        .commands()
        .iter()
        .any(|line| line.to_ascii_uppercase().contains("CAPABILITY")));
}

#[tokio::test]
async fn the_production_verifier_rejects_the_self_signed_cert() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let dialer = Dialer::new(CONNECT);
    let error = dialer
        .connect(&fake.endpoint(Security::Tls))
        .await
        .expect_err("a self-signed cert must be rejected");
    assert!(matches!(error, MailError::CertRejected { .. }), "{error:?}");
}

#[tokio::test]
async fn plain_never_upgrades_even_when_the_server_offers_starttls() {
    let fake = FakeImap::spawn_starttls(fixture_mailbox(1)).await;
    let dialer = Dialer::new(CONNECT);
    let stream = dialer
        .connect(&fake.endpoint(Security::Plain))
        .await
        .expect("plain connects");
    drop(stream);
    let commands = fake.commands();
    assert!(
        !commands
            .iter()
            .any(|line| line.to_ascii_uppercase().contains("STARTTLS")),
        "plain must never upgrade: {commands:?}"
    );
}

#[tokio::test]
async fn starttls_is_refused_when_not_advertised() {
    let fake = FakeImap::spawn(fixture_mailbox(1)).await;
    let dialer = Dialer::new(CONNECT);
    let error = dialer
        .connect(&fake.endpoint(Security::StartTls))
        .await
        .expect_err("no STARTTLS offered");
    assert!(matches!(error, MailError::NoStartTls { .. }), "{error:?}");
}

#[tokio::test]
async fn starttls_upgrade_succeeds_with_the_test_verifier() {
    let fake = FakeImap::spawn_starttls(fixture_mailbox(1)).await;
    let cert = fake.cert().expect("starttls fake has a cert");
    let dialer = Dialer::with_client_config(cert.client_config(), CONNECT);
    let stream = dialer
        .connect(&fake.endpoint(Security::StartTls))
        .await
        .expect("the test verifier accepts the upgrade");
    drop(stream);
    assert!(fake
        .commands()
        .iter()
        .any(|line| line.to_ascii_uppercase().contains("STARTTLS")));
}

#[tokio::test]
async fn plain_login_with_a_password_is_refused_before_dialing() {
    let fake = FakeImap::spawn(fixture_mailbox(3)).await;
    let dialer = Dialer::new(CONNECT);
    let error = mailbox::login(
        &settings(&fake, Security::Plain),
        "me@example.org",
        "secret",
        &dialer,
        &Limits::tight(),
    )
    .await
    .expect_err("plain must never carry a password");
    assert!(
        matches!(error, MailError::InsecurePassword { .. }),
        "{error:?}"
    );
    assert!(
        fake.commands().is_empty(),
        "no LOGIN may reach the wire: {:?}",
        fake.commands()
    );
    assert_eq!(
        fake.connections(),
        0,
        "the refusal must happen before the socket"
    );
}

#[tokio::test]
async fn mailbox_login_and_logout_over_tls() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(3)).await;
    let cert = fake.cert().expect("tls fake has a cert");
    let limits = Limits::default();
    let dialer = Dialer::with_client_config(cert.client_config(), limits.connect_timeout);
    let session = mailbox::login(
        &settings(&fake, Security::Tls),
        "me@example.org",
        "secret",
        &dialer,
        &limits,
    )
    .await
    .expect("login");
    mailbox::logout(session, CONNECT).await.expect("logout");
    let commands = fake.commands();
    assert!(commands
        .iter()
        .any(|line| line.to_ascii_uppercase().contains("LOGIN")));
    assert!(commands
        .iter()
        .any(|line| line.to_ascii_uppercase().contains("LOGOUT")));
}

#[tokio::test]
async fn a_bad_password_maps_to_auth() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let cert = fake.cert().expect("tls fake has a cert");
    let limits = Limits::default();
    let dialer = Dialer::with_client_config(cert.client_config(), limits.connect_timeout);
    let error = mailbox::login(
        &settings(&fake, Security::Tls),
        "me@example.org",
        "wrong-password",
        &dialer,
        &limits,
    )
    .await
    .expect_err("bad password");
    assert!(matches!(error, MailError::Auth), "{error:?}");
}

/// A canary the hostile fakes echo; it must be absent from every rendered error.
const CANARY: &str = "canary-password-abc123";

/// Log in to `fake` with the canary password and return the refusal.
async fn login_error(fake: FakeImap) -> MailError {
    let cert = fake.cert().expect("tls fake has a cert");
    // Short budgets: a fake whose answer is ignored cannot hold the test open.
    let limits = limits_with(Duration::from_secs(3), Duration::from_secs(2));
    let dialer = Dialer::with_client_config(cert.client_config(), limits.connect_timeout);
    mailbox::login(
        &settings(&fake, Security::Tls),
        "me@example.org",
        CANARY,
        &dialer,
        &limits,
    )
    .await
    .expect_err("the hostile server must fail the login")
}

/// The canary must be absent from the Display, Debug and EN/FR messages, and
/// from every `source()` in the chain.
fn assert_no_canary(error: &MailError) {
    let en = error.user_message(Lang::En);
    let fr = error.user_message(Lang::Fr);
    let mut texts = vec![
        ("Display".to_string(), error.to_string()),
        ("Debug".to_string(), format!("{error:?}")),
        (
            "EN message".to_string(),
            format!("{} {} {}", en.title, en.cause, en.action),
        ),
        (
            "FR message".to_string(),
            format!("{} {} {}", fr.title, fr.cause, fr.action),
        ),
    ];
    let mut source = std::error::Error::source(error);
    while let Some(next) = source {
        texts.push(("source".to_string(), format!("{next}")));
        texts.push(("source Debug".to_string(), format!("{next:?}")));
        source = next.source();
    }
    for (label, text) in texts {
        assert!(
            !text.contains(CANARY),
            "{label} leaked the server-echoed password: {text}"
        );
    }
}

#[tokio::test]
async fn a_hostile_login_rejection_never_leaks_the_password() {
    // This fake echoes the whole LOGIN line — password included — in its NO.
    let error = login_error(FakeImap::spawn_tls_echoing_login(fixture_mailbox(1)).await).await;
    assert!(matches!(error, MailError::Auth), "{error:?}");
    assert_no_canary(&error);
}

#[tokio::test]
async fn an_untagged_garbage_login_response_never_leaks_the_password() {
    let error = login_error(FakeImap::spawn_tls_untagged_garbage(fixture_mailbox(1)).await).await;
    assert_no_canary(&error);
}

#[tokio::test]
async fn a_malformed_tagged_login_response_never_leaks_the_password() {
    let error =
        login_error(FakeImap::spawn_tls_malformed_login_reply(fixture_mailbox(1)).await).await;
    assert_no_canary(&error);
}

#[tokio::test]
async fn a_login_dropped_after_echoing_never_leaks_the_password() {
    let error = login_error(FakeImap::spawn_tls_dropping_login(fixture_mailbox(1)).await).await;
    assert_no_canary(&error);
}

#[tokio::test]
async fn a_certificate_for_another_name_is_rejected() {
    // The server presents a certificate issued for `localhost`; the dialer
    // asks for `127.0.0.1`, so the pinned verifier must refuse the name.
    let fake = FakeImap::spawn_tls_named(fixture_mailbox(1), "localhost").await;
    let cert = fake.cert().expect("tls fake has a cert");
    let dialer = Dialer::with_client_config(cert.client_config(), CONNECT);
    let error = dialer
        .connect(&fake.endpoint(Security::Tls))
        .await
        .expect_err("the pinned name must not match 127.0.0.1");
    assert!(matches!(error, MailError::CertRejected { .. }), "{error:?}");
}

fn limits_with(call_timeout: Duration, connect_timeout: Duration) -> Limits {
    Limits::new(
        64 * 1024,
        512 * 1024,
        5,
        call_timeout,
        connect_timeout,
        1,
        1,
    )
}

#[tokio::test]
async fn a_silent_server_is_bounded_by_the_connect_budget() {
    let fake = FakeImap::spawn_silent().await;
    let limits = limits_with(Duration::from_secs(5), Duration::from_millis(100));
    let dialer = Dialer::from_limits(&limits);
    let started = tokio::time::Instant::now();
    let error = mailbox::login(
        &settings(&fake, Security::StartTls),
        "me@example.org",
        "secret",
        &dialer,
        &limits,
    )
    .await
    .expect_err("a server that never greets must time out");
    assert!(
        matches!(error, MailError::Timeout { budget } if budget == limits.connect_timeout),
        "{error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the connect budget, not the call budget, must fire"
    );
}

#[tokio::test]
async fn the_whole_login_runs_inside_the_call_budget() {
    let fake = FakeImap::spawn_silent().await;
    // connect 5 s, call 100 ms: only the outer, whole-login budget can fire.
    let limits = limits_with(Duration::from_millis(100), Duration::from_secs(5));
    let dialer = Dialer::from_limits(&limits);
    let started = tokio::time::Instant::now();
    let error = mailbox::login(
        &settings(&fake, Security::StartTls),
        "me@example.org",
        "secret",
        &dialer,
        &limits,
    )
    .await
    .expect_err("the whole login must be bounded");
    assert!(
        matches!(error, MailError::Timeout { budget } if budget == limits.call_timeout),
        "{error:?}"
    );
    assert!(
        started.elapsed() < limits.connect_timeout,
        "the call budget must fire before the connect budget"
    );
}
