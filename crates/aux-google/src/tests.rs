use super::*;
use std::collections::HashMap;
use std::io::Write;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const GMAIL_ONLY: &[Scope] = &[Scope::GmailReadonly];
const CALENDAR_ONLY: &[Scope] = &[Scope::CalendarEventsReadonly];
const EMAIL: &str = "alex@example.test";
const ACCESS_CANARY: &str = "access-token-canary";
const REFRESH_CANARY: &str = "refresh-token-canary";
const ACCOUNT_A_REFRESH: &str = "account-a-refresh-canary";
const ACCOUNT_B_REFRESH: &str = "account-b-refresh-canary";
const CODE_CANARY: &str = "authorization-code-canary";
const SECRET_CANARY: &str = "client-secret-canary";

#[test]
fn pkce_rfc_7636_appendix_b_vector() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        pkce_challenge(verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn scope_set_has_exactly_the_five_supported_minimal_permissions() {
    assert_eq!(Scope::ALL.len(), 5);
    assert_eq!(
        Scope::ALL.map(Scope::as_google_scope),
        [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/calendar.events.readonly",
            "https://www.googleapis.com/auth/calendar.events",
        ]
    );
    // `gmail.compose` is the narrowest drafts scope: it is not `gmail.modify`
    // and not the full-mailbox scope.
    assert!(Scope::ALL
        .iter()
        .all(|scope| !scope.as_google_scope().contains("gmail.modify")
            && !scope.as_google_scope().ends_with("/mail")));
}

#[test]
fn consent_scopes_add_only_gmail_compose_to_the_reads_and_never_gmail_send() {
    assert_eq!(
        CONNECT_SCOPES,
        [
            Scope::GmailReadonly,
            Scope::GmailCompose,
            Scope::CalendarEventsReadonly,
        ]
    );
    assert!(!CONNECT_SCOPES.contains(&Scope::GmailSend));
    assert!(CONNECT_SCOPES.contains(&Scope::GmailReadonly));
    assert!(CONNECT_SCOPES.contains(&Scope::CalendarEventsReadonly));
    // Consent is a strict superset of the read-only subset: adding drafts
    // never drops a read permission.
    assert!(READ_SCOPES
        .iter()
        .all(|scope| CONNECT_SCOPES.contains(scope)));
}

#[test]
fn send_scopes_stay_disjoint_from_connect_scopes_and_reads() {
    assert_eq!(SEND_SCOPES, [Scope::GmailSend, Scope::CalendarEvents]);
    // Connecting never requests a send or event-write permission.
    assert!(CONNECT_SCOPES
        .iter()
        .all(|scope| !SEND_SCOPES.contains(scope)));
    assert!(READ_SCOPES.iter().all(|scope| !SEND_SCOPES.contains(scope)));
    // The enable-sending request is the union, not the send-only subset.
    assert!(SEND_SCOPES
        .iter()
        .all(|scope| SEND_WITH_CONNECT_SCOPES.contains(scope)));
    assert!(CONNECT_SCOPES
        .iter()
        .all(|scope| SEND_WITH_CONNECT_SCOPES.contains(scope)));
}

#[tokio::test]
async fn enable_sending_scopes_requests_and_stores_the_connect_union() {
    let union = CONNECT_SCOPES
        .iter()
        .chain(SEND_SCOPES.iter())
        .copied()
        .collect::<Vec<_>>();
    let server = FakeGoogleServer::start(
        200,
        success_json_for_scopes(&union, Some(REFRESH_CANARY)),
        200,
    )
    .await;
    let home = new_home();
    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    );

    connection
        .enable_sending_scopes(&FakeBrowser::default())
        .await
        .unwrap();
    assert_eq!(server.auth_hits.load(Ordering::SeqCst), 1);
    assert_eq!(server.token_hits.load(Ordering::SeqCst), 1);

    // The authorize request asks for the union and never asks Google to carry
    // over scopes from an earlier grant: that would let a plain `connect` pick
    // up a write permission it did not request.
    let query = server.authorize_query.lock().unwrap().clone().unwrap();
    assert!(!query.contains("include_granted_scopes"), "{query}");
    let requested = url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "scope")
        .map(|(_, value)| value.into_owned())
        .expect("the authorize URL carries a scope");
    let requested: Vec<&str> = requested.split(' ').collect();
    for scope in CONNECT_SCOPES.iter().chain(SEND_SCOPES.iter()) {
        assert!(requested.contains(&scope.as_google_scope()), "{query}");
    }

    // The stored grant keeps every read and draft permission.
    let store = GrantStore::new(home.as_path().to_path_buf(), mac_account_key(CLIENT_ID));
    let grant = store.load().unwrap().unwrap();
    for scope in &union {
        assert!(grant.scopes.contains(scope), "missing {scope:?}");
    }
    assert!(!connection.needs_reconsent());

    // A plain connect still never asks Google for `gmail.send`.
    let plain = FakeGoogleServer::start(
        200,
        success_json_for_scopes(&CONNECT_SCOPES, Some(REFRESH_CANARY)),
        200,
    )
    .await;
    let plain_home = new_home();
    let plain_connection = MacConnection::for_test(
        plain_home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            plain.url("/authorize"),
            plain.url("/token"),
            plain.url("/revoke"),
        ),
    );
    plain_connection
        .connect(&FakeBrowser::default(), &CONNECT_SCOPES)
        .await
        .unwrap();
    let plain_query = plain.authorize_query.lock().unwrap().clone().unwrap();
    assert!(
        !plain_query.contains("include_granted_scopes"),
        "{plain_query}"
    );
    let plain_scope = url::form_urlencoded::parse(plain_query.as_bytes())
        .find(|(key, _)| key == "scope")
        .map(|(_, value)| value.into_owned())
        .expect("the authorize URL carries a scope");
    let plain_scopes: Vec<&str> = plain_scope.split(' ').collect();
    assert!(
        !plain_scopes.contains(&Scope::GmailSend.as_google_scope()),
        "{plain_query}"
    );
    assert!(
        !plain_scopes.contains(&Scope::CalendarEvents.as_google_scope()),
        "{plain_query}"
    );
}

/// Google can still hold an older write grant. A plain `connect` must store
/// only what it asked for, never a scope it did not request.
#[tokio::test]
async fn plain_connect_never_stores_a_scope_it_did_not_request() {
    let mut granted = CONNECT_SCOPES.to_vec();
    granted.push(Scope::GmailSend);
    let server = FakeGoogleServer::start(
        200,
        success_json_for_scopes(&granted, Some(REFRESH_CANARY)),
        200,
    )
    .await;
    let home = new_home();
    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    );
    let client = connection
        .connect(&FakeBrowser::default(), &CONNECT_SCOPES)
        .await
        .unwrap();

    let store = GrantStore::new(home.as_path().to_path_buf(), mac_account_key(CLIENT_ID));
    let grant = store.load().unwrap().unwrap();
    assert!(
        !grant.scopes.contains(&Scope::GmailSend),
        "{:?}",
        grant.scopes
    );
    assert!(
        client.access_token(&[Scope::GmailSend]).await.is_err(),
        "the cached token must not carry an unrequested scope"
    );
    assert_eq!(
        client.access_token(&CONNECT_SCOPES).await.unwrap().as_str(),
        ACCESS_CANARY
    );
}

#[test]
fn access_token_formatting_is_redacted() {
    let token = AccessToken(SecretString::new(ACCESS_CANARY.to_string()));
    assert_eq!(token.to_string(), "[REDACTED]");
    assert_eq!(format!("{token:?}"), "AccessToken([REDACTED])");
    assert!(!token.to_string().contains(ACCESS_CANARY));
    assert!(!format!("{token:?}").contains(ACCESS_CANARY));
}

#[test]
fn app_credentials_prefer_process_environment_then_existing_agent_env_store() {
    let directory = tempfile::tempdir().unwrap();
    let env_path = directory.path().join(".env");
    std::fs::write(
        &env_path,
        "AUXESIS_GOOGLE_CLIENT_ID=file-client-id\nAUXESIS_GOOGLE_CLIENT_SECRET=file-client-secret\n",
    )
    .unwrap();
    let dotenv = aux_providers::key::AgentEnvStore::load(&env_path).unwrap();

    let credentials = resolve_app_credentials_with(
        Some("environment-client-id".to_string()),
        None,
        Some(&dotenv),
    )
    .unwrap();
    assert_eq!(credentials.client_id, "environment-client-id");
    assert_eq!(credentials.client_secret.expose(), "file-client-secret");
    assert_eq!(credentials.client_secret.to_string(), "[REDACTED]");
}

#[tokio::test]
async fn installed_app_flow_uses_state_pkce_offline_consent_and_static_page() {
    let body = success_json(Some(REFRESH_CANARY));
    let server = FakeGoogleServer::start(200, body, 200).await;
    let home = new_home();
    let client = test_client(EMAIL, &home, &server);
    let opener = FakeBrowser::default();

    let authorization = client
        .authorize(&opener, GMAIL_ONLY, kernel_core::Lang::Fr)
        .await;
    assert!(
        authorization.is_ok(),
        "authorization failed: {:?}; auth_hits={}, token_hits={}",
        authorization.err(),
        server.auth_hits.load(Ordering::SeqCst),
        server.token_hits.load(Ordering::SeqCst)
    );
    let token = client.access_token(GMAIL_ONLY).await.unwrap();
    assert_eq!(token.as_str(), ACCESS_CANARY);
    assert_eq!(server.auth_hits.load(Ordering::SeqCst), 1);
    assert_eq!(server.token_hits.load(Ordering::SeqCst), 1);
    assert_eq!(server.auth_request_valid.load(Ordering::SeqCst), 1);
    assert_eq!(server.code_exchange_valid.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while opener.page_seen.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let grant = client.grant_store().load().unwrap().unwrap();
    assert_eq!(grant.refresh.expose(), REFRESH_CANARY);
    assert_eq!(grant.scopes, GMAIL_ONLY);
    let serialized = std::fs::read_to_string(client.grant_store().path()).unwrap();
    assert!(!serialized.contains(EMAIL));
    assert!(
        client
            .grant_store()
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            == format!("google-auth-{}.json", account_email_hash(EMAIL).unwrap())
    );
}

#[tokio::test]
async fn callback_rejects_state_mismatch() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(1)));
    let response = send_callback(
        address,
        &format!("127.0.0.1:{}", address.port()),
        "wrong-state",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
    send_callback(
        address,
        &format!("127.0.0.1:{}", address.port()),
        "expected-state",
    )
    .await;
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
}

#[tokio::test]
async fn callback_rejects_wrong_host() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(1)));
    let response = send_callback(address, "localhost:9999", "expected-state").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
    send_callback(
        address,
        &format!("127.0.0.1:{}", address.port()),
        "expected-state",
    )
    .await;
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
}

#[tokio::test]
async fn invalid_loopback_probe_does_not_consume_oauth_callback() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(1)));
    let host = format!("127.0.0.1:{}", address.port());
    for request in [
        format!("GET /favicon.ico HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        format!("GET /oauth2/callback HTTP/1.1\r\nHost: {host}\r\nBadHeader\r\n\r\n"),
    ] {
        let response = send_raw_request(address, &request).await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
    }
    send_callback(address, &host, "expected-state").await;
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
}

#[tokio::test]
async fn callback_listener_accepts_only_one_request() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("state-once", Duration::from_secs(1)));
    let response = send_raw_request(
        address,
        &format!(
            "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            address.port()
        ),
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
    send_callback(
        address,
        &format!("127.0.0.1:{}", address.port()),
        "state-once",
    )
    .await;
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn slow_partial_callback_request_does_not_block_real_redirect() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(2)));
    let mut slow = TcpStream::connect(address).await.unwrap();
    let partial = format!(
        "GET /oauth2/callback?code={CODE_CANARY}&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n",
        address.port()
    );
    slow.write_all(partial.as_bytes()).await.unwrap();

    let response = send_callback(
        address,
        &format!("127.0.0.1:{}", address.port()),
        "expected-state",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .expose(),
        CODE_CANARY
    );
}

#[tokio::test]
async fn valid_callback_succeeds_when_all_pending_slots_are_slow() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(3)));
    let mut idle = Vec::new();
    for _ in 0..12 {
        idle.push(TcpStream::connect(address).await.unwrap());
    }

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        send_callback(
            address,
            &format!("127.0.0.1:{}", address.port()),
            "expected-state",
        ),
    )
    .await
    .expect("callback should not wait for idle handlers");
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
    drop(idle);
}

#[tokio::test]
async fn valid_callback_started_before_flow_deadline_survives_full_handler_cap() {
    raise_nofile_limit_for_callback_floods();
    let (listener, address) = callback::test_listener_with(256, Duration::from_millis(500)).await;
    let host = format!("127.0.0.1:{}", address.port());
    // Start accepting before filling the handler budget. Leaving these sockets
    // in the kernel backlog is platform-dependent (macOS may reset connects
    // before the backlog can hold all 256).
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_millis(300)));
    let mut idle = Vec::new();
    for _ in 0..256 {
        idle.push(TcpStream::connect(address).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(40)).await;

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        send_callback(address, &host, "expected-state"),
    )
    .await
    .expect("a complete callback should survive full-handler eviction and the flow deadline");
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
    drop(idle);
}

#[tokio::test]
async fn flood_of_1024_idle_sockets_followed_by_valid_callback() {
    raise_nofile_limit_for_callback_floods();
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(10)));
    let mut idle = Vec::new();
    for _ in 0..1024 {
        idle.push(TcpStream::connect(address).await.unwrap());
    }

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        send_callback(
            address,
            &format!("127.0.0.1:{}", address.port()),
            "expected-state",
        ),
    )
    .await
    .expect("callback should be served after evicting the oldest idle handler");
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .expose(),
        CODE_CANARY
    );
    drop(idle);
}

#[tokio::test]
async fn handler_budget_preserves_a_valid_partial_callback_when_new_idle_sockets_arrive() {
    raise_nofile_limit_for_callback_floods();
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(10)));
    let mut callback_stream = TcpStream::connect(address).await.unwrap();
    let callback_prefix = format!(
        "GET /oauth2/callback?code={CODE_CANARY}&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1"
    );
    callback_stream
        .write_all(callback_prefix.as_bytes())
        .await
        .unwrap();
    // Let the handler consume the partial header before filling its budget.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut idle = Vec::new();
    for _ in 0..1024 {
        idle.push(TcpStream::connect(address).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    callback_stream
        .write_all(format!(":{}\r\nConnection: close\r\n\r\n", address.port()).as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        callback_stream.read_to_end(&mut response),
    )
    .await
    .expect("the partial callback should survive newer idle connections")
    .unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
    drop(idle);
}

#[tokio::test]
async fn handler_budget_rejects_new_socket_when_all_handlers_have_received_bytes() {
    let (listener, address) = callback::test_listener_with(4, Duration::ZERO).await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(10)));
    let mut in_progress = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"G").await.unwrap();
        in_progress.push(stream);
    }
    // Give each handler a chance to read its first byte before overflowing
    // the budget with a fifth connection.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut rejected = TcpStream::connect(address).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut byte))
        .await
        .expect("the over-budget socket should be closed immediately")
        .unwrap();
    assert_eq!(read, 0);

    for stream in in_progress.iter_mut().take(3) {
        stream
            .write_all(
                format!(
                    "ET /invalid HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
    }

    let valid = &mut in_progress[3];
    valid
        .write_all(
            format!(
                "ET /oauth2/callback?code={CODE_CANARY}&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                address.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    valid.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(task.await.unwrap().unwrap().expose(), CODE_CANARY);
}

#[tokio::test]
async fn callback_header_limit_rejects_the_8193rd_byte() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(3)));
    let request = "A".repeat(8193);
    let response = send_raw_request(address, &request).await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
    assert_eq!(task.await.unwrap().unwrap_err(), AuthError::Timeout);
}

#[tokio::test]
async fn callback_after_flow_deadline_is_refused() {
    let (listener, address) = callback::test_listener().await;
    // Connect before the flow starts, so the callback is already in flight when
    // the deadline passes. Never reconnect to the freed port: another process
    // may own it by then, which made this check flaky.
    let mut late = TcpStream::connect(address).await.unwrap();
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_millis(40)));
    assert_eq!(task.await.unwrap().unwrap_err(), AuthError::Timeout);
    let request = format!(
        "GET /oauth2/callback?state=expected-state&code=late-code HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        address.port()
    );
    let _ = late.write_all(request.as_bytes()).await;
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), late.read_to_end(&mut response))
        .await
        .expect("a refused late callback should be closed");
    assert!(
        !response.starts_with(b"HTTP/1.1 200"),
        "a callback after the flow deadline was served: {}",
        String::from_utf8_lossy(&response)
    );
}

#[tokio::test]
async fn slowloris_byte_drip_is_cut_at_the_five_second_header_deadline() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("expected-state", Duration::from_secs(8)));
    let mut slow = TcpStream::connect(address).await.unwrap();
    slow.write_all(b"G").await.unwrap();
    let start = tokio::time::Instant::now();
    let writer = tokio::spawn(async move {
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if slow.write_all(b"A").await.is_err() {
                break;
            }
        }
        slow
    });
    let mut slow = writer.await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), slow.read(&mut byte))
        .await
        .expect("the partial request should be closed by its header deadline");
    let elapsed = start.elapsed();
    assert!(
        matches!(&read, Ok(0))
            || matches!(
                &read,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset
            ),
        "the partial request should be closed by EOF or connection reset: {read:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(4),
        "closed too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(7),
        "closed too late: {elapsed:?}"
    );
    assert_eq!(task.await.unwrap().unwrap_err(), AuthError::Timeout);
}

#[cfg(unix)]
fn raise_nofile_limit_for_callback_floods() {
    const REQUIRED: libc::rlim_t = 8192;
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the supplied rlimit structure on success.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
        0
    );
    // SAFETY: the preceding successful getrlimit initialized the value.
    let mut limit = unsafe { limit.assume_init() };
    if limit.rlim_cur < REQUIRED {
        limit.rlim_cur = REQUIRED.min(limit.rlim_max);
        // SAFETY: the new soft limit is no greater than the process hard limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    }
    assert!(
        limit.rlim_cur >= REQUIRED,
        "host hard limit is below {REQUIRED}"
    );
}

#[tokio::test]
async fn second_valid_callback_does_not_replace_the_first() {
    let (listener, address) = callback::test_listener().await;
    let task = tokio::spawn(listener.receive("once-state", Duration::from_secs(2)));
    let host = format!("127.0.0.1:{}", address.port());
    let first_response = send_raw_request(
        address,
        &format!(
            "GET /oauth2/callback?code=first-code&state=once-state HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(String::from_utf8_lossy(&first_response).starts_with("HTTP/1.1 200"));
    assert_eq!(task.await.unwrap().unwrap().expose(), "first-code");

    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn callback_listener_times_out() {
    let (listener, _) = callback::test_listener().await;
    let error = listener
        .receive("state", Duration::from_millis(20))
        .await
        .unwrap_err();
    assert_eq!(error, AuthError::Timeout);
}

#[tokio::test]
async fn refresh_is_single_flight_for_concurrent_callers() {
    let server = FakeGoogleServer::start(200, success_json(None), 200).await;
    let home = new_home();
    let client = Arc::new(test_client(EMAIL, &home, &server));
    client
        .grant_store()
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    server.delay_token.store(1, Ordering::SeqCst);

    let mut calls = Vec::new();
    for _ in 0..16 {
        let client = Arc::clone(&client);
        calls.push(tokio::spawn(async move {
            client.access_token(GMAIL_ONLY).await.unwrap()
        }));
    }
    for call in calls {
        assert_eq!(call.await.unwrap().as_str(), ACCESS_CANARY);
    }
    assert_eq!(server.token_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn access_token_cache_observes_the_sixty_second_expiry_skew() {
    let server = FakeGoogleServer::start(200, success_json_with_expiry(60), 200).await;
    let home = new_home();
    let client = test_client(EMAIL, &home, &server);
    client
        .grant_store()
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    client.access_token(GMAIL_ONLY).await.unwrap();
    client.access_token(GMAIL_ONLY).await.unwrap();
    assert_eq!(server.token_hits.load(Ordering::SeqCst), 2);

    let server = FakeGoogleServer::start(200, success_json_with_expiry(61), 200).await;
    let home = new_home();
    let client = test_client(EMAIL, &home, &server);
    client
        .grant_store()
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    client.access_token(GMAIL_ONLY).await.unwrap();
    client.access_token(GMAIL_ONLY).await.unwrap();
    assert_eq!(server.token_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_grant_requires_reauthentication_and_removes_stale_grant() {
    let server = FakeGoogleServer::start(
        400,
        format!(r#"{{"error":"invalid_grant","error_description":"{REFRESH_CANARY}"}}"#),
        200,
    )
    .await;
    let home = new_home();
    let client = test_client(EMAIL, &home, &server);
    client
        .grant_store()
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let path = client.grant_store().path();

    let error = client.access_token(GMAIL_ONLY).await.unwrap_err();
    assert_eq!(error, AuthError::ReauthRequired);
    assert_eq!(error.to_string(), "Reconnect to Google");
    assert!(!path.exists());
    assert!(!format!("{error:?}{error}").contains(REFRESH_CANARY));
}

#[tokio::test]
async fn disconnect_removes_grant_even_when_revoke_network_fails() {
    let server = FakeGoogleServer::start(200, success_json(None), 200).await;
    let home = new_home();
    let closed = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let closed_addr = closed.local_addr().unwrap();
    drop(closed);
    let endpoints = OAuthEndpoints::test(
        server.url("/authorize"),
        server.url("/token"),
        Url::parse(&format!("http://{closed_addr}/revoke")).unwrap(),
    );
    let client = GoogleClient::for_test(EMAIL, home.as_path().to_path_buf(), endpoints);
    client
        .grant_store()
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let path = client.grant_store().path();

    assert_eq!(client.disconnect().await.unwrap_err(), AuthError::Network);
    assert!(!path.exists());
    assert_eq!(server.revoke_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn disconnect_posts_revoke_and_removes_the_local_grant() {
    let server = FakeGoogleServer::start(200, success_json(None), 200).await;
    let home = new_home();
    let client = test_client(EMAIL, &home, &server);
    client
        .grant_store()
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let path = client.grant_store().path();

    client.disconnect().await.unwrap();
    assert_eq!(server.revoke_hits.load(Ordering::SeqCst), 1);
    assert!(!path.exists());
}

#[tokio::test]
async fn oauth_clients_do_not_follow_redirects_off_google_hosts() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Both OAuth clients refuse redirects. If one followed the 302 it would
    // issue a second request to `/steal`; `/steal` must never be hit.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/steal"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/steal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    let home = new_home();
    let endpoint = |tail: &str| Url::parse(&format!("{}{tail}", server.uri())).expect("endpoint");
    let endpoints = || {
        OAuthEndpoints::test(
            endpoint("/authorize"),
            endpoint("/token"),
            endpoint("/revoke"),
        )
    };
    let client = GoogleClient::for_test(EMAIL, home.path.clone(), endpoints());

    // The token/refresh client built in `build_with_key`.
    let response = client.http.get(endpoint("/token")).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);

    // The revoke client built by `MacConnection::http_client()`.
    let mac = MacConnection::for_test(
        home.path.clone(),
        "desktop-client-id",
        "client-secret-canary",
        endpoints(),
    );
    let response = mac
        .http_client()
        .unwrap()
        .get(endpoint("/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2, "a redirect was followed");
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() == "/token"),
        "a request escaped the token endpoint"
    );
}

// ---------------------------------------------------------------------------
// Mac-wide connection (G4): no email, one key from the OAuth client id
// ---------------------------------------------------------------------------

const CLIENT_ID: &str = "desktop-client-id";
const CLIENT_SECRET: &str = "client-secret-canary";

#[test]
fn mac_account_key_is_a_stable_client_id_hash_that_never_needs_an_email() {
    let key = mac_account_key(CLIENT_ID);
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(key, mac_account_key(" Desktop-Client-Id "));
    assert_ne!(key, mac_account_key("another-client-id"));
    // An email address is never part of this key: two different addresses for
    // the same OAuth client land on the same Mac-wide connection.
    assert_eq!(mac_account_key(CLIENT_ID), mac_account_key(CLIENT_ID));
}

#[test]
fn grant_exists_only_accepts_the_exact_grant_file_name() {
    // The temp dir itself is the home: `tempfile` creates it, so the test
    // needs no raw `create_dir_all` and no allowlist exception.
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path();
    let key = mac_account_key(CLIENT_ID);
    assert!(!grant_exists(home, &key));
    std::fs::write(home.join(format!("google-auth-{key}.json")), b"{}").unwrap();
    assert!(grant_exists(home, &key));
    assert!(!grant_exists(home, "not-a-key"));
    assert!(!grant_exists(home, &"A".repeat(64)));
    assert!(!grant_exists(home, &"a".repeat(63)));
    // A symlink to a real file is not a grant this home wrote.
    #[cfg(unix)]
    {
        let linked = home.join(format!("google-auth-{}.json", "b".repeat(64)));
        std::os::unix::fs::symlink(home.join(format!("google-auth-{key}.json")), &linked).unwrap();
        assert!(!grant_exists(home, &"b".repeat(64)));
    }
}

#[tokio::test]
async fn mac_connection_connect_stores_a_grant_keyed_by_the_client_id_and_disconnect_removes_it() {
    let server = FakeGoogleServer::start(200, success_json(Some(REFRESH_CANARY)), 200).await;
    let home = new_home();
    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    );
    assert!(!connection.connected());

    let opener = FakeBrowser::default();
    let client = connection.connect(&opener, GMAIL_ONLY).await.unwrap();
    assert!(connection.connected());
    assert_eq!(server.auth_hits.load(Ordering::SeqCst), 1);
    // The fake counts an authorization request "valid" only when it carries the
    // email hint: this Mac-wide connection must never send one.
    assert_eq!(server.auth_request_valid.load(Ordering::SeqCst), 0);

    let key = mac_account_key(CLIENT_ID);
    let path = home.as_path().join(format!("google-auth-{key}.json"));
    assert!(
        path.exists(),
        "the grant is keyed by the client id, not an email"
    );
    let serialized = std::fs::read_to_string(&path).unwrap();
    assert!(!serialized.contains(EMAIL));
    assert!(!serialized.contains(CLIENT_ID));
    assert!(!serialized.contains(CLIENT_SECRET));
    assert_eq!(
        client.access_token(GMAIL_ONLY).await.unwrap().as_str(),
        ACCESS_CANARY
    );

    connection.disconnect().await.unwrap();
    assert!(!path.exists());
    assert!(!connection.connected());
    assert_eq!(server.revoke_hits.load(Ordering::SeqCst), 1);
}

#[test]
fn mac_connection_flags_old_grants_that_need_more_permissions() {
    let home = new_home();
    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::google(),
    );
    let client = connection.client().unwrap();
    client
        .grant_store()
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    assert!(connection.connected());
    assert!(connection.needs_reconsent());

    client
        .grant_store()
        .save(
            &SecretString::new(REFRESH_CANARY.to_string()),
            &CONNECT_SCOPES,
        )
        .unwrap();
    assert!(!connection.needs_reconsent());
}

/// Reconnect while switching accounts: Google answers a valid exchange but
/// grants no durable refresh token. The previous account's token must never be
/// re-used, and no grant may be written.
#[tokio::test]
async fn connect_without_a_refresh_token_never_reuses_the_previous_grant() {
    let server = FakeGoogleServer::start(200, success_json(None), 200).await;
    let home = new_home();
    let store = GrantStore::new(home.as_path().to_path_buf(), mac_account_key(CLIENT_ID));
    store
        .save(
            &SecretString::new(ACCOUNT_A_REFRESH.to_string()),
            CALENDAR_ONLY,
        )
        .unwrap();
    let path = store.path();
    let before = std::fs::read(&path).unwrap();

    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    );
    let Err(error) = connection
        .connect(&FakeBrowser::default(), GMAIL_ONLY)
        .await
    else {
        panic!("a token-less exchange must never connect the previous account");
    };
    assert_eq!(error, AuthError::DurableAccessMissing);
    assert!(!format!("{error:?}{error}").contains(ACCOUNT_A_REFRESH));

    // No grant was written: the file is byte-for-byte the previous one, still
    // account A's token and scopes. Account A is never silently adopted as B.
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let grant = store.load().unwrap().unwrap();
    assert_eq!(grant.refresh.expose(), ACCOUNT_A_REFRESH);
    assert_eq!(grant.scopes, CALENDAR_ONLY);
    assert!(connection.connected());

    // With nothing stored before, a token-less exchange writes nothing at all.
    let fresh_home = new_home();
    let fresh_store = GrantStore::new(
        fresh_home.as_path().to_path_buf(),
        mac_account_key(CLIENT_ID),
    );
    let fresh_connection = MacConnection::for_test(
        fresh_home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    );
    let Err(fresh_error) = fresh_connection
        .connect(&FakeBrowser::default(), GMAIL_ONLY)
        .await
    else {
        panic!("a token-less exchange must never connect");
    };
    assert_eq!(fresh_error, AuthError::DurableAccessMissing);
    assert!(!fresh_store.path().exists());
    assert!(!fresh_connection.connected());
}

/// A successful exchange writes exactly the new token: the previous account's
/// token never survives under the shared client-id key.
#[tokio::test]
async fn a_successful_exchange_writes_only_the_new_refresh_token() {
    let server = FakeGoogleServer::start(200, success_json(Some(ACCOUNT_B_REFRESH)), 200).await;
    let home = new_home();
    let store = GrantStore::new(home.as_path().to_path_buf(), mac_account_key(CLIENT_ID));
    store
        .save(
            &SecretString::new(ACCOUNT_A_REFRESH.to_string()),
            CALENDAR_ONLY,
        )
        .unwrap();

    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    );
    let client = connection
        .connect(&FakeBrowser::default(), GMAIL_ONLY)
        .await
        .unwrap();

    let grant = client.grant_store().load().unwrap().unwrap();
    assert_eq!(grant.refresh.expose(), ACCOUNT_B_REFRESH);
    assert_eq!(grant.scopes, GMAIL_ONLY);
    let serialized = std::fs::read_to_string(store.path()).unwrap();
    assert!(!serialized.contains(ACCOUNT_A_REFRESH));
}

/// A failed exchange (including a refused grant) leaves the previous grant
/// intact: it must not be deleted or rewritten behind the owner's back.
#[tokio::test]
async fn a_failed_exchange_leaves_the_previous_grant_unchanged() {
    let server =
        FakeGoogleServer::start(400, r#"{"error":"invalid_grant"}"#.to_string(), 200).await;
    let home = new_home();
    let store = GrantStore::new(home.as_path().to_path_buf(), mac_account_key(CLIENT_ID));
    store
        .save(
            &SecretString::new(ACCOUNT_A_REFRESH.to_string()),
            CALENDAR_ONLY,
        )
        .unwrap();
    let path = store.path();
    let before = std::fs::read(&path).unwrap();

    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    );
    let Err(error) = connection
        .connect(&FakeBrowser::default(), GMAIL_ONLY)
        .await
    else {
        panic!("a refused exchange must not connect");
    };
    assert_eq!(error, AuthError::ReauthRequired);

    assert!(path.exists());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let grant = store.load().unwrap().unwrap();
    assert_eq!(grant.refresh.expose(), ACCOUNT_A_REFRESH);
    assert_eq!(grant.scopes, CALENDAR_ONLY);
    assert!(connection.connected());
}

#[tokio::test]
async fn a_mac_connection_without_credentials_is_honestly_disconnected() {
    let home = new_home();
    let connection = MacConnection::for_test(
        home.as_path().to_path_buf(),
        CLIENT_ID,
        CLIENT_SECRET,
        OAuthEndpoints::test(
            Url::parse("http://127.0.0.1:1/authorize").unwrap(),
            Url::parse("http://127.0.0.1:1/token").unwrap(),
            Url::parse("http://127.0.0.1:1/revoke").unwrap(),
        ),
    );
    assert!(!connection.connected());
    // A disconnect with nothing stored is a no-op, never a request.
    connection.disconnect().await.unwrap();
}

#[tokio::test]
async fn errors_never_include_code_or_token_canaries() {
    let server = FakeGoogleServer::start(
        500,
        format!(
            r#"{{"error":"server_error","error_description":"{CODE_CANARY} {ACCESS_CANARY} {REFRESH_CANARY} {SECRET_CANARY}"}}"#
        ),
        200,
    )
    .await;
    let home = new_home();
    let client = test_client(EMAIL, &home, &server);
    let error = client
        .authorize(&FakeBrowser::default(), GMAIL_ONLY, kernel_core::Lang::En)
        .await
        .unwrap_err();
    let display = error.to_string();
    let debug = format!("{error:?}");
    for canary in [CODE_CANARY, ACCESS_CANARY, REFRESH_CANARY, SECRET_CANARY] {
        assert!(!display.contains(canary));
        assert!(!debug.contains(canary));
    }
}

#[cfg(unix)]
#[test]
fn grant_file_and_home_have_private_modes_and_no_plain_email_key() {
    use std::os::unix::fs::PermissionsExt;
    let home = new_home();
    let store = GrantStore::new(
        home.as_path().to_path_buf(),
        account_email_hash(EMAIL).unwrap(),
    );
    store
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    assert_eq!(
        std::fs::metadata(home.as_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!store
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains(EMAIL));
    assert!(!std::fs::read_to_string(store.path())
        .unwrap()
        .contains(EMAIL));
}

#[cfg(unix)]
#[test]
fn grant_store_refuses_symlinks_fifos_oversize_duplicate_keys_and_unknown_versions() {
    use std::os::unix::fs::symlink;
    let home = new_home();
    let store = GrantStore::new(
        home.as_path().to_path_buf(),
        account_email_hash(EMAIL).unwrap(),
    );
    kernel_core::paths::ensure_home(&home).unwrap();
    kernel_core::paths::ensure_home(&home).unwrap();
    std::fs::write(home.join("target"), "safe").unwrap();
    symlink(home.join("target"), store.path()).unwrap();
    assert_eq!(store.load().unwrap_err(), AuthError::Storage);
    std::fs::remove_file(store.path()).unwrap();

    let fifo = std::process::Command::new("mkfifo")
        .arg(store.path())
        .status()
        .unwrap();
    assert!(fifo.success());
    assert_eq!(store.load().unwrap_err(), AuthError::Storage);
    std::fs::remove_file(store.path()).unwrap();

    write_raw_grant(&store, &vec![b' '; 16 * 1024 + 1]);
    assert_eq!(store.load().unwrap_err(), AuthError::Storage);
    write_raw_grant(
        &store,
        br#"{"version":1,"version":1,"account_hash":"x","refresh_token":"r","scopes":["gmail_readonly"]}"#,
    );
    assert_eq!(store.load().unwrap_err(), AuthError::Storage);
    let version_999 = format!(
        r#"{{"version":999,"account_hash":"{}","refresh_token":"r","scopes":["gmail_readonly"]}}"#,
        account_email_hash(EMAIL).unwrap()
    );
    write_raw_grant(&store, version_999.as_bytes());
    assert_eq!(store.load().unwrap_err(), AuthError::Storage);
}

#[cfg(unix)]
#[test]
fn grant_store_refuses_hard_linked_token_files() {
    use std::os::unix::fs::MetadataExt;

    let home = new_home();
    let store = GrantStore::new(
        home.as_path().to_path_buf(),
        account_email_hash(EMAIL).unwrap(),
    );
    store
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let outside_home = tempfile::tempdir().unwrap();
    let linked_path = outside_home.path().join("linked-token.json");
    std::fs::hard_link(store.path(), &linked_path).unwrap();

    assert_eq!(store.load().unwrap_err(), AuthError::Storage);
    assert_eq!(
        store.save(
            &SecretString::new("replacement-token".to_string()),
            GMAIL_ONLY
        ),
        Err(AuthError::Storage)
    );
    assert_eq!(std::fs::metadata(store.path()).unwrap().nlink(), 2);
}

#[cfg(unix)]
#[test]
fn grant_load_refuses_hard_link_created_between_check_and_read() {
    use std::os::unix::fs::MetadataExt;

    let home = new_home();
    let store = GrantStore::new(
        home.as_path().to_path_buf(),
        account_email_hash(EMAIL).unwrap(),
    );
    store
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let outside_home = tempfile::tempdir().unwrap();
    let linked_path = outside_home.path().join("racing-token.json");

    let result = store.load_with_pre_read_hook(|| {
        std::fs::hard_link(store.path(), &linked_path).unwrap();
    });
    assert_eq!(result.unwrap_err(), AuthError::Storage);
    assert_eq!(std::fs::metadata(store.path()).unwrap().nlink(), 2);
}

#[cfg(unix)]
#[test]
fn grant_load_may_allow_a_hard_link_created_and_removed_during_one_read() {
    use std::os::unix::fs::MetadataExt;

    let home = new_home();
    let store = GrantStore::new(
        home.as_path().to_path_buf(),
        account_email_hash(EMAIL).unwrap(),
    );
    store
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let outside_home = tempfile::tempdir().unwrap();
    let transient_link = outside_home.path().join("transient-token.json");

    // A same-user process can create and remove a link between the before/after
    // fstats. Mode 0600 already allows this same user to read the grant, so the
    // store documents and accepts this residual case.
    let loaded = store
        .load_with_read_hooks(
            || {
                std::fs::hard_link(store.path(), &transient_link).unwrap();
            },
            || std::fs::remove_file(&transient_link).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(loaded.refresh.expose(), REFRESH_CANARY);
    assert_eq!(std::fs::metadata(store.path()).unwrap().nlink(), 1);
}

#[cfg(unix)]
#[test]
fn grant_load_refuses_a_hard_linked_path_entry_after_read() {
    use std::os::unix::fs::MetadataExt;

    let home = new_home();
    let store = GrantStore::new(
        home.as_path().to_path_buf(),
        account_email_hash(EMAIL).unwrap(),
    );
    store
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let outside_home = tempfile::tempdir().unwrap();
    let linked_path = outside_home.path().join("replacement-link.json");

    let result = store.load_with_path_entry_hook(|| {
        std::fs::hard_link(store.path(), &linked_path).unwrap();
    });
    assert_eq!(result.unwrap_err(), AuthError::Storage);
    assert_eq!(std::fs::metadata(store.path()).unwrap().nlink(), 2);
}

#[cfg(unix)]
#[test]
fn grant_save_refuses_a_hard_link_swap_after_load() {
    use std::os::unix::fs::MetadataExt;

    let home = new_home();
    let store = GrantStore::new(
        home.as_path().to_path_buf(),
        account_email_hash(EMAIL).unwrap(),
    );
    store
        .save(&SecretString::new(REFRESH_CANARY.to_string()), GMAIL_ONLY)
        .unwrap();
    let outside_home = tempfile::tempdir().unwrap();
    let linked_path = outside_home.path().join("swapped-token.json");

    let result = store.save_with_pre_rename_hook(
        &SecretString::new("replacement-token".to_string()),
        GMAIL_ONLY,
        || std::fs::hard_link(store.path(), &linked_path).unwrap(),
    );
    assert_eq!(result, Err(AuthError::Storage));
    assert_eq!(std::fs::metadata(store.path()).unwrap().nlink(), 2);
}

fn write_raw_grant(store: &GrantStore, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(store.path())
        .unwrap();
    file.write_all(bytes).unwrap();
}

struct TestHome {
    directory: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl TestHome {
    fn as_path(&self) -> &std::path::Path {
        let _ = &self.directory;
        &self.path
    }
}

impl Deref for TestHome {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        self.as_path()
    }
}

fn new_home() -> TestHome {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auxesis-home");
    TestHome { directory, path }
}

fn success_json(refresh: Option<&str>) -> String {
    success_json_parts(refresh, 3600)
}

fn success_json_with_expiry(expires_in: u64) -> String {
    success_json_parts(None, expires_in)
}

/// A token reply granting exactly `scopes`, for consent-union tests.
fn success_json_for_scopes(scopes: &[Scope], refresh: Option<&str>) -> String {
    let scope = scopes
        .iter()
        .map(|scope| scope.as_google_scope())
        .collect::<Vec<_>>()
        .join(" ");
    let refresh = refresh
        .map(|value| format!(r#", "refresh_token":"{value}""#))
        .unwrap_or_default();
    format!(r#"{{"access_token":"{ACCESS_CANARY}","expires_in":3600,"scope":"{scope}"{refresh}}}"#)
}

fn success_json_parts(refresh: Option<&str>, expires_in: u64) -> String {
    let refresh = refresh
        .map(|value| format!(r#", "refresh_token":"{value}""#))
        .unwrap_or_default();
    format!(
        r#"{{"access_token":"{ACCESS_CANARY}","expires_in":{expires_in},"scope":"{}"{refresh}}}"#,
        Scope::GmailReadonly.as_google_scope()
    )
}

fn test_client(email: &str, home: &std::path::Path, server: &FakeGoogleServer) -> GoogleClient {
    GoogleClient::for_test(
        email,
        home.to_path_buf(),
        OAuthEndpoints::test(
            server.url("/authorize"),
            server.url("/token"),
            server.url("/revoke"),
        ),
    )
}

async fn send_callback(address: std::net::SocketAddr, host: &str, state: &str) -> Vec<u8> {
    let request = format!(
        "GET /oauth2/callback?code={CODE_CANARY}&state={state} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    send_raw_request(address, &request).await
}

async fn send_raw_request(address: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    match stream.read_to_end(&mut response).await {
        Ok(_) => {}
        // Some platforms report a reset instead of EOF when the peer closes a
        // connection with unread data. Keep any response bytes already read;
        // callers still assert the expected HTTP status (including 200 for a
        // valid callback).
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => panic!("failed to read response: {error}"),
    }
    response
}

#[derive(Default)]
struct FakeBrowser {
    page_seen: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl UrlOpener for FakeBrowser {
    async fn open_url(&self, authorization: &Url) -> Result<(), UrlOpenError> {
        let host = authorization.host_str().ok_or(UrlOpenError)?;
        let port = authorization.port_or_known_default().ok_or(UrlOpenError)?;
        let target = format!(
            "{}{}",
            authorization.path(),
            authorization
                .query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        let mut stream = TcpStream::connect((host, port))
            .await
            .map_err(|_| UrlOpenError)?;
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| UrlOpenError)?;
        let response =
            tokio::time::timeout(Duration::from_secs(2), read_test_response(&mut stream))
                .await
                .map_err(|_| UrlOpenError)?
                .map_err(|_| UrlOpenError)?;
        let headers = String::from_utf8(response).map_err(|_| UrlOpenError)?;
        let location = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("Location:")
                    .or_else(|| line.strip_prefix("location:"))
            })
            .map(str::trim)
            .ok_or(UrlOpenError)?;
        let callback = Url::parse(location).map_err(|_| UrlOpenError)?;
        let callback_host = callback.host_str().ok_or(UrlOpenError)?;
        let callback_port = callback.port_or_known_default().ok_or(UrlOpenError)?;
        let callback_target = format!(
            "{}{}",
            callback.path(),
            callback
                .query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        let mut callback_stream = TcpStream::connect((callback_host, callback_port))
            .await
            .map_err(|_| UrlOpenError)?;
        let callback_request = format!(
                "GET {callback_target} HTTP/1.1\r\nHost: {callback_host}:{callback_port}\r\nConnection: close\r\n\r\n"
            );
        callback_stream
            .write_all(callback_request.as_bytes())
            .await
            .map_err(|_| UrlOpenError)?;
        let page_seen = Arc::clone(&self.page_seen);
        tokio::spawn(async move {
            if let Ok(response) = read_test_response(&mut callback_stream).await {
                if String::from_utf8_lossy(&response)
                    .contains("Connexion réussie, tu peux fermer cet onglet")
                {
                    page_seen.store(1, Ordering::SeqCst);
                }
            }
        });
        Ok(())
    }
}

struct FakeGoogleServer {
    address: std::net::SocketAddr,
    task: JoinHandle<()>,
    auth_hits: Arc<AtomicUsize>,
    token_hits: Arc<AtomicUsize>,
    revoke_hits: Arc<AtomicUsize>,
    auth_request_valid: Arc<AtomicUsize>,
    code_exchange_valid: Arc<AtomicUsize>,
    delay_token: Arc<AtomicUsize>,
    authorize_query: Arc<StdMutex<Option<String>>>,
}

#[derive(Clone)]
struct FakeState {
    token_reply: Arc<StdMutex<(u16, String)>>,
    revoke_status: Arc<StdMutex<u16>>,
    auth_hits: Arc<AtomicUsize>,
    token_hits: Arc<AtomicUsize>,
    revoke_hits: Arc<AtomicUsize>,
    auth_request_valid: Arc<AtomicUsize>,
    code_exchange_valid: Arc<AtomicUsize>,
    challenge: Arc<StdMutex<Option<String>>>,
    delay_token: Arc<AtomicUsize>,
    authorize_query: Arc<StdMutex<Option<String>>>,
}

impl FakeGoogleServer {
    async fn start(token_status: u16, token_body: String, revoke_status: u16) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let state = FakeState {
            token_reply: Arc::new(StdMutex::new((token_status, token_body))),
            revoke_status: Arc::new(StdMutex::new(revoke_status)),
            auth_hits: Arc::new(AtomicUsize::new(0)),
            token_hits: Arc::new(AtomicUsize::new(0)),
            revoke_hits: Arc::new(AtomicUsize::new(0)),
            auth_request_valid: Arc::new(AtomicUsize::new(0)),
            code_exchange_valid: Arc::new(AtomicUsize::new(0)),
            challenge: Arc::new(StdMutex::new(None)),
            delay_token: Arc::new(AtomicUsize::new(0)),
            authorize_query: Arc::new(StdMutex::new(None)),
        };
        let task = {
            let state = state.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let state = state.clone();
                    tokio::spawn(async move {
                        let _ = serve_fake_request(stream, state).await;
                    });
                }
            })
        };
        Self {
            address,
            task,
            auth_hits: Arc::clone(&state.auth_hits),
            token_hits: Arc::clone(&state.token_hits),
            revoke_hits: Arc::clone(&state.revoke_hits),
            auth_request_valid: Arc::clone(&state.auth_request_valid),
            code_exchange_valid: Arc::clone(&state.code_exchange_valid),
            delay_token: Arc::clone(&state.delay_token),
            authorize_query: Arc::clone(&state.authorize_query),
        }
    }

    fn url(&self, path: &str) -> Url {
        Url::parse(&format!("http://{}{}", self.address, path)).unwrap()
    }
}

impl Drop for FakeGoogleServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_fake_request(mut stream: TcpStream, state: FakeState) -> std::io::Result<()> {
    let (request, body) = read_fake_request(&mut stream).await?;
    let (method, target, _) = parse_request_line(&request)?;
    let request_url = Url::parse(&format!("http://fake{target}"))
        .map_err(|_| std::io::Error::other("bad test request"))?;
    match request_url.path() {
        "/authorize" if method == "GET" => {
            state.auth_hits.fetch_add(1, Ordering::SeqCst);
            *state.authorize_query.lock().unwrap() = request_url.query().map(str::to_string);
            let params = request_url
                .query_pairs()
                .into_owned()
                .collect::<HashMap<_, _>>();
            let mut redirect = params
                .get("redirect_uri")
                .map(|value| Url::parse(value).expect("redirect URL"))
                .ok_or_else(|| std::io::Error::other("missing redirect"))?;
            let oauth_state = params
                .get("state")
                .cloned()
                .ok_or_else(|| std::io::Error::other("missing state"))?;
            let code_challenge = params
                .get("code_challenge")
                .cloned()
                .ok_or_else(|| std::io::Error::other("missing code challenge"))?;
            let redirect_valid = redirect.scheme() == "http"
                && redirect.host_str() == Some("127.0.0.1")
                && redirect.path() == "/oauth2/callback";
            if params.get("client_id").map(String::as_str) == Some("desktop-client-id")
                && params.get("response_type").map(String::as_str) == Some("code")
                && params.get("scope").map(String::as_str)
                    == Some(Scope::GmailReadonly.as_google_scope())
                && params.get("login_hint").map(String::as_str) == Some(EMAIL)
                && params.get("access_type").map(String::as_str) == Some("offline")
                && params.get("prompt").map(String::as_str) == Some("consent")
                && params.get("code_challenge_method").map(String::as_str) == Some("S256")
                && oauth_state.len() == 22
                && oauth_state
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                && code_challenge.len() == 43
                && redirect_valid
            {
                state.auth_request_valid.fetch_add(1, Ordering::SeqCst);
                *state.challenge.lock().unwrap() = Some(code_challenge);
            }
            redirect
                .query_pairs_mut()
                .append_pair("code", CODE_CANARY)
                .append_pair("state", &oauth_state);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {redirect}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/token" if method == "POST" => {
            state.token_hits.fetch_add(1, Ordering::SeqCst);
            if state.delay_token.load(Ordering::SeqCst) > 0 {
                tokio::time::sleep(Duration::from_millis(60)).await;
            }
            let params = url::form_urlencoded::parse(&body)
                .into_owned()
                .collect::<HashMap<_, _>>();
            if params.get("grant_type").map(String::as_str) == Some("authorization_code") {
                let expected_challenge = state.challenge.lock().unwrap().clone();
                let verifier = params
                    .get("code_verifier")
                    .map(String::as_str)
                    .unwrap_or_default();
                if params.get("code").map(String::as_str) == Some(CODE_CANARY)
                    && params.get("client_id").map(String::as_str) == Some("desktop-client-id")
                    && params.get("client_secret").map(String::as_str) == Some(SECRET_CANARY)
                    && verifier.len() == 43
                    && expected_challenge.as_deref() == Some(pkce_challenge(verifier).as_str())
                    && params
                        .get("redirect_uri")
                        .is_some_and(|value| value.starts_with("http://127.0.0.1:"))
                {
                    state.code_exchange_valid.fetch_add(1, Ordering::SeqCst);
                }
            }
            let (status, response_body) = state.token_reply.lock().unwrap().clone();
            write_fake_response(&mut stream, status, &response_body).await?;
        }
        "/revoke" if method == "POST" => {
            state.revoke_hits.fetch_add(1, Ordering::SeqCst);
            let status = *state.revoke_status.lock().unwrap();
            write_fake_response(&mut stream, status, "{}").await?;
        }
        _ => write_fake_response(&mut stream, 404, "{}").await?,
    }
    Ok(())
}

async fn read_fake_request(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut header = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fake request closed",
            ));
        }
        header.push(byte[0]);
        if header.len() > 16 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fake request too large",
            ));
        }
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let headers = std::str::from_utf8(&header).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0; content_length];
    stream.read_exact(&mut body).await?;
    Ok((headers.to_string(), body))
}

async fn read_test_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fake response closed",
            ));
        }
        response.push(byte[0]);
        if response.len() > 16 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fake response too large",
            ));
        }
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let headers = std::str::from_utf8(&response).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_start = response.len();
    response.resize(body_start + content_length, 0);
    stream.read_exact(&mut response[body_start..]).await?;
    Ok(response)
}

fn parse_request_line(headers: &str) -> std::io::Result<(&str, &str, &str)> {
    let line = headers
        .lines()
        .next()
        .ok_or_else(|| std::io::Error::other("missing request line"))?;
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    Ok((method, target, version))
}

async fn write_fake_response(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
) -> std::io::Result<()> {
    let phrase = if (200..300).contains(&status) {
        "OK"
    } else {
        "Error"
    };
    let response = format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}
