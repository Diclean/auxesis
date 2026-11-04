//! The IMAP read path against the in-process fake. Offline only.

use std::sync::Arc;
use std::time::Duration;

use aux_fakemail::{
    fixture_date, fixture_mailbox, fixture_multipart_with_pdf, fixture_multipart_with_zip,
    fixture_oversized, fixture_understated_parts, FakeImap, RawMessage, StaticCredentials,
};
use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security};
use aux_mail::dial::Dialer;
use aux_mail::error::MailError;
use aux_mail::imap_read::{days_ago_date, ListQuery, MailService, SearchQuery};
use aux_mail::limits::Limits;

fn account(fake: &FakeImap) -> MailAccount {
    MailAccount {
        id: "personal".to_string(),
        email: "me@example.org".to_string(),
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

fn service_with(fake: &FakeImap, limits: Limits, account: MailAccount) -> MailService {
    let cert = fake.cert().expect("tls fake has a cert");
    MailService::new(
        Dialer::with_client_config(cert.client_config(), limits.connect_timeout),
        limits,
        vec![account],
        Arc::new(StaticCredentials::new("personal", "secret")),
    )
}

fn service(fake: &FakeImap, limits: Limits) -> MailService {
    service_with(fake, limits, account(fake))
}

/// The read half must never send a mutating command.
fn assert_read_only(commands: &[String]) {
    for verb in ["STORE", "COPY", "MOVE", "EXPUNGE", "APPEND"] {
        assert!(
            !commands
                .iter()
                .any(|line| line.to_ascii_uppercase().contains(verb)),
            "{verb} was sent: {commands:?}"
        );
    }
}

/// `mail_search` through the production service, as the model calls it.
async fn tool_search(fake: &FakeImap, args: serde_json::Value) -> String {
    let api: Arc<dyn aux_mail::tools::MailApi> = Arc::new(service(fake, Limits::default()));
    tool_search_api(api, args).await
}

async fn tool_search_api(
    api: Arc<dyn aux_mail::tools::MailApi>,
    args: serde_json::Value,
) -> String {
    let tools = aux_mail::tools::MailToolset::new(api, None).tools();
    let search = tools
        .iter()
        .find(|tool| tool.native_name() == "mail_search")
        .expect("mail_search is registered");
    let home = std::env::temp_dir();
    search
        .run(&args, &kernel_broker::ToolCtx::new("test", home))
        .await
        .expect("mail_search runs")
        .content
}

#[tokio::test]
async fn list_returns_envelopes_and_never_fetches_a_body() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(5)).await;
    let service = service(&fake, Limits::default());

    let items = service
        .list("personal", &ListQuery::default())
        .await
        .expect("list");

    assert_eq!(items.len(), 5);
    // Servers answer a FETCH in UID order; the list must still be newest first.
    assert!(
        items.windows(2).all(|pair| pair[0].uid > pair[1].uid),
        "{:?}",
        items.iter().map(|item| item.uid).collect::<Vec<_>>()
    );
    assert!(items.iter().any(|item| item.unread));
    assert!(items.iter().all(|item| !item.message_id.is_empty()));

    let commands = fake.commands();
    assert!(
        commands.iter().any(|line| line.contains("ENVELOPE")),
        "{commands:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|line| line.contains("BODY[]") || line.contains("BODY.PEEK[]")),
        "list must not fetch a body: {commands:?}"
    );
    assert_read_only(&commands);
}

#[tokio::test]
async fn read_returns_the_body_without_setting_seen() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(3)).await;
    let service = service(&fake, Limits::default());

    let raw = service.read("personal", 1, "INBOX", 0).await.expect("read");
    let item = aux_mail::parse_message(&raw).expect("parse");
    assert!(item.text.contains("Hello fixture body."), "{}", item.text);

    let commands = fake.commands();
    assert!(
        commands.iter().any(|line| line.contains("BODY.PEEK[]")),
        "{commands:?}"
    );
    assert!(
        !commands.iter().any(|line| line.contains("\\Seen")),
        "no command may carry \\Seen: {commands:?}"
    );
    assert_read_only(&commands);
}

#[tokio::test]
async fn search_sends_a_bounded_since_and_clamps_the_window() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(4)).await;
    let service = service(&fake, Limits::default());

    let items = service
        .search(
            "personal",
            &SearchQuery {
                query: "fixture".to_string(),
                days: Some(365),
                ..SearchQuery::default()
            },
        )
        .await
        .expect("search");
    assert!(!items.is_empty());

    let commands = fake.commands();
    let search = commands
        .iter()
        .find(|line| line.contains("UID SEARCH"))
        .expect("a UID SEARCH command");
    assert!(
        search.contains(&format!("SINCE {}", days_ago_date(90))),
        "a 365-day window must clamp to 90: {search}"
    );
    assert!(search.contains("TEXT \"fixture\""), "{search}");
    assert_read_only(&commands);
}

/// The demo world's late-payment mails are received from the
/// clients (the owner replies "sorry for the delay, paying this week"), not
/// owner-sent reminders. The model asks for a bounded page (`limit`); a
/// server that ignores `TEXT` hands it the newest mail of the folder
/// regardless of the query, so Invoice 101 falls off the page while Invoice
/// 100 survives. The tool result the agent gets must still hold every overdue
/// invoice, both clients and both people, and none of the unrelated mail.
#[tokio::test]
async fn a_who_owes_search_returns_both_overdue_invoices_of_the_demo_world() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock")
        .as_secs() as i64;
    // The world's owner-sent mail lives in Sent; the inbox is what the tool
    // searches by default.
    let inbox: Vec<RawMessage> = aux_fakemail::world_mailbox(now)
        .into_iter()
        .filter(|mail| {
            mail.folder
                .as_deref()
                .is_none_or(|folder| folder.eq_ignore_ascii_case("INBOX"))
        })
        .map(|mail| mail.into_raw())
        .collect();
    let fake = FakeImap::spawn_tls(inbox).await;

    let rendered = tool_search(&fake, serde_json::json!({"query": "overdue", "limit": 50})).await;

    for expected in [
        "Invoice 100",
        "Lea",
        "blueharbor",
        "Invoice 101",
        "Lena",
        "harborline",
    ] {
        assert!(
            rendered.to_lowercase().contains(&expected.to_lowercase()),
            "missing {expected:?} in the tool result: {rendered}"
        );
    }
    // A search returns its matches, not the newest page of the folder.
    assert!(
        !rendered.contains("General update") && !rendered.contains("Studio Weekly"),
        "unrelated mail filled the page: {rendered}"
    );
    // A reminder received from the client is money the
    // owner owes, never money owed to the owner.
    assert!(rendered.contains("direction: you_owe"), "{rendered}");
    assert!(!rendered.contains("direction: owed_to_you"), "{rendered}");
}

/// The same words, "Invoice overdue", in both directions.
/// A reminder the owner sent to a client is money owed to the owner; the same
/// words received from a supplier are money the owner owes. The mail tool
/// labels the rows itself, so the model never has to infer the direction.
#[tokio::test]
async fn the_same_overdue_words_read_opposite_ways_sent_and_received() {
    fn overdue(uid: u32, from: &str, to: &str) -> RawMessage {
        RawMessage {
            uid,
            message_id: format!("<{uid}@fixture.example>"),
            subject: "Invoice overdue".to_string(),
            from: from.to_string(),
            to: vec![to.to_string()],
            cc: Vec::new(),
            date: fixture_date(),
            body: "From: fixture\r\nSubject: Invoice overdue\r\n\r\nPlease pay.\r\n",
            flags: Vec::new(),
            bodystructure: None,
            parts: Vec::new(),
            in_reply_to: None,
        }
    }
    let fake = FakeImap::spawn_tls(vec![overdue(
        1,
        "Supplier <billing@supplier.example>",
        "Owner <me@example.org>",
    )])
    .await;
    fake.mailbox().push(
        "Sent",
        overdue(2, "Owner <me@example.org>", "Client <client@example.org>"),
    );
    let mut account = account(&fake);
    account.only_folders = vec!["INBOX".to_string(), "Sent".to_string()];
    let api: Arc<dyn aux_mail::tools::MailApi> =
        Arc::new(service_with(&fake, Limits::default(), account));

    let inbox = tool_search_api(Arc::clone(&api), serde_json::json!({"query": "overdue"})).await;
    let outbox = tool_search_api(
        api,
        serde_json::json!({"query": "overdue", "folder": "Sent"}),
    )
    .await;

    assert!(inbox.contains("direction: you_owe"), "{inbox}");
    assert!(!inbox.contains("direction: owed_to_you"), "{inbox}");
    assert!(outbox.contains("direction: owed_to_you"), "{outbox}");
    assert!(!outbox.contains("direction: you_owe"), "{outbox}");
}

#[tokio::test]
async fn list_clamps_the_requested_limit_to_the_hard_cap() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(250)).await;
    let service = service(&fake, Limits::default());

    let items = service
        .list(
            "personal",
            &ListQuery {
                limit: 1000,
                ..ListQuery::default()
            },
        )
        .await
        .expect("list");
    assert_eq!(items.len(), 200);

    let fetch = fake
        .commands()
        .into_iter()
        .find(|line| line.contains("UID FETCH"))
        .expect("a UID FETCH command");
    let set = fetch.split_whitespace().nth(3).unwrap_or("");
    assert!(set.split(',').count() <= 200, "{fetch}");
}

#[tokio::test]
async fn read_skips_a_message_over_the_byte_limit() {
    let mut messages = fixture_mailbox(1);
    messages.push(fixture_oversized(2, 5 * 1024 * 1024));
    let fake = FakeImap::spawn_tls(messages).await;
    let service = service(&fake, Limits::default());

    let error = service
        .read("personal", 2, "INBOX", 0)
        .await
        .expect_err("over the cap");
    assert!(matches!(error, MailError::TooLarge { .. }), "{error:?}");

    let commands = fake.commands();
    assert!(
        !commands
            .iter()
            .any(|line| line.contains("BODY[]") || line.contains("BODY.PEEK[]")),
        "the oversized body must never be fetched: {commands:?}"
    );

    let raw = service
        .read("personal", 1, "INBOX", 0)
        .await
        .expect("a small message still reads");
    assert!(!raw.bytes.is_empty());
}

#[tokio::test]
async fn read_refuses_a_folder_outside_only_folders() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let service = service(&fake, Limits::default());

    let error = service
        .read("personal", 1, "Trash", 0)
        .await
        .expect_err("Trash is not allowed");
    match error {
        MailError::FolderUnavailable { name, seen } => {
            assert_eq!(name, "Trash");
            assert!(seen.contains(&"INBOX".to_string()), "{seen:?}");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        !fake.commands().iter().any(|line| line.contains("SELECT")),
        "the check must happen before connecting: {:?}",
        fake.commands()
    );
}

#[tokio::test]
async fn a_garbage_fetch_is_a_protocol_error() {
    let fake = FakeImap::spawn_garbage(fixture_mailbox(1)).await;
    let service = service(&fake, Limits::default());

    let error = service
        .read("personal", 1, "INBOX", 0)
        .await
        .expect_err("garbage response");
    assert!(matches!(error, MailError::Protocol), "{error:?}");
}

#[tokio::test]
async fn a_stalled_fetch_hits_the_call_budget() {
    let fake = FakeImap::spawn_stall(fixture_mailbox(1)).await;
    let service = service(&fake, Limits::tight());

    let started = std::time::Instant::now();
    let error = service
        .list("personal", &ListQuery::default())
        .await
        .expect_err("the fake never answers");
    assert!(matches!(error, MailError::Timeout { .. }), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn folders_lists_and_maps_canonical_roles() {
    assert_eq!(
        aux_mail::canonical_name("Boîte de réception"),
        Some("inbox")
    );
    assert_eq!(
        aux_mail::canonical_name("INBOX.Gelöschte Elemente"),
        Some("trash")
    );
    assert_eq!(aux_mail::canonical_name("Projets"), None);

    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let service = service(&fake, Limits::default());
    let folders = service.folders("personal").await.expect("folders");
    assert_eq!(folders.len(), 5);
    let inbox = folders
        .iter()
        .find(|folder| folder.name == "INBOX")
        .expect("INBOX");
    assert_eq!(inbox.canonical, Some("inbox"));
    let sent = folders
        .iter()
        .find(|folder| folder.canonical == Some("sent"))
        .unwrap();
    assert_eq!(sent.special_use, Some("sent"));
    assert!(folders.iter().all(|folder| folder.selectable));
    assert_read_only(&fake.commands());
}

#[tokio::test]
async fn thread_groups_replies_via_references_and_subject() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(7)).await;
    let service = service(&fake, Limits::default());

    let items = service
        .thread("personal", "<0@fixture.example>", 100)
        .await
        .expect("thread");
    let uids: Vec<u32> = items.iter().map(|item| item.uid).collect();
    assert_eq!(uids, vec![1, 4, 7], "{items:?}");
    assert_read_only(&fake.commands());
}

#[tokio::test]
async fn reading_a_multipart_message_never_fetches_an_attachment_part() {
    let fake = FakeImap::spawn_tls(vec![fixture_multipart_with_pdf()]).await;
    let service = service(&fake, Limits::default());

    let raw = service
        .read("personal", 42, "INBOX", 0)
        .await
        .expect("read");
    let item = aux_mail::parse_message(&raw).expect("parse");
    assert_eq!(item.attachments.len(), 1);
    let attachment = &item.attachments[0];
    assert_eq!(attachment.file_name, "invoice.pdf");
    assert_eq!(attachment.mime, "application/pdf");
    assert_eq!(attachment.part_id, "2");
    assert!(attachment.size > 0);

    let commands = fake.commands();
    assert!(
        commands.iter().any(|line| line.contains("BODY.PEEK[]")),
        "{commands:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|line| line.contains("BODY[2]") || line.contains("BODY.PEEK[2]")),
        "no attachment part may be fetched in MA2: {commands:?}"
    );
    assert_read_only(&commands);
}

#[tokio::test]
async fn a_missing_password_is_an_auth_error() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let cert = fake.cert().expect("tls fake has a cert");
    let limits = Limits::default();
    let service = MailService::new(
        Dialer::with_client_config(cert.client_config(), limits.connect_timeout),
        limits,
        vec![account(&fake)],
        Arc::new(StaticCredentials::empty()),
    );

    let error = service
        .list("personal", &ListQuery::default())
        .await
        .expect_err("no password");
    assert!(matches!(error, MailError::Auth), "{error:?}");
}

#[tokio::test]
async fn read_requests_a_partial_body_capped_at_the_message_bound() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let limits = Limits::new(
        64 * 1024,
        512 * 1024,
        5,
        Duration::from_secs(10),
        Duration::from_secs(2),
        1,
        1,
    );
    let service = service(&fake, limits);

    service.read("personal", 1, "INBOX", 0).await.expect("read");

    let fetch = fake
        .commands()
        .into_iter()
        .find(|line| line.contains("BODY.PEEK[]"))
        .expect("a body fetch");
    assert!(
        fetch.contains("BODY.PEEK[]<0.65537>"),
        "the body fetch must carry the partial range: {fetch}"
    );
}

#[tokio::test]
async fn an_oversized_literal_is_refused_and_the_connection_is_dropped() {
    // The fake reports RFC822.SIZE = 1 KiB, then ignores the partial range and
    // declares a 32 MiB body literal.
    let fake = FakeImap::spawn_overlong(vec![fixture_oversized(1, 1024)]).await;
    let limits = Limits::new(
        4 * 1024,
        512 * 1024,
        5,
        Duration::from_secs(10),
        Duration::from_secs(2),
        1,
        1,
    );
    let service = service(&fake, limits);

    let error = service
        .read("personal", 1, "INBOX", 0)
        .await
        .expect_err("the declared literal is far past the cap");
    assert!(matches!(error, MailError::TooLarge { .. }), "{error:?}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fake.active() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(fake.active(), 0, "the connection must be dropped");
    assert!(
        fake.overlong_written() < 32 * 1024 * 1024,
        "the fake wrote {} bytes of a 32 MiB literal; the guard must stop it",
        fake.overlong_written()
    );
}

fn huge_header_limits() -> Limits {
    Limits::new(
        4 * 1024,
        512 * 1024,
        5,
        Duration::from_secs(10),
        Duration::from_secs(2),
        1,
        1,
    )
}

/// The guard must reject at the `{536870000}` header, before async-imap sizes
/// its buffer from it, so only the preceding protocol bytes are forwarded.
async fn assert_huge_header_refused(fake: &FakeImap) {
    let service = service(fake, huge_header_limits());
    let error = service
        .read("personal", 1, "INBOX", 0)
        .await
        .expect_err("the header declares far past the cap");
    match error {
        MailError::TooLarge { seen, .. } => {
            assert!(seen < 1024, "forwarded {seen} bytes before the header");
        }
        other => panic!("{other:?}"),
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fake.active() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(fake.active(), 0, "the connection must be dropped");
}

#[tokio::test]
async fn an_oversized_literal_header_is_refused_before_the_body() {
    let fake = FakeImap::spawn_huge_header(vec![fixture_oversized(1, 1024)]).await;
    assert_huge_header_refused(&fake).await;
}

#[tokio::test]
async fn an_oversized_literal_header_split_across_reads_is_refused() {
    let fake = FakeImap::spawn_huge_header_split(vec![fixture_oversized(1, 1024)]).await;
    assert_huge_header_refused(&fake).await;
}

#[tokio::test]
async fn a_literal_under_the_ceiling_still_reads() {
    let fake = FakeImap::spawn_tls(fixture_mailbox(1)).await;
    let service = service(&fake, Limits::default());
    let raw = service
        .read("personal", 1, "INBOX", 0)
        .await
        .expect("a small literal must pass the scanner");
    let item = aux_mail::parse_message(&raw).expect("parse");
    assert!(item.text.contains("Hello fixture body."), "{}", item.text);
}

#[tokio::test]
async fn a_body_containing_a_literal_lookalike_still_reads() {
    const BODY: &str = "From: a@example.org\r\n\
        Subject: brace\r\n\
        Content-Type: text/plain; charset=UTF-8\r\n\
        \r\n\
        {999999999}\r\n";
    let message = RawMessage {
        uid: 1,
        message_id: "<brace@fixture.example>".to_string(),
        subject: "brace".to_string(),
        from: "a@example.org".to_string(),
        to: vec!["me@example.org".to_string()],
        cc: Vec::new(),
        date: aux_fakemail::fixture_date(),
        body: BODY,
        flags: Vec::new(),
        bodystructure: None,
        parts: Vec::new(),
        in_reply_to: None,
    };
    let fake = FakeImap::spawn_tls(vec![message]).await;
    let service = service(&fake, Limits::default());
    let raw = service
        .read("personal", 1, "INBOX", 0)
        .await
        .expect("the body's brace text must not trip the guard");
    let item = aux_mail::parse_message(&raw).expect("parse");
    assert!(item.text.contains("{999999999}"), "{}", item.text);
}

#[tokio::test]
async fn fetch_attachments_downloads_an_allowed_part_without_the_whole_body() {
    let fake = FakeImap::spawn_tls(vec![fixture_multipart_with_pdf()]).await;
    let service = service(&fake, Limits::default());

    let fetched = service
        .fetch_attachments("personal", "INBOX", 42, 0)
        .await
        .expect("fetch");

    assert_eq!(fetched.message_id, "<invoice@fixture.example>");
    assert_eq!(fetched.downloaded.len(), 1, "{fetched:?}");
    assert!(fetched.skipped.is_empty(), "{fetched:?}");
    let attachment = &fetched.downloaded[0];
    assert_eq!(attachment.file_name, "invoice.pdf");
    assert_eq!(attachment.mime, "application/pdf");
    assert_eq!(attachment.part, "2");
    assert_eq!(attachment.bytes, b"%PDF-1.4 fake invoice\r\n");
    // sha256 of those exact 23 bytes.
    assert_eq!(
        attachment.sha256,
        "60d040d7f7d984714ed9110dc712f5a98a0456e00796718df568a225a29cf44e"
    );
    assert_eq!(attachment.size, 23);

    let commands = fake.commands();
    assert!(
        commands.iter().any(|line| line.contains("BODYSTRUCTURE")),
        "{commands:?}"
    );
    assert!(
        commands.iter().any(|line| line.contains("BODY.PEEK[2]")),
        "{commands:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|line| line.contains("BODY.PEEK[]") || line.contains("BODY[]")),
        "fetch_attachments must not download the whole message: {commands:?}"
    );
    assert!(
        !commands.iter().any(|line| line.contains("\\Seen")),
        "no command may carry \\Seen: {commands:?}"
    );
    assert_read_only(&commands);
}

#[tokio::test]
async fn fetch_attachments_lists_a_disallowed_mime_as_skipped() {
    let fake = FakeImap::spawn_tls(vec![fixture_multipart_with_zip()]).await;
    let service = service(&fake, Limits::default());

    let fetched = service
        .fetch_attachments("personal", "INBOX", 43, 0)
        .await
        .expect("fetch");
    assert_eq!(fetched.downloaded.len(), 1, "{fetched:?}");
    assert_eq!(fetched.downloaded[0].file_name, "invoice.pdf");
    assert_eq!(fetched.skipped.len(), 1, "{fetched:?}");
    let skipped = &fetched.skipped[0];
    assert_eq!(skipped.file_name, "archive.zip");
    assert_eq!(skipped.mime, "application/zip");
    assert!(
        skipped.reason.contains("not allowed"),
        "reason must say why: {}",
        skipped.reason
    );
    assert!(
        !fake
            .commands()
            .iter()
            .any(|line| line.contains("BODY.PEEK[3]")),
        "the disallowed part must never be fetched: {:?}",
        fake.commands()
    );
}

#[tokio::test]
async fn fetch_attachments_skips_a_part_over_the_per_attachment_cap() {
    let fake = FakeImap::spawn_tls(vec![fixture_multipart_with_pdf()]).await;
    // 8-byte ceiling: the 22-byte PDF is refused without a part fetch.
    let service = service(&fake, Limits::default().with_attachments(8, 1024));

    let fetched = service
        .fetch_attachments("personal", "INBOX", 42, 0)
        .await
        .expect("fetch");
    assert!(fetched.downloaded.is_empty(), "{fetched:?}");
    assert_eq!(fetched.skipped.len(), 1, "{fetched:?}");
    assert!(fetched.skipped[0].reason.contains("cap"));
    assert!(
        !fake
            .commands()
            .iter()
            .any(|line| line.contains("BODY.PEEK[2]")),
        "an oversized part must not be fetched: {:?}",
        fake.commands()
    );
}

#[tokio::test]
async fn fetch_attachments_charges_the_call_cap_the_actual_bytes() {
    // Each part DECLARES 10 bytes but returns 20 MiB. The declared preflight
    // passes; the actual-byte accounting must stop after two parts so the
    // retained total stays at or below the 50 MiB call cap.
    const PART: usize = 20 * 1024 * 1024;
    const CALL_CAP: usize = 50 * 1024 * 1024;
    let part: &'static str = Box::leak("x".repeat(PART).into_boxed_str());
    let fake = FakeImap::spawn_tls(vec![fixture_understated_parts(part, 10)]).await;
    let service = service(&fake, Limits::default());

    let fetched = service
        .fetch_attachments("personal", "INBOX", 44, 0)
        .await
        .expect("fetch");

    let retained: usize = fetched.downloaded.iter().map(|part| part.size).sum();
    assert!(
        retained <= CALL_CAP,
        "retained {retained} bytes, above the {CALL_CAP}-byte call cap"
    );
    assert_eq!(retained, 2 * PART, "{fetched:?}");
    assert_eq!(fetched.downloaded.len(), 2, "{fetched:?}");
    assert_eq!(fetched.skipped.len(), 1, "{fetched:?}");
    assert!(
        fetched.skipped[0].reason.contains("budget"),
        "the stop reason must name the budget: {}",
        fetched.skipped[0].reason
    );
}

#[tokio::test]
async fn fetch_attachments_uses_a_bounded_partial_and_skips_the_oversized_part() {
    // Each part DECLARES 10 bytes but is 4 KiB. With a 1 KiB per-part cap the
    // fetch must ask for `<0.1025>` (one past the cap), the honest fake returns
    // exactly that, and the part is skipped without being retained.
    const PART: usize = 4096;
    let part: &'static str = Box::leak("y".repeat(PART).into_boxed_str());
    let fake = FakeImap::spawn_tls(vec![fixture_understated_parts(part, 10)]).await;
    let service = service(&fake, Limits::default().with_attachments(1024, 4096));

    let fetched = service
        .fetch_attachments("personal", "INBOX", 44, 0)
        .await
        .expect("fetch");
    assert!(fetched.downloaded.is_empty(), "{fetched:?}");
    assert_eq!(fetched.skipped.len(), 3, "{fetched:?}");
    assert!(fetched.skipped[0].reason.contains("cap"), "{fetched:?}");

    let commands = fake.commands();
    assert!(
        commands.iter().any(|line| line.contains("<0.1025>")),
        "the request must carry the bounded partial: {commands:?}"
    );
}

#[tokio::test]
async fn fetch_attachments_refuses_a_literal_above_the_guard_limit() {
    // The server ignores `<0.1025>` and declares a 1 MiB literal. The
    // connection guard must refuse the declaration at the header, before
    // async-imap sizes a buffer from it, and the fetch reports the typed
    // oversize.
    const PART: usize = 1024 * 1024;
    let part: &'static str = Box::leak("z".repeat(PART).into_boxed_str());
    let fake = FakeImap::spawn_ignore_partial_tls(vec![fixture_understated_parts(part, 10)]).await;
    let service = service(&fake, Limits::default().with_attachments(1024, 4096));

    let error = service
        .fetch_attachments("personal", "INBOX", 44, 0)
        .await
        .expect_err("the guard must refuse the oversized literal");
    match error {
        MailError::TooLarge { limit, .. } => {
            assert_eq!(limit, 1025, "the per-part literal ceiling");
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(
        fake.commands().iter().any(|line| line.contains("<0.1025>")),
        "the partial was requested before the server ignored it: {:?}",
        fake.commands()
    );
}

/// A plain UTF-8 message whose body is `repeat` copies of a mixed-width line.
fn fixture_long_utf8(uid: u32, repeat: usize) -> RawMessage {
    let text = "héllo wörld 你好 ".repeat(repeat);
    let body: &'static str = Box::leak(
        format!(
            "From: fixture\r\nSubject: long\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 8bit\r\n\r\n{text}\r\n"
        )
        .into_boxed_str(),
    );
    let mut message = fixture_oversized(uid, 0);
    message.subject = "Long".to_string();
    message.body = body;
    message
}

/// `mail_read` through the production service, as the model calls it.
async fn tool_read(fake: &FakeImap, args: serde_json::Value) -> String {
    let api: Arc<dyn aux_mail::tools::MailApi> = Arc::new(service(fake, Limits::default()));
    let toolset = aux_mail::tools::MailToolset::new(api, None);
    let tools = toolset.tools();
    let read = tools
        .iter()
        .find(|tool| tool.native_name() == "mail_read")
        .expect("mail_read is registered");
    let home = std::env::temp_dir();
    let out = read
        .run(&args, &kernel_broker::ToolCtx::new("test", home))
        .await
        .expect("mail_read runs");
    out.content
}

/// The body is everything after the banner and the header line.
fn body_of(rendered: &str) -> &str {
    let mut lines = rendered.splitn(3, '\n');
    assert_eq!(
        lines.next(),
        Some(aux_mail::UNTRUSTED_MAIL_TAG),
        "{rendered}"
    );
    assert!(lines.next().expect("header line").starts_with("from: "));
    lines.next().unwrap_or("")
}

#[tokio::test]
async fn mail_read_never_returns_more_body_than_max_chars() {
    let fake = FakeImap::spawn_tls(vec![fixture_long_utf8(1, 400)]).await;
    let rendered = tool_read(&fake, serde_json::json!({"uid": 1, "max_chars": 500})).await;
    let body = body_of(&rendered);
    let (kept, marker) = body
        .rsplit_once('\n')
        .expect("a marker line follows the cut");
    assert_eq!(marker, aux_mail::sanitize::READ_CUT_MARKER);
    assert!(
        kept.chars().count() <= 500,
        "{} chars",
        kept.chars().count()
    );
    assert!(kept.starts_with("héllo wörld 你好"), "{kept}");
    assert_read_only(&fake.commands());
}

#[tokio::test]
async fn mail_read_without_max_chars_or_above_the_limit_keeps_the_default() {
    let fake = FakeImap::spawn_tls(vec![fixture_long_utf8(1, 400)]).await;
    let default = tool_read(&fake, serde_json::json!({"uid": 1})).await;
    assert!(body_of(&default).chars().count() > 5000);
    assert!(!default.contains(aux_mail::sanitize::READ_CUT_MARKER));
    let huge = tool_read(
        &fake,
        serde_json::json!({"uid": 1, "max_chars": 10_000_000}),
    )
    .await;
    assert_eq!(
        huge, default,
        "a larger max_chars never raises the default cap"
    );
}
