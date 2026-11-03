//! `SEARCH … SINCE <date>`: the fake honours it the way a real server does.

use aux_fakemail::{fixture_mailbox, read_line, read_until_tag, send_line, FakeImap, RawMessage};
use tokio::net::TcpStream;

/// Five unread mails, one per day, 6 to 10 October 2025 (UIDs 1 to 5).
fn mails() -> Vec<RawMessage> {
    let dates = [
        "Mon, 6 Oct 2025 23:59:00 -0500",
        "Tue, 7 Oct 2025 00:01:00 +0900",
        "Wed, 8 Oct 2025 09:00:00 +0000",
        "Thu, 9 Oct 2025 09:00:00 +0000",
        "Fri, 10 Oct 2025 09:00:00 +0000",
    ];
    let mut mails = fixture_mailbox(5);
    for (mail, date) in mails.iter_mut().zip(dates) {
        mail.date = date.to_string();
        mail.flags = Vec::new();
    }
    mails
}

async fn session(fake: &FakeImap) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", fake.port))
        .await
        .expect("connect the fake");
    assert!(read_line(&mut stream).await.starts_with("* OK"));
    send_line(&mut stream, "a1 LOGIN me@example.org secret").await;
    assert!(read_until_tag(&mut stream, "a1").await.contains("a1 OK"));
    send_line(&mut stream, "a2 SELECT INBOX").await;
    assert!(read_until_tag(&mut stream, "a2").await.contains("a2 OK"));
    stream
}

async fn ask(stream: &mut TcpStream, command: &str) -> String {
    send_line(stream, &format!("t9 {command}")).await;
    read_until_tag(stream, "t9").await
}

#[tokio::test]
async fn since_keeps_only_mail_on_or_after_the_day() {
    let fake = FakeImap::spawn(mails()).await;
    let mut stream = session(&fake).await;

    let reply = ask(&mut stream, "UID SEARCH UNSEEN SINCE 8-Oct-2025").await;
    assert!(reply.contains("* SEARCH 3 4 5\r\n"), "{reply}");
    assert!(reply.contains("t9 OK"), "{reply}");

    let reply = ask(&mut stream, "UID SEARCH SINCE 10-Oct-2025").await;
    assert!(reply.contains("* SEARCH 5\r\n"), "{reply}");

    let reply = ask(&mut stream, "UID SEARCH SINCE 11-Oct-2025").await;
    assert!(reply.contains("* SEARCH \r\n"), "{reply}");
}

#[tokio::test]
async fn since_reads_the_day_in_the_header_and_ignores_the_timezone() {
    let fake = FakeImap::spawn(mails()).await;
    let mut stream = session(&fake).await;

    // Mail 1 is 6 Oct 23:59 in UTC-5 and mail 2 is 7 Oct 00:01 in UTC+9:
    // each counts on the day it is written, not on its UTC day.
    let reply = ask(&mut stream, "UID SEARCH SINCE 7-Oct-2025").await;
    assert!(reply.contains("* SEARCH 2 3 4 5\r\n"), "{reply}");
    let reply = ask(&mut stream, "UID SEARCH SINCE \"6-oct-2025\" TEXT hello").await;
    assert!(reply.contains("* SEARCH 1 2 3 4 5\r\n"), "{reply}");
}

#[tokio::test]
async fn without_since_the_search_is_unchanged() {
    let fake = FakeImap::spawn(mails()).await;
    let mut stream = session(&fake).await;

    let reply = ask(&mut stream, "UID SEARCH UNSEEN").await;
    assert!(reply.contains("* SEARCH 1 2 3 4 5\r\n"), "{reply}");
    let reply = ask(&mut stream, "UID SEARCH ALL").await;
    assert!(reply.contains("* SEARCH 1 2 3 4 5\r\n"), "{reply}");
}

#[tokio::test]
async fn a_malformed_since_gets_a_tagged_bad_and_the_session_lives_on() {
    let fake = FakeImap::spawn(mails()).await;
    let mut stream = session(&fake).await;

    for bad in [
        "UID SEARCH SINCE",
        "UID SEARCH SINCE yesterday",
        "UID SEARCH SINCE 32-Oct-2025",
        "UID SEARCH SINCE 8-Foo-2025",
        "UID SEARCH SINCE 8-Oct-20x5",
        "UID SEARCH UNSEEN SINCE 2025-10-08",
    ] {
        let reply = ask(&mut stream, bad).await;
        assert!(reply.contains("t9 BAD"), "{bad}: {reply}");
        assert!(!reply.contains("* SEARCH"), "{bad}: {reply}");
    }

    let reply = ask(&mut stream, "UID SEARCH ALL").await;
    assert!(reply.contains("* SEARCH 1 2 3 4 5\r\n"), "{reply}");
}

#[tokio::test]
async fn the_word_since_inside_a_text_value_is_not_the_keyword() {
    let mut messages = mails();
    messages[4].body = "From: fixture\r\nSubject: body\r\n\r\n\
        say \"since\" now, invoice since march\r\n";
    let fake = FakeImap::spawn(messages).await;
    let mut stream = session(&fake).await;

    // What `mail_search` sends: a real SINCE plus a quoted TEXT value. The
    // value is a substring match (mail 5), never a SINCE date.
    let reply = ask(
        &mut stream,
        "UID SEARCH SINCE 9-Oct-2025 TEXT \"invoice since march\"",
    )
    .await;
    assert!(reply.contains("* SEARCH 5\r\n"), "{reply}");

    let reply = ask(&mut stream, "UID SEARCH TEXT \"invoice since march\"").await;
    assert!(reply.contains("* SEARCH 5\r\n"), "{reply}");
    assert!(reply.contains("t9 OK"), "{reply}");

    // SUBJECT since is a criterion too: no subject carries the word.
    let reply = ask(&mut stream, "UID SEARCH SUBJECT since").await;
    assert!(reply.contains("* SEARCH \r\n"), "{reply}");

    // A quoted value with an escaped quote still ends where it should.
    let reply = ask(
        &mut stream,
        "UID SEARCH TEXT \"say \\\"since\\\" now\" SINCE 10-Oct-2025",
    )
    .await;
    assert!(reply.contains("* SEARCH 5\r\n"), "{reply}");
}

#[tokio::test]
async fn a_mail_with_a_missing_or_unreadable_date_stays_in_the_results() {
    let mut mails = mails();
    mails[0].date = String::new();
    mails[1].date = "sometime last week".to_string();
    let fake = FakeImap::spawn(mails).await;
    let mut stream = session(&fake).await;

    let reply = ask(&mut stream, "UID SEARCH SINCE 9-Oct-2025").await;
    assert!(reply.contains("* SEARCH 1 2 4 5\r\n"), "{reply}");
}

#[tokio::test]
async fn a_text_that_is_an_address_keeps_only_the_mail_carrying_it() {
    let mut mails = mails();
    mails[1].body = "From: Camille <Camille@Northwind.example>\r\n\r\nHello.\r\n";
    let fake = FakeImap::spawn(mails).await;
    let mut stream = session(&fake).await;

    let reply = ask(&mut stream, "UID SEARCH TEXT \"camille@northwind.example\"").await;
    assert!(reply.contains("* SEARCH 2\r\n"), "{reply}");
    let reply = ask(&mut stream, "UID SEARCH TEXT \"nobody@nowhere.example\"").await;
    assert!(reply.contains("* SEARCH \r\n"), "{reply}");
}
