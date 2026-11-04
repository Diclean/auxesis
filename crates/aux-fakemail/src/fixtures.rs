//! Message fixtures the fakes serve.

/// One message a fake serves.
#[derive(Debug, Clone)]
pub struct RawMessage {
    /// IMAP UID.
    pub uid: u32,
    /// `Message-ID` header.
    pub message_id: String,
    /// `Subject` header.
    pub subject: String,
    /// `From` header.
    pub from: String,
    /// `To` header values.
    pub to: Vec<String>,
    /// `Cc` header values.
    pub cc: Vec<String>,
    /// `Date` header.
    pub date: String,
    /// The whole RFC822 message served by `BODY.PEEK[]`.
    pub body: &'static str,
    /// Flags reported by `FETCH FLAGS`.
    pub flags: Vec<&'static str>,
    /// `BODYSTRUCTURE` for a multipart message; `None` means a plain text part.
    pub bodystructure: Option<&'static str>,
    /// `(part, bytes)` served by `BODY.PEEK[part]`.
    pub parts: Vec<(&'static str, &'static str)>,
    /// `In-Reply-To` reported inside `FETCH ENVELOPE`; `None` is `NIL`.
    pub in_reply_to: Option<String>,
}

/// The `Date` header every fixture mail carries: today, 09:00 UTC. A fixed
/// date would age out of any `SINCE` window the fake now honours. The weekday
/// is a placeholder; the fake reads only the day, month and year.
pub fn fixture_date() -> String {
    format!(
        "Mon, {} 09:00:00 +0000",
        aux_mail::days_ago_date(0).replace('-', " ")
    )
}

/// A deterministic mailbox: `n` messages whose subjects form three threads.
pub fn fixture_mailbox(n: usize) -> Vec<RawMessage> {
    (0..n)
        .map(|index| {
            let thread = index % 3;
            let subject = if index >= 3 {
                format!("Re: Thread {thread}")
            } else {
                format!("Thread {thread}")
            };
            RawMessage {
                uid: (index as u32) + 1,
                message_id: format!("<{index}@fixture.example>"),
                subject,
                from: format!("Person {thread} <person{thread}@example.org>"),
                to: vec!["me@example.org".to_string()],
                cc: Vec::new(),
                date: fixture_date(),
                body: "From: fixture\r\nSubject: body\r\n\r\nHello fixture body.\r\n",
                flags: if index % 2 == 0 {
                    vec!["\\Seen"]
                } else {
                    Vec::new()
                },
                bodystructure: None,
                parts: Vec::new(),
                in_reply_to: if index >= 3 {
                    Some(format!("<{thread}@fixture.example>"))
                } else {
                    None
                },
            }
        })
        .collect()
}

/// One multipart message with a text part and a PDF attachment.
pub fn fixture_multipart_with_pdf() -> RawMessage {
    const TEXT_PART: &str = "Please find the invoice attached.\r\n";
    const PDF_PART: &str = "%PDF-1.4 fake invoice\r\n";
    const BODY: &str = "From: Billing <billing@example.org>\r\n\
        To: me@example.org\r\n\
        Subject: Your invoice\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=\"aux-mail-fixture\"\r\n\
        \r\n\
        --aux-mail-fixture\r\n\
        Content-Type: text/plain; charset=UTF-8\r\n\
        \r\n\
        Please find the invoice attached.\r\n\
        --aux-mail-fixture\r\n\
        Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
        Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
        Content-Transfer-Encoding: 7bit\r\n\
        \r\n\
        %PDF-1.4 fake invoice\r\n\
        --aux-mail-fixture--\r\n";
    RawMessage {
        uid: 42,
        message_id: "<invoice@fixture.example>".to_string(),
        subject: "Your invoice".to_string(),
        from: "Billing <billing@example.org>".to_string(),
        to: vec!["me@example.org".to_string()],
        cc: Vec::new(),
        date: fixture_date(),
        body: BODY,
        flags: Vec::new(),
        bodystructure: Some(
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 31 1)\
             (\"APPLICATION\" \"PDF\" (\"NAME\" \"invoice.pdf\") NIL NIL \"7BIT\" 22 NIL \
             (\"ATTACHMENT\" (\"FILENAME\" \"invoice.pdf\")) NIL) \"MIXED\" \
             (\"BOUNDARY\" \"aux-mail-fixture\") NIL NIL)",
        ),
        parts: vec![("1", TEXT_PART), ("2", PDF_PART)],
        in_reply_to: None,
    }
}

/// One multipart message with a PDF (allowed) and a ZIP (skipped) attachment.
pub fn fixture_multipart_with_zip() -> RawMessage {
    const TEXT_PART: &str = "Two files attached.\r\n";
    const PDF_PART: &str = "%PDF-1.4 fake invoice\r\n";
    const ZIP_PART: &str = "PK\u{3}\u{4}fakezip";
    RawMessage {
        uid: 43,
        message_id: "<two-files@fixture.example>".to_string(),
        subject: "Two files".to_string(),
        from: "Billing <billing@example.org>".to_string(),
        to: vec!["me@example.org".to_string()],
        cc: Vec::new(),
        date: fixture_date(),
        body: &*Box::leak(
            format!(
                "From: Billing <billing@example.org>\r\n\
                 To: me@example.org\r\n\
                 Subject: Two files\r\n\
                 MIME-Version: 1.0\r\n\
                 Content-Type: multipart/mixed; boundary=\"aux-mail-fixture\"\r\n\
                 \r\n\
                 --aux-mail-fixture\r\n\
                 Content-Type: text/plain; charset=UTF-8\r\n\
                 \r\n\
                 {TEXT_PART}\
                 --aux-mail-fixture\r\n\
                 Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
                 Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
                 Content-Transfer-Encoding: 7bit\r\n\
                 \r\n\
                 {PDF_PART}\
                 --aux-mail-fixture\r\n\
                 Content-Type: application/zip; name=\"archive.zip\"\r\n\
                 Content-Disposition: attachment; filename=\"archive.zip\"\r\n\
                 Content-Transfer-Encoding: base64\r\n\
                 \r\n\
                 {ZIP_PART}\r\n\
                 --aux-mail-fixture--\r\n"
            )
            .into_boxed_str(),
        ),
        flags: Vec::new(),
        bodystructure: Some(
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 31 1)\
             (\"APPLICATION\" \"PDF\" (\"NAME\" \"invoice.pdf\") NIL NIL \"7BIT\" 22 NIL \
             (\"ATTACHMENT\" (\"FILENAME\" \"invoice.pdf\")) NIL)\
             (\"APPLICATION\" \"ZIP\" (\"NAME\" \"archive.zip\") NIL NIL \"BASE64\" 12 NIL \
             (\"ATTACHMENT\" (\"FILENAME\" \"archive.zip\")) NIL) \"MIXED\" \
             (\"BOUNDARY\" \"aux-mail-fixture\") NIL NIL)",
        ),
        parts: vec![("1", TEXT_PART), ("2", PDF_PART), ("3", ZIP_PART)],
        in_reply_to: None,
    }
}

/// One multipart message whose three attachment parts each DECLARE `declared`
/// bytes while the fake serves `part` bytes for every one of them.
///
/// The understated-size case: the declared BODYSTRUCTURE total is tiny, but the
/// actual parts are large, so a call-budget check that trusts the declaration
/// can be blown past.
pub fn fixture_understated_parts(part: &'static str, declared: usize) -> RawMessage {
    let body: &'static str = Box::leak(
        "From: fixture\r\nSubject: understated\r\n\r\nunderstated parts\r\n"
            .to_string()
            .into_boxed_str(),
    );
    let bodystructure: &'static str = Box::leak(
        format!(
            "((\"APPLICATION\" \"PDF\" (\"NAME\" \"a.pdf\") NIL NIL \"7BIT\" {declared} NIL \
             (\"ATTACHMENT\" (\"FILENAME\" \"a.pdf\")) NIL)\
             (\"APPLICATION\" \"PDF\" (\"NAME\" \"b.pdf\") NIL NIL \"7BIT\" {declared} NIL \
             (\"ATTACHMENT\" (\"FILENAME\" \"b.pdf\")) NIL)\
             (\"APPLICATION\" \"PDF\" (\"NAME\" \"c.pdf\") NIL NIL \"7BIT\" {declared} NIL \
             (\"ATTACHMENT\" (\"FILENAME\" \"c.pdf\")) NIL) \"MIXED\" \
             (\"BOUNDARY\" \"aux-mail-fixture\") NIL NIL)"
        )
        .into_boxed_str(),
    );
    RawMessage {
        uid: 44,
        message_id: "<understated@fixture.example>".to_string(),
        subject: "Understated".to_string(),
        from: "Sender <sender@example.org>".to_string(),
        to: vec!["me@example.org".to_string()],
        cc: Vec::new(),
        date: fixture_date(),
        body,
        flags: Vec::new(),
        bodystructure: Some(bodystructure),
        parts: vec![("1", part), ("2", part), ("3", part)],
        in_reply_to: None,
    }
}

/// One message whose declared size is `bytes`, for the `TooLarge` path.
///
/// The body is leaked because [`RawMessage::body`] is `&'static str`; tests are
/// short-lived processes, so one bounded leak is fine.
pub fn fixture_oversized(uid: u32, bytes: usize) -> RawMessage {
    let body: &'static str = Box::leak("x".repeat(bytes).into_boxed_str());
    RawMessage {
        uid,
        message_id: format!("<{uid}@fixture.example>"),
        subject: "Huge".to_string(),
        from: "Person <person@example.org>".to_string(),
        to: vec!["me@example.org".to_string()],
        cc: Vec::new(),
        date: fixture_date(),
        body,
        flags: Vec::new(),
        bodystructure: None,
        parts: Vec::new(),
        in_reply_to: None,
    }
}
