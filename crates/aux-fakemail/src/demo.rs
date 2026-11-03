//! The daily-use demo mailbox: FICTIONAL DATA, dates relative to "now".
//!
//! `aux-fakemail demo` writes `<dir>/mailbox.json` once (twelve mails over the
//! last three days); `demo --seed` appends a fresh batch for today, so
//! tomorrow's brief has new mail. Senders are invented, every domain is
//! `*.example`. Newest mail has the highest UID, as the brief reads newest first.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fixture::{civil_from_days, StoredMail};

const OWNER: &str = "Owner <owner@mailsim.test>";
const TEXT: &str = "Content-Type: text/plain; charset=UTF-8\r\n";
const HOUR: i64 = 3_600;
const CAMILLE: &str = "Camille Example <camille@northwind.example>";
const JONAS: &str = "Jonas Sample <jonas@brightpath.example>";
/// Seed leads, one per day in rotation: (sender, subject, body).
const LEADS: [(&str, &str, &str); 5] = [
    (
        "Ines Fictive <ines@copperleaf.example>",
        "Quote for a booklet",
        "Hello, could you send me a quote for a 24-page booklet?",
    ),
    (
        "Tomas Placeholder <tomas@redwharf.example>",
        "A date in December?",
        "Hello, are you available for a short project in December?",
    ),
    (
        "Nora Testman <nora@silvergate.example>",
        "Introduction",
        "Hello, Jonas Sample recommended you to me. Could we talk this week?",
    ),
    (
        "Sam Invented <sam@oakridge.example>",
        "Pricing for a logo",
        "Hello, what do you charge for a simple logo refresh?",
    ),
    (
        "Lea Sample <lea@blueharbor.example>",
        "Booking you in spring",
        "Hello, I would like to book a call about a spring project.",
    ),
];

/// The twelve-mail set written at install.
pub fn demo_mailbox(now: i64) -> Vec<StoredMail> {
    let m = |uid, hours_ago: i64, from, subject, extra: &str, body: &str, unread| {
        mail(
            uid,
            now - hours_ago * HOUR,
            from,
            subject,
            extra,
            body,
            unread,
        )
    };
    let list = "List-Id: <weekly.studioweekly.example>\r\nList-Unsubscribe: <mailto:unsubscribe@studioweekly.example>\r\n";
    let auto = "Auto-Submitted: auto-replied\r\n";
    let mut mails = vec![
        m(1, 70, CAMILLE, "Notes from Friday's call", TEXT, "Hello, thanks for the call. Notes are in the shared folder.", false),
        m(2, 68, JONAS, "Draft copy for the launch page", TEXT, "Hello, the draft copy is ready for your review.", false),
        m(3, 50, "Priya Testman <priya@verdant.example>", "Automatic reply: out of office", &format!("{auto}{TEXT}"), "I am away until Monday with limited availability. This is an automatic reply.", false),
        m(4, 46, "Studio Weekly <news@studioweekly.example>", "Studio Weekly: pricing trends in design", &format!("{list}{TEXT}"), "This week: how studios talk about pricing and proposals. Unsubscribe any time.", false),
        m(6, 26, CAMILLE, "Re: Notes from Friday's call", TEXT, "Hello, one more point on the notes: the delivery window moved.", true),
        m(7, 25, "Mira Fictive <mira@lumenworks.example>", "Quote for a new brand site", TEXT, "Hello, I found your work online. Could you send me a quote for a five-page brand site?", true),
        m(8, 22, JONAS, "Launch page: second round", TEXT, "Hello, a few small changes for the second round.", true),
        m(9, 5, "Owen Placeholder <owen@quaystone.example>", "Are you free in November?", TEXT, "Hello, are you available for a two-week project starting early November?", true),
        m(10, 4, "Lena Sample <lena@harborline.example>", "Introduction from Camille", TEXT, "Hello, Camille Example recommended you to me. I would like to talk about a small project.", true),
        m(11, 3, CAMILLE, "Question about the delivery window", TEXT, "Hello, can we confirm the delivery window for next week?", true),
        m(12, 2, JONAS, "Thanks, looks good", TEXT, "Hello, the second round looks good. Thank you.", true),
    ];
    mails.insert(4, receipt(5, now - 30 * HOUR));
    mails
}

/// A fresh "today" batch: one new lead, one newsletter, two client mails.
pub fn seed_batch(existing: &[StoredMail], now: i64) -> Vec<StoredMail> {
    let first = existing.iter().map(|m| m.uid).max().unwrap_or(0) + 1;
    let (from, subject, body) = LEADS[now.div_euclid(86_400).rem_euclid(5) as usize];
    let (client, other) = if now.div_euclid(86_400) % 2 == 0 {
        (CAMILLE, JONAS)
    } else {
        (JONAS, CAMILLE)
    };
    let news = "List-Id: <weekly.studioweekly.example>\r\nList-Unsubscribe: <mailto:unsubscribe@studioweekly.example>\r\n";
    vec![
        mail(
            first,
            now - 4 * HOUR,
            "Studio Weekly <news@studioweekly.example>",
            "Studio Weekly: this week in design",
            &format!("{news}{TEXT}"),
            "This week: type, pricing and calm layouts. Unsubscribe any time.",
            true,
        ),
        mail(first + 1, now - 3 * HOUR, from, subject, TEXT, body, true),
        mail(
            first + 2,
            now - 2 * HOUR,
            client,
            "Quick update",
            TEXT,
            "Hello, a quick update: everything is on track.",
            true,
        ),
        mail(
            first + 3,
            now - HOUR,
            other,
            "Files for review",
            TEXT,
            "Hello, the files are in the shared folder.",
            true,
        ),
    ]
}

/// The Unix time now, in seconds.
fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Write the demo set to `<dir>/mailbox.json` (kept if present), or append a
/// seed batch. Returns the number of mails now stored.
pub fn write_demo(dir: &Path, seed: bool) -> io::Result<usize> {
    let now = now_epoch();
    let path = dir.join("mailbox.json");
    let mut mails: Vec<StoredMail> = match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    if seed {
        let batch = seed_batch(&mails, now);
        mails.extend(batch);
    } else if mails.is_empty() {
        mails = demo_mailbox(now);
    } else {
        return Ok(mails.len());
    }
    write_mailbox(dir, &mails)?;
    Ok(mails.len())
}

/// Write the mailbox back to `<dir>/mailbox.json`, atomically and 0600.
fn write_mailbox(dir: &Path, mails: &[StoredMail]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join("mailbox.json");
    let tmp = dir.join("mailbox.json.tmp");
    fs::write(
        &tmp,
        serde_json::to_vec_pretty(mails).map_err(io::Error::other)?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Re-seed the demo messages in `<dir>/mailbox.json` to the current demo
/// content, and leave every other message exactly as it is.
///
/// The demo owns its twelve messages: a demo mailbox written before a demo
/// change (an old receipt attachment, say) still holds the old bytes, and
/// the owner's copy of the app would then read a document the demo no longer
/// has. The re-seed is by message, not by file: the demo's marker
/// (`<demo-<uid>@mailsim.test>`) picks the messages it owns, so a message the
/// owner added is never touched.
///
/// The owner's own state of a demo message stays: its date and its flags. Only
/// the demo's content is refreshed, so the brief's window still measures the
/// same mail. Returns how many messages were refreshed.
pub(crate) fn refresh_demo(dir: &Path) -> io::Result<usize> {
    let path = dir.join("mailbox.json");
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(0);
    };
    let mut mails: Vec<StoredMail> =
        serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let current: std::collections::HashMap<u32, StoredMail> = demo_mailbox(now_epoch())
        .into_iter()
        .map(|mail| (mail.uid, mail))
        .collect();
    let mut refreshed = 0;
    for mail in mails.iter_mut() {
        let demo =
            mail.message_id.starts_with("<demo-") && mail.message_id.ends_with("@mailsim.test>");
        // Only the demo set is re-seeded: a seeded batch (uid past the set)
        // is yesterday's mail and keeps the day it was written for.
        let Some(fresh) = current.get(&mail.uid).filter(|_| demo) else {
            continue;
        };
        let date = mail.date.clone();
        let mut fresh = fresh.clone();
        fresh.body = fresh.body.replace(&fresh.date, &date);
        fresh.date = date;
        fresh.flags = mail.flags.clone();
        if mail.body == fresh.body && mail.parts == fresh.parts {
            continue;
        }
        *mail = fresh;
        refreshed += 1;
    }
    if refreshed > 0 {
        write_mailbox(dir, &mails)?;
    }
    Ok(refreshed)
}

fn mail(
    uid: u32,
    epoch: i64,
    from: &str,
    subject: &str,
    extra: &str,
    text: &str,
    unread: bool,
) -> StoredMail {
    let date = rfc2822(epoch);
    let id = format!("<demo-{uid}@mailsim.test>");
    StoredMail {
        uid,
        message_id: id.clone(),
        subject: subject.to_string(),
        from: from.to_string(),
        to: vec![OWNER.to_string()],
        body: format!(
            "From: {from}\r\nTo: {OWNER}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {id}\r\nMIME-Version: 1.0\r\n{extra}\r\n{text}\r\n"
        ),
        date,
        flags: if unread { Vec::new() } else { vec!["\\Seen".to_string()] },
        ..StoredMail::default()
    }
}

/// The receipt's PDF: a real, minimal one-page PDF (DOC-COLLECT-2).
///
/// Before, the attachment was a `%PDF-1.4` header followed by plain text: not
/// a PDF at all, so PDFKit refused it and the document stayed empty ("other,
/// no total") in the owner's Documents list. These bytes are a genuine PDF —
/// a catalog, one page, one Helvetica font and an uncompressed content stream
/// whose text layer carries the seller, the invoice number, the date and the
/// total.
///
/// The cross-reference offsets are the byte positions of the five objects.
/// Every line ends with CRLF, as a PDF file's lines do, and the file is ASCII,
/// so it travels as a `7bit` MIME part, without a transfer encoding.
const RECEIPT_PDF: &str = concat!(
    "%PDF-1.4\r\n",
    "1 0 obj\r\n<< /Type /Catalog /Pages 2 0 R >>\r\nendobj\r\n",
    "2 0 obj\r\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\r\nendobj\r\n",
    "3 0 obj\r\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\r\nendobj\r\n",
    "4 0 obj\r\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\r\nendobj\r\n",
    "5 0 obj\r\n<< /Length 152 >>\r\nstream\r\n",
    "BT\r\n/F1 12 Tf\r\n14 TL\r\n72 780 Td\r\n",
    "(Verdant Billing) Tj\r\nT*\r\n(Invoice VF-2210 - 2026-10-14) Tj\r\nT*\r\n",
    "(Date 14 Oct 2026) Tj\r\nT*\r\n(Total 120.00 EUR) Tj\r\nET\r\n",
    "endstream\r\nendobj\r\n",
    "xref\r\n0 6\r\n0000000000 65535 f\r\n0000000010 00000 n\r\n0000000062 00000 n\r\n",
    "0000000122 00000 n\r\n0000000251 00000 n\r\n0000000351 00000 n\r\n",
    "trailer\r\n<< /Size 6 /Root 1 0 R >>\r\nstartxref\r\n558\r\n%%EOF\r\n",
);

/// An invoice receipt with a small PDF attachment (for the M5 document flow).
///
/// The attachment is a real PDF (see [`RECEIPT_PDF`]): the Mac bridge reads
/// its text layer, so the receipt carries the invoice number and the amount
/// the owner asks about.
fn receipt(uid: u32, epoch: i64) -> StoredMail {
    const TEXT_PART: &str = "Hello, your receipt for invoice VF-2210 is attached.\r\n";
    let extra = "Content-Type: multipart/mixed; boundary=\"demo-receipt\"\r\n";
    let text = format!(
        "--demo-receipt\r\n{TEXT}\r\n{TEXT_PART}--demo-receipt\r\nContent-Type: application/pdf; name=\"receipt-VF-2210.pdf\"\r\nContent-Disposition: attachment; filename=\"receipt-VF-2210.pdf\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n{RECEIPT_PDF}--demo-receipt--"
    );
    StoredMail {
        bodystructure: Some(format!(
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" {} 1)(\"APPLICATION\" \"PDF\" (\"NAME\" \"receipt-VF-2210.pdf\") NIL NIL \"7BIT\" {} NIL (\"ATTACHMENT\" (\"FILENAME\" \"receipt-VF-2210.pdf\")) NIL) \"MIXED\" (\"BOUNDARY\" \"demo-receipt\") NIL NIL)",
            TEXT_PART.len(),
            RECEIPT_PDF.len()
        )),
        parts: vec![("1".to_string(), TEXT_PART.to_string()), ("2".to_string(), RECEIPT_PDF.to_string())],
        ..mail(uid, epoch, "Verdant Billing <billing@verdant.example>", "Receipt for invoice VF-2210", extra, &text, true)
    }
}

/// A UTC RFC 2822 date for a Unix time.
fn rfc2822(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][(days + 4).rem_euclid(7) as usize];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{weekday}, {day} {} {year} {:02}:{:02}:{:02} +0000",
        months[(month - 1) as usize],
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}
