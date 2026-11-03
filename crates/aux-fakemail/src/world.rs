//! A rich fictional freelancer world for demos (`aux-fakemail demo --world`).
//!
//! ~120 mails over the last 60 days, ~15 client companies + prospects + partners,
//! both directions, covering the situations the demos exercise. Pure fictional
//! data; every domain is `*.example` except tracker hosts in HTML. Deterministic
//! for a fixed `now`.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::fixture::{civil_from_days, StoredMail};

const OWNER: &str = "Owner <owner@mailsim.test>";

#[derive(Deserialize)]
struct Desc {
    uid: u32,
    days_ago: i64,
    from: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    subject: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    extra: String,
    #[serde(default)]
    unread: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    attachments: Vec<Attachment>,
    #[serde(default)]
    message_id: String,
    #[serde(default)]
    in_reply_to: Option<String>,
}

#[derive(Deserialize)]
struct Attachment {
    name: String,
    mime: String,
    content: String,
}

// Sensitive-value bait (fictional, clearly fake): a test IBAN (DE89370400440532013000),
// a French fiction-reserved phone (+33639981234) and an ID-like number (123456789012).
// Tagged "sensitive-bait" in their `tags`.
pub fn world_mailbox(now: i64) -> Vec<StoredMail> {
    let raw: Vec<Desc> = serde_json::from_str(include_str!("world.json")).expect("world.json");
    let mut out = Vec::with_capacity(raw.len());
    for d in raw {
        let epoch = now - d.days_ago * 86_400;
        let date = rfc2822(epoch);
        let id = if d.message_id.is_empty() {
            format!("<world-{}@mailsim.test>", d.uid)
        } else {
            d.message_id.clone()
        };
        let to = if d.to.is_empty() {
            vec![OWNER.to_string()]
        } else {
            d.to.clone()
        };
        let (body, bodystructure, parts) = if d.attachments.is_empty() {
            let extra = if d.extra.is_empty() {
                "Content-Type: text/plain; charset=UTF-8\r\n".to_string()
            } else {
                d.extra.clone()
            };
            let body = format!(
                "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: {}\r\nMIME-Version: 1.0\r\n{}\r\n{}\r\n",
                d.from,
                to.join(", "),
                d.subject,
                date,
                id,
                extra,
                d.text
            );
            (body, None, Vec::new())
        } else {
            build_multipart(
                d.uid,
                &d.from,
                &to,
                &d.subject,
                &date,
                &id,
                &d.text,
                &d.attachments,
            )
        };
        out.push(StoredMail {
            uid: d.uid,
            message_id: id.clone(),
            subject: d.subject.clone(),
            from: d.from.clone(),
            to: to.clone(),
            cc: d.cc.clone(),
            date: date.clone(),
            body,
            flags: if d.unread {
                Vec::new()
            } else {
                vec!["\\Seen".to_string()]
            },
            in_reply_to: d.in_reply_to.clone(),
            bodystructure,
            parts,
            tags: d.tags.clone(),
            // The owner's own mails live in Sent, as on a real account.
            folder: (d.from == OWNER).then(|| "Sent".to_string()),
        });
    }
    // newest = highest uid: ensure sorted by date asc then uid asc (already).
    out
}

#[allow(clippy::too_many_arguments)]
fn build_multipart(
    uid: u32,
    from: &str,
    to: &[String],
    subject: &str,
    date: &str,
    id: &str,
    text: &str,
    attachments: &[Attachment],
) -> (String, Option<String>, Vec<(String, String)>) {
    let boundary = format!("world-{}", uid);
    let mut body = String::new();
    body.push_str(&format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: {}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n",
        from,
        to.join(", "),
        subject,
        date,
        id,
        boundary
    ));
    // text part
    body.push_str(&format!(
        "--{}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}\r\n",
        boundary, text
    ));
    let mut parts: Vec<(String, String)> = vec![("1".to_string(), text.to_string())];
    let mut bs_parts = vec![format!(
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" {} 1)",
        text.len()
    )];
    for (idx, att) in attachments.iter().enumerate() {
        let part_no = idx + 2;
        body.push_str(&format!(
            "--{}\r\nContent-Type: {}; name=\"{}\"\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n{}\r\n",
            boundary, att.mime, att.name, att.name, att.content
        ));
        parts.push((part_no.to_string(), att.content.clone()));
        bs_parts.push(format!(
            "(\"{}\" \"{}\" (\"NAME\" \"{}\") NIL NIL \"7BIT\" {} NIL (\"ATTACHMENT\" (\"FILENAME\" \"{}\")) NIL)",
            att.mime.split('/').next().unwrap_or("APPLICATION").to_uppercase(),
            att.mime.split('/').nth(1).unwrap_or("OCTET-STREAM").to_uppercase(),
            att.name,
            att.content.len(),
            att.name
        ));
    }
    body.push_str(&format!("--{}--\r\n", boundary));
    // RFC 3501 body-type-mpart is `1*body SP media-subtype`: the child parts are
    // concatenated with no separator. A space between them is a parse error for
    // the real client (FAKEMAIL-MULTIPART).
    let bodystructure = format!(
        "({} \"MIXED\" (\"BOUNDARY\" \"{}\") NIL NIL)",
        bs_parts.concat(),
        boundary
    );
    (body, Some(bodystructure), parts)
}

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
        "{}, {} {} {} {:02}:{:02}:{:02} +0000",
        weekday,
        day,
        months[(month - 1) as usize],
        year,
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}

pub fn write_world(dir: &Path, force: bool) -> io::Result<usize> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| io::Error::other("system clock before unix epoch"))?;
    let path = dir.join("mailbox.json");
    if path.exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "mailbox.json already exists; use --force to overwrite",
        ));
    }
    let mails = world_mailbox(now);
    fs::create_dir_all(dir)?;
    let tmp = dir.join("mailbox.json.tmp");
    fs::write(
        &tmp,
        serde_json::to_vec_pretty(&mails).map_err(io::Error::other)?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, &path)?;
    Ok(mails.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security};
    use aux_mail::dial::Dialer;
    use aux_mail::imap_read::{FetchedAttachments, MailService};
    use aux_mail::limits::Limits;

    use crate::{serve, SimConfig, StaticCredentials};

    const NOW: i64 = 1_792_000_000;
    #[test]
    fn deterministic() {
        assert_eq!(world_mailbox(NOW).len(), world_mailbox(NOW).len());
        let a = world_mailbox(NOW);
        let b = world_mailbox(NOW);
        assert_eq!(a[0].subject, b[0].subject);
    }

    /// FAKEMAIL-MULTIPART: demo mails with attachments must read through the real
    /// aux-mail client. The client's `BODYSTRUCTURE` parser is strict RFC 3501, so
    /// one attachment (uid 114, a demo-world invoice) and two attachments (uid
    /// 9001, built here) must both list every part with its MIME type.
    #[tokio::test]
    async fn demo_mails_with_attachments_read_through_the_real_client() {
        const TWO_PARTS: u32 = 9_001;
        let attachments = [
            Attachment {
                name: "receipt.pdf".to_string(),
                mime: "application/pdf".to_string(),
                content: "%PDF-1.4 demo receipt\r\n".to_string(),
            },
            Attachment {
                name: "invoice.xml".to_string(),
                mime: "application/xml".to_string(),
                content: "<Invoice><Total>120.00</Total></Invoice>\r\n".to_string(),
            },
        ];
        let to = vec![OWNER.to_string()];
        let date = "Mon, 5 Oct 2026 09:00:00 +0000";
        let id = "<two-receipts@mailsim.test>";
        let (body, bodystructure, parts) = build_multipart(
            TWO_PARTS,
            "Client <client@client.example>",
            &to,
            "Two receipts",
            date,
            id,
            "Both receipts attached.",
            &attachments,
        );
        let mut mails: Vec<StoredMail> = world_mailbox(NOW)
            .into_iter()
            .filter(|mail| mail.uid == 114)
            .collect();
        mails.push(StoredMail {
            uid: TWO_PARTS,
            message_id: id.to_string(),
            subject: "Two receipts".to_string(),
            from: "Client <client@client.example>".to_string(),
            to,
            cc: Vec::new(),
            date: date.to_string(),
            body,
            flags: Vec::new(),
            in_reply_to: None,
            bodystructure,
            parts,
            tags: Vec::new(),
            folder: None,
        });
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("mailbox.json"),
            serde_json::to_string(&mails).expect("mailbox json"),
        )
        .expect("write mailbox.json");
        let server = serve(SimConfig {
            dir: dir.path().to_path_buf(),
            imap_port: 0,
            smtp_port: 0,
        })
        .await
        .expect("start the simulator");

        let limits = Limits::default();
        let ca = server.ca_file.to_string_lossy().into_owned();
        let account = MailAccount {
            id: "mailsim".to_string(),
            email: "owner@mailsim.test".to_string(),
            display: None,
            imap: ImapSettings {
                host: "127.0.0.1".to_string(),
                port: server.imap_port,
                security: Security::Tls,
                username: None,
                ca_file: Some(ca),
            },
            smtp: None,
            folders: FolderMap::default(),
            only_folders: vec!["INBOX".to_string()],
        };
        let service = MailService::new(
            Dialer::new(limits.connect_timeout),
            limits,
            vec![account],
            Arc::new(StaticCredentials::new("mailsim", "any-password")),
        );

        let mimes = |fetched: &FetchedAttachments| -> Vec<String> {
            fetched
                .downloaded
                .iter()
                .map(|part| part.mime.clone())
                .chain(fetched.skipped.iter().map(|part| part.mime.clone()))
                .collect()
        };
        let invoice = service
            .fetch_attachments("mailsim", "INBOX", 114, 0)
            .await
            .expect("the demo-world invoice reads");
        assert_eq!(mimes(&invoice), vec!["application/xml"]);
        let two = service
            .fetch_attachments("mailsim", "INBOX", TWO_PARTS, 0)
            .await
            .expect("the two-attachment demo mail reads");
        assert_eq!(
            mimes(&two),
            vec!["application/pdf", "application/xml"],
            "every attachment part is listed with its MIME type"
        );
    }
}
