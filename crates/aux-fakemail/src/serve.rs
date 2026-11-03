//! The long-running simulator the `aux-fakemail` binary serves.
//!
//! It writes one self-signed certificate (`cert.pem`, `key.pem` mode 0600),
//! loads a fictional mailbox (`mailbox.json` when present, else the built-in
//! fixture), and runs the fake IMAP and SMTP servers on loopback. Every SMTP
//! submission is mirrored into the IMAP `Sent` folder and written to
//! `outbox/<n>.eml`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::fake_imap::{FakeImap, MailboxHandle};
use crate::fake_smtp::FakeSmtp;
use crate::fixture::{daily_mail, default_mailbox, today, StoredMail};
use crate::fixtures::RawMessage;
use crate::{TestCert, SIM_LOGIN};

/// What the simulator binds and where it keeps its files (`0` = ephemeral).
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Directory holding `cert.pem`, `key.pem`, optional `mailbox.json` and `outbox/`.
    pub dir: PathBuf,
    /// IMAP port; `0` binds an ephemeral port.
    pub imap_port: u16,
    /// SMTP port; `0` binds an ephemeral port.
    pub smtp_port: u16,
}

/// A running simulator. Dropping it stops both listeners.
pub struct SimServer {
    /// The bound IMAP port.
    pub imap_port: u16,
    /// The bound SMTP port.
    pub smtp_port: u16,
    /// The self-signed CA file the client pins.
    pub ca_file: PathBuf,
    /// Where accepted SMTP messages are written.
    pub outbox: PathBuf,
    // Held to keep both listeners alive for the server's lifetime.
    imap: FakeImap,
    smtp: FakeSmtp,
}

/// Start the simulator. Binds loopback only.
pub async fn serve(config: SimConfig) -> io::Result<SimServer> {
    // A busy port is a plain error, not a panic inside the fakes.
    for port in [config.imap_port, config.smtp_port] {
        if port != 0 {
            std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("cannot listen on 127.0.0.1:{port}: {error}"),
                )
            })?;
        }
    }
    fs::create_dir_all(&config.dir)?;
    // The demo messages the demo owns are re-seeded to the current demo
    // content, so a mailbox written before a demo change serves the new
    // bytes. The owner's own messages are never touched.
    crate::demo::refresh_demo(&config.dir)?;
    let cert = load_or_create_cert(&config.dir)?;
    let ca_file = config.dir.join("cert.pem");
    let outbox = config.dir.join("outbox");
    fs::create_dir_all(&outbox)?;

    // A mail stored with another `folder` (the world's Sent) is served there.
    let (inbox, other): (Vec<_>, Vec<_>) =
        load_mailbox(&config.dir)?.into_iter().partition(|mail| {
            mail.folder
                .as_deref()
                .is_none_or(|f| f.eq_ignore_ascii_case("INBOX"))
        });
    let messages = inbox.into_iter().map(StoredMail::into_raw).collect();
    let imap = FakeImap::spawn_sim(messages, cert.clone(), config.imap_port, SIM_LOGIN).await;
    let mailbox = imap.mailbox();
    for mail in other {
        mailbox.push(&mail.folder.clone().unwrap_or_default(), mail.into_raw());
    }
    let smtp = FakeSmtp::spawn_sim(cert, config.smtp_port).await;

    let counter = Arc::new(Mutex::new(next_outbox_number(&outbox)));
    let outbox_for_callback = outbox.clone();
    smtp.set_on_accept(move |body: &str| {
        let number = {
            let mut next = counter.lock().expect("outbox counter");
            *next += 1;
            *next
        };
        let _ = fs::write(outbox_for_callback.join(format!("{number}.eml")), body);
        mailbox.push("Sent", raw_from_submission(body, number));
    });

    Ok(SimServer {
        imap_port: imap.port,
        smtp_port: smtp.port,
        ca_file,
        outbox,
        imap,
        smtp,
    })
}

/// How many daily mails `--daily-mail` keeps in INBOX.
const DAILY_MAIL_KEEP: i64 = 14;

/// Drop the daily mails older than the newest `DAILY_MAIL_KEEP` days (up to `now`).
fn prune_daily(mailbox: &MailboxHandle, now: i64) {
    mailbox.retain("INBOX", |message| {
        let day = message.message_id.strip_prefix("<sim-daily-");
        let day = day.and_then(|rest| rest.split('@').next()?.parse::<i64>().ok());
        day.is_none_or(|day| day > now - DAILY_MAIL_KEEP)
    });
}

impl SimServer {
    /// Drop one new unread fictional mail into INBOX each UTC day, for as long
    /// as the returned task runs, keeping the newest 14. The mailbox loaded at
    /// start is already dated today, so the first drop is the next day.
    pub fn drip_daily_mail(&self) -> tokio::task::JoinHandle<()> {
        let mailbox = self.imap.mailbox();
        let mut last = today();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                let now = today();
                if now > last {
                    last = now;
                    mailbox.push("INBOX", daily_mail(now).into_raw());
                    prune_daily(&mailbox, now);
                }
            }
        })
    }
}

/// Load `<dir>/mailbox.json`, or the built-in fictional fixture.
fn load_mailbox(dir: &Path) -> io::Result<Vec<StoredMail>> {
    let path = dir.join("mailbox.json");
    let stored: Vec<StoredMail> = if path.exists() {
        let text = fs::read_to_string(&path)?;
        serde_json::from_str(&text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
    } else {
        default_mailbox()
    };
    Ok(stored)
}

/// Reuse `<dir>/cert.pem`+`key.pem`, or generate and write them once.
fn load_or_create_cert(dir: &Path) -> io::Result<TestCert> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        let cert = CertificateDer::from_pem_file(&cert_path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let key = PrivateKeyDer::from_pem_file(&key_path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        return Ok(TestCert::from_der(cert, key.secret_der().to_vec()));
    }
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .map_err(io::Error::other)?;
    write_private(&key_path, signing_key.serialize_pem().as_bytes())?;
    fs::write(&cert_path, cert.pem())?;
    Ok(TestCert::from_der(
        cert.der().clone(),
        signing_key.serialize_der(),
    ))
}

/// Write a file readable only by its owner (the private key).
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// The next `outbox/<n>.eml` number, so a restart never overwrites one.
fn next_outbox_number(dir: &Path) -> u32 {
    let mut highest = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(number) = entry
                .path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u32>().ok())
            {
                highest = highest.max(number);
            }
        }
    }
    highest
}

/// Build a `Sent` fixture from the RFC822 bytes SMTP accepted.
fn raw_from_submission(body: &str, number: u32) -> RawMessage {
    let header = |name: &str| -> Option<String> {
        body.lines()
            .take_while(|line| !line.is_empty())
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
    };
    let from = header("From").unwrap_or_default();
    let to: Vec<String> = header("To")
        .map(|value| {
            value
                .split(',')
                .map(|address| address.trim().to_string())
                .filter(|address| !address.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let subject = header("Subject").unwrap_or_default();
    let date = header("Date").unwrap_or_default();
    let message_id = header("Message-ID").unwrap_or_else(|| format!("<out-{number}@mailsim.test>"));
    let in_reply_to = header("In-Reply-To");
    RawMessage {
        uid: number,
        message_id,
        subject,
        from,
        to,
        cc: Vec::new(),
        date,
        body: Box::leak(body.to_string().into_boxed_str()),
        flags: Vec::new(),
        bodystructure: None,
        parts: Vec::new(),
        in_reply_to,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_imap::FakeImap;

    #[tokio::test]
    async fn daily_mail_keeps_only_the_newest_fourteen() {
        let imap = FakeImap::spawn(vec![default_mailbox().remove(0).into_raw()]).await;
        let mailbox = imap.mailbox();
        for day in 100..130 {
            mailbox.push("INBOX", daily_mail(day).into_raw());
            prune_daily(&mailbox, day);
        }
        assert_eq!(mailbox.len("INBOX"), 1 + DAILY_MAIL_KEEP as usize);
    }

    #[tokio::test]
    async fn a_busy_port_is_an_error_not_a_panic() {
        let busy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = busy.local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("aux-fakemail-busy-{port}"));
        let config = SimConfig {
            dir: dir.clone(),
            imap_port: port,
            smtp_port: 0,
        };
        let error = serve(config).await.err().expect("port is busy");
        assert!(error.to_string().contains(&port.to_string()));
        let _ = fs::remove_dir_all(dir);
    }
}
