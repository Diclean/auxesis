//! SMTP submission: one message, one attempt (`docs/mail.md` §5).
//!
//! The sender shares MA1's dial and TLS: [`Dialer::secure`] is the same
//! `tokio-rustls` handshake the IMAP path uses, with the same `webpki-roots`
//! verifier and the same typed certificate refusal. Implicit TLS wraps the
//! socket from the first byte (465); STARTTLS upgrades a plain socket after
//! `EHLO` and refuses to continue when the server does not advertise it (587).
//!
//! # No retry, ever
//!
//! A retried send is a duplicate email to a person. Every command is written
//! once and its reply typed: a `4xx` (the `421` throttling case included) comes
//! back as [`MailError::RateLimited`], a refused password as
//! [`MailError::SmtpAuth`], a refused sender as [`MailError::RelayDenied`], and
//! the loop never runs the exchange again.

use std::fmt::Debug;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::b64;
use crate::config::{Security, SmtpSettings};
use crate::dial::Dialer;
use crate::error::MailError;
use crate::limits::Limits;
use crate::presets::Endpoint;
use crate::send::SendOutcome;

/// Longest protocol line buffered.
const MAX_LINE: usize = 8 * 1024;

/// Most continuation lines tolerated in one reply.
const MAX_REPLY_LINES: usize = 64;

/// The `EHLO` name the client introduces itself with. A literal address would
/// leak the owner's network; this fixed name carries nothing.
const CLIENT_NAME: &str = "auxesis.local";

/// Send `message` to `recipients` from `from`, exactly once.
///
/// The whole exchange — dial, TLS, `EHLO`, `AUTH`, `MAIL FROM`, each `RCPT TO`,
/// `DATA`, `QUIT` — runs inside [`Limits::call_timeout`], so a silent server
/// cannot hold the caller forever.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_once(
    settings: &SmtpSettings,
    account_email: &str,
    password: &str,
    from: &str,
    recipients: &[String],
    message: &[u8],
    dialer: &Dialer,
    limits: &Limits,
) -> Result<SendOutcome, MailError> {
    let endpoint = Endpoint {
        host: settings.host.clone(),
        port: settings.port,
        security: settings.security,
    };
    // A password is never sent without encryption, and the refusal happens
    // before any socket opens (`docs/mail.md` §5). A `plain` account with no
    // credential is a local relay with nothing to leak, so it may proceed.
    if !endpoint.security.is_encrypted() && !password.is_empty() {
        return Err(MailError::InsecurePassword {
            host: endpoint.host,
            port: endpoint.port,
        });
    }
    // A `ca_file` pins exactly that certificate and is loopback-only; both the
    // host check and the file read happen before any socket is opened. Without
    // it the caller's dialer (the webpki-roots production path) is unchanged.
    let pinned;
    let dialer = match settings.ca_file.as_deref() {
        Some(ca_file) => {
            crate::tlsutil::ensure_loopback_ca(&endpoint.host)?;
            pinned = Dialer::with_ca_file(std::path::Path::new(ca_file), dialer.connect_timeout())?;
            &pinned
        }
        None => dialer,
    };
    let username = settings.username(account_email).to_string();
    let data_started = Arc::new(AtomicBool::new(false));
    let outcome = tokio::time::timeout(limits.call_timeout, async {
        let tcp = connect_tcp(&endpoint, dialer).await?;
        match endpoint.security {
            Security::Tls => {
                let mut stream = dialer.secure(tcp, &endpoint.host, endpoint.port).await?;
                greet(&mut stream).await?;
                let capabilities = ehlo(&mut stream).await?;
                let (accepted, code) = submit(
                    &mut stream,
                    &capabilities,
                    &username,
                    password,
                    from,
                    recipients,
                    message,
                    &data_started,
                )
                .await?;
                quit(&mut stream).await;
                Ok(SendOutcome::new(accepted, code, message.len()))
            }
            Security::StartTls => {
                let mut plain = tcp;
                greet(&mut plain).await?;
                let capabilities = ehlo(&mut plain).await?;
                if !advertises(&capabilities, "STARTTLS") {
                    return Err(MailError::NoStartTls {
                        host: endpoint.host,
                        port: endpoint.port,
                    });
                }
                let reply = command(&mut plain, "STARTTLS").await?;
                if reply.code != 220 {
                    return Err(reply_error(reply.code, ReplyStage::Ehlo));
                }
                let mut stream = dialer.secure(plain, &endpoint.host, endpoint.port).await?;
                let capabilities = ehlo(&mut stream).await?;
                let (accepted, code) = submit(
                    &mut stream,
                    &capabilities,
                    &username,
                    password,
                    from,
                    recipients,
                    message,
                    &data_started,
                )
                .await?;
                quit(&mut stream).await;
                Ok(SendOutcome::new(accepted, code, message.len()))
            }
            // Refused above when a credential would cross in the clear; with no
            // credential this is an explicit local relay.
            Security::Plain => {
                let mut stream = tcp;
                greet(&mut stream).await?;
                let capabilities = ehlo(&mut stream).await?;
                let (accepted, code) = submit(
                    &mut stream,
                    &capabilities,
                    &username,
                    password,
                    from,
                    recipients,
                    message,
                    &data_started,
                )
                .await?;
                quit(&mut stream).await;
                Ok(SendOutcome::new(accepted, code, message.len()))
            }
        }
    })
    .await;
    match outcome {
        // A timeout after DATA began is ambiguous: the server may have the
        // message even though the client never read its final reply.
        Err(_) if data_started.load(Ordering::SeqCst) => Err(MailError::Uncertain),
        Err(_) => Err(MailError::Timeout {
            budget: limits.call_timeout,
        }),
        Ok(result) => result,
    }
}

async fn connect_tcp(endpoint: &Endpoint, dialer: &Dialer) -> Result<TcpStream, MailError> {
    let connect = tokio::time::timeout(
        dialer.connect_timeout(),
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| MailError::Connect {
        host: endpoint.host.clone(),
        port: endpoint.port,
    })?
    .map_err(|error| classify_connect(&endpoint.host, endpoint.port, error))?;
    Ok(connect)
}

/// The whole authenticated submission after the socket is secure.
#[allow(clippy::too_many_arguments)]
async fn submit<S>(
    stream: &mut S,
    capabilities: &[String],
    username: &str,
    password: &str,
    from: &str,
    recipients: &[String],
    message: &[u8],
    data_started: &AtomicBool,
) -> Result<(usize, u16), MailError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Debug,
{
    // No credential means no AUTH: an explicit local relay with nothing to
    // authenticate.
    if !password.is_empty() {
        authenticate(stream, capabilities, username, password).await?;
    }

    let reply = command(stream, &format!("MAIL FROM:<{from}>")).await?;
    mail_from_reply(reply.code, from)?;
    let mut accepted = 0usize;
    for recipient in recipients {
        let reply = command(stream, &format!("RCPT TO:<{recipient}>")).await?;
        if reply.code != 250 && reply.code != 251 {
            return Err(MailError::RecipientDenied {
                to: recipient.clone(),
            });
        }
        accepted += 1;
    }

    let ready = command(stream, "DATA").await?;
    if ready.code != 354 {
        return Err(reply_error(ready.code, ReplyStage::Data));
    }
    // From here the server may accept the message even if the connection or
    // the final reply fails: every outcome is `Uncertain`, never a release.
    data_started.store(true, Ordering::SeqCst);
    write_all(stream, message)
        .await
        .map_err(|_| MailError::Uncertain)?;
    let reply = read_reply(stream).await.map_err(|_| MailError::Uncertain)?;
    if reply.code != 250 {
        return Err(MailError::Uncertain);
    }
    Ok((accepted, reply.code))
}

/// Authenticate with `AUTH PLAIN`, then `AUTH LOGIN`, one mechanism only.
async fn authenticate<S>(
    stream: &mut S,
    capabilities: &[String],
    username: &str,
    password: &str,
) -> Result<(), MailError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mechanisms = auth_mechanisms(capabilities);
    if mechanisms.iter().any(|name| name == "PLAIN") {
        let token = b64::encode(format!("\0{username}\0{password}").as_bytes());
        write_line(stream, &format!("AUTH PLAIN {token}")).await?;
        let mut reply = read_reply(stream).await?;
        // A server that wants the token on the continuation line.
        if reply.code == 334 {
            write_line(stream, &token).await?;
            reply = read_reply(stream).await?;
        }
        return auth_result(reply.code);
    }
    if mechanisms.iter().any(|name| name == "LOGIN") {
        write_line(stream, "AUTH LOGIN").await?;
        let reply = read_reply(stream).await?;
        if reply.code != 334 {
            return auth_result(reply.code);
        }
        write_line(stream, &b64::encode(username.as_bytes())).await?;
        let reply = read_reply(stream).await?;
        if reply.code != 334 {
            return auth_result(reply.code);
        }
        write_line(stream, &b64::encode(password.as_bytes())).await?;
        let reply = read_reply(stream).await?;
        return auth_result(reply.code);
    }
    Err(MailError::NoAuthMechanism)
}

fn auth_result(code: u16) -> Result<(), MailError> {
    if code == 235 {
        Ok(())
    } else {
        Err(MailError::SmtpAuth)
    }
}

/// Send `EHLO` and return the advertised capability lines.
async fn ehlo<S>(stream: &mut S) -> Result<Vec<String>, MailError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let reply = command(stream, &format!("EHLO {CLIENT_NAME}")).await?;
    if reply.code != 250 {
        return Err(reply_error(reply.code, ReplyStage::Ehlo));
    }
    Ok(reply
        .lines
        .iter()
        .filter_map(|line| line.get(4..).map(str::trim).map(str::to_string))
        .filter(|line| !line.is_empty())
        .collect())
}

/// Read and check the server greeting.
async fn greet<S>(stream: &mut S) -> Result<(), MailError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let reply = read_reply(stream).await?;
    if reply.code == 220 {
        Ok(())
    } else {
        Err(reply_error(reply.code, ReplyStage::Greeting))
    }
}

/// Send one command and read its reply (no retry).
async fn command<S>(stream: &mut S, line: &str) -> Result<Reply, MailError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_line(stream, line).await?;
    read_reply(stream).await
}

/// Best-effort `QUIT`; a failure here never changes the send's outcome.
async fn quit<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = write_line(stream, "QUIT").await;
    let _ = read_reply(stream).await;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

/// Why a command was refused, for the reply's typed error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyStage {
    Greeting,
    Ehlo,
    Data,
}

/// Map a refused reply to the error vocabulary.
fn reply_error(code: u16, _stage: ReplyStage) -> MailError {
    if code == 421 || (400..500).contains(&code) {
        MailError::RateLimited
    } else {
        MailError::Protocol
    }
}

/// The `MAIL FROM` refusal carries the sender so the message can name it.
fn mail_from_error(code: u16, from: &str) -> MailError {
    if code == 421 || (400..500).contains(&code) {
        MailError::RateLimited
    } else {
        MailError::RelayDenied {
            from: from.to_string(),
        }
    }
}

/// The mechanisms one `AUTH …` capability advertises (`AUTH PLAIN LOGIN` and
/// the `AUTH=PLAIN` spelling both count).
fn auth_mechanisms(capabilities: &[String]) -> Vec<String> {
    let mut mechanisms = Vec::new();
    for capability in capabilities {
        let upper = capability.to_ascii_uppercase();
        let rest = if let Some(rest) = upper.strip_prefix("AUTH=") {
            rest.to_string()
        } else if let Some(rest) = upper.strip_prefix("AUTH ") {
            rest.to_string()
        } else {
            continue;
        };
        for name in rest.split_whitespace() {
            if !mechanisms.iter().any(|known| known == name) {
                mechanisms.push(name.to_string());
            }
        }
    }
    mechanisms
}

/// True when the capability list advertises exactly `name`.
fn advertises(capabilities: &[String], name: &str) -> bool {
    capabilities
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case(name))
}

/// Read one full SMTP reply: a run of `NNN-…` lines ended by `NNN …`.
async fn read_reply<S>(stream: &mut S) -> Result<Reply, MailError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut lines = Vec::new();
    loop {
        let line = read_line(stream)
            .await
            .map_err(|_| MailError::Protocol)?
            .ok_or(MailError::Protocol)?;
        let bytes = line.as_bytes();
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return Err(MailError::Protocol);
        }
        let code: u16 = std::str::from_utf8(&bytes[..3])
            .map_err(|_| MailError::Protocol)?
            .parse()
            .map_err(|_| MailError::Protocol)?;
        let continued = bytes.get(3) == Some(&b'-');
        lines.push(line);
        if lines.len() > MAX_REPLY_LINES {
            return Err(MailError::Protocol);
        }
        if !continued {
            return Ok(Reply { code, lines });
        }
    }
}

/// A malformed reply may quote the `AUTH` line (the password included), so a
/// parse failure collapses to the typed kind alone and never carries text.
async fn read_line<S>(stream: &mut S) -> io::Result<Option<String>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => {
                return Ok(if buffer.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&buffer).into_owned())
                })
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        if byte[0] == b'\n' {
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
            return Ok(Some(String::from_utf8_lossy(&buffer).into_owned()));
        }
        buffer.push(byte[0]);
        if buffer.len() > MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }
}

async fn write_line<S>(stream: &mut S, line: &str) -> Result<(), MailError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .map_err(|_| MailError::Protocol)?;
    stream.flush().await.map_err(|_| MailError::Protocol)
}

/// Write the message body with SMTP dot-stuffing and the terminating `.` line.
async fn write_all<S>(stream: &mut S, message: &[u8]) -> Result<(), MailError>
where
    S: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(message.len() + 8);
    let mut line_start = true;
    for &byte in message {
        if line_start && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        line_start = byte == b'\n';
    }
    if !message.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    stream
        .write_all(&out)
        .await
        .map_err(|_| MailError::Protocol)?;
    stream.flush().await.map_err(|_| MailError::Protocol)
}

/// Split a connect failure into "the name did not resolve" and everything else.
fn classify_connect(host: &str, port: u16, error: io::Error) -> MailError {
    let text = error.to_string().to_ascii_lowercase();
    let dns = text.contains("lookup")
        || text.contains("name or service not known")
        || text.contains("nodename nor servname")
        || text.contains("no such host");
    if dns {
        MailError::Dns {
            host: host.to_string(),
            port,
        }
    } else {
        MailError::Connect {
            host: host.to_string(),
            port,
        }
    }
}

/// The `MailFrom` stage's typed refusal, used by [`submit`].
fn mail_from_reply(code: u16, from: &str) -> Result<(), MailError> {
    if code == 250 {
        Ok(())
    } else {
        Err(mail_from_error(code, from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_mechanisms_read_both_spellings() {
        let caps = vec![
            "SIZE 35882577".to_string(),
            "AUTH PLAIN LOGIN".to_string(),
            "8BITMIME".to_string(),
        ];
        assert_eq!(auth_mechanisms(&caps), vec!["PLAIN", "LOGIN"]);
        let caps = vec!["auth=login".to_string()];
        assert_eq!(auth_mechanisms(&caps), vec!["LOGIN"]);
        assert!(auth_mechanisms(&["8BITMIME".to_string()]).is_empty());
    }

    #[test]
    fn advertiser_is_case_sensitive_only_on_our_side() {
        let caps = vec!["starttls".to_string()];
        assert!(advertises(&caps, "STARTTLS"));
        assert!(!advertises(&caps, "SMTPUTF8"));
    }

    #[test]
    fn a_4xx_reply_is_the_transient_kind() {
        assert_eq!(reply_error(421, ReplyStage::Data), MailError::RateLimited);
        assert_eq!(reply_error(452, ReplyStage::Data), MailError::RateLimited);
        assert_eq!(
            mail_from_error(550, "me@example.org"),
            MailError::RelayDenied {
                from: "me@example.org".to_string()
            }
        );
        assert_eq!(reply_error(554, ReplyStage::Data), MailError::Protocol);
    }

    #[test]
    fn dot_stuffing_only_touches_a_leading_dot() {
        let mut out = Vec::new();
        let mut line_start = true;
        for &byte in b".first\r\n.no\r\nok .dot\r\n" {
            if line_start && byte == b'.' {
                out.push(b'.');
            }
            out.push(byte);
            line_start = byte == b'\n';
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "..first\r\n..no\r\nok .dot\r\n"
        );
    }

    #[test]
    fn mail_from_refusal_names_the_sender() {
        assert_eq!(
            mail_from_error(550, "me@example.org"),
            MailError::RelayDenied {
                from: "me@example.org".to_string()
            }
        );
        assert_eq!(
            mail_from_error(421, "me@example.org"),
            MailError::RateLimited
        );
    }

    #[test]
    fn a_stream_type_is_boxable() {
        // A compile-time check that the generic submit can take a boxed stream.
        fn _assert<T: AsyncRead + AsyncWrite + Unpin + Send + Debug>() {}
        _assert::<crate::dial::BoxedStream>();
    }
}
