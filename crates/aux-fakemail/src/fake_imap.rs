//! A hand-rolled, in-process IMAP server for offline tests.
//!
//! It speaks the same wire protocol the client does, binds `127.0.0.1:0`, and
//! records every command line it receives so a test can assert *what was asked
//! for*. It answers the read path (`ENVELOPE`, flags, size, `BODY.PEEK[]`) and
//! the MA3 pieces (`BODYSTRUCTURE`, `BODY.PEEK[part]`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aux_mail::config::Security;
use aux_mail::dial::AsyncReadWrite;
use aux_mail::presets::Endpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::certs::TestCert;
use super::fake_imap_proto::{handle_append, handle_uid};
use super::fixtures::RawMessage;

pub(super) type Stream = Box<dyn AsyncReadWrite>;

const MAX_LINE: usize = 8 * 1024;
const FOLDERS: &[&str] = &["INBOX", "Sent", "Drafts", "Trash", "Archive"];

/// How the fake answers `LOGIN`; a hostile test picks a non-`NORMAL` mode.
const LOGIN_NORMAL: u8 = 0;
/// `{tag} NO <raw line>` — the server echoes the command in a refusal.
const LOGIN_ECHO_NO: u8 = 1;
/// An untagged garbage line then a tagged `NO`, both echoing the command.
const LOGIN_UNTAGGED_GARBAGE: u8 = 2;
/// A malformed tagged response echoing the command.
const LOGIN_MALFORMED_TAGGED: u8 = 3;
/// Echo the command as an invalid response, then drop the socket.
const LOGIN_ECHO_THEN_CLOSE: u8 = 4;

/// How a spawned fake misbehaves, for the error-path tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Behavior {
    /// Answer every command normally.
    Normal,
    /// Answer `UID FETCH` with an unparsable response.
    Garbage,
    /// Accept `UID FETCH` and never answer, so the caller's budget fires.
    Stall,
    /// Answer the body fetch with a literal far past the cap, ignoring the
    /// partial range the client asked for.
    Overlong,
    /// Answer the body fetch with an oversized literal header and no body.
    HugeHeader,
    /// As `HugeHeader`, but split the header across two writes.
    HugeHeaderSplit,
    /// Answer a part fetch with the whole literal, ignoring the `<0.N>`
    /// partial range the client asked for.
    IgnorePartial,
}

/// How many body bytes the `Overlong` fake tries to send.
const OVERLONG_LITERAL_BYTES: usize = 32 * 1024 * 1024;

/// Decrements the active-connection count when a connection task ends.
struct Active(Arc<Shared>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(super) struct Shared {
    /// Messages per folder, keyed by the server-side folder name.
    pub(super) folders: Mutex<HashMap<String, Vec<RawMessage>>>,
    pub(super) commands: Mutex<Vec<String>>,
    pub(super) appended: Mutex<Vec<String>>,
    pub(super) connections: AtomicUsize,
    pub(super) active: AtomicUsize,
    pub(super) login_mode: AtomicU8,
    /// When set, only this login name is accepted (the simulator's fixed user).
    pub(super) login_user: Option<String>,
    pub(super) overlong_written: AtomicUsize,
    pub(super) tasks: Mutex<Vec<JoinHandle<()>>>,
    /// The spawned behaviour, so the protocol handler can tell when to ignore a
    /// `<0.N>` partial (MA3's `IgnorePartial`).
    pub(super) behavior: Behavior,
}

/// A cloneable handle to a fake's mailbox, so another server (the simulator's
/// SMTP side) can append accepted messages to a folder.
#[derive(Clone)]
pub struct MailboxHandle {
    shared: Arc<Shared>,
}

impl MailboxHandle {
    /// Append `message` to `folder`, creating the folder when absent.
    pub fn push(&self, folder: &str, message: RawMessage) {
        self.shared
            .folders
            .lock()
            .expect("folders lock")
            .entry(folder.to_string())
            .or_default()
            .push(message);
    }

    /// Keep only the messages of `folder` for which `keep` is true.
    pub fn retain(&self, folder: &str, keep: impl FnMut(&RawMessage) -> bool) {
        if let Some(messages) = self
            .shared
            .folders
            .lock()
            .expect("folders lock")
            .get_mut(folder)
        {
            messages.retain(keep);
        }
    }

    /// How many messages `folder` holds.
    pub fn len(&self, folder: &str) -> usize {
        self.shared
            .folders
            .lock()
            .expect("folders lock")
            .get(folder)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// True when `folder` holds no messages.
    pub fn is_empty(&self, folder: &str) -> bool {
        self.len(folder) == 0
    }
}

/// A live fake IMAP server on a loopback port.
pub struct FakeImap {
    /// The bound port.
    pub port: u16,
    /// True when the listener speaks implicit TLS from the first byte.
    pub tls: bool,
    addr: SocketAddr,
    cert: Option<TestCert>,
    shared: Arc<Shared>,
    task: Option<JoinHandle<()>>,
}

impl FakeImap {
    /// A plaintext server (STARTTLS is not advertised).
    pub async fn spawn(messages: Vec<RawMessage>) -> Self {
        Self::start(messages, false, false, false, "127.0.0.1", Behavior::Normal).await
    }

    /// An implicit-TLS server presenting an `rcgen` self-signed certificate.
    pub async fn spawn_tls(messages: Vec<RawMessage>) -> Self {
        Self::start(messages, true, false, false, "127.0.0.1", Behavior::Normal).await
    }

    /// An implicit-TLS server whose certificate is issued for `cert_name`.
    pub async fn spawn_tls_named(messages: Vec<RawMessage>, cert_name: &str) -> Self {
        Self::start(messages, true, false, false, cert_name, Behavior::Normal).await
    }

    /// An implicit-TLS server that refuses `LOGIN` by echoing the whole line.
    pub async fn spawn_tls_echoing_login(messages: Vec<RawMessage>) -> Self {
        Self::with_login_mode(messages, LOGIN_ECHO_NO).await
    }

    /// An implicit-TLS server that answers `LOGIN` with an untagged garbage
    /// line echoing the raw command.
    pub async fn spawn_tls_untagged_garbage(messages: Vec<RawMessage>) -> Self {
        Self::with_login_mode(messages, LOGIN_UNTAGGED_GARBAGE).await
    }

    /// An implicit-TLS server that answers `LOGIN` with a malformed tagged
    /// response echoing the raw command.
    pub async fn spawn_tls_malformed_login_reply(messages: Vec<RawMessage>) -> Self {
        Self::with_login_mode(messages, LOGIN_MALFORMED_TAGGED).await
    }

    /// An implicit-TLS server that echoes the command as an invalid response
    /// and then drops the connection.
    pub async fn spawn_tls_dropping_login(messages: Vec<RawMessage>) -> Self {
        Self::with_login_mode(messages, LOGIN_ECHO_THEN_CLOSE).await
    }

    async fn with_login_mode(messages: Vec<RawMessage>, mode: u8) -> Self {
        let fake = Self::start(messages, true, false, false, "127.0.0.1", Behavior::Normal).await;
        fake.shared.login_mode.store(mode, Ordering::SeqCst);
        fake
    }

    /// A plaintext server that advertises and accepts STARTTLS.
    pub async fn spawn_starttls(messages: Vec<RawMessage>) -> Self {
        Self::start(messages, false, true, false, "127.0.0.1", Behavior::Normal).await
    }

    /// A server that accepts TCP and then never writes a greeting.
    pub async fn spawn_silent() -> Self {
        Self::start(
            Vec::new(),
            false,
            false,
            true,
            "127.0.0.1",
            Behavior::Normal,
        )
        .await
    }

    /// An implicit-TLS server that answers `UID FETCH` with garbage.
    pub async fn spawn_garbage(messages: Vec<RawMessage>) -> Self {
        Self::start(messages, true, false, false, "127.0.0.1", Behavior::Garbage).await
    }

    /// An implicit-TLS server that accepts `UID FETCH` and never answers.
    pub async fn spawn_stall(messages: Vec<RawMessage>) -> Self {
        Self::start(messages, true, false, false, "127.0.0.1", Behavior::Stall).await
    }

    /// An implicit-TLS server that ignores a part's `<0.N>` partial and sends
    /// the whole literal, so the connection guard must refuse it.
    pub async fn spawn_ignore_partial_tls(messages: Vec<RawMessage>) -> Self {
        Self::start(
            messages,
            true,
            false,
            false,
            "127.0.0.1",
            Behavior::IgnorePartial,
        )
        .await
    }

    /// An implicit-TLS server that answers the body fetch with a huge literal,
    /// ignoring the partial range the client asks for.
    pub async fn spawn_overlong(messages: Vec<RawMessage>) -> Self {
        Self::start(
            messages,
            true,
            false,
            false,
            "127.0.0.1",
            Behavior::Overlong,
        )
        .await
    }

    /// An implicit-TLS server that declares a 536 870 000-byte literal and
    /// sends no body.
    pub async fn spawn_huge_header(messages: Vec<RawMessage>) -> Self {
        Self::start(
            messages,
            true,
            false,
            false,
            "127.0.0.1",
            Behavior::HugeHeader,
        )
        .await
    }

    /// As [`FakeImap::spawn_huge_header`], but the header arrives in two writes.
    pub async fn spawn_huge_header_split(messages: Vec<RawMessage>) -> Self {
        Self::start(
            messages,
            true,
            false,
            false,
            "127.0.0.1",
            Behavior::HugeHeaderSplit,
        )
        .await
    }

    /// An implicit-TLS server on `port` (0 = ephemeral) presenting `cert` and
    /// accepting only `login_user` with any password: the simulator's shape.
    pub async fn spawn_sim(
        messages: Vec<RawMessage>,
        cert: TestCert,
        port: u16,
        login_user: &str,
    ) -> Self {
        Self::start_with(
            messages,
            true,
            false,
            false,
            Some(cert),
            Behavior::Normal,
            port,
            Some(login_user.to_string()),
        )
        .await
    }

    async fn start(
        messages: Vec<RawMessage>,
        implicit_tls: bool,
        starttls: bool,
        silent: bool,
        cert_name: &str,
        behavior: Behavior,
    ) -> Self {
        let cert = (implicit_tls || starttls).then(|| TestCert::new_for(cert_name));
        Self::start_with(
            messages,
            implicit_tls,
            starttls,
            silent,
            cert,
            behavior,
            0,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_with(
        messages: Vec<RawMessage>,
        implicit_tls: bool,
        starttls: bool,
        silent: bool,
        cert: Option<TestCert>,
        behavior: Behavior,
        port: u16,
        login_user: Option<String>,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind the fake to loopback");
        let addr = listener.local_addr().expect("local addr");
        let acceptor = cert
            .as_ref()
            .map(|cert| TlsAcceptor::from(cert.server_config()));
        let mut folders = HashMap::new();
        folders.insert("INBOX".to_string(), messages);
        let shared = Arc::new(Shared {
            folders: Mutex::new(folders),
            commands: Mutex::new(Vec::new()),
            appended: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            login_mode: AtomicU8::new(LOGIN_NORMAL),
            login_user,
            overlong_written: AtomicUsize::new(0),
            tasks: Mutex::new(Vec::new()),
            behavior,
        });
        let task = tokio::spawn(accept_loop(
            listener,
            shared.clone(),
            acceptor,
            implicit_tls,
            starttls,
            silent,
            behavior,
        ));
        Self {
            port: addr.port(),
            tls: implicit_tls,
            addr,
            cert,
            shared,
            task: Some(task),
        }
    }

    /// An endpoint for this fake with the caller's transport security.
    pub fn endpoint(&self, security: Security) -> Endpoint {
        Endpoint {
            host: "127.0.0.1".to_string(),
            port: self.port,
            security,
        }
    }

    /// Every raw command line received so far.
    pub fn commands(&self) -> Vec<String> {
        self.shared.commands.lock().expect("commands lock").clone()
    }

    /// How many TCP connections the fake has accepted.
    pub fn connections(&self) -> usize {
        self.shared.connections.load(Ordering::SeqCst)
    }

    /// How many accepted connections are still open.
    pub fn active(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    /// Body bytes the `Overlong` fake managed to write before the peer closed.
    pub fn overlong_written(&self) -> usize {
        self.shared.overlong_written.load(Ordering::SeqCst)
    }

    /// Every `APPEND` payload received so far, as UTF-8 lossy text.
    pub fn appended(&self) -> Vec<String> {
        self.shared.appended.lock().expect("appended lock").clone()
    }

    /// A cloneable handle to this fake's folder state.
    pub fn mailbox(&self) -> MailboxHandle {
        MailboxHandle {
            shared: self.shared.clone(),
        }
    }

    /// How many messages `folder` holds.
    pub fn message_count(&self, folder: &str) -> usize {
        self.shared
            .folders
            .lock()
            .expect("folders lock")
            .get(folder)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// The bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The self-signed certificate, for a matching test verifier.
    pub fn cert(&self) -> Option<&TestCert> {
        self.cert.as_ref()
    }
}

impl Drop for FakeImap {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        // The accept loop's per-connection tasks are not children of the
        // listener task, so abort them explicitly: a connection a test still
        // holds must close when the fake is dropped.
        let mut tasks = self.shared.tasks.lock().expect("tasks lock");
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    acceptor: Option<TlsAcceptor>,
    implicit_tls: bool,
    starttls: bool,
    silent: bool,
    behavior: Behavior,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        shared.connections.fetch_add(1, Ordering::SeqCst);
        shared.active.fetch_add(1, Ordering::SeqCst);
        let connection = shared.clone();
        let active = Active(shared.clone());
        let acceptor = acceptor.clone();
        let handle = tokio::spawn(async move {
            let _active = active;
            serve(
                stream,
                connection,
                acceptor,
                implicit_tls,
                starttls,
                silent,
                behavior,
            )
            .await;
        });
        shared.tasks.lock().expect("tasks lock").push(handle);
    }
}

async fn serve(
    stream: TcpStream,
    shared: Arc<Shared>,
    acceptor: Option<TlsAcceptor>,
    implicit_tls: bool,
    starttls: bool,
    silent: bool,
    behavior: Behavior,
) {
    let mut stream: Stream = Box::new(stream);
    if silent {
        // Hold the connection open and never write a greeting.
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }
    if implicit_tls {
        let Some(acceptor) = acceptor.as_ref() else {
            return;
        };
        let Ok(tls) = acceptor.accept(stream).await else {
            return;
        };
        stream = Box::new(tls);
    }

    let greeting = if starttls {
        "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] aux-mail fake ready\r\n"
    } else {
        "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] aux-mail fake ready\r\n"
    };
    if write(&mut stream, greeting.as_bytes()).await.is_err() {
        return;
    }

    // The folder the connection last selected; `UID FETCH` reads from it.
    let mut selected = "INBOX".to_string();
    loop {
        let Some(line) = read_line(&mut stream).await else {
            return;
        };
        record(&shared, &line);
        let Some((tag, rest)) = split_tag(&line) else {
            continue;
        };
        let tag = tag.to_string();
        if behavior != Behavior::Normal
            && first_word(rest).eq_ignore_ascii_case("UID")
            && rest.to_ascii_uppercase().contains("FETCH")
        {
            match behavior {
                Behavior::Garbage => {
                    let reply =
                        format!("* 1 FETCH (UID not-a-number)\r\n{tag} OK FETCH completed\r\n");
                    let _ = write(&mut stream, reply.as_bytes()).await;
                    continue;
                }
                // `Stall`: answer nothing; the caller's call budget must fire.
                Behavior::Stall => continue,
                // The size fetch falls through to the normal handler; only the
                // body fetch gets the oversized literal.
                Behavior::Overlong if !rest.to_ascii_uppercase().contains("BODY") => {}
                Behavior::Overlong => {
                    serve_overlong(&mut stream, &shared, &tag, rest).await;
                    continue;
                }
                Behavior::HugeHeader if !rest.to_ascii_uppercase().contains("BODY") => {}
                Behavior::HugeHeader => {
                    serve_huge_header(&mut stream, rest, false).await;
                    continue;
                }
                Behavior::HugeHeaderSplit if !rest.to_ascii_uppercase().contains("BODY") => {}
                Behavior::HugeHeaderSplit => {
                    serve_huge_header(&mut stream, rest, true).await;
                    continue;
                }
                // The partial is ignored inside `handle_fetch`; the command
                // still takes the normal path.
                Behavior::IgnorePartial => {}
                Behavior::Normal => {}
            }
        }
        match first_word(rest).to_ascii_uppercase().as_str() {
            "CAPABILITY" => {
                let capabilities = if starttls {
                    "IMAP4rev1 STARTTLS AUTH=PLAIN"
                } else {
                    "IMAP4rev1 AUTH=PLAIN"
                };
                let reply =
                    format!("* CAPABILITY {capabilities}\r\n{tag} OK CAPABILITY completed\r\n");
                let _ = write(&mut stream, reply.as_bytes()).await;
            }
            "LOGIN" => {
                let mode = shared.login_mode.load(Ordering::SeqCst);
                let reply = match mode {
                    // A hostile server echoing the raw LOGIN line, password
                    // included, in a valid refusal.
                    LOGIN_ECHO_NO => format!("{tag} NO {line}\r\n"),
                    // An untagged line `imap-proto` cannot parse, then a tagged
                    // refusal: both echo the command.
                    LOGIN_UNTAGGED_GARBAGE => {
                        format!("* GARBAGE {line}\r\n{tag} NO {line}\r\n")
                    }
                    // A malformed tagged response: `imap-proto` embeds the raw
                    // line in its parse error.
                    LOGIN_MALFORMED_TAGGED => format!("{tag} ??? {line}\r\n"),
                    // The command echoed as an invalid response, then EOF.
                    LOGIN_ECHO_THEN_CLOSE => format!("{line}\r\n"),
                    _ => {
                        let mut words = rest.split_whitespace();
                        let _verb = words.next();
                        let user = words.next().unwrap_or("").trim_matches('"');
                        let password = words.next().unwrap_or("").trim_matches('"');
                        let wrong_user = shared
                            .login_user
                            .as_deref()
                            .is_some_and(|expected| !user.eq_ignore_ascii_case(expected));
                        if wrong_user || password == "wrong-password" {
                            format!("{tag} NO [AUTHENTICATIONFAILED] invalid credentials\r\n")
                        } else {
                            format!("{tag} OK LOGIN completed\r\n")
                        }
                    }
                };
                let _ = write(&mut stream, reply.as_bytes()).await;
                if mode == LOGIN_ECHO_THEN_CLOSE {
                    return;
                }
            }
            "LIST" => {
                let mut reply = String::new();
                for folder in FOLDERS {
                    let special = if *folder == "Sent" { " \\Sent" } else { "" };
                    reply.push_str(&format!(
                        "* LIST (\\HasNoChildren{special}) \".\" {folder}\r\n"
                    ));
                }
                reply.push_str(&format!("{tag} OK LIST completed\r\n"));
                let _ = write(&mut stream, reply.as_bytes()).await;
            }
            "SELECT" => {
                let folder = rest
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("INBOX")
                    .trim_matches('"');
                let count = shared
                    .folders
                    .lock()
                    .expect("folders lock")
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(folder))
                    .map(|(_, messages)| messages.len())
                    .unwrap_or(0);
                selected = folder.to_string();
                let reply = format!(
                    "* {count} EXISTS\r\n\
                     * 1 RECENT\r\n\
                     * OK [UIDVALIDITY 1] UIDs valid\r\n\
                     * OK [UIDNEXT 1000] Predicted next UID\r\n\
                     * FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n\
                     {tag} OK [READ-WRITE] SELECT completed\r\n"
                );
                let _ = write(&mut stream, reply.as_bytes()).await;
            }
            "UID" => handle_uid(&mut stream, &tag, rest, &shared, &selected).await,
            "APPEND" => handle_append(&mut stream, &tag, rest, &shared).await,
            "STORE" | "MOVE" | "COPY" | "EXPUNGE" | "NOOP" | "CLOSE" | "CHECK" => {
                let reply = format!("{tag} OK completed\r\n");
                let _ = write(&mut stream, reply.as_bytes()).await;
            }
            "STARTTLS" if starttls => {
                let reply = format!("{tag} OK Begin TLS\r\n");
                let _ = write(&mut stream, reply.as_bytes()).await;
                let Some(acceptor) = acceptor.clone() else {
                    return;
                };
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                stream = Box::new(tls);
            }
            "LOGOUT" => {
                let reply = format!("* BYE aux-mail fake closing\r\n{tag} OK LOGOUT completed\r\n");
                let _ = write(&mut stream, reply.as_bytes()).await;
                return;
            }
            _ => {
                let reply = format!("{tag} BAD unknown command\r\n");
                let _ = write(&mut stream, reply.as_bytes()).await;
            }
        }
    }
}

/// Answer a body fetch with a literal far past the cap, ignoring the partial
/// range the client asked for, and record how much the client actually drained.
async fn serve_overlong(stream: &mut Stream, shared: &Shared, tag: &str, rest: &str) {
    let uid = rest.split_whitespace().nth(2).unwrap_or("1");
    let head = format!("* 1 FETCH (UID {uid} BODY[] {{{OVERLONG_LITERAL_BYTES}}}\r\n");
    if write(stream, head.as_bytes()).await.is_err() {
        return;
    }
    let chunk = [b'x'; 64 * 1024];
    let mut remaining = OVERLONG_LITERAL_BYTES;
    let mut written = 0usize;
    while remaining > 0 {
        let take = remaining.min(chunk.len());
        if write(stream, &chunk[..take]).await.is_err() {
            break;
        }
        written += take;
        remaining -= take;
    }
    shared.overlong_written.store(written, Ordering::SeqCst);
    let _ = write(stream, b")\r\n").await;
    let _ = write(stream, format!("{tag} OK FETCH completed\r\n").as_bytes()).await;
}

/// Declare a 536 870 000-byte literal and send no body. With `split`, the
/// header arrives in two writes so the scanner must carry it across reads.
async fn serve_huge_header(stream: &mut Stream, rest: &str, split: bool) {
    let uid = rest.split_whitespace().nth(2).unwrap_or("1");
    let head = format!("* 1 FETCH (UID {uid} BODY[] {{536870000}}\r\n");
    if split {
        let split_at = head.find("{5368").map(|index| index + 5).unwrap_or(5);
        if write(stream, &head.as_bytes()[..split_at]).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = write(stream, &head.as_bytes()[split_at..]).await;
    } else {
        let _ = write(stream, head.as_bytes()).await;
    }
}

fn record(shared: &Shared, line: &str) {
    shared
        .commands
        .lock()
        .expect("commands lock")
        .push(line.to_string());
}

async fn write(stream: &mut Stream, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}

async fn read_line(stream: &mut Stream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => {
                return if buffer.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&buffer).into_owned())
                }
            }
            Ok(_) => {}
            Err(_) => return None,
        }
        if byte[0] == b'\n' {
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
            return Some(String::from_utf8_lossy(&buffer).into_owned());
        }
        buffer.push(byte[0]);
        if buffer.len() > MAX_LINE {
            return None;
        }
    }
}

fn split_tag(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(2, char::is_whitespace);
    let tag = parts.next()?;
    let rest = parts.next().unwrap_or("");
    Some((tag, rest))
}

fn first_word(text: &str) -> &str {
    text.split_whitespace().next().unwrap_or("")
}
