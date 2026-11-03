//! A hand-rolled, in-process SMTP server for offline tests.
//!
//! Advertises `AUTH PLAIN LOGIN`, relays for a small allowlist, refuses any
//! other recipient with `550`, and records every command and every accepted
//! message. The TLS variants present an `rcgen` self-signed certificate the
//! test verifier trusts; `spawn_starttls` upgrades after `STARTTLS`.
//!
//! `spawn_throttle_mail_from` answers the first `MAIL FROM` with `421` so a test
//! can prove the sender does not retry.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aux_mail::config::Security;
use aux_mail::dial::AsyncReadWrite;
use aux_mail::presets::Endpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::certs::TestCert;

type Stream = Box<dyn AsyncReadWrite>;

/// Recipients the fake relays for; anything else gets `550`.
const RELAY_ALLOWED: &[&str] = &[
    "me@example.org",
    "you@example.org",
    "ok@example.org",
    "camille@exemple.fr",
    "jonas.weber@exemple.test",
];

/// Senders the fake accepts on `MAIL FROM`; anything else gets `550`.
const SENDER_ALLOWED: &[&str] = &[
    "me@example.org",
    "you@example.org",
    "ok@example.org",
    "owner@exemple.test",
];

/// How the fake answers a submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behavior {
    /// The normal relay.
    Normal,
    /// The first `MAIL FROM` is refused with `421` (transient).
    ThrottleMailFrom,
    /// The data is read in full, then the connection closes with no final
    /// reply: the server may have queued the message.
    DropAfterData,
    /// The data is read in full, then the server stalls past the client budget.
    StallAfterData,
}

struct Shared {
    commands: Mutex<Vec<String>>,
    accepted: Mutex<Vec<String>>,
    connections: AtomicUsize,
    mail_from: AtomicUsize,
    /// Relay for any sender/recipient (the simulator) instead of the allowlists.
    relay_all: bool,
    /// Run once per accepted `DATA` body (the simulator mirrors to Sent/outbox).
    on_accept: Mutex<Option<AcceptFn>>,
}

/// A callback run once per accepted `DATA` body.
type AcceptFn = Arc<dyn Fn(&str) + Send + Sync>;

/// A live fake SMTP server on a loopback port.
pub struct FakeSmtp {
    /// The bound port.
    pub port: u16,
    addr: SocketAddr,
    cert: Option<TestCert>,
    shared: Arc<Shared>,
    task: Option<JoinHandle<()>>,
}

impl FakeSmtp {
    /// Start a plaintext fake on `127.0.0.1:0` (no STARTTLS advertised).
    pub async fn spawn() -> Self {
        Self::start(false, false, Behavior::Normal).await
    }

    /// An implicit-TLS fake presenting a self-signed certificate.
    pub async fn spawn_tls() -> Self {
        Self::start(true, false, Behavior::Normal).await
    }

    /// A plaintext fake that advertises and accepts STARTTLS.
    pub async fn spawn_starttls() -> Self {
        Self::start(false, true, Behavior::Normal).await
    }

    /// An implicit-TLS fake whose first `MAIL FROM` is refused with `421`.
    pub async fn spawn_throttle_mail_from() -> Self {
        Self::start(true, false, Behavior::ThrottleMailFrom).await
    }

    /// An implicit-TLS fake that reads the whole message then drops the
    /// connection without its final reply.
    pub async fn spawn_drop_after_data() -> Self {
        Self::start(true, false, Behavior::DropAfterData).await
    }

    /// An implicit-TLS fake that reads the whole message then stalls.
    pub async fn spawn_stall_after_data() -> Self {
        Self::start(true, false, Behavior::StallAfterData).await
    }

    /// An implicit-TLS simulator on `port` (0 = ephemeral) presenting `cert`
    /// and relaying for any sender and recipient.
    pub async fn spawn_sim(cert: TestCert, port: u16) -> Self {
        Self::start_with(true, false, Behavior::Normal, port, Some(cert), true).await
    }

    async fn start(implicit_tls: bool, starttls: bool, behavior: Behavior) -> Self {
        let cert = (implicit_tls || starttls).then(|| TestCert::new_for("127.0.0.1"));
        Self::start_with(implicit_tls, starttls, behavior, 0, cert, false).await
    }

    async fn start_with(
        implicit_tls: bool,
        starttls: bool,
        behavior: Behavior,
        port: u16,
        cert: Option<TestCert>,
        relay_all: bool,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind the fake to loopback");
        let addr = listener.local_addr().expect("local addr");
        let acceptor = cert
            .as_ref()
            .map(|cert| TlsAcceptor::from(cert.server_config()));
        let shared = Arc::new(Shared {
            commands: Mutex::new(Vec::new()),
            accepted: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            mail_from: AtomicUsize::new(0),
            relay_all,
            on_accept: Mutex::new(None),
        });
        let task = tokio::spawn(accept_loop(
            listener,
            shared.clone(),
            acceptor,
            implicit_tls,
            starttls,
            behavior,
        ));
        Self {
            port: addr.port(),
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

    /// Every command line received so far.
    pub fn commands(&self) -> Vec<String> {
        self.shared.commands.lock().expect("commands lock").clone()
    }

    /// Every accepted `DATA` body, in order.
    pub fn accepted(&self) -> Vec<String> {
        self.shared.accepted.lock().expect("accepted lock").clone()
    }

    /// Register a callback run once per accepted `DATA` body.
    pub fn set_on_accept(&self, f: impl Fn(&str) + Send + Sync + 'static) {
        *self.shared.on_accept.lock().expect("on_accept lock") = Some(Arc::new(f));
    }

    /// How many `MAIL FROM` lines arrived (no retry means exactly one).
    pub fn mail_from_count(&self) -> usize {
        self.shared.mail_from.load(Ordering::SeqCst)
    }

    /// How many TCP connections the fake accepted.
    pub fn connections(&self) -> usize {
        self.shared.connections.load(Ordering::SeqCst)
    }

    /// The self-signed certificate, for a matching test verifier.
    pub fn cert(&self) -> Option<&TestCert> {
        self.cert.as_ref()
    }

    /// The bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for FakeSmtp {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
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
    behavior: Behavior,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        shared.connections.fetch_add(1, Ordering::SeqCst);
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            serve(stream, shared, acceptor, implicit_tls, starttls, behavior).await;
        });
    }
}

async fn serve(
    stream: TcpStream,
    shared: Arc<Shared>,
    acceptor: Option<TlsAcceptor>,
    implicit_tls: bool,
    starttls: bool,
    behavior: Behavior,
) {
    let mut stream: Stream = Box::new(stream);
    if implicit_tls {
        let Some(acceptor) = acceptor.as_ref() else {
            return;
        };
        let Ok(tls) = acceptor.accept(stream).await else {
            return;
        };
        stream = Box::new(tls);
    }
    if write(&mut stream, b"220 aux-mail fake ESMTP ready\r\n")
        .await
        .is_err()
    {
        return;
    }

    let mut upgraded = !starttls;
    let mut in_data = false;
    let mut data = String::new();
    let mut auth_plain_pending = false;
    let mut auth_login_stage = 0u8;

    loop {
        let Some(line) = read_line(&mut stream).await else {
            return;
        };
        if in_data {
            if line == "." {
                let body = std::mem::take(&mut data);
                if let Some(callback) = shared
                    .on_accept
                    .lock()
                    .expect("on_accept lock")
                    .as_ref()
                    .cloned()
                {
                    callback(&body);
                }
                shared.accepted.lock().expect("accepted lock").push(body);
                in_data = false;
                if behavior == Behavior::DropAfterData {
                    // The server may have queued it; the client never sees 250.
                    return;
                }
                if behavior == Behavior::StallAfterData {
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    return;
                }
                let _ = write(&mut stream, b"250 2.0.0 Ok: queued\r\n").await;
            } else {
                data.push_str(&line);
                data.push_str("\r\n");
            }
            continue;
        }

        // AUTH lines carry credentials; record only that an AUTH happened.
        let continuing = auth_plain_pending || auth_login_stage > 0;
        let upper = line.to_ascii_uppercase();
        if !continuing {
            let recorded = if upper.starts_with("AUTH") {
                "AUTH <redacted>".to_string()
            } else {
                line.clone()
            };
            shared
                .commands
                .lock()
                .expect("commands lock")
                .push(recorded);
        }
        if upper.starts_with("MAIL FROM") {
            shared.mail_from.fetch_add(1, Ordering::SeqCst);
        }

        let reply: &[u8] = if auth_plain_pending {
            auth_plain_pending = false;
            b"235 2.7.0 Authentication successful\r\n"
        } else if auth_login_stage == 1 {
            auth_login_stage = 2;
            b"334 UGFzc3dvcmQ6\r\n"
        } else if auth_login_stage == 2 {
            auth_login_stage = 0;
            b"235 2.7.0 Authentication successful\r\n"
        } else if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            if starttls && !upgraded {
                b"250-aux-mail fake\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"
            } else {
                b"250-aux-mail fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"
            }
        } else if upper.starts_with("STARTTLS") {
            if !starttls || upgraded {
                b"503 5.5.1 Bad sequence\r\n"
            } else {
                upgraded = true;
                b"220 2.0.0 Ready to start TLS\r\n"
            }
        } else if upper.starts_with("AUTH PLAIN") {
            if line.split_whitespace().count() >= 3 {
                b"235 2.7.0 Authentication successful\r\n"
            } else {
                auth_plain_pending = true;
                b"334 \r\n"
            }
        } else if upper.starts_with("AUTH LOGIN") {
            auth_login_stage = 1;
            b"334 VXNlcm5hbWU6\r\n"
        } else if upper.starts_with("MAIL FROM") {
            if behavior == Behavior::ThrottleMailFrom {
                b"421 4.7.0 Try again later\r\n"
            } else if shared.relay_all || sender_allowed(&line) {
                b"250 2.1.0 Ok\r\n"
            } else {
                b"550 5.7.1 Sender address rejected\r\n"
            }
        } else if upper.starts_with("RCPT TO") {
            if shared.relay_all || recipient_allowed(&line) {
                b"250 2.1.5 Ok\r\n"
            } else {
                b"550 5.1.1 Relay access denied\r\n"
            }
        } else if upper.starts_with("DATA") {
            in_data = true;
            data.clear();
            b"354 End data with <CR><LF>.<CR><LF>\r\n"
        } else if upper.starts_with("QUIT") {
            let _ = write(&mut stream, b"221 2.0.0 Bye\r\n").await;
            return;
        } else {
            b"250 2.0.0 Ok\r\n"
        };
        let _ = write(&mut stream, reply).await;

        // The TLS upgrade happens after the `220` reply is on the wire.
        if upper.starts_with("STARTTLS") && starttls && upgraded {
            let Some(acceptor) = acceptor.as_ref() else {
                return;
            };
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            stream = Box::new(tls);
        }
    }
}

fn recipient_allowed(line: &str) -> bool {
    let address = bracketed_address(line);
    RELAY_ALLOWED
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(address.trim()))
}

fn sender_allowed(line: &str) -> bool {
    let address = bracketed_address(line);
    SENDER_ALLOWED
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(address.trim()))
}

/// The address inside `<…>`, or after the first `:`, whichever the line has.
fn bracketed_address(line: &str) -> &str {
    line.split_once('<')
        .and_then(|(_, rest)| rest.split_once('>').map(|(address, _)| address))
        .or_else(|| {
            line.split_once(':')
                .map(|(_, rest)| rest.trim().trim_matches('<'))
        })
        .unwrap_or("")
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
        if buffer.len() > 8 * 1024 {
            return None;
        }
    }
}
