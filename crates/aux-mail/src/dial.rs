//! The dialer every fake plugs into.
//!
//! [`Dialer::connect`] is the only place in the crate that opens a socket:
//! `TcpStream::connect`, then optional implicit TLS, then a CAPABILITY probe,
//! then an optional mandatory STARTTLS upgrade. It returns a boxed
//! `AsyncRead + AsyncWrite` stream whose IMAP greeting (and the capability
//! response) have **already been consumed**; `mailbox.rs` therefore hands the
//! stream straight to `async_imap::Client::new` and never reads a greeting.

use std::fmt::Debug;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::Error as TlsError;
use tokio_rustls::TlsConnector;

use crate::config::Security;
use crate::error::MailError;
use crate::guard::{GuardedStream, READ_GUARD_OVERHEAD};
use crate::limits::Limits;
use crate::presets::Endpoint;
use crate::tlsutil;

/// The test seam: any stream the dialer returns, plain or TLS.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Debug {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Debug {}

/// A boxed [`AsyncReadWrite`] stream.
pub type BoxedStream = Box<dyn AsyncReadWrite>;

/// Longest protocol line the dialer buffers while probing.
const MAX_LINE: usize = 8 * 1024;

/// Most response lines tolerated before a tagged completion.
const MAX_LINES: usize = 64;

/// Opens IMAP connections.
pub struct Dialer {
    config: Arc<ClientConfig>,
    connect_timeout: Duration,
}

impl Dialer {
    /// The production dialer: the one webpki-roots `ClientConfig`.
    pub fn new(connect_timeout: Duration) -> Self {
        Self {
            config: tlsutil::client_config(),
            connect_timeout,
        }
    }

    /// The production dialer built from the operation's hard bounds: the
    /// connect and TLS-handshake budget is [`Limits::connect_timeout`], so the
    /// config value actually reaches the socket code.
    pub fn from_limits(limits: &Limits) -> Self {
        Self::new(limits.connect_timeout)
    }

    /// A dialer that trusts exactly the certificate in `ca_file` (no webpki
    /// roots). The caller has already checked the host is loopback
    /// ([`crate::tlsutil::ensure_loopback_ca`]); a missing or unparsable file
    /// is a config error raised before any socket.
    pub fn with_ca_file(
        ca_file: &std::path::Path,
        connect_timeout: Duration,
    ) -> Result<Self, MailError> {
        Ok(Self {
            config: tlsutil::pinned_client_config(ca_file)?,
            connect_timeout,
        })
    }

    /// A dialer over a caller-supplied configuration.
    ///
    /// This is the seam tests use to trust the `rcgen` self-signed fake. It
    /// never relaxes verification itself; production always uses
    /// [`Dialer::new`]. Compiled only with the `test-support` feature, which
    /// only this crate's `[dev-dependencies]` self-reference enables.
    #[cfg(feature = "test-support")]
    pub fn with_client_config(config: Arc<ClientConfig>, connect_timeout: Duration) -> Self {
        Self {
            config,
            connect_timeout,
        }
    }

    /// Connect, secure the stream, and return it with the greeting read.
    pub async fn connect(&self, endpoint: &Endpoint) -> Result<BoxedStream, MailError> {
        let host = endpoint.host.clone();
        let port = endpoint.port;
        let tcp = tokio::time::timeout(
            self.connect_timeout,
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| MailError::Connect {
            host: host.clone(),
            port,
        })?
        .map_err(|error| classify_connect_error(&host, port, error))?;

        match endpoint.security {
            Security::Tls => {
                let mut stream = self.handshake(tcp, &host, port).await?;
                self.bounded(probe_capabilities(&mut stream)).await?;
                Ok(Box::new(stream))
            }
            Security::Plain => {
                let mut stream = tcp;
                self.bounded(probe_capabilities(&mut stream)).await?;
                Ok(Box::new(stream))
            }
            Security::StartTls => {
                let mut stream = tcp;
                let capabilities = self.bounded(probe_capabilities(&mut stream)).await?;
                if !capabilities
                    .iter()
                    .any(|capability| capability == "STARTTLS")
                {
                    return Err(MailError::NoStartTls { host, port });
                }
                let lines = self
                    .bounded(send_command(&mut stream, "a2", "STARTTLS"))
                    .await?;
                if !lines.last().is_some_and(|line| is_tagged_ok(line, "a2")) {
                    return Err(MailError::Protocol);
                }
                let secure = self.handshake(stream, &host, port).await?;
                Ok(Box::new(secure))
            }
        }
    }

    /// The connect budget, shared with the SMTP path so one config value
    /// bounds both protocols.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// The one TLS handshake, exposed to the SMTP sender so both the IMAP and
    /// SMTP paths share the same stack, verifier and error classification.
    pub(crate) async fn secure(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, MailError> {
        self.handshake(tcp, host, port).await
    }

    /// [`Dialer::connect`], then wrap the stream in the per-operation read
    /// guard armed from `limits`.
    ///
    /// A server can never make the client buffer more than
    /// `max_message_bytes` plus [`READ_GUARD_OVERHEAD`] of IMAP framing: once
    /// that ceiling is crossed the read fails with a
    /// [`crate::guard::ByteLimit`] marker that [`crate::imap_read`] turns into
    /// [`MailError::TooLarge`].
    pub async fn connect_guarded(
        &self,
        endpoint: &Endpoint,
        limits: &Limits,
    ) -> Result<BoxedStream, MailError> {
        let ceiling = limits.max_message_bytes.saturating_add(READ_GUARD_OVERHEAD);
        let stream = self.connect(endpoint).await?;
        Ok(Box::new(GuardedStream::new(stream, ceiling)))
    }

    /// [`Dialer::connect_guarded`] with explicit ceilings: `total` bounds every
    /// byte the connection reads and `literal_limit` the largest single `{N}`
    /// declaration it accepts. MA3's attachment fetch arms the literal ceiling
    /// at the per-part cap plus one (the partial it asks for) while the total
    /// follows the per-call attachment budget.
    pub async fn connect_guarded_caps(
        &self,
        endpoint: &Endpoint,
        total: usize,
        literal_limit: usize,
    ) -> Result<BoxedStream, MailError> {
        let stream = self.connect(endpoint).await?;
        Ok(Box::new(GuardedStream::with_literal_limit(
            stream,
            total,
            literal_limit,
        )))
    }

    /// Run one dial-phase future inside the connect budget, so a server that
    /// accepts TCP and then goes silent cannot hang the caller.
    async fn bounded<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, MailError>>,
    ) -> Result<T, MailError> {
        match tokio::time::timeout(self.connect_timeout, future).await {
            Err(_) => Err(MailError::Timeout {
                budget: self.connect_timeout,
            }),
            Ok(result) => result,
        }
    }

    async fn handshake(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, MailError> {
        let name = tlsutil::server_name(host)?;
        let connector = TlsConnector::from(self.config.clone());
        match tokio::time::timeout(self.connect_timeout, connector.connect(name, tcp)).await {
            Err(_) => Err(MailError::Connect {
                host: host.to_string(),
                port,
            }),
            Ok(Err(error)) => Err(classify_tls_error(host, port, error)),
            Ok(Ok(stream)) => Ok(stream),
        }
    }
}

/// Read the greeting, then the CAPABILITY response; return the capabilities.
async fn probe_capabilities<S>(stream: &mut S) -> Result<Vec<String>, MailError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if read_line(stream)
        .await
        .map_err(|_| MailError::Protocol)?
        .is_none()
    {
        return Err(MailError::Protocol);
    }

    let lines = send_command(stream, "a1", "CAPABILITY").await?;
    let mut capabilities = Vec::new();
    for line in lines {
        let upper = line.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("* CAPABILITY ") {
            capabilities.extend(rest.split_whitespace().map(str::to_string));
        }
    }
    Ok(capabilities)
}

/// Send one command and collect the response lines up to its tagged end.
async fn send_command<S>(stream: &mut S, tag: &str, command: &str) -> Result<Vec<String>, MailError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(format!("{tag} {command}\r\n").as_bytes())
        .await
        .map_err(|_| MailError::Protocol)?;
    stream.flush().await.map_err(|_| MailError::Protocol)?;

    let mut lines = Vec::new();
    loop {
        let Some(line) = read_line(stream).await.map_err(|_| MailError::Protocol)? else {
            return Err(MailError::Protocol);
        };
        let done = is_tagged(&line, tag);
        lines.push(line);
        if done {
            return Ok(lines);
        }
        if lines.len() > MAX_LINES {
            return Err(MailError::Protocol);
        }
    }
}

/// Read one CRLF-terminated line, without its terminator.
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

fn is_tagged(line: &str, tag: &str) -> bool {
    line.get(..tag.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(tag))
        && line.as_bytes().get(tag.len()) == Some(&b' ')
}

fn is_tagged_ok(line: &str, tag: &str) -> bool {
    is_tagged(line, tag) && line.split_whitespace().nth(1) == Some("OK")
}

/// Split a connect failure into "the name did not resolve" and everything else.
fn classify_connect_error(host: &str, port: u16, error: io::Error) -> MailError {
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

/// A certificate rejection gets its own variant; every other TLS error is `Tls`.
///
/// The library reason is deliberately dropped: rustls can quote the offending
/// bytes, and this error is returned during the login phase.
fn classify_tls_error(host: &str, port: u16, error: io::Error) -> MailError {
    if let Some(inner) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
    {
        if matches!(inner, TlsError::InvalidCertificate(_)) {
            return MailError::CertRejected {
                host: host.to_string(),
                port,
            };
        }
        return MailError::Tls {
            host: host.to_string(),
            port,
        };
    }
    MailError::Tls {
        host: host.to_string(),
        port,
    }
}
