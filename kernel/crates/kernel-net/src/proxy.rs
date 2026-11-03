//! Minimal HTTP CONNECT egress proxy for sandboxed extensions.
//!
//! A stdio extension's Seatbelt profile allows exactly one loopback port
//! (`kernel-mcp::sandbox`); this proxy is what listens there. It accepts only
//! `CONNECT host:port` (a plain-HTTP absolute-form request is refused with
//! 403), matches the target against the entry's exact host:port allowlist
//! (case-insensitive host, no wildcards), resolves the host through the
//! kernel's SSRF/DNS-pinning policy, connects to the validated address and
//! splices bytes both ways.
//!
//! Nothing here inspects or records payload bytes: the proxy is a transport,
//! and the entry's allowlist is the policy. Every refusal carries a stable
//! reason label ([`ProxyRefusal::reason`]) for the audit; the client sees the
//! label, never the bytes it sent.

use crate::ssrf::{refuses_host_shape, AddressPolicy};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Largest request head accepted, in bytes. Past this the proxy answers 431
/// and closes; it never buffers an unbounded header block.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Wall-clock budget for one upstream connect.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the proxy refused a request. Stable labels, no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyRefusal {
    /// The client closed (or sent nothing) before a complete head arrived.
    EmptyRequest,
    /// The head crossed [`MAX_HEADER_BYTES`] without a terminator.
    HeaderTooLarge,
    /// The request line was not `METHOD target HTTP/1.x`.
    MalformedRequest,
    /// The method was not `CONNECT`.
    NotConnect,
    /// The CONNECT target was not `host:port`.
    MalformedTarget,
    /// The host is not an exact entry of the allowlist.
    HostNotAllowed,
    /// The host is allowed but not on the port the entry pins.
    PortNotAllowed,
    /// The host spelling is one the SSRF policy never resolves
    /// (`localhost`, `*.localhost`, a trailing dot, `.lan`/`.local`/`.internal`).
    RefusedHostShape,
    /// The host did not resolve.
    DnsFailure,
    /// An answer (or the literal) is not globally routable: private, loopback,
    /// link-local, CGNAT, metadata, ...
    BlockedAddress,
    /// The validated upstream address refused the connection or timed out.
    ConnectFailed,
    /// The connection failed while reading the head or writing a response.
    Io,
}

impl ProxyRefusal {
    /// Stable lowercase label for the audit record.
    pub fn reason(self) -> &'static str {
        match self {
            ProxyRefusal::EmptyRequest => "empty_request",
            ProxyRefusal::HeaderTooLarge => "header_too_large",
            ProxyRefusal::MalformedRequest => "malformed_request",
            ProxyRefusal::NotConnect => "not_connect",
            ProxyRefusal::MalformedTarget => "malformed_target",
            ProxyRefusal::HostNotAllowed => "host_not_allowed",
            ProxyRefusal::PortNotAllowed => "port_not_allowed",
            ProxyRefusal::RefusedHostShape => "refused_host_shape",
            ProxyRefusal::DnsFailure => "dns_failure",
            ProxyRefusal::BlockedAddress => "blocked_address",
            ProxyRefusal::ConnectFailed => "connect_failed",
            ProxyRefusal::Io => "io",
        }
    }

    /// The HTTP status line sent back for this refusal.
    fn status(self) -> &'static str {
        match self {
            ProxyRefusal::HeaderTooLarge => "431 Request Header Fields Too Large",
            _ => "403 Forbidden",
        }
    }
}

/// Why the proxy could not start.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// The loopback listener could not be bound.
    #[error("egress proxy could not bind 127.0.0.1: {0}")]
    Bind(#[from] std::io::Error),
}

/// A running egress proxy.
///
/// Dropping the value stops the listener; call [`EgressProxy::shutdown`] to
/// stop it and wait for the accept loop to finish.
#[derive(Debug)]
pub struct EgressProxy {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl EgressProxy {
    /// The loopback port the proxy listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Stop accepting connections and wait for the listener task to end.
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// Bind an egress proxy on an ephemeral loopback port.
///
/// `allow` is the entry's `network` list: exact `(host, port)` pairs. The host
/// is matched case-insensitively and stripped of a trailing dot; there are no
/// wildcards and no implicit subdomains.
pub async fn spawn_egress_proxy(allow: Vec<(String, u16)>) -> Result<EgressProxy, ProxyError> {
    spawn_with(allow, Resolver::System(AddressPolicy::PublicOnly)).await
}

async fn spawn_with(
    allow: Vec<(String, u16)>,
    resolver: Resolver,
) -> Result<EgressProxy, ProxyError> {
    let allow: BTreeSet<(String, u16)> = allow
        .into_iter()
        .map(|(host, port)| (host.trim().trim_end_matches('.').to_ascii_lowercase(), port))
        .collect();
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0)).await?;
    let port = listener.local_addr()?.port();
    let state = Arc::new(ProxyState { allow, resolver });
    let (shutdown, mut stop) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut stop => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&state);
                            connections.spawn(async move { serve(stream, state).await; });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    Ok(EgressProxy {
        port,
        shutdown: Some(shutdown),
        task: Some(task),
    })
}

/// The allowlist and resolver shared by every connection.
struct ProxyState {
    /// Exact `(host, port)` pairs. A host may be allowed on several ports;
    /// keying by host alone would silently keep only the last one.
    allow: BTreeSet<(String, u16)>,
    resolver: Resolver,
}

impl ProxyState {
    /// Match `host:port` against the exact allowlist.
    fn authorize(&self, host: &str, port: u16) -> Result<(), ProxyRefusal> {
        let host = host.to_ascii_lowercase();
        if self.allow.contains(&(host.clone(), port)) {
            return Ok(());
        }
        if self.allow.iter().any(|(allowed, _)| *allowed == host) {
            return Err(ProxyRefusal::PortNotAllowed);
        }
        Err(ProxyRefusal::HostNotAllowed)
    }
}

/// How a host is resolved before the connect.
#[derive(Clone)]
enum Resolver {
    /// Production: the SSRF/DNS-pinning policy, every answer checked.
    System(AddressPolicy),
    /// Tests only: a fixed host → address map (plus the policy), so a local
    /// echo server can stand in for an upstream.
    #[cfg(test)]
    TestHosts {
        hosts: Arc<std::collections::BTreeMap<String, IpAddr>>,
        policy: AddressPolicy,
        lookups: Arc<std::sync::Mutex<Vec<String>>>,
    },
}

impl Resolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<IpAddr, ProxyRefusal> {
        match self {
            Resolver::System(policy) => resolve_host(*policy, host, port).await,
            #[cfg(test)]
            Resolver::TestHosts {
                hosts,
                policy,
                lookups,
            } => {
                let key = host.to_ascii_lowercase();
                if let Ok(mut log) = lookups.lock() {
                    log.push(key.clone());
                }
                if let Some(ip) = hosts.get(&key) {
                    if !policy.allows(*ip) {
                        return Err(ProxyRefusal::BlockedAddress);
                    }
                    return Ok(*ip);
                }
                resolve_host(*policy, host, port).await
            }
        }
    }
}

/// Resolve `host` under `policy`: refuse the host shape first (no DNS), then
/// check **every** answer so a mixed public/private reply cannot slip through,
/// and return the first validated address to pin the connect to.
async fn resolve_host(
    policy: AddressPolicy,
    host: &str,
    port: u16,
) -> Result<IpAddr, ProxyRefusal> {
    if refuses_host_shape(host) {
        return Err(ProxyRefusal::RefusedHostShape);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !policy.allows(ip) {
            return Err(ProxyRefusal::BlockedAddress);
        }
        return Ok(ip);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ProxyRefusal::DnsFailure)?
        .collect();
    if addrs.is_empty() {
        return Err(ProxyRefusal::DnsFailure);
    }
    for addr in &addrs {
        if !policy.allows(addr.ip()) {
            return Err(ProxyRefusal::BlockedAddress);
        }
    }
    Ok(addrs[0].ip())
}

/// Serve one client connection.
async fn serve(mut stream: TcpStream, state: Arc<ProxyState>) {
    if let Err(refusal) = handle(&mut stream, &state).await {
        let _ = write_status(&mut stream, refusal).await;
    }
}

async fn handle(stream: &mut TcpStream, state: &ProxyState) -> Result<(), ProxyRefusal> {
    let (head, leftover) = read_head(stream).await?;
    let (method, target) = request_line(&head)?;
    if method != "CONNECT" {
        return Err(ProxyRefusal::NotConnect);
    }
    let (host, port) = parse_authority(target)?;
    state.authorize(&host, port)?;
    let ip = state.resolver.resolve(&host, port).await?;
    let mut upstream = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    .map_err(|_| ProxyRefusal::ConnectFailed)?
    .map_err(|_| ProxyRefusal::ConnectFailed)?;

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|_| ProxyRefusal::Io)?;
    // A client may pipeline bytes behind the CONNECT head; they belong to the
    // tunnel and are forwarded before the splice starts.
    if !leftover.is_empty() {
        upstream
            .write_all(&leftover)
            .await
            .map_err(|_| ProxyRefusal::Io)?;
    }
    // The splice ends when either side closes; its error is the end of the
    // tunnel, not a proxy decision.
    let _ = tokio::io::copy_bidirectional(stream, &mut upstream).await;
    Ok(())
}

/// Read one request head, bounded by [`MAX_HEADER_BYTES`].
///
/// Returns the head text (terminator excluded) and any bytes already read past
/// it, which are tunnel data and must not be dropped.
async fn read_head(stream: &mut TcpStream) -> Result<(String, Vec<u8>), ProxyRefusal> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&buf) {
            if end > MAX_HEADER_BYTES {
                return Err(ProxyRefusal::HeaderTooLarge);
            }
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let leftover = buf[end + 4..].to_vec();
            return Ok((head, leftover));
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(ProxyRefusal::HeaderTooLarge);
        }
        let room = (MAX_HEADER_BYTES + 4 - buf.len()).min(chunk.len());
        let read = stream
            .read(&mut chunk[..room])
            .await
            .map_err(|_| ProxyRefusal::Io)?;
        if read == 0 {
            return Err(ProxyRefusal::EmptyRequest);
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Index of the `\r\n\r\n` terminator, when the head is complete.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Split the request line into method and target.
fn request_line(head: &str) -> Result<(&str, &str), ProxyRefusal> {
    let line = head.lines().next().ok_or(ProxyRefusal::EmptyRequest)?;
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(ProxyRefusal::MalformedRequest)?;
    let target = parts.next().ok_or(ProxyRefusal::MalformedRequest)?;
    let version = parts.next().ok_or(ProxyRefusal::MalformedRequest)?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(ProxyRefusal::MalformedRequest);
    }
    Ok((method, target))
}

/// Parse a CONNECT authority (`host:port`, or `[v6]:port`).
fn parse_authority(target: &str) -> Result<(String, u16), ProxyRefusal> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or(ProxyRefusal::MalformedTarget)?;
        (
            host,
            rest.strip_prefix(':')
                .ok_or(ProxyRefusal::MalformedTarget)?,
        )
    } else {
        target
            .rsplit_once(':')
            .ok_or(ProxyRefusal::MalformedTarget)?
    };
    if host.is_empty() {
        return Err(ProxyRefusal::MalformedTarget);
    }
    let port: u16 = port.parse().map_err(|_| ProxyRefusal::MalformedTarget)?;
    if port == 0 {
        return Err(ProxyRefusal::MalformedTarget);
    }
    Ok((host.to_string(), port))
}

/// Answer a refusal: a status line plus the stable reason label.
async fn write_status(stream: &mut TcpStream, refusal: ProxyRefusal) -> std::io::Result<()> {
    let body = format!("egress proxy: {}\n", refusal.reason());
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        refusal.status(),
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Spawn the proxy with a fixed host → address map and a recording
    /// resolver, so a test proves both what resolved and what did not.
    async fn spawn_for_tests(
        allow: Vec<(&str, u16)>,
        hosts: Vec<(&str, IpAddr)>,
        policy: AddressPolicy,
    ) -> (EgressProxy, Arc<Mutex<Vec<String>>>) {
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let resolver = Resolver::TestHosts {
            hosts: Arc::new(
                hosts
                    .into_iter()
                    .map(|(host, ip)| (host.to_ascii_lowercase(), ip))
                    .collect(),
            ),
            policy,
            lookups: Arc::clone(&lookups),
        };
        let allow = allow
            .into_iter()
            .map(|(host, port)| (host.to_string(), port))
            .collect();
        let proxy = spawn_with(allow, resolver).await.expect("spawn proxy");
        (proxy, lookups)
    }

    async fn read_head(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("read head");
            assert_eq!(read, 1, "connection closed before the head was complete");
            buf.push(byte[0]);
            assert!(buf.len() <= 16 * 1024, "head grew unbounded");
        }
        String::from_utf8(buf).expect("utf-8 head")
    }

    /// Read a refusal response: head plus the `Content-Length` body (the
    /// stable reason label).
    async fn read_response(stream: &mut TcpStream) -> String {
        let head = read_head(stream).await;
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.expect("read body");
        format!("{head}{}", String::from_utf8_lossy(&body))
    }

    async fn echo_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("echo bind");
        let port = listener.local_addr().expect("echo addr").port();
        let task = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if stream.write_all(&buf[..read]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (port, task)
    }

    #[tokio::test]
    async fn refused_host_is_refused_before_any_resolution() {
        let (proxy, lookups) = spawn_for_tests(
            vec![("allowed.test", 443)],
            vec![],
            AddressPolicy::PublicOnly,
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect proxy");
        client
            .write_all(b"CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n")
            .await
            .expect("write");
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("host_not_allowed"), "{response}");
        assert!(
            lookups.lock().expect("lookups").is_empty(),
            "a refused host must not be resolved"
        );
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn allowed_host_resolving_to_loopback_is_refused_by_the_ssrf_policy() {
        let (proxy, lookups) = spawn_for_tests(
            vec![("private.test", 443)],
            vec![("private.test", IpAddr::from([127, 0, 0, 1]))],
            AddressPolicy::PublicOnly,
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect proxy");
        client
            .write_all(b"CONNECT private.test:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("blocked_address"), "{response}");
        assert_eq!(
            lookups.lock().expect("lookups").as_slice(),
            ["private.test"],
            "the host was resolved, then its address refused"
        );
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn allowed_host_round_trips_bytes_through_the_echo_server() {
        let (echo_port, echo) = echo_server().await;
        let (proxy, _) = spawn_for_tests(
            vec![("echo.test", echo_port)],
            vec![("echo.test", IpAddr::from([127, 0, 0, 1]))],
            AddressPolicy::AllowLoopback,
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect proxy");
        client
            .write_all(format!("CONNECT echo.test:{echo_port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        client.write_all(b"ping").await.expect("write tunnel");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("read tunnel");
        assert_eq!(&echoed, b"ping");

        proxy.shutdown().await;
        echo.abort();
    }

    #[tokio::test]
    async fn a_non_connect_method_is_refused() {
        let (proxy, lookups) = spawn_for_tests(
            vec![("allowed.test", 80)],
            vec![],
            AddressPolicy::PublicOnly,
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect proxy");
        client
            .write_all(b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            .await
            .expect("write");
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("not_connect"), "{response}");
        assert!(lookups.lock().expect("lookups").is_empty());
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn an_oversized_head_is_refused_with_431() {
        let (proxy, _) = spawn_for_tests(
            vec![("allowed.test", 80)],
            vec![],
            AddressPolicy::PublicOnly,
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect proxy");
        let mut request = b"CONNECT allowed.test:80 HTTP/1.1\r\nX-Pad: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 16));
        request.extend_from_slice(b"\r\n\r\n");
        client.write_all(&request).await.expect("write");
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 431"), "{response}");
        assert!(response.contains("header_too_large"), "{response}");
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn a_malformed_connect_target_is_refused() {
        let (proxy, _) = spawn_for_tests(
            vec![("allowed.test", 80)],
            vec![],
            AddressPolicy::PublicOnly,
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect proxy");
        client
            .write_all(b"CONNECT allowed.test HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("malformed_target"), "{response}");
        proxy.shutdown().await;
    }

    #[test]
    fn authority_parsing_handles_ipv6_and_rejects_junk() {
        assert_eq!(
            parse_authority("example.org:443").expect("authority"),
            ("example.org".to_string(), 443)
        );
        assert_eq!(
            parse_authority("[2606:4700::1111]:443").expect("authority"),
            ("2606:4700::1111".to_string(), 443)
        );
        for bad in [
            "example.org",
            ":443",
            "example.org:",
            "example.org:0",
            "example.org:x",
        ] {
            assert!(parse_authority(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn one_host_may_be_allowed_on_several_ports() {
        // Keying the allowlist by host alone kept only the last port, so a
        // second allowed port was refused. The set keeps every pair.
        let state = ProxyState {
            allow: BTreeSet::from([
                ("example.test".to_string(), 443),
                ("example.test".to_string(), 8443),
            ]),
            resolver: Resolver::System(AddressPolicy::PublicOnly),
        };
        assert_eq!(state.authorize("example.test", 443), Ok(()));
        assert_eq!(state.authorize("EXAMPLE.test", 8443), Ok(()));
        assert_eq!(
            state.authorize("example.test", 80),
            Err(ProxyRefusal::PortNotAllowed)
        );
        assert_eq!(
            state.authorize("other.test", 443),
            Err(ProxyRefusal::HostNotAllowed)
        );
    }

    #[tokio::test]
    async fn a_host_allowed_on_two_ports_reaches_both() {
        let (port_a, echo_a) = echo_server().await;
        let (port_b, echo_b) = echo_server().await;
        let (proxy, _) = spawn_for_tests(
            vec![("echo.test", port_a), ("echo.test", port_b)],
            vec![("echo.test", IpAddr::from([127, 0, 0, 1]))],
            AddressPolicy::AllowLoopback,
        )
        .await;
        for port in [port_a, port_b] {
            let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
                .await
                .expect("connect proxy");
            client
                .write_all(format!("CONNECT echo.test:{port} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .expect("write");
            let response = read_response(&mut client).await;
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "port {port}: {response}"
            );
        }
        proxy.shutdown().await;
        echo_a.abort();
        echo_b.abort();
    }
}
