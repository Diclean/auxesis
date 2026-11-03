//! Integration tests for the CONNECT egress proxy.
//!
//! Every test stays on loopback and opens no external socket: the refusals are
//! decided before any DNS lookup, and the one allowed-address path is exercised
//! by the unit tests in `proxy.rs` with an injected resolver.

use kernel_net::spawn_egress_proxy;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send one raw request to the proxy and return the response head.
async fn request(port: u16, bytes: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect proxy");
    stream.write_all(bytes).await.expect("write request");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn a_host_outside_the_allowlist_gets_403() {
    let proxy = spawn_egress_proxy(vec![("allowed.test".to_string(), 443)])
        .await
        .expect("spawn proxy");
    let response = request(
        proxy.port(),
        b"CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains("host_not_allowed"), "{response}");
    proxy.shutdown().await;
}

#[tokio::test]
async fn an_allowed_host_on_another_port_gets_403() {
    let proxy = spawn_egress_proxy(vec![("Allowed.Test".to_string(), 443)])
        .await
        .expect("spawn proxy");
    // The host matches case-insensitively; the port does not, so the exact
    // host:port pair is refused before any resolution.
    let response = request(proxy.port(), b"CONNECT ALLOWED.TEST:8443 HTTP/1.1\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains("port_not_allowed"), "{response}");
    proxy.shutdown().await;
}

#[tokio::test]
async fn an_allowed_host_that_is_loopback_is_refused_by_the_ssrf_policy() {
    let proxy = spawn_egress_proxy(vec![("localhost".to_string(), 9)])
        .await
        .expect("spawn proxy");
    let response = request(proxy.port(), b"CONNECT localhost:9 HTTP/1.1\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains("refused_host_shape"), "{response}");
    proxy.shutdown().await;
}

#[tokio::test]
async fn a_non_connect_method_gets_403() {
    let proxy = spawn_egress_proxy(vec![("allowed.test".to_string(), 80)])
        .await
        .expect("spawn proxy");
    let response = request(
        proxy.port(),
        b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains("not_connect"), "{response}");
    proxy.shutdown().await;
}

#[tokio::test]
async fn an_oversized_head_gets_431() {
    let proxy = spawn_egress_proxy(vec![("allowed.test".to_string(), 80)])
        .await
        .expect("spawn proxy");
    let mut oversized = b"CONNECT allowed.test:80 HTTP/1.1\r\nX-Pad: ".to_vec();
    oversized.extend(std::iter::repeat_n(b'a', 9 * 1024));
    oversized.extend_from_slice(b"\r\n\r\n");
    let response = request(proxy.port(), &oversized).await;
    assert!(response.starts_with("HTTP/1.1 431"), "{response}");
    assert!(response.contains("header_too_large"), "{response}");
    proxy.shutdown().await;
}
