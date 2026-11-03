//! K07: the SSRF-pinned client factory is public API.
//!
//! The app's L1 fetch runtime resolves a URL with `resolve_checked` and builds
//! its client with `build_client`. These tests pin the public surface and the
//! refusal of private and loopback addresses.

use kernel_net::{resolve_checked, AddressPolicy, FetchError};
use reqwest::Url;

#[tokio::test]
async fn the_exported_guard_refuses_loopback_and_private_addresses() {
    for url in [
        "http://127.0.0.1:9/",
        "http://[::1]:9/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
    ] {
        let parsed = Url::parse(url).expect("test URL");
        let err = resolve_checked(AddressPolicy::PublicOnly, &parsed)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::BlockedAddress { .. }),
            "{url} must be refused, got {err}"
        );
    }
}

#[test]
fn the_exported_policy_allows_only_public_addresses() {
    assert!(AddressPolicy::PublicOnly.allows("8.8.8.8".parse().unwrap()));
    assert!(!AddressPolicy::PublicOnly.allows("127.0.0.1".parse().unwrap()));
}

#[test]
fn the_client_factory_refuses_a_rejected_address() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
    ] {
        let ip: std::net::IpAddr = ip.parse().expect("test address");
        let err = kernel_net::build_client("example.com", ip).unwrap_err();
        assert!(
            matches!(err, FetchError::BlockedAddress { .. }),
            "{ip} must be refused, got {err}"
        );
    }
    let public: std::net::IpAddr = "8.8.8.8".parse().expect("public address");
    assert!(kernel_net::build_client("example.com", public).is_ok());
}

#[test]
fn the_client_factory_refuses_a_mismatched_literal_host() {
    let public: std::net::IpAddr = "8.8.8.8".parse().expect("address");
    let err = kernel_net::build_client("127.0.0.1", public).unwrap_err();
    assert!(matches!(err, FetchError::PinnedMismatch { .. }), "{err}");
    // A literal host that is the pinned address is allowed.
    let literal: std::net::IpAddr = "8.8.8.8".parse().expect("address");
    assert!(kernel_net::build_client("8.8.8.8", literal).is_ok());
}

#[test]
fn the_pinned_client_refuses_a_different_host() {
    let public: std::net::IpAddr = "8.8.8.8".parse().expect("address");
    let client = kernel_net::build_client("example.com", public).expect("client");
    let err = client.get("http://127.0.0.1:9/").unwrap_err();
    assert!(matches!(err, FetchError::UnpinnedHost { .. }), "{err}");
    // The pinned host is allowed; no request is sent here.
    assert!(client.get("http://example.com/").is_ok());
    assert!(client
        .request(reqwest::Method::POST, "https://example.com/hook")
        .is_ok());
    assert!(client
        .request(reqwest::Method::GET, "http://other.example/")
        .is_err());
}
