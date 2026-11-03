//! SSRF guard kept from the legacy fetch tool: resolve, check every answer,
//! block anything that is not globally routable, pin the validated address.

use crate::FetchError;
use reqwest::{Client, Url};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Which address families a fetch may reach.
///
/// Production always uses [`AddressPolicy::PublicOnly`]. The loopback variant
/// exists so tests can talk to a local `wiremock` server; it is reachable
/// only through constructors gated on `cfg(test)`/the `testing` feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressPolicy {
    /// Globally routable unicast addresses only.
    PublicOnly,
    /// Tests only: public addresses plus loopback. The loopback bypass is
    /// gated on `cfg(test)` or the `testing` feature, which is enabled only
    /// by `[dev-dependencies]` edges, never by a production dependency.
    #[cfg(any(test, feature = "testing"))]
    #[allow(dead_code)]
    AllowLoopback,
}

impl AddressPolicy {
    /// Whether `addr` may be reached under this policy.
    pub fn allows(self, addr: IpAddr) -> bool {
        match self {
            AddressPolicy::PublicOnly => is_public_address(addr),
            #[cfg(any(test, feature = "testing"))]
            AddressPolicy::AllowLoopback => is_public_address(addr) || addr.is_loopback(),
        }
    }
}

/// True when `addr` is a globally routable unicast address.
///
/// This is deliberately conservative: blocking a reserved-but-harmless range
/// only costs a failed fetch, while missing one can reach the metadata
/// service or the local network.
pub fn is_public_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(addr: Ipv4Addr) -> bool {
    let [a, b, ..] = addr.octets();
    !(addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_documentation()
        || a == 0 // "this network" (RFC 1122)
        || a >= 240 // reserved, includes broadcast (RFC 1112)
        || (a == 100 && (64..=127).contains(&b)) // CGNAT (RFC 6598)
        || (a == 192 && b == 0) // IETF protocol assignments (RFC 5736)
        || (a == 192 && b == 88) // 6to4 relay anycast (RFC 7526)
        || (a == 198 && (b == 18 || b == 19))) // benchmarking (RFC 2544)
}

fn is_public_v6(addr: Ipv6Addr) -> bool {
    // IPv4-mapped (::ffff:a.b.c.d) hides an IPv4 address: inspect that one.
    if let Some(v4) = addr.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let segments = addr.segments();
    // IPv4-compatible (::/96, e.g. ::8.8.8.8) is deprecated and unroutable.
    let ipv4_compatible = segments[..6].iter().all(|segment| *segment == 0);
    // SIIT IPv4-translated `::ffff:0:a.b.c.d` (`::ffff:0:0/96`): refused even
    // though `to_ipv4_mapped` does not catch this spelling.
    let ipv4_translated = segments[..4].iter().all(|segment| *segment == 0)
        && segments[4] == 0xffff
        && segments[5] == 0;
    !(ipv4_compatible
        || ipv4_translated
        || addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.is_unique_local() // fc00::/7
        || addr.is_unicast_link_local() // fe80::/10
        || (segments[0] & 0xffc0) == 0xfec0 // site-local fec0::/10 (deprecated)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || (segments[0] == 0x0100 && segments[1..4].iter().all(|s| *s == 0)) // discard-only 100::/64
        || (segments[0] == 0x0064 && segments[1] == 0xff9b) // NAT64 well-known
        || (segments[0] == 0x2002) // 6to4 embeds an IPv4 address
        || (segments[0] == 0x2001 && segments[1] == 0x0000)) // Teredo 2001::/32
}

/// Refuse a host **spelling** that must never be reached, before any DNS
/// answer: `localhost`, any `*.localhost`, a trailing dot, and the `.lan`,
/// `.local` and `.internal` suffixes. This runs on the raw URL host, so it
/// closes the shape gap that a resolution-only guard leaves open.
pub fn refuses_host_shape(host: &str) -> bool {
    if host.ends_with('.') {
        return true;
    }
    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".lan")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
}

/// Resolve a URL and return the bare host plus one validated public address.
///
/// Every refused host **shape** is rejected first (no DNS), then every DNS
/// answer is checked: a single non-public answer refuses the whole host, so a
/// mixed public/private answer (a rebinding attempt) cannot slip through.
pub async fn resolve_public_url(url: &Url) -> Result<(String, IpAddr), FetchError> {
    if let Some(host) = url.host_str() {
        if refuses_host_shape(host) {
            return Err(FetchError::RefusedHost {
                host: host.to_owned(),
            });
        }
    }
    resolve_checked(AddressPolicy::PublicOnly, url).await
}

/// Resolve the URL host and refuse anything that is not public.
///
/// Returns the bare host (brackets stripped for IPv6 literals) and one
/// validated address to pin the connection to. If *any* DNS answer is
/// non-public the whole host is refused: a mixed public/private answer is a
/// rebinding attempt.
pub async fn resolve_checked(
    policy: AddressPolicy,
    url: &Url,
) -> Result<(String, IpAddr), FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::Dns {
            host: String::new(),
            message: "URL has no host".to_string(),
        })?
        .to_string();
    let port = url.port_or_known_default().ok_or_else(|| FetchError::Dns {
        host: host.clone(),
        message: "URL has no known port".to_string(),
    })?;

    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        check_address(policy, ip)?;
        return Ok((bare.to_string(), ip));
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bare, port))
        .await
        .map_err(|err| FetchError::Dns {
            host: host.clone(),
            message: err.to_string(),
        })?
        .collect();
    if addrs.is_empty() {
        return Err(FetchError::NoAddresses { host });
    }
    for addr in &addrs {
        check_address(policy, addr.ip())?;
    }
    Ok((bare.to_string(), addrs[0].ip()))
}

pub(crate) fn check_address(policy: AddressPolicy, ip: IpAddr) -> Result<(), FetchError> {
    if policy.allows(ip) {
        return Ok(());
    }
    Err(FetchError::BlockedAddress {
        addr: ip.to_string(),
    })
}

/// A DNS resolver that answers for exactly one host, with exactly one address,
/// and refuses every other name.
///
/// The client built for `example.com` cannot resolve `127.0.0.1` or any other
/// name, so a pinned client cannot be steered to a host the caller never
/// validated.
#[derive(Debug, Clone)]
struct PinnedResolver {
    /// The one host this resolver answers for, normalised by [`normal_host`].
    host: String,
    /// The one address it answers with.
    addr: SocketAddr,
}

impl PinnedResolver {
    fn new(host: &str, addr: SocketAddr) -> Self {
        Self {
            host: normal_host(host),
            addr,
        }
    }
}

/// A host in the one form pinned requests compare: a trailing dot removed, then
/// the IPv6 brackets, lower-cased, and an IPv6 address in its canonical form.
/// `[::1]`, `[::1].` and `::1` name the same host, `Example.COM.` and
/// `example.com` too, and an uncompressed address equals its compressed form.
fn normal_host(host: &str) -> String {
    let undotted = host.trim_end_matches('.');
    let bare = undotted
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(undotted)
        .to_ascii_lowercase();
    match bare.parse::<Ipv6Addr>() {
        Ok(address) => address.to_string(),
        Err(_) => bare,
    }
}

impl reqwest::dns::Resolve for PinnedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let pinned = normal_host(name.as_str()) == self.host;
        let addr = self.addr;
        let requested = name.as_str().to_string();
        Box::pin(async move {
            if pinned {
                let addrs: reqwest::dns::Addrs = Box::new(std::iter::once(addr));
                Ok(addrs)
            } else {
                let error: Box<dyn std::error::Error + Send + Sync> =
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("host `{requested}` is not the pinned host"),
                    ));
                Err(error)
            }
        })
    }
}

/// A client pinned to one host: every request must name that host, or it is
/// refused before a socket is opened.
///
/// [`build_client`] returns this type, so a client built for `example.com`
/// cannot be sent to `127.0.0.1` or any other name, even by a caller that
/// builds the request itself.
#[derive(Debug, Clone)]
pub struct PinnedClient {
    client: Client,
    /// The host every request must name, normalised by [`normal_host`].
    host: String,
}

impl PinnedClient {
    /// The host every request must name.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Start a `GET` for `url`, refused when its host is not the pinned host.
    pub fn get(&self, url: impl reqwest::IntoUrl) -> Result<reqwest::RequestBuilder, FetchError> {
        let url = self.checked(url)?;
        Ok(self.client.get(url))
    }

    /// Start a request for `url`, refused when its host is not the pinned host.
    pub fn request(
        &self,
        method: reqwest::Method,
        url: impl reqwest::IntoUrl,
    ) -> Result<reqwest::RequestBuilder, FetchError> {
        let url = self.checked(url)?;
        Ok(self.client.request(method, url))
    }

    /// Parse `url` and refuse it unless it names the pinned host.
    fn checked(&self, url: impl reqwest::IntoUrl) -> Result<reqwest::Url, FetchError> {
        let url = url
            .into_url()
            .map_err(|err| FetchError::InvalidUrl(err.to_string()))?;
        let host = url.host_str().unwrap_or_default();
        if normal_host(host) == self.host {
            Ok(url)
        } else {
            Err(FetchError::UnpinnedHost {
                host: host.to_string(),
                pinned: self.host.clone(),
            })
        }
    }
}

/// Build a client whose DNS answer for `host` is pinned to the address we
/// validated (no proxies, no automatic redirects), and whose requests must
/// name that same host.
///
/// This is the public factory the app's L1 fetch runtime builds clients with:
/// call [`resolve_checked`] first, then build the client for the bare host and
/// the one validated address. The address must itself pass the public-address
/// guard; an IP-literal `host` that differs from `ip` is refused; the installed
/// [`PinnedResolver`] answers only for `host`; and the returned
/// [`PinnedClient`] refuses any request to another host.
pub fn build_client(host: &str, ip: IpAddr) -> Result<PinnedClient, FetchError> {
    // The pinned address must itself pass the public-address guard: a caller
    // that resolves without checking (or passes a loopback literal) cannot use
    // this factory to reach a private host.
    check_address(AddressPolicy::PublicOnly, ip)?;
    // No per-request timeout: the caller wraps the whole fetch (all hops) in
    // one wall-clock budget, and a client timeout would race it and surface
    // a less useful error.
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(crate::CONNECT_TIMEOUT)
        .user_agent(crate::USER_AGENT);
    let pinned = normal_host(host);
    match pinned.parse::<IpAddr>() {
        Ok(literal) if literal == ip => {}
        Ok(_) => {
            return Err(FetchError::PinnedMismatch {
                host: host.to_string(),
                addr: ip.to_string(),
            });
        }
        Err(_) => {
            builder = builder.dns_resolver(PinnedResolver::new(&pinned, SocketAddr::new(ip, 0)));
        }
    }
    let client = builder
        .build()
        .map_err(|err| FetchError::Client(err.to_string()))?;
    Ok(PinnedClient {
        client,
        host: pinned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_host_removes_brackets_then_the_trailing_dot() {
        assert_eq!(normal_host("[::1]."), "::1");
        assert_eq!(normal_host("[::1]"), "::1");
        assert_eq!(normal_host("Example.COM."), "example.com");
    }

    #[test]
    fn uncompressed_ipv6_matches_its_compressed_form() {
        assert_eq!(normal_host("[0:0:0:0:0:0:0:1]"), normal_host("[::1]"));
        assert_eq!(
            normal_host("2001:DB8:0:0:0:0:0:1"),
            normal_host("2001:db8::1")
        );
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn address_guard_blocks_reserved_ranges() {
        for text in [
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "100.64.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::8.8.8.8",
            "::ffff:0:8.8.8.8",
            "::ffff:0:127.0.0.1",
        ] {
            assert!(!is_public_address(ip(text)), "{text} must be blocked");
        }
    }

    #[test]
    fn siit_ipv4_translated_addresses_are_refused() {
        // Item 13: `::ffff:0:a.b.c.d` hides an IPv4 address behind the SIIT
        // spelling; a globally routable embedded address must still be refused.
        for text in [
            "::ffff:0:8.8.8.8",
            "::ffff:0:1.1.1.1",
            "::ffff:0:93.184.216.34",
        ] {
            assert!(
                !is_public_address(ip(text)),
                "{text} (SIIT) must be blocked"
            );
        }
    }

    #[test]
    fn address_guard_allows_public_ranges() {
        for text in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(is_public_address(ip(text)), "{text} must be allowed");
        }
    }

    #[test]
    fn loopback_policy_is_the_only_way_to_reach_loopback() {
        assert!(!AddressPolicy::PublicOnly.allows(ip("127.0.0.1")));
        assert!(AddressPolicy::AllowLoopback.allows(ip("127.0.0.1")));
        // The loopback policy still refuses private ranges.
        assert!(!AddressPolicy::AllowLoopback.allows(ip("10.0.0.1")));
        assert!(!AddressPolicy::AllowLoopback.allows(ip("169.254.169.254")));
    }

    #[tokio::test]
    async fn the_pinned_resolver_answers_only_its_host() {
        use reqwest::dns::{Name, Resolve};
        let resolver = PinnedResolver::new("example.com", SocketAddr::new(ip("8.8.8.8"), 0));
        let pinned: Name = "example.com".parse().expect("name");
        let addrs: Vec<SocketAddr> = resolver.resolve(pinned).await.expect("pinned").collect();
        assert_eq!(addrs, vec![SocketAddr::new(ip("8.8.8.8"), 0)]);
        for other in ["127.0.0.1", "other.example"] {
            let name: Name = other.parse().expect("name");
            assert!(resolver.resolve(name).await.is_err(), "{other} resolved");
        }
        // The pin is case-insensitive.
        let upper: Name = "EXAMPLE.COM".parse().expect("name");
        assert!(resolver.resolve(upper).await.is_ok());
    }

    #[tokio::test]
    async fn the_pinned_resolver_normalises_host_names() {
        use reqwest::dns::{Name, Resolve};
        let resolver = PinnedResolver::new("Example.com.", SocketAddr::new(ip("8.8.8.8"), 0));
        let name: Name = "example.com".parse().expect("name");
        assert!(resolver.resolve(name).await.is_ok());
    }

    #[test]
    fn a_bracketed_ipv6_host_must_match_its_pinned_address() {
        let err = build_client("[::1]", ip("8.8.8.8")).unwrap_err();
        assert!(
            matches!(err, FetchError::PinnedMismatch { .. }),
            "expected a pinned mismatch, got {err}"
        );
    }

    #[test]
    fn a_pinned_host_compares_after_normalisation() {
        let client = build_client("Example.COM.", ip("8.8.8.8")).expect("client");
        assert_eq!(client.host(), "example.com");
        assert!(client.get("https://example.com/").is_ok());
        assert!(client.get("https://EXAMPLE.com./path").is_ok());
        assert!(client.get("https://other.example/").is_err());
    }

    #[test]
    fn a_pinned_ipv6_literal_is_allowed_with_its_brackets() {
        let address = ip("2606:4700:4700::1111");
        let client = build_client("2606:4700:4700::1111", address).expect("client");
        assert!(client.get("http://[2606:4700:4700::1111]/").is_ok());
        assert!(client.get("http://[2606:4700:4700::1112]/").is_err());
    }

    #[tokio::test]
    async fn dns_answers_are_checked_before_any_connection() {
        let url = Url::parse("http://localhost:9/").unwrap();
        let err = resolve_checked(AddressPolicy::PublicOnly, &url)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::BlockedAddress { .. }),
            "expected a blocked address, got {err}"
        );
    }

    #[test]
    fn refused_host_shapes_are_rejected_without_dns() {
        for host in [
            "localhost",
            "foo.localhost",
            "printer.lan",
            "thing.local",
            "service.internal",
            "example.com.",
        ] {
            assert!(refuses_host_shape(host), "{host} must be refused");
        }
        for host in ["example.com", "mcp.data.gouv.fr", "8.8.8.8", "2606:4700::1"] {
            assert!(!refuses_host_shape(host), "{host} must be allowed");
        }
    }

    #[tokio::test]
    async fn public_resolution_refuses_host_shapes_and_ranges() {
        for url in [
            "https://localhost/mcp",
            "https://foo.localhost/mcp",
            "https://service.internal/mcp",
            "https://localhost./mcp",
            "https://127.0.0.1/mcp",
            "https://10.0.0.1/mcp",
        ] {
            let parsed = Url::parse(url).unwrap();
            assert!(resolve_public_url(&parsed).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn loopback_policy_resolves_localhost_for_tests() {
        let url = Url::parse("http://localhost:9/").unwrap();
        let (host, ip) = resolve_checked(AddressPolicy::AllowLoopback, &url)
            .await
            .unwrap();
        assert_eq!(host, "localhost");
        assert!(ip.is_loopback());
    }
}
