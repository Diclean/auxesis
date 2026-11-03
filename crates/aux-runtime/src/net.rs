//! The pinned HTTP client every outbound fetch and download is built with.
//!
//! Production resolves the host through kernel-net's `resolve_checked` and
//! builds the client with `build_client`: every DNS answer must be public, the
//! request goes to that one validated address, and the client never follows a
//! redirect. The kernel's `build_client` refuses loopback for every caller, so a
//! test server on loopback gets a client pinned by hand, and only under the
//! test-only policy.

use kernel_net::{
    build_client, refuses_host_shape, resolve_checked, AddressPolicy, FetchError, PinnedClient,
};
use reqwest::Url;

/// A client pinned to the address a policy validated for one host.
pub(crate) enum PinnedHttp {
    Kernel(PinnedClient),
    #[cfg(any(test, feature = "testing"))]
    Loopback(reqwest::Client),
}

impl PinnedHttp {
    /// Start a GET for `url`.
    pub(crate) fn get(&self, url: Url) -> Result<reqwest::RequestBuilder, FetchError> {
        match self {
            Self::Kernel(client) => client.get(url),
            #[cfg(any(test, feature = "testing"))]
            Self::Loopback(client) => Ok(client.get(url)),
        }
    }

    /// Start a POST for `url` (the OAuth token exchange, E5).
    pub(crate) fn post(&self, url: Url) -> Result<reqwest::RequestBuilder, FetchError> {
        match self {
            Self::Kernel(client) => client.request(reqwest::Method::POST, url),
            #[cfg(any(test, feature = "testing"))]
            Self::Loopback(client) => Ok(client.post(url)),
        }
    }
}

/// Resolve `url` under `policy` and pin a client to the one validated address.
pub(crate) async fn pinned_client(
    policy: AddressPolicy,
    url: &Url,
) -> Result<PinnedHttp, FetchError> {
    // Production refuses the host shape first (localhost, *.localhost, a trailing
    // dot, .lan, .local, .internal): the kernel's public-URL check does the same,
    // and resolve_checked does not. The loopback test seam keeps `localhost`, which
    // its redirect tests name on purpose.
    if policy == AddressPolicy::PublicOnly {
        if let Some(host) = url.host_str() {
            if refuses_host_shape(host) {
                return Err(FetchError::RefusedHost {
                    host: host.to_owned(),
                });
            }
        }
    }
    let (host, ip) = resolve_checked(policy, url).await?;
    #[cfg(any(test, feature = "testing"))]
    if policy == AddressPolicy::AllowLoopback {
        return loopback_client(&host, ip).map(PinnedHttp::Loopback);
    }
    Ok(PinnedHttp::Kernel(build_client(&host, ip)?))
}

/// Tests only: the same pinning as the kernel's client, for a loopback address
/// that `build_client` refuses.
#[cfg(any(test, feature = "testing"))]
fn loopback_client(host: &str, ip: std::net::IpAddr) -> Result<reqwest::Client, FetchError> {
    use std::net::SocketAddr;

    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(kernel_net::CONNECT_TIMEOUT)
        .user_agent(kernel_net::USER_AGENT)
        .resolve(host, SocketAddr::new(ip, 0))
        .build()
        .map_err(|err| FetchError::Client(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_host_names_are_refused_before_any_lookup() {
        for target in [
            "http://localhost/",
            "http://printer.local/",
            "http://nas.internal/",
            "http://office.lan/",
        ] {
            let url = Url::parse(target).unwrap();
            match pinned_client(AddressPolicy::PublicOnly, &url).await {
                Err(FetchError::RefusedHost { .. }) => {}
                Err(other) => panic!("{target}: refused for the wrong reason: {other:?}"),
                Ok(_) => panic!("{target} must be refused"),
            }
        }
    }

    #[tokio::test]
    async fn the_production_policy_refuses_loopback_and_the_metadata_address() {
        for target in [
            "http://127.0.0.1:8080/",
            "http://169.254.169.254/latest/meta-data",
        ] {
            let url = Url::parse(target).unwrap();
            assert!(
                pinned_client(AddressPolicy::PublicOnly, &url)
                    .await
                    .is_err(),
                "{target} must be refused under the default policy"
            );
        }
    }
}
