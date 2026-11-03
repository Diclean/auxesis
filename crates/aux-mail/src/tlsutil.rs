//! The production TLS client configurations.
//!
//! rustls only, the `ring` provider. [`client_config`] is the one webpki-roots
//! configuration, built once and cached in a [`OnceLock`]. There is
//! deliberately **no** "accept any certificate" switch: the only other
//! configuration is [`pinned_client_config`], which trusts exactly the PEM
//! certificate in a configured `ca_file` and is refused for any non-loopback
//! host. The test-only verifier for the self-signed fake lives in the
//! `aux-fakemail` crate and reaches the dialer only through
//! [`crate::dial::Dialer::with_client_config`], which tests alone call.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::error::MailError;

static CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

/// The process-wide client configuration: webpki roots, `ring`, TLS 1.2 + 1.3.
///
/// The `ring` provider is selected explicitly because `lettre` unifies in
/// `tokio-rustls`' default `aws-lc-rs` provider, which leaves rustls' process
/// default ambiguous; `builder_with_provider` never consults it.
pub fn client_config() -> Arc<ClientConfig> {
    CLIENT_CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(build(roots))
        })
        .clone()
}

/// A client configuration that trusts exactly the certificates in `ca_file`.
///
/// No webpki roots are loaded: a connection built from this trusts the pinned
/// PEM certificate(s) alone. Only ever reached for a loopback simulator host
/// ([`ensure_loopback_ca`]); a missing or unparsable file is a config error.
pub fn pinned_client_config(ca_file: &Path) -> Result<Arc<ClientConfig>, MailError> {
    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    let invalid = || MailError::Config { field: "ca_file" };
    for certificate in CertificateDer::pem_file_iter(ca_file).map_err(|_| invalid())? {
        roots
            .add(certificate.map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        count += 1;
    }
    if count == 0 {
        return Err(invalid());
    }
    Ok(Arc::new(build(roots)))
}

/// Refuse a `ca_file` on anything but a loopback host, before any socket.
///
/// The pinned certificate is the local simulator's; trusting it for a remote
/// name would silently disable certificate verification there.
pub fn ensure_loopback_ca(host: &str) -> Result<(), MailError> {
    if is_loopback_host(host) {
        Ok(())
    } else {
        Err(MailError::Config { field: "ca_file" })
    }
}

/// True for the three loopback spellings a `ca_file` may pin.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn build(roots: RootCertStore) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// The rustls server name for `host`, or a `Protocol` error when unusable.
pub fn server_name(host: &str) -> Result<ServerName<'static>, MailError> {
    ServerName::try_from(host.to_owned()).map_err(|_| MailError::Protocol)
}
