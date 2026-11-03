//! Self-signed certificates and the certificate verifier that trusts exactly one.
//!
//! This is the only "accept this self-signed cert" code in the workspace. The
//! tests reach the dialer through `Dialer::with_client_config`; the simulator
//! uses [`TestCert::from_der`] to present the certificate it wrote to
//! `cert.pem`.

use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use tokio_rustls::rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
};

/// One `rcgen` self-signed certificate plus the configs built from it.
#[derive(Clone)]
pub struct TestCert {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
    name: ServerName<'static>,
}

impl TestCert {
    /// Generate a fresh self-signed certificate for `localhost`.
    pub fn new() -> Self {
        Self::new_for("localhost")
    }

    /// Generate a fresh self-signed certificate valid only for `name`.
    ///
    /// An IP-literal `name` becomes an IP SAN (rcgen parses it), which is what
    /// the loopback fake dials as `127.0.0.1`.
    pub fn new_for(name: &str) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![name.to_string()]).expect("rcgen self-signed");
        Self {
            cert: cert.der().clone(),
            key: signing_key.serialize_der(),
            name: ServerName::try_from(name.to_owned()).expect("a valid server name"),
        }
    }

    /// A certificate from DER plus its PKCS#8 private-key bytes, as the
    /// simulator loads the pair it wrote to `cert.pem`/`key.pem`.
    pub fn from_der(cert: CertificateDer<'static>, key: Vec<u8>) -> Self {
        Self {
            cert,
            key,
            name: ServerName::try_from("localhost".to_owned()).expect("a valid server name"),
        }
    }

    /// The TLS server configuration the fake hands to `TlsAcceptor`.
    pub fn server_config(&self) -> Arc<ServerConfig> {
        let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![self.cert.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
            )
            .expect("the self-signed certificate is valid");
        Arc::new(config)
    }

    /// A client configuration that trusts exactly this certificate.
    pub fn client_config(&self) -> Arc<ClientConfig> {
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustOneCert {
                cert: self.cert.clone(),
                name: self.name.clone(),
            }))
            .with_no_client_auth();
        Arc::new(config)
    }
}

impl Default for TestCert {
    fn default() -> Self {
        Self::new()
    }
}

/// Trusts exactly the pinned self-signed certificate, for its pinned name.
#[derive(Debug)]
struct TrustOneCert {
    cert: CertificateDer<'static>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for TrustOneCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity != &self.cert {
            return Err(Error::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        // The real verifier checks the name too, so a cert pinned for
        // `localhost` must not be accepted for `127.0.0.1`.
        if server_name.to_owned() != self.name {
            return Err(Error::InvalidCertificate(CertificateError::NotValidForName));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
