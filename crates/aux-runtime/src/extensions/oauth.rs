//! Local OAuth 2.0 authorization-code + PKCE for extensions (Phase 1, E5).
//!
//! The whole flow runs on this Mac: `auxd` binds a one-shot loopback listener
//! on `127.0.0.1` with a random port, checks the returned `state`, and sends
//! the authorization code and PKCE verifier to the catalog entry's **https**
//! token endpoint through the same DNS-pinned kernel client every other
//! outbound fetch uses. There is no relay.
//!
//! State and verifier come from the OS CSPRNG. Tokens are stored through the
//! `.env` secret store (the same protected file provider keys live in) and
//! never appear in a log line, an error or an API response.
//!
//! The only loopback seam is compiled under `cfg(test)` or the `testing`
//! feature (a dev-dependency edge): a production build refuses a plaintext
//! `http` token endpoint, full stop.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use kernel_net::AddressPolicy;

use super::catalog::{secret_prefix, OAuthConfig};
use super::install::{remove_secrets, set_secret};
use super::valid_name;
use crate::net::{pinned_client, PinnedHttp};

/// How long a started flow waits for the browser callback (5 minutes).
pub const OAUTH_TIMEOUT: Duration = Duration::from_secs(300);

/// One token request, connect and body included.
pub const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// The one path the loopback listener answers.
pub const CALLBACK_PATH: &str = "/oauth2/callback";

/// Refresh an access token this many seconds before it actually expires.
const EXPIRY_SKEW_SECS: u64 = 60;

const MAX_HEADER_BYTES: usize = 8192;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CODE_BYTES: usize = 4096;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const LISTEN_BACKLOG: u32 = 64;

/// Every way the local OAuth flow can fail. No variant ever carries a token:
/// the message of a stored token never becomes an error string.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// The extension has no `[oauth]` table.
    #[error("this extension has no OAuth configuration")]
    NotConfigured,
    /// An endpoint was not a public https URL.
    #[error("the OAuth endpoints must be public https URLs")]
    InsecureEndpoint,
    /// The `[oauth]` client secret named a key outside the extension's own
    /// `.env` namespace.
    #[error("the OAuth client secret must be this extension's own .env key")]
    ClientSecretRefused,
    /// The token endpoint could not be reached.
    #[error("the OAuth request failed")]
    Network,
    /// The `state` in the callback did not match the one we generated.
    #[error("the authorization state did not match")]
    StateMismatch,
    /// The authorization server refused the request (`error=...` or non-2xx).
    #[error("the authorization server refused the request")]
    ProviderRefused,
    /// The stored authorization is gone or unusable.
    #[error("this extension is not connected")]
    NotConnected,
    /// The authorization flow timed out.
    #[error("the authorization flow timed out")]
    Timeout,
    /// The token reply was missing or malformed.
    #[error("the token reply was malformed")]
    InvalidResponse,
    /// The token store failed to read or write.
    #[error("the token store failed")]
    Store,
    /// The OS random source failed.
    #[error("the system random source failed")]
    Random,
    /// The loopback listener failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One stored authorization. `Debug` redacts both token values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSet {
    access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    /// Unix seconds after which the access token is treated as expired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    token_type: String,
}

impl TokenSet {
    /// The bearer token a caller injects. Never logged by this module.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The refresh token, when the provider issued one.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Unix seconds the access token expires at, when known.
    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    /// Scopes the provider returned.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// True when the access token is missing or within `skew` of expiry.
    pub fn is_expired(&self, now: u64, skew: u64) -> bool {
        match self.expires_at {
            Some(at) => at <= now.saturating_add(skew),
            None => false,
        }
    }
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// Where a token set is kept. File-backed in production and in tests; the
/// real Keychain is never touched by this module.
pub trait TokenStore: Send + Sync {
    /// The stored tokens, or `None` when the extension is not connected.
    fn load(&self, extension: &str) -> Result<Option<TokenSet>, OAuthError>;
    /// Store (or replace) the tokens for `extension`.
    fn save(&self, extension: &str, tokens: &TokenSet) -> Result<(), OAuthError>;
    /// Delete the tokens for `extension`; a no-op when none are stored.
    fn clear(&self, extension: &str) -> Result<(), OAuthError>;
}

/// The `~/.auxesis/.env` token store: one `EXT_<NAME>__OAUTH_TOKENS=<json>`
/// line, written 0600 through the shared sandbox gateway.
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    home: PathBuf,
}

impl FileTokenStore {
    /// A store rooted at an Auxesis home.
    pub fn new(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
        }
    }

    /// The `.env` name holding this extension's tokens.
    fn var_name(extension: &str) -> Result<String, OAuthError> {
        if !valid_name(extension) {
            return Err(OAuthError::NotConfigured);
        }
        Ok(format!("{}OAUTH_TOKENS", secret_prefix(extension)))
    }
}

impl TokenStore for FileTokenStore {
    fn load(&self, extension: &str) -> Result<Option<TokenSet>, OAuthError> {
        let name = Self::var_name(extension)?;
        let names: BTreeSet<String> = std::iter::once(name.clone()).collect();
        let values = kernel_core::env_file::read_values(&self.home, &names);
        let Some(raw) = values.get(&name) else {
            return Ok(None);
        };
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let tokens = serde_json::from_str(raw).map_err(|_| OAuthError::Store)?;
        Ok(Some(tokens))
    }

    fn save(&self, extension: &str, tokens: &TokenSet) -> Result<(), OAuthError> {
        let name = Self::var_name(extension)?;
        let raw = serde_json::to_string(tokens).map_err(|_| OAuthError::Store)?;
        set_secret(&self.home, &name, &raw).map_err(|_| OAuthError::Store)
    }

    fn clear(&self, extension: &str) -> Result<(), OAuthError> {
        let name = Self::var_name(extension)?;
        remove_secrets(&self.home, std::slice::from_ref(&name)).map_err(|_| OAuthError::Store)
    }
}

/// The validated endpoints of one extension's `[oauth]` table.
#[derive(Clone)]
pub struct OAuthEndpoints {
    authorization: Url,
    token: Url,
    client_id: String,
    client_secret: Option<String>,
    scopes: Vec<String>,
    allow_loopback: bool,
}

/// Whether this build may talk to a loopback authorization server.
///
/// True only under `cfg(test)` or the `testing` feature, which a production
/// dependency edge never enables.
pub fn loopback_endpoints_allowed() -> bool {
    cfg!(any(test, feature = "testing"))
}

/// Validate an `[oauth]` table and resolve its optional client secret.
///
/// The token exchange may only reach a public `https` origin. `allow_loopback`
/// is the test-only seam that also accepts an `http` loopback origin. A named
/// client secret must be `EXT_<EXTENSION>__…`: the extension can never point
/// the reader at another extension's or a provider's `.env` key.
pub fn oauth_endpoints(
    config: &OAuthConfig,
    extension: &str,
    home: &Path,
    allow_loopback: bool,
) -> Result<OAuthEndpoints, OAuthError> {
    let authorization = parse_endpoint(&config.authorization_url, allow_loopback)?;
    let token = parse_endpoint(&config.token_url, allow_loopback)?;
    let client_id = config.client_id.trim();
    if client_id.is_empty() {
        return Err(OAuthError::InvalidResponse);
    }
    let client_secret = match config.client_secret_env.as_deref() {
        Some(name) if !name.is_empty() => {
            if !super::catalog::valid_secret_name(extension, name) {
                return Err(OAuthError::ClientSecretRefused);
            }
            let names: BTreeSet<String> = std::iter::once(name.to_owned()).collect();
            kernel_core::env_file::read_values(home, &names).remove(name)
        }
        _ => None,
    };
    Ok(OAuthEndpoints {
        authorization,
        token,
        client_id: client_id.to_owned(),
        client_secret,
        scopes: config.scopes.clone(),
        allow_loopback,
    })
}

fn parse_endpoint(raw: &str, allow_loopback: bool) -> Result<Url, OAuthError> {
    let url = Url::parse(raw).map_err(|_| OAuthError::InsecureEndpoint)?;
    if url.scheme() == "https" {
        return Ok(url);
    }
    if allow_loopback && url.scheme() == "http" && is_loopback_host(&url) {
        return Ok(url);
    }
    Err(OAuthError::InsecureEndpoint)
}

fn is_loopback_host(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("localhost") | Some("[::1]") | Some("::1")
    )
}

impl OAuthEndpoints {
    /// The token endpoint URL (used by callers that only inspect it).
    pub fn token_url(&self) -> &Url {
        &self.token
    }

    /// Bind the one-shot callback listener and build the authorization URL.
    pub async fn begin(&self) -> Result<PendingFlow, OAuthError> {
        let listener = CallbackListener::bind().await?;
        let redirect_uri = listener.redirect_uri();
        let state = random_b64url(32)?;
        let verifier = random_b64url(32)?;
        let challenge = pkce_challenge(&verifier);

        let mut authorize_url = self.authorization.clone();
        {
            let mut query = authorize_url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("state", &state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
            if !self.scopes.is_empty() {
                query.append_pair("scope", &self.scopes.join(" "));
            }
        }
        Ok(PendingFlow {
            endpoints: self.clone(),
            listener,
            state,
            verifier,
            authorize_url,
        })
    }
}

/// A bound loopback listener and the pending authorization it belongs to.
pub struct PendingFlow {
    endpoints: OAuthEndpoints,
    listener: CallbackListener,
    state: String,
    verifier: String,
    authorize_url: Url,
}

impl PendingFlow {
    /// The URL the app opens in the owner's browser.
    pub fn authorize_url(&self) -> &Url {
        &self.authorize_url
    }

    /// The loopback address the browser is redirected to.
    pub fn callback_addr(&self) -> SocketAddr {
        self.listener.address()
    }

    /// Wait for the callback (up to [`OAUTH_TIMEOUT`]) and exchange the code.
    pub async fn complete(self) -> Result<TokenSet, OAuthError> {
        self.complete_with_timeout(OAUTH_TIMEOUT).await
    }

    /// [`Self::complete`] with an explicit wait budget (tests).
    pub async fn complete_with_timeout(self, timeout: Duration) -> Result<TokenSet, OAuthError> {
        self.complete_if(timeout, || true).await
    }

    /// [`Self::complete_with_timeout`], but `still_allowed` runs after the
    /// callback and before the code exchange: `false` ends the flow with
    /// [`OAuthError::NotConnected`] and no request to the token endpoint.
    pub async fn complete_if(
        self,
        timeout: Duration,
        still_allowed: impl FnOnce() -> bool,
    ) -> Result<TokenSet, OAuthError> {
        let redirect_uri = self.listener.redirect_uri();
        let code = self.listener.receive(&self.state, timeout).await?;
        if !still_allowed() {
            return Err(OAuthError::NotConnected);
        }
        exchange_code(&self.endpoints, &code, &self.verifier, &redirect_uri).await
    }
}

/// The one-shot loopback HTTP listener.
struct CallbackListener {
    listener: TcpListener,
    port: u16,
}

impl CallbackListener {
    async fn bind() -> Result<Self, OAuthError> {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let listener = socket.listen(LISTEN_BACKLOG)?;
        let address = listener.local_addr()?;
        if !address.ip().is_loopback() {
            return Err(OAuthError::InvalidResponse);
        }
        Ok(Self {
            listener,
            port: address.port(),
        })
    }

    fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port)
    }

    fn address(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }

    /// Accept exactly one valid callback. A wrong `state` is terminal: the
    /// listener closes and the flow fails. A malformed or unrelated request
    /// gets a `400` and the listener keeps waiting until the deadline.
    async fn receive(self, expected_state: &str, timeout: Duration) -> Result<String, OAuthError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let accepted = tokio::time::timeout_at(deadline, self.listener.accept()).await;
            let (mut stream, peer) = match accepted {
                Ok(Ok(pair)) => pair,
                Ok(Err(err)) => return Err(OAuthError::Io(err)),
                Err(_) => return Err(OAuthError::Timeout),
            };
            if peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
                write_page(&mut stream, false).await;
                continue;
            }
            let header_deadline = deadline.min(tokio::time::Instant::now() + HEADER_READ_TIMEOUT);
            let header =
                match tokio::time::timeout_at(header_deadline, read_header(&mut stream)).await {
                    Ok(Ok(header)) => header,
                    Ok(Err(_)) => {
                        write_page(&mut stream, false).await;
                        continue;
                    }
                    Err(_) => {
                        if tokio::time::Instant::now() >= deadline {
                            return Err(OAuthError::Timeout);
                        }
                        write_page(&mut stream, false).await;
                        continue;
                    }
                };
            match validate_request(&header, self.port, expected_state) {
                Ok(code) => {
                    write_page(&mut stream, true).await;
                    return Ok(code);
                }
                Err(OAuthError::StateMismatch) => {
                    write_page(&mut stream, false).await;
                    return Err(OAuthError::StateMismatch);
                }
                Err(_) => {
                    write_page(&mut stream, false).await;
                    continue;
                }
            }
        }
    }
}

async fn read_header(stream: &mut TcpStream) -> Result<Vec<u8>, OAuthError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(OAuthError::InvalidResponse);
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(OAuthError::InvalidResponse);
        }
    }
}

fn validate_request(header: &[u8], port: u16, expected_state: &str) -> Result<String, OAuthError> {
    let text = std::str::from_utf8(header).map_err(|_| OAuthError::InvalidResponse)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or(OAuthError::InvalidResponse)?;
    let mut parts = request.split(' ');
    let method = parts.next().ok_or(OAuthError::InvalidResponse)?;
    let target = parts.next().ok_or(OAuthError::InvalidResponse)?;
    let version = parts.next().ok_or(OAuthError::InvalidResponse)?;
    if method != "GET"
        || version != "HTTP/1.1"
        || parts.next().is_some()
        || !target.starts_with('/')
    {
        return Err(OAuthError::InvalidResponse);
    }

    let expected_host = format!("127.0.0.1:{port}");
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(OAuthError::InvalidResponse);
        }
        let (name, value) = line.split_once(':').ok_or(OAuthError::InvalidResponse)?;
        if name.eq_ignore_ascii_case("host") && host.replace(value.trim()).is_some() {
            return Err(OAuthError::InvalidResponse);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(OAuthError::InvalidResponse);
        }
        if name.eq_ignore_ascii_case("content-length") && value.trim() != "0" {
            return Err(OAuthError::InvalidResponse);
        }
    }
    if host != Some(expected_host.as_str()) {
        return Err(OAuthError::InvalidResponse);
    }

    let parsed = Url::parse(&format!("http://{expected_host}{target}"))
        .map_err(|_| OAuthError::InvalidResponse)?;
    if parsed.path() != CALLBACK_PATH || parsed.fragment().is_some() {
        return Err(OAuthError::InvalidResponse);
    }
    let mut state = None;
    let mut code = None;
    let mut rejection = None;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "state" => {
                if state.replace(value.into_owned()).is_some() {
                    return Err(OAuthError::InvalidResponse);
                }
            }
            "code" => {
                if code.replace(value.into_owned()).is_some() {
                    return Err(OAuthError::InvalidResponse);
                }
            }
            "error" if rejection.is_some() => return Err(OAuthError::InvalidResponse),
            "error" => rejection = Some(value.into_owned()),
            _ => {}
        }
    }
    let state = state.ok_or(OAuthError::InvalidResponse)?;
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(OAuthError::StateMismatch);
    }
    if let Some(error) = rejection {
        if error.is_empty() || code.is_some() {
            return Err(OAuthError::InvalidResponse);
        }
        return Err(OAuthError::ProviderRefused);
    }
    let code = code.ok_or(OAuthError::InvalidResponse)?;
    if code.is_empty() || code.len() > MAX_CODE_BYTES {
        return Err(OAuthError::InvalidResponse);
    }
    Ok(code)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

async fn write_page(stream: &mut TcpStream, success: bool) {
    let (status, text) = if success {
        ("200 OK", "Connected. You can close this tab.")
    } else {
        ("400 Bad Request", "This sign-in could not be completed.")
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Auxesis</title><p>{text}</p></html>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(RESPONSE_WRITE_TIMEOUT, async {
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;
}

/// Exchange an authorization code for tokens at the pinned token endpoint.
async fn exchange_code(
    endpoints: &OAuthEndpoints,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenSet, OAuthError> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", endpoints.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = endpoints.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    token_request(endpoints, &form, None).await
}

/// Renew an access token from a stored refresh token.
pub async fn refresh_tokens(
    endpoints: &OAuthEndpoints,
    current: &TokenSet,
) -> Result<TokenSet, OAuthError> {
    let refresh = current
        .refresh_token
        .as_deref()
        .ok_or(OAuthError::NotConnected)?;
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", endpoints.client_id.as_str()),
    ];
    if let Some(secret) = endpoints.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    token_request(endpoints, &form, Some(refresh)).await
}

/// A non-expired access token, refreshing and re-saving when the stored one is
/// within [`EXPIRY_SKEW_SECS`] of expiry.
pub async fn access_token(
    endpoints: &OAuthEndpoints,
    store: &dyn TokenStore,
    extension: &str,
) -> Result<String, OAuthError> {
    let current = store.load(extension)?.ok_or(OAuthError::NotConnected)?;
    if !current.is_expired(now_unix(), EXPIRY_SKEW_SECS) {
        return Ok(current.access_token().to_owned());
    }
    let refreshed = refresh_tokens(endpoints, &current).await?;
    store.save(extension, &refreshed)?;
    Ok(refreshed.access_token().to_owned())
}

async fn send_token_request(
    endpoints: &OAuthEndpoints,
    form: &[(&str, &str)],
) -> Result<reqwest::Response, OAuthError> {
    let http = token_client(endpoints).await?;
    let request = http
        .post(endpoints.token.clone())
        .map_err(|_| OAuthError::Network)?;
    request
        .form(form)
        .send()
        .await
        .map_err(|_| OAuthError::Network)
}

/// Bound the complete exchange, including receiving and decoding the reply.
async fn token_request(
    endpoints: &OAuthEndpoints,
    form: &[(&str, &str)],
    previous_refresh: Option<&str>,
) -> Result<TokenSet, OAuthError> {
    tokio::time::timeout(TOKEN_TIMEOUT, async {
        let response = send_token_request(endpoints, form).await?;
        parse_token_reply(response, previous_refresh).await
    })
    .await
    .map_err(|_| OAuthError::Network)?
}

async fn token_client(endpoints: &OAuthEndpoints) -> Result<PinnedHttp, OAuthError> {
    let policy = if endpoints.allow_loopback {
        loopback_policy()?
    } else {
        AddressPolicy::PublicOnly
    };
    pinned_client(policy, &endpoints.token)
        .await
        .map_err(|_| OAuthError::Network)
}

/// The loopback policy exists only in test builds; a production build has no
/// variant it could construct.
fn loopback_policy() -> Result<AddressPolicy, OAuthError> {
    #[cfg(any(test, feature = "testing"))]
    {
        Ok(AddressPolicy::AllowLoopback)
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        Err(OAuthError::InsecureEndpoint)
    }
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// Read one token reply. The body is consumed and never logged.
async fn parse_token_reply(
    response: reqwest::Response,
    previous_refresh: Option<&str>,
) -> Result<TokenSet, OAuthError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_TOKEN_RESPONSE_BYTES as u64)
    {
        return Err(OAuthError::InvalidResponse);
    }
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(|_| OAuthError::Network)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_TOKEN_RESPONSE_BYTES {
            return Err(OAuthError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(OAuthError::ProviderRefused);
    }
    let reply: TokenReply =
        serde_json::from_slice(&bytes).map_err(|_| OAuthError::InvalidResponse)?;
    let access_token = reply
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or(OAuthError::InvalidResponse)?;
    let refresh_token = reply
        .refresh_token
        .filter(|token| !token.is_empty())
        .or_else(|| previous_refresh.map(str::to_owned));
    let expires_at = reply.expires_in.map(|secs| now_unix().saturating_add(secs));
    let scopes = reply
        .scope
        .map(|scope| scope.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    Ok(TokenSet {
        access_token,
        refresh_token,
        expires_at,
        scopes,
        token_type: reply.token_type.unwrap_or_default(),
    })
}

fn random_b64url(length: usize) -> Result<String, OAuthError> {
    let mut bytes = vec![0u8; length];
    // The OS CSPRNG, the same `/dev/urandom` source the daemon's API token
    // uses. It exists on every platform `auxd` targets, so no RNG crate is
    // pulled in for 32 bytes.
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
        .map_err(|_| OAuthError::Random)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// RFC 7636 S256: `BASE64URL(SHA256(ASCII(verifier)))`.
fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ACCESS_CANARY: &str = "access-token-canary-7f3a";
    const REFRESH_CANARY: &str = "refresh-token-canary-2b9c";

    fn loopback_config(server: &MockServer) -> OAuthConfig {
        OAuthConfig {
            authorization_url: format!("{}/authorize", server.uri()),
            token_url: format!("{}/token", server.uri()),
            client_id: "test-client".to_owned(),
            scopes: vec!["read".to_owned()],
            client_secret_env: None,
        }
    }

    fn query_value(url: &Url, key: &str) -> String {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    }

    async fn hit_callback(addr: SocketAddr, state: &str, code: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(addr).await?;
        let request = format!(
            "GET {CALLBACK_PATH}?state={state}&code={code} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            addr.port()
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    }

    #[tokio::test]
    async fn a_full_pkce_flow_connects_and_stores_the_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code_verifier="))
            .and(body_string_contains("code=the-code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": ACCESS_CANARY,
                "refresh_token": REFRESH_CANARY,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read write",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let endpoints = oauth_endpoints(&loopback_config(&server), "demo", home, true).unwrap();
        let flow = endpoints.begin().await.unwrap();
        let addr = flow.callback_addr();
        let state = query_value(flow.authorize_url(), "state");
        assert!(!state.is_empty());
        assert_eq!(
            query_value(flow.authorize_url(), "code_challenge_method"),
            "S256"
        );
        assert!(!query_value(flow.authorize_url(), "code_challenge").is_empty());

        // Drive the callback and the listener's accept loop together: the
        // listener only answers once `complete` is polling it.
        let (response, tokens) = tokio::join!(
            hit_callback(addr, &state, "the-code"),
            flow.complete_with_timeout(Duration::from_secs(5)),
        );
        let response = response.unwrap();
        assert!(response.contains("200 OK"), "{response}");
        let tokens = tokens.unwrap();
        assert_eq!(tokens.access_token(), ACCESS_CANARY);
        assert_eq!(tokens.refresh_token(), Some(REFRESH_CANARY));
        assert_eq!(tokens.scopes(), ["read", "write"]);

        let store = FileTokenStore::new(home);
        store.save("demo", &tokens).unwrap();
        let stored = store.load("demo").unwrap().unwrap();
        assert_eq!(stored.access_token(), ACCESS_CANARY);
        assert!(
            !format!("{stored:?}").contains(ACCESS_CANARY),
            "Debug must redact the access token"
        );
        assert!(
            !format!("{stored:?}").contains(REFRESH_CANARY),
            "Debug must redact the refresh token"
        );
    }

    #[tokio::test]
    async fn an_oversized_token_reply_is_rejected_before_deserialization() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"access_token":"{}"}}"#,
                "x".repeat(MAX_TOKEN_RESPONSE_BYTES)
            )))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let endpoints =
            oauth_endpoints(&loopback_config(&server), "demo", dir.path(), true).unwrap();
        let result = token_request(&endpoints, &[("grant_type", "authorization_code")], None).await;
        assert!(matches!(result, Err(OAuthError::InvalidResponse)));
    }

    #[tokio::test]
    async fn a_state_mismatch_is_refused_and_nothing_is_exchanged() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": ACCESS_CANARY,
            })))
            .expect(0)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let endpoints =
            oauth_endpoints(&loopback_config(&server), "demo", dir.path(), true).unwrap();
        let flow = endpoints.begin().await.unwrap();
        let addr = flow.callback_addr();

        let (response, err) = tokio::join!(
            hit_callback(addr, "wrong-state", "the-code"),
            flow.complete_with_timeout(Duration::from_secs(5)),
        );
        let response = response.unwrap();
        assert!(response.contains("400"), "{response}");
        assert!(matches!(err, Err(OAuthError::StateMismatch)), "{err:?}");
    }

    #[tokio::test]
    async fn a_replayed_authorization_code_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": ACCESS_CANARY,
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let endpoints =
            oauth_endpoints(&loopback_config(&server), "demo", dir.path(), true).unwrap();
        let flow = endpoints.begin().await.unwrap();
        let addr = flow.callback_addr();
        let state = query_value(flow.authorize_url(), "state");

        let (response, result) = tokio::join!(
            hit_callback(addr, &state, "the-code"),
            flow.complete_with_timeout(Duration::from_secs(5)),
        );
        assert!(response.unwrap().contains("200 OK"));
        result.unwrap();

        // The one-shot listener is gone: the same code cannot be replayed.
        let replay = hit_callback(addr, &state, "the-code").await;
        assert!(
            !replay
                .as_deref()
                .map(|response| response.contains("200 OK"))
                .unwrap_or(false),
            "a replayed code must never be answered"
        );
    }

    #[tokio::test]
    async fn the_timeout_closes_the_listener() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let endpoints =
            oauth_endpoints(&loopback_config(&server), "demo", dir.path(), true).unwrap();
        let flow = endpoints.begin().await.unwrap();
        let addr = flow.callback_addr();

        let started = tokio::time::Instant::now();
        let err = flow
            .complete_with_timeout(Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(matches!(err, OAuthError::Timeout), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(10));

        // The listener closed on timeout: a late callback cannot be served.
        let late = hit_callback(addr, "state", "code").await;
        assert!(
            !late
                .as_deref()
                .map(|response| response.contains("200 OK"))
                .unwrap_or(false),
            "the listener must be closed after the timeout"
        );
    }

    /// RFC 7636 Appendix B; it also pins the challenge across a sha2 upgrade.
    #[test]
    fn pkce_rfc_7636_appendix_b_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn an_http_token_endpoint_is_refused_outside_the_test_seam() {
        let dir = tempfile::tempdir().unwrap();
        let loopback = OAuthConfig {
            authorization_url: "https://auth.example/authorize".to_owned(),
            token_url: "http://127.0.0.1:8123/token".to_owned(),
            client_id: "test-client".to_owned(),
            scopes: Vec::new(),
            client_secret_env: None,
        };
        assert!(matches!(
            oauth_endpoints(&loopback, "demo", dir.path(), false),
            Err(OAuthError::InsecureEndpoint)
        ));
        // The test seam accepts it, and only it.
        assert!(oauth_endpoints(&loopback, "demo", dir.path(), true).is_ok());

        let public_http = OAuthConfig {
            authorization_url: "https://auth.example/authorize".to_owned(),
            token_url: "http://auth.example/token".to_owned(),
            ..loopback.clone()
        };
        assert!(matches!(
            oauth_endpoints(&public_http, "demo", dir.path(), true),
            Err(OAuthError::InsecureEndpoint)
        ));

        let plaintext_authorize = OAuthConfig {
            authorization_url: "http://auth.example/authorize".to_owned(),
            token_url: "https://auth.example/token".to_owned(),
            ..loopback
        };
        assert!(matches!(
            oauth_endpoints(&plaintext_authorize, "demo", dir.path(), false),
            Err(OAuthError::InsecureEndpoint)
        ));
    }

    #[test]
    fn an_oauth_client_secret_outside_the_extension_namespace_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let foreign = OAuthConfig {
            authorization_url: "https://auth.example/authorize".to_owned(),
            token_url: "https://auth.example/token".to_owned(),
            client_id: "test-client".to_owned(),
            scopes: Vec::new(),
            // `demo` may never read a provider key or another extension's key.
            client_secret_env: Some("AUX_KEY_DEEPSEEK".to_owned()),
        };
        assert!(matches!(
            oauth_endpoints(&foreign, "demo", dir.path(), false),
            Err(OAuthError::ClientSecretRefused)
        ));
        let own = OAuthConfig {
            client_secret_env: Some("EXT_DEMO__CLIENT_SECRET".to_owned()),
            ..foreign
        };
        assert!(oauth_endpoints(&own, "demo", dir.path(), false).is_ok());
        assert!(matches!(
            oauth_endpoints(&own, "other", dir.path(), false),
            Err(OAuthError::ClientSecretRefused)
        ));
    }

    #[tokio::test]
    async fn a_refresh_token_renews_the_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=refresh-canary"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "fresh-access-canary",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let endpoints = oauth_endpoints(&loopback_config(&server), "demo", home, true).unwrap();
        let store = FileTokenStore::new(home);
        let expired = TokenSet {
            access_token: "old-canary".to_owned(),
            refresh_token: Some("refresh-canary".to_owned()),
            expires_at: Some(1),
            scopes: vec!["read".to_owned()],
            token_type: "Bearer".to_owned(),
        };
        store.save("demo", &expired).unwrap();

        let value = access_token(&endpoints, &store, "demo").await.unwrap();
        assert_eq!(value, "fresh-access-canary");
        let stored = store.load("demo").unwrap().unwrap();
        assert_eq!(stored.access_token(), "fresh-access-canary");
        assert_eq!(
            stored.refresh_token(),
            Some("refresh-canary"),
            "the old refresh token is kept when the provider does not rotate it"
        );
    }

    #[tokio::test]
    async fn the_token_never_reaches_a_log() {
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": ACCESS_CANARY,
                "refresh_token": REFRESH_CANARY,
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let endpoints =
            oauth_endpoints(&loopback_config(&server), "demo", dir.path(), true).unwrap();
        let flow = endpoints.begin().await.unwrap();
        let addr = flow.callback_addr();
        let state = query_value(flow.authorize_url(), "state");
        let (response, result) = tokio::join!(
            hit_callback(addr, &state, "the-code"),
            flow.complete_with_timeout(Duration::from_secs(5)),
        );
        assert!(response.unwrap().contains("200 OK"));
        result.unwrap();
        drop(guard);

        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(
            !logs.contains(ACCESS_CANARY),
            "an access token leaked to a log"
        );
        assert!(
            !logs.contains(REFRESH_CANARY),
            "a refresh token leaked to a log"
        );
    }
}
