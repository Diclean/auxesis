//! Native Google OAuth support for Auxesis.
//!
//! This crate owns the installed-app authorization code flow and the local
//! refresh grant. It does not open a browser itself: callers explicitly pass
//! a [`UrlOpener`] to [`connect_interactive`].

pub mod browser;
pub mod calendar;
mod callback;
pub mod gmail;
mod grant;
pub mod tools;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use grant::{GrantStore, StoredGrant};
use kernel_core::Lang;
use reqwest::{Client, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(test))]
const AUTH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const EXPIRY_SKEW: Duration = Duration::from_secs(60);

/// The only Google API scopes supported by this connector.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Scope {
    #[serde(rename = "gmail_readonly")]
    GmailReadonly,
    /// The narrowest Gmail scope that permits `drafts.create` (and nothing
    /// more): it can compose drafts but can never send mail.
    #[serde(rename = "gmail_compose")]
    GmailCompose,
    #[serde(rename = "gmail_send")]
    GmailSend,
    #[serde(rename = "calendar_events_readonly")]
    CalendarEventsReadonly,
    #[serde(rename = "calendar_events")]
    CalendarEvents,
}

impl Scope {
    /// All supported scopes, in the connector's stable order.
    pub const ALL: [Self; 5] = [
        Self::GmailReadonly,
        Self::GmailCompose,
        Self::GmailSend,
        Self::CalendarEventsReadonly,
        Self::CalendarEvents,
    ];

    /// Google OAuth scope string for this permission.
    pub const fn as_google_scope(self) -> &'static str {
        match self {
            Self::GmailReadonly => "https://www.googleapis.com/auth/gmail.readonly",
            Self::GmailCompose => "https://www.googleapis.com/auth/gmail.compose",
            Self::GmailSend => "https://www.googleapis.com/auth/gmail.send",
            Self::CalendarEventsReadonly => {
                "https://www.googleapis.com/auth/calendar.events.readonly"
            }
            Self::CalendarEvents => "https://www.googleapis.com/auth/calendar.events",
        }
    }
}

/// The permissions the five native read tools need, in stable order.
///
/// Gmail and Calendar reads only: the connector never asks for a write
/// permission to answer a read, so a read-only grant can never mutate.
pub const READ_SCOPES: [Scope; 2] = [Scope::GmailReadonly, Scope::CalendarEventsReadonly];

/// The permissions the native Google tools need to connect, in stable order.
///
/// All reads plus Gmail drafts: [`Scope::GmailCompose`] is the narrowest
/// scope Google offers that permits `drafts.create`, and it explicitly does
/// **not** permit `messages.send`. [`Scope::GmailSend`] is deliberately absent
/// from this list and from every request the connector makes: an Auxesis
/// grant can never send mail, so even a bug in the draft tool cannot turn
/// into a send.
///
/// A token granted before this scope existed lacks `gmail.compose`; the
/// daemon reports `insufficient_scope`/`reconnect_needed` and the owner must
/// re-run consent (`aux connect google`) to add it.
pub const CONNECT_SCOPES: [Scope; 3] = [
    Scope::GmailReadonly,
    Scope::GmailCompose,
    Scope::CalendarEventsReadonly,
];

/// The write permissions the two skill-only tools need: `gmail.send` to send
/// mail and `calendar.events` to create events.
///
/// Deliberately separate from [`CONNECT_SCOPES`]: connecting **never**
/// requests a send or event-write permission. They are requested only by
/// [`MacConnection::enable_sending_scopes`], an explicit owner action.
pub const SEND_SCOPES: [Scope; 2] = [Scope::GmailSend, Scope::CalendarEvents];

/// Everything [`MacConnection::enable_sending_scopes`] asks for: the connect
/// permissions plus the skill-only writes.
///
/// Enabling sending is additive, never a narrower re-consent: the request and
/// the stored grant keep every read and draft permission. Requesting only
/// [`SEND_SCOPES`] would overwrite the stored grant with a subset and break
/// reads.
pub const SEND_WITH_CONNECT_SCOPES: [Scope; 5] = [
    Scope::GmailReadonly,
    Scope::GmailCompose,
    Scope::CalendarEventsReadonly,
    Scope::GmailSend,
    Scope::CalendarEvents,
];

/// Errors from Google authorization and local grant handling.
///
/// Variants intentionally carry no provider response, URL, code, or token.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("AUXESIS_GOOGLE_CLIENT_ID and AUXESIS_GOOGLE_CLIENT_SECRET must be configured")]
    ClientConfiguration,
    #[error("Google authentication requires at least one supported permission")]
    InvalidScopes,
    #[error("Google consent was rejected")]
    ConsentRejected,
    #[error("Reconnect to Google")]
    ReauthRequired,
    #[error("Google did not return durable access; retry and accept the requested access")]
    DurableAccessMissing,
    #[error("Google authentication timed out")]
    Timeout,
    #[error("Google authorization callback was invalid")]
    Callback,
    #[error("Google request failed")]
    Network,
    #[error("Google returned an invalid response")]
    InvalidResponse,
    #[error("Google credentials could not be read or stored safely")]
    Storage,
    #[error("Could not create the Google HTTP client")]
    HttpClient,
}

impl AuthError {
    /// Return user-facing copy in the selected language. `Display` remains
    /// an English fallback for logs and legacy callers.
    pub fn localized_message(&self, lang: Lang) -> String {
        match self {
            Self::ReauthRequired => {
                kernel_core::i18n::text(kernel_core::Message::GoogleReauthRequired, lang)
                    .to_string()
            }
            Self::DurableAccessMissing => {
                kernel_core::i18n::text(kernel_core::Message::GoogleDurableAccessMissing, lang)
                    .to_string()
            }
            _ => self.to_string(),
        }
    }
}

/// A secret string that never formats its contents and clears its allocation
/// on drop.
pub(crate) struct SecretString(String);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// A short-lived Google access token. Its contents are only available through
/// [`AccessToken::as_str`] for the request that needs it.
pub struct AccessToken(SecretString);

impl AccessToken {
    /// Borrow the bearer token for an outbound API request.
    pub fn as_str(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccessToken([REDACTED])")
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// A caller-controlled handoff for opening the authorization URL.
///
/// The daemon has no default implementation and cannot launch a browser by
/// accident. A later interactive application can provide its system opener.
#[async_trait::async_trait]
pub trait UrlOpener: Send + Sync {
    /// Open the Google authorization URL in the user's default browser.
    async fn open_url(&self, url: &Url) -> Result<(), UrlOpenError>;
}

/// A redacted browser-opening failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("Could not open the Google authorization page")]
pub struct UrlOpenError;

/// Authentication methods shared by future Gmail and Calendar tools.
#[async_trait::async_trait]
pub trait GoogleAuth: Send + Sync {
    /// Return a cached or freshly refreshed access token with these scopes.
    async fn access_token(&self, scopes: &[Scope]) -> Result<AccessToken, AuthError>;

    /// Revoke the stored refresh token and remove its local grant file.
    async fn disconnect(&self) -> Result<(), AuthError>;
}

/// A configured native Google OAuth client for one account.
pub struct GoogleClient {
    client_id: String,
    client_secret: SecretString,
    login_hint: String,
    endpoints: OAuthEndpoints,
    http: Client,
    grant_store: GrantStore,
    cache: Mutex<Option<CachedAccess>>,
}

struct CachedAccess {
    value: SecretString,
    expires_at: Instant,
    scopes: Vec<Scope>,
}

#[derive(Clone)]
struct OAuthEndpoints {
    authorization: Url,
    token: Url,
    revoke: Url,
}

impl OAuthEndpoints {
    fn google() -> Self {
        Self {
            authorization: Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .expect("static URL"),
            token: Url::parse("https://oauth2.googleapis.com/token").expect("static URL"),
            revoke: Url::parse("https://oauth2.googleapis.com/revoke").expect("static URL"),
        }
    }

    fn validate(&self) -> Result<(), AuthError> {
        #[cfg(not(test))]
        let valid = self.authorization.scheme() == "https"
            && self.authorization.host_str() == Some("accounts.google.com")
            && self.token.scheme() == "https"
            && self.token.host_str() == Some("oauth2.googleapis.com")
            && self.revoke.scheme() == "https"
            && self.revoke.host_str() == Some("oauth2.googleapis.com");
        #[cfg(test)]
        let valid = (self.authorization.scheme() == "https"
            && self.authorization.host_str() == Some("accounts.google.com")
            && self.token.scheme() == "https"
            && self.token.host_str() == Some("oauth2.googleapis.com")
            && self.revoke.scheme() == "https"
            && self.revoke.host_str() == Some("oauth2.googleapis.com"))
            || [&self.authorization, &self.token, &self.revoke]
                .iter()
                .all(|url| {
                    url.scheme() == "http"
                        && matches!(url.host_str(), Some("127.0.0.1") | Some("localhost"))
                });
        if valid {
            Ok(())
        } else {
            Err(AuthError::InvalidResponse)
        }
    }

    #[cfg(test)]
    fn test(authorization: Url, token: Url, revoke: Url) -> Self {
        Self {
            authorization,
            token,
            revoke,
        }
    }
}

#[derive(Clone)]
struct AppCredentials {
    client_id: String,
    client_secret: SecretString,
}

impl GoogleClient {
    /// Configure a client for an account that has already completed consent.
    pub fn for_account_email(account_email: &str) -> Result<Self, AuthError> {
        let credentials = resolve_app_credentials()?;
        Self::build(
            account_email,
            credentials,
            OAuthEndpoints::google(),
            kernel_core::auxesis_home(),
        )
    }

    fn build(
        account_email: &str,
        credentials: AppCredentials,
        endpoints: OAuthEndpoints,
        home: std::path::PathBuf,
    ) -> Result<Self, AuthError> {
        let account_hash = account_email_hash(account_email)?;
        Self::build_with_key(
            account_hash,
            account_email.trim().to_string(),
            credentials,
            endpoints,
            home,
        )
    }

    /// Build from an explicit storage key (no email involved).
    fn build_with_key(
        account_hash: String,
        login_hint: String,
        credentials: AppCredentials,
        endpoints: OAuthEndpoints,
        home: std::path::PathBuf,
    ) -> Result<Self, AuthError> {
        endpoints.validate()?;
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| AuthError::HttpClient)?;
        Ok(Self {
            grant_store: GrantStore::new(home, account_hash),
            client_id: credentials.client_id,
            client_secret: credentials.client_secret,
            login_hint,
            endpoints,
            http,
            cache: Mutex::new(None),
        })
    }

    async fn authorize(
        &self,
        opener: &dyn UrlOpener,
        scopes: &[Scope],
        lang: Lang,
    ) -> Result<(), AuthError> {
        let scopes = normalise_scopes(scopes)?;
        let callback = callback::CallbackListener::bind_for_lang(lang).await?;
        let redirect_uri = callback.redirect_uri().to_string();
        let state = random_b64url(16)?;
        let verifier = SecretString::new(random_b64url(32)?);
        let challenge = pkce_challenge(verifier.expose());
        let flow_deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
        let mut authorization_url = self.endpoints.authorization.clone();
        {
            let scope_string = scopes
                .iter()
                .map(|scope| scope.as_google_scope())
                .collect::<Vec<_>>()
                .join(" ");
            let mut query = authorization_url.query_pairs_mut();
            query
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", &scope_string);
            // The Mac-wide connection needs no address: Google then asks for
            // the account itself instead of pre-filling an address we do not
            // have and never store.
            if !self.login_hint_email().is_empty() {
                query.append_pair("login_hint", self.login_hint_email());
            }
            query
                .append_pair("state", &state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("access_type", "offline")
                .append_pair("prompt", "consent");
        }
        tokio::time::timeout(
            flow_deadline.saturating_duration_since(tokio::time::Instant::now()),
            opener.open_url(&authorization_url),
        )
        .await
        .map_err(|_| AuthError::Timeout)?
        .map_err(|_| AuthError::Network)?;
        let remaining = flow_deadline.saturating_duration_since(tokio::time::Instant::now());
        let code = callback.receive(&state, remaining).await?;
        let reply = self
            .exchange_code(code.expose(), verifier.expose(), &redirect_uri, &scopes)
            .await?;
        // A fresh consent must return its own durable grant. Without it we
        // cannot know which account the owner just approved, so falling back to
        // a stored token would silently reconnect the previous account. Fail
        // instead, and write nothing: any existing grant stays untouched until a
        // new exchange has actually succeeded.
        let refresh = reply.refresh_token.ok_or(AuthError::DurableAccessMissing)?;
        if !scopes_are_included(&reply.scopes, &scopes) {
            return Err(AuthError::InvalidResponse);
        }
        // Persist only what this call asked for. Google can still hold an older
        // write grant, and storing everything it returns would make a plain
        // `connect` look like the owner enabled sending.
        let granted: Vec<Scope> = reply
            .scopes
            .iter()
            .copied()
            .filter(|scope| scopes.contains(scope))
            .collect();
        self.grant_store.save(&refresh, &granted)?;
        *self.cache.lock().await = Some(CachedAccess {
            value: reply.access_token,
            expires_at: Instant::now() + Duration::from_secs(reply.expires_in),
            scopes: granted,
        });
        Ok(())
    }

    async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        scopes: &[Scope],
    ) -> Result<TokenReply, AuthError> {
        let response = self
            .http
            .post(self.endpoints.token.clone())
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.expose()),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?;
        parse_token_reply(response, None, scopes).await
    }

    #[cfg(test)]
    fn for_test(account_email: &str, home: std::path::PathBuf, endpoints: OAuthEndpoints) -> Self {
        Self::build(
            account_email,
            AppCredentials {
                client_id: "desktop-client-id".to_string(),
                client_secret: SecretString::new("client-secret-canary".to_string()),
            },
            endpoints,
            home,
        )
        .expect("test client")
    }

    #[cfg(test)]
    fn grant_store(&self) -> &GrantStore {
        &self.grant_store
    }

    fn login_hint_email(&self) -> &str {
        &self.login_hint
    }
}

#[async_trait::async_trait]
impl GoogleAuth for GoogleClient {
    async fn access_token(&self, scopes: &[Scope]) -> Result<AccessToken, AuthError> {
        let scopes = normalise_scopes(scopes)?;
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if cached.expires_at > Instant::now() + EXPIRY_SKEW
                && scopes_are_included(&cached.scopes, &scopes)
            {
                return Ok(AccessToken(cached.value.clone()));
            }
        }

        let mut grant = self.grant_store.load()?.ok_or(AuthError::ReauthRequired)?;
        if !scopes_are_included(&grant.scopes, &scopes) {
            return Err(AuthError::ReauthRequired);
        }
        let response = self
            .http
            .post(self.endpoints.token.clone())
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", grant.refresh.expose()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.expose()),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?;
        let reply = match parse_token_reply(response, Some(&grant), &scopes).await {
            Ok(reply) => reply,
            Err(AuthError::ReauthRequired) => {
                let _ = self.grant_store.remove();
                *cache = None;
                return Err(AuthError::ReauthRequired);
            }
            Err(error) => return Err(error),
        };
        if let Some(rotated) = reply.refresh_token {
            grant.refresh = rotated;
            self.grant_store.save(&grant.refresh, &grant.scopes)?;
        }
        let value = reply.access_token;
        let access = AccessToken(value.clone());
        *cache = Some(CachedAccess {
            value,
            expires_at: Instant::now() + Duration::from_secs(reply.expires_in),
            scopes: grant.scopes,
        });
        Ok(access)
    }

    async fn disconnect(&self) -> Result<(), AuthError> {
        let grant_result = self.grant_store.load();
        let revoke_result = match grant_result {
            Ok(Some(grant)) => self.revoke(grant.refresh.expose()).await,
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        let delete_result = self.grant_store.remove();
        *self.cache.lock().await = None;
        match (revoke_result, delete_result) {
            (_, Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl GoogleClient {
    async fn revoke(&self, refresh_token: &str) -> Result<(), AuthError> {
        revoke_token(&self.http, &self.endpoints.revoke, refresh_token).await
    }
}

/// Run the installed-app consent flow and store the resulting refresh grant.
///
/// `account_email` is used only as a SHA-256 storage key and as Google's
/// `login_hint`; it is never written to the grant file. The redirect listener
/// binds only to `127.0.0.1` and accepts one request.
pub async fn connect_interactive(
    opener: &dyn UrlOpener,
    account_email: &str,
    scopes: &[Scope],
) -> Result<GoogleClient, AuthError> {
    let credentials = resolve_app_credentials()?;
    let client = GoogleClient::build(
        account_email,
        credentials,
        OAuthEndpoints::google(),
        kernel_core::auxesis_home(),
    )?;
    client.authorize(opener, scopes, Lang::En).await?;
    Ok(client)
}

/// The single, Mac-wide Google connection rooted at one Auxesis home.
///
/// One connection keyed by the configured OAuth client id — **no email
/// address is needed, stored or echoed**. It is the shape the CLI and the app
/// share: the owner runs one command or clicks one button and this Mac is
/// connected.
pub struct MacConnection {
    home: std::path::PathBuf,
    endpoints: OAuthEndpoints,
    /// Explicit credentials for the crate's own tests (the fake server); the
    /// production constructor always leaves this `None` and resolves the
    /// client id/secret from the process env or `home/.env`.
    credentials: Option<AppCredentials>,
}

impl MacConnection {
    /// The connection rooted at `home`.
    pub fn at(home: impl Into<std::path::PathBuf>) -> Self {
        Self {
            home: home.into(),
            endpoints: OAuthEndpoints::google(),
            credentials: None,
        }
    }

    #[cfg(test)]
    fn for_test(
        home: std::path::PathBuf,
        client_id: &str,
        client_secret: &str,
        endpoints: OAuthEndpoints,
    ) -> Self {
        Self {
            home,
            endpoints,
            credentials: Some(AppCredentials {
                client_id: client_id.to_string(),
                client_secret: SecretString::new(client_secret.to_string()),
            }),
        }
    }

    fn app_credentials(&self) -> Result<AppCredentials, AuthError> {
        match &self.credentials {
            Some(credentials) => Ok(credentials.clone()),
            None => resolve_app_credentials_at(&self.home),
        }
    }

    /// True when this home has a stored grant for its configured client id.
    ///
    /// Honest per call and cheap: it checks the grant file's name and type,
    /// never its contents, so a status read needs no credential and can never
    /// leak one.
    pub fn connected(&self) -> bool {
        let Ok(credentials) = self.app_credentials() else {
            return false;
        };
        let key = mac_account_key(&credentials.client_id);
        grant_exists(&self.home, &key)
    }

    /// True when a stored grant exists but is missing one or more of the
    /// permissions Auxesis currently requests. The answer contains no account
    /// or credential data and is derived from the local grant only.
    pub fn needs_reconsent(&self) -> bool {
        let Ok(credentials) = self.app_credentials() else {
            return false;
        };
        let key = mac_account_key(&credentials.client_id);
        let store = GrantStore::new(self.home.clone(), key);
        match store.load() {
            Ok(Some(grant)) => !scopes_are_included(&grant.scopes, &CONNECT_SCOPES),
            Ok(None) | Err(_) => false,
        }
    }

    /// The refresh-capable client for this home's connection.
    pub fn client(&self) -> Result<GoogleClient, AuthError> {
        let credentials = self.app_credentials()?;
        let key = mac_account_key(&credentials.client_id);
        GoogleClient::build_with_key(
            key,
            String::new(),
            credentials,
            self.endpoints.clone(),
            self.home.clone(),
        )
    }

    /// Run the installed-app consent flow and store the refresh grant.
    ///
    /// The browser opens only through the `opener` the caller names — the
    /// owner's command or click, never a background path.
    pub async fn connect(
        &self,
        opener: &dyn UrlOpener,
        scopes: &[Scope],
    ) -> Result<GoogleClient, AuthError> {
        self.connect_with_lang(opener, scopes, Lang::En).await
    }

    /// Run OAuth with the requesting UI language for the callback page.
    pub async fn connect_with_lang(
        &self,
        opener: &dyn UrlOpener,
        scopes: &[Scope],
        lang: Lang,
    ) -> Result<GoogleClient, AuthError> {
        let client = self.client()?;
        client.authorize(opener, scopes, lang).await?;
        Ok(client)
    }

    /// Run consent for the skill-only write scopes ([`SEND_SCOPES`]).
    ///
    /// This is the **only** path that ever requests `gmail.send` or
    /// `calendar.events`; [`Self::connect`] never does. It is an explicit
    /// owner action, not a side effect of connecting or of a skill run.
    ///
    /// The request is [`SEND_WITH_CONNECT_SCOPES`] (the union of
    /// [`CONNECT_SCOPES`] and [`SEND_SCOPES`]), and the union Google actually
    /// grants is what gets stored: enabling sending must not drop the reads.
    pub async fn enable_sending_scopes(
        &self,
        opener: &dyn UrlOpener,
    ) -> Result<GoogleClient, AuthError> {
        self.connect(opener, &SEND_WITH_CONNECT_SCOPES).await
    }

    /// Revoke the stored grant and delete it locally. A missing grant is a
    /// no-op; revocation needs no app credentials.
    pub async fn disconnect(&self) -> Result<(), AuthError> {
        let key = match self.app_credentials() {
            Ok(credentials) => mac_account_key(&credentials.client_id),
            // Without a client id we cannot name the file we wrote, so fall
            // back to the only grant this home holds rather than leave a live
            // authorization behind.
            Err(_) => {
                let Some(key) = stored_grant_key(&self.home) else {
                    return Ok(());
                };
                key
            }
        };
        self.endpoints.validate()?;
        let store = GrantStore::new(self.home.clone(), key);
        let Some(grant) = store.load()? else {
            // Nothing stored: nothing to revoke, nothing to delete.
            return Ok(());
        };
        let revoked = revoke_token(
            &self.http_client()?,
            &self.endpoints.revoke,
            grant.refresh.expose(),
        )
        .await;
        let deleted = store.remove();
        match (revoked, deleted) {
            (_, Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// The one HTTP policy this crate uses for Google: no redirects, bounded
    /// connect and request timeouts.
    fn http_client(&self) -> Result<Client, AuthError> {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| AuthError::HttpClient)
    }
}

/// The storage key of a Mac-wide connection: a SHA-256 of the OAuth client id,
/// so no email address is ever needed or kept.
pub fn mac_account_key(client_id: &str) -> String {
    sha256_hex(client_id.trim().to_lowercase().as_bytes())
}

/// True when `home` holds the grant file for `account_key`.
///
/// The name shape is checked (`google-auth-<64 lowercase hex>.json`), the entry
/// must be a regular file (never a symlink) and the contents are validated when
/// the grant is loaded — this is a cheap presence check for a status read.
pub fn grant_exists(home: &std::path::Path, account_key: &str) -> bool {
    if !valid_grant_key(account_key) {
        return false;
    }
    let path = home.join(format!("google-auth-{account_key}.json"));
    std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file())
}

/// The first stored grant key in `home`, whatever client id wrote it.
fn stored_grant_key(home: &std::path::Path) -> Option<String> {
    let entries = std::fs::read_dir(home).ok()?;
    let mut keys: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("google-auth-"))
                .and_then(|rest| rest.strip_suffix(".json"))
                .map(str::to_string)
        })
        .filter(|key| valid_grant_key(key))
        .collect();
    keys.sort_unstable();
    keys.into_iter().next()
}

fn valid_grant_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn revoke_token(http: &Client, revoke: &Url, refresh_token: &str) -> Result<(), AuthError> {
    // The revoke endpoint takes the token; no client secret is involved, so a
    // disconnect works even after the app credentials are gone.
    let response = http
        .post(revoke.clone())
        .form(&[("token", refresh_token)])
        .send()
        .await
        .map_err(|_| AuthError::Network)?;
    let status = response.status();
    let _ = limited_body(response).await?;
    if status.is_success() {
        Ok(())
    } else {
        Err(AuthError::Network)
    }
}
async fn parse_token_reply(
    response: Response,
    current: Option<&StoredGrant>,
    requested: &[Scope],
) -> Result<TokenReply, AuthError> {
    let status = response.status();
    let body = limited_body(response).await?;
    if !status.is_success() {
        #[derive(Deserialize)]
        struct ProviderError {
            error: Option<SecretString>,
        }
        let provider_error: ProviderError =
            serde_json::from_slice(&body[..]).map_err(|_| AuthError::Network)?;
        if provider_error.error.as_ref().map(SecretString::expose) == Some("invalid_grant") {
            return Err(AuthError::ReauthRequired);
        }
        return Err(AuthError::Network);
    }

    #[derive(Deserialize)]
    struct ProviderReply {
        access_token: Option<SecretString>,
        expires_in: Option<u64>,
        refresh_token: Option<SecretString>,
        scope: Option<String>,
    }
    let mut provider: ProviderReply =
        serde_json::from_slice(&body[..]).map_err(|_| AuthError::InvalidResponse)?;
    let access_token = provider
        .access_token
        .take()
        .filter(|value| !value.expose().is_empty() && value.expose().len() <= 16 * 1024)
        .ok_or(AuthError::InvalidResponse)?;
    let expires_in = provider
        .expires_in
        .filter(|value| *value > 0 && *value <= 31 * 24 * 60 * 60)
        .ok_or(AuthError::InvalidResponse)?;
    let scopes = match provider.scope.take() {
        Some(value) => parse_scope_reply(&value)?,
        None => current
            .map(|grant| grant.scopes.clone())
            .unwrap_or_else(|| requested.to_vec()),
    };
    if !requested.is_empty() && !scopes_are_included(&scopes, requested) {
        return Err(AuthError::InvalidResponse);
    }
    let refresh_token = provider
        .refresh_token
        .take()
        .filter(|value| !value.expose().is_empty() && value.expose().len() <= 8 * 1024);
    Ok(TokenReply {
        access_token,
        expires_in,
        refresh_token,
        scopes,
    })
}

struct TokenReply {
    access_token: SecretString,
    expires_in: u64,
    refresh_token: Option<SecretString>,
    scopes: Vec<Scope>,
}

async fn limited_body(mut response: Response) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(AuthError::InvalidResponse);
    }
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let chunk = response.chunk().await.map_err(|_| AuthError::Network)?;
        let Some(chunk) = chunk else { break };
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(AuthError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_scope_reply(scope_value: &str) -> Result<Vec<Scope>, AuthError> {
    let mut scopes = Vec::new();
    for value in scope_value.split_ascii_whitespace() {
        let scope = Scope::ALL
            .into_iter()
            .find(|scope| scope.as_google_scope() == value)
            .ok_or(AuthError::InvalidResponse)?;
        scopes.push(scope);
    }
    normalise_scopes(&scopes)
}

fn normalise_scopes(scopes: &[Scope]) -> Result<Vec<Scope>, AuthError> {
    if scopes.is_empty() {
        return Err(AuthError::InvalidScopes);
    }
    let mut result = scopes.to_vec();
    result.sort_unstable();
    result.dedup();
    Ok(result)
}

fn scopes_are_included(granted: &[Scope], requested: &[Scope]) -> bool {
    requested.iter().all(|scope| granted.contains(scope))
}

fn resolve_app_credentials() -> Result<AppCredentials, AuthError> {
    resolve_app_credentials_at(&kernel_core::auxesis_home())
}

fn resolve_app_credentials_at(home: &std::path::Path) -> Result<AppCredentials, AuthError> {
    // Use the same bounded `.env` source as provider keys, but intentionally
    // skip KeychainStore: this native connector has no Keychain dependency.
    let env_id = nonblank_env("AUXESIS_GOOGLE_CLIENT_ID");
    let env_secret = nonblank_env("AUXESIS_GOOGLE_CLIENT_SECRET");
    let dotenv = if env_id.is_some() && env_secret.is_some() {
        None
    } else {
        Some(
            aux_providers::key::AgentEnvStore::load(&home.join(".env"))
                .map_err(|_| AuthError::Storage)?,
        )
    };
    resolve_app_credentials_with(env_id, env_secret, dotenv.as_ref())
}

fn resolve_app_credentials_with(
    env_id: Option<String>,
    env_secret: Option<String>,
    dotenv: Option<&aux_providers::key::AgentEnvStore>,
) -> Result<AppCredentials, AuthError> {
    let file_value = |name: &str| {
        dotenv
            .and_then(|store| store.get_var(name))
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty())
    };
    let client_id = env_id
        .filter(|value| !value.trim().is_empty())
        .or_else(|| file_value("AUXESIS_GOOGLE_CLIENT_ID"))
        .ok_or(AuthError::ClientConfiguration)?;
    let client_secret = env_secret
        .filter(|value| !value.trim().is_empty())
        .or_else(|| file_value("AUXESIS_GOOGLE_CLIENT_SECRET"))
        .ok_or(AuthError::ClientConfiguration)?;
    Ok(AppCredentials {
        client_id,
        client_secret: SecretString::new(client_secret),
    })
}

fn nonblank_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn account_email_hash(account_email: &str) -> Result<String, AuthError> {
    let email = account_email.trim();
    if email.is_empty()
        || email.len() > 254
        || email
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || email.matches('@').count() != 1
    {
        return Err(AuthError::InvalidResponse);
    }
    Ok(sha256_hex(email.to_lowercase().as_bytes()))
}

/// Lowercase hex SHA-256, the only key derivation this crate uses.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn random_b64url(length: usize) -> Result<String, AuthError> {
    let mut bytes = vec![0u8; length];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Network)?;
    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    bytes.zeroize();
    Ok(encoded)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests;
