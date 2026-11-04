//! Per-account mailbox configuration — the `[connectors.mail]` table.
//!
//! The shape is the connector's contract: a list of [`MailAccount`]s plus one
//! [`MailLimits`] block. New fields are additive (`#[serde(default)]`) so an
//! older config keeps loading, and the **leaf** structs (`MailAccount`,
//! `ImapSettings`, `SmtpSettings`, `FolderMap`, `MailLimits`) carry
//! `deny_unknown_fields`: a typo — or a secret pasted at the wrong level —
//! must fail loudly, not silently fall back to a default endpoint.
//!
//! No password, token or credential of any kind lives here. The mailbox
//! secret is one `AUX_MAIL_<ACCOUNT_ID_UPPER>` entry (see
//! [`MailAccount::secret_key`]) resolved at call time; configuration only
//! names the account. Account ids are canonical lowercase slugs, and
//! [`MailConfig::load`] refuses a duplicate id or two ids that fold to the
//! same secret key, so credentials can never resolve under the wrong account.

use crate::limits::{
    Limits, DEFAULT_CALL_TIMEOUT_SECS, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_MAX_ATTACHMENT_BYTES,
    DEFAULT_MAX_CALL_ATTACHMENT_BYTES, DEFAULT_MAX_CALL_BYTES, DEFAULT_MAX_INFLIGHT_PER_AGENT,
    DEFAULT_MAX_MESSAGES, DEFAULT_MAX_MESSAGE_BYTES, DEFAULT_MAX_SEARCH_DAYS,
};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How an IMAP or SMTP connection is protected.
///
/// The wire spellings are the user-facing ones: `"tls"`
/// (implicit TLS, usually 993/465), `"starttls"` (plain first, then a
/// mandatory upgrade, usually 587) and `"plain"` (no encryption — only ever
/// explicit). `starttls` is pinned with an explicit rename because
/// `snake_case` would spell it `start_tls`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    /// Implicit TLS from the first byte (usually port 993 or 465).
    #[default]
    Tls,
    /// Plain connection, then a **mandatory** STARTTLS upgrade (usually 587).
    #[serde(rename = "starttls")]
    StartTls,
    /// No encryption. A login or a write that carries a password is refused
    /// **before any socket is opened**.
    Plain,
}

impl Security {
    /// The config/CLI spelling (`tls` | `starttls` | `plain`).
    pub fn as_str(self) -> &'static str {
        match self {
            Security::Tls => "tls",
            Security::StartTls => "starttls",
            Security::Plain => "plain",
        }
    }

    /// True when the connection is encrypted, implicitly or after upgrading.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Security::Tls | Security::StartTls)
    }
}

/// The user's folder names, mapped to whatever the server calls them.
///
/// `inbox` etc. are the words the user sees; the value is the server-side
/// name. Defaults are the canonical IMAP names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FolderMap {
    /// Folder a read defaults to.
    pub inbox: String,
    /// Folder holding sent mail.
    pub sent: String,
    /// Folder drafts are appended to.
    pub drafts: String,
    /// Folder `mail_move`/`mail_delete` prefer over expunge.
    pub trash: String,
    /// Optional archive folder.
    pub archive: String,
}

impl Default for FolderMap {
    fn default() -> Self {
        Self {
            inbox: "INBOX".to_string(),
            sent: "Sent".to_string(),
            drafts: "Drafts".to_string(),
            trash: "Trash".to_string(),
            archive: "Archive".to_string(),
        }
    }
}

/// The incoming (IMAP) endpoint for one account.
///
/// `username` defaults to the account's email address when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImapSettings {
    /// Server hostname (no scheme, no port).
    pub host: String,
    /// TCP port; 993 with [`Security::Tls`] by default.
    pub port: u16,
    /// Transport security.
    pub security: Security,
    /// Login name; the account email when absent or empty.
    pub username: Option<String>,
    /// A PEM certificate to trust **instead of** the webpki roots. Only ever
    /// accepted for a loopback host (`127.0.0.1`, `::1`, `localhost`); it is
    /// the local simulator's self-signed certificate, never a real server.
    pub ca_file: Option<String>,
}

impl Default for ImapSettings {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 993,
            security: Security::Tls,
            username: None,
            ca_file: None,
        }
    }
}

impl ImapSettings {
    /// The effective login name: `username` when set and non-empty, else the
    /// account's email address.
    pub fn username<'a>(&'a self, account_email: &'a str) -> &'a str {
        self.username
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(account_email)
    }
}

/// The outgoing (SMTP) endpoint for one account.
///
/// `username` defaults to the account's email address when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpSettings {
    /// Server hostname (no scheme, no port).
    pub host: String,
    /// TCP port; 587 with [`Security::StartTls`] by default.
    pub port: u16,
    /// Transport security.
    pub security: Security,
    /// Login name; the account email when absent or empty.
    pub username: Option<String>,
    /// A PEM certificate to trust **instead of** the webpki roots. Only ever
    /// accepted for a loopback host (`127.0.0.1`, `::1`, `localhost`); it is
    /// the local simulator's self-signed certificate, never a real server.
    pub ca_file: Option<String>,
}

impl Default for SmtpSettings {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 587,
            security: Security::StartTls,
            username: None,
            ca_file: None,
        }
    }
}

impl SmtpSettings {
    /// The effective login name: `username` when set and non-empty, else the
    /// account's email address.
    pub fn username<'a>(&'a self, account_email: &'a str) -> &'a str {
        self.username
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(account_email)
    }
}

/// One configured mailbox.
///
/// `only_folders` is a hard read allowlist: an agent only ever sees the folders
/// the owner ticked, and the default `["INBOX"]` means adding a mailbox never
/// silently exposes the whole account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MailAccount {
    /// Stable canonical slug — `[a-z0-9][a-z0-9_-]{0,31}`, validated at load
    /// — also part of the secret name `AUX_MAIL_<ID_UPPER>` (with `-` folded
    /// to `_` so the name is a valid environment key).
    pub id: String,
    /// The address; also the default IMAP/SMTP username.
    pub email: String,
    /// Human label for the UI/CLI.
    pub display: Option<String>,
    /// Incoming server.
    pub imap: ImapSettings,
    /// Outgoing server; absent means this account cannot send at all.
    pub smtp: Option<SmtpSettings>,
    /// User-facing folder names mapped to server names.
    pub folders: FolderMap,
    /// Folders an agent may read. Defaults to `["INBOX"]`.
    pub only_folders: Vec<String>,
}

impl Default for MailAccount {
    fn default() -> Self {
        Self {
            id: String::new(),
            email: String::new(),
            display: None,
            imap: ImapSettings::default(),
            smtp: None,
            folders: FolderMap::default(),
            only_folders: vec!["INBOX".to_string()],
        }
    }
}

impl MailAccount {
    /// True when `folder` is inside the account's read allowlist
    /// (ASCII case-insensitive, matching IMAP folder-name semantics).
    pub fn reads_folder(&self, folder: &str) -> bool {
        self.only_folders
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(folder))
    }

    /// The `~/.auxesis/.env` key holding this account's mailbox password:
    /// `AUX_MAIL_<ACCOUNT_ID_UPPER>`, with `-` folded to `_` so the name is a
    /// valid environment key. Never the Keychain. Because the
    /// fold can make two ids collide, [`MailConfig::load`] refuses two
    /// accounts with the same key.
    pub fn secret_key(&self) -> String {
        env_var_name(&self.id)
    }
}

/// The `.env` key for one account id (the account-key naming): `AUX_MAIL_<ID_UPPER>`, with
/// every `-` folded to `_`. [`MailAccount::secret_key`] resolves the same key;
/// this free form lets the credential source and the CLI share it.
pub fn env_var_name(account_id: &str) -> String {
    format!(
        "AUX_MAIL_{}",
        account_id.to_ascii_uppercase().replace('-', "_")
    )
}

/// The config half of the hard bounds, in whole seconds.
///
/// [`MailLimits::limits`] converts to the runtime [`Limits`] and applies the
/// same zero-falls-back-to-default rule the rest of the workspace uses: a
/// hand-edited `0` must not silently disable a cap (a `max_inflight_per_agent`
/// of `0` would deadlock the semaphore forever).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MailLimits {
    /// Largest single message, in bytes.
    pub max_message_bytes: usize,
    /// Largest total per call, in bytes.
    pub max_call_bytes: usize,
    /// Largest message count per call.
    pub max_messages: usize,
    /// Attachment bytes downloaded per attachment. The documented ceiling is
    /// [`DEFAULT_MAX_ATTACHMENT_BYTES`] (25 MiB); a config may ask for less and
    /// [`MailLimits::limits`] never lets it rise above the ceiling.
    pub max_attachment_bytes: usize,
    /// Attachment bytes downloaded across one call. The ceiling is
    /// [`DEFAULT_MAX_CALL_ATTACHMENT_BYTES`] (50 MiB).
    pub max_call_attachment_bytes: usize,
    /// Wall clock per call, in seconds.
    pub call_timeout_secs: u64,
    /// Connect and TLS-handshake budget, in seconds.
    pub connect_timeout_secs: u64,
    /// Server-side search window, in days.
    pub max_search_days: u32,
    /// Concurrent mail calls per agent.
    pub max_inflight_per_agent: usize,
}

impl Default for MailLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_call_bytes: DEFAULT_MAX_CALL_BYTES,
            max_messages: DEFAULT_MAX_MESSAGES,
            max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
            max_call_attachment_bytes: DEFAULT_MAX_CALL_ATTACHMENT_BYTES,
            call_timeout_secs: DEFAULT_CALL_TIMEOUT_SECS,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            max_search_days: DEFAULT_MAX_SEARCH_DAYS,
            max_inflight_per_agent: DEFAULT_MAX_INFLIGHT_PER_AGENT,
        }
    }
}

impl MailLimits {
    /// The configured per-attachment budget (read-only view of the field).
    pub fn max_attachment_bytes(&self) -> usize {
        self.max_attachment_bytes
    }

    /// The configured per-call attachment budget.
    pub fn max_call_attachment_bytes(&self) -> usize {
        self.max_call_attachment_bytes
    }

    /// Convert to the runtime bounds, replacing a zero count/timeout with the
    /// documented default.
    ///
    /// The two attachment budgets are lowered to the documented ceilings
    /// ([`DEFAULT_MAX_ATTACHMENT_BYTES`], [`DEFAULT_MAX_CALL_ATTACHMENT_BYTES`])
    /// so a config can grant less, never more.
    pub fn limits(&self) -> Limits {
        Limits::new(
            fallback_usize(self.max_message_bytes, DEFAULT_MAX_MESSAGE_BYTES),
            fallback_usize(self.max_call_bytes, DEFAULT_MAX_CALL_BYTES),
            fallback_usize(self.max_messages, DEFAULT_MAX_MESSAGES),
            fallback_secs(self.call_timeout_secs, DEFAULT_CALL_TIMEOUT_SECS),
            fallback_secs(self.connect_timeout_secs, DEFAULT_CONNECT_TIMEOUT_SECS),
            fallback_days(self.max_search_days, DEFAULT_MAX_SEARCH_DAYS),
            fallback_usize(self.max_inflight_per_agent, DEFAULT_MAX_INFLIGHT_PER_AGENT),
        )
        .with_attachments(
            fallback_usize(self.max_attachment_bytes, DEFAULT_MAX_ATTACHMENT_BYTES),
            fallback_usize(
                self.max_call_attachment_bytes,
                DEFAULT_MAX_CALL_ATTACHMENT_BYTES,
            ),
        )
    }
}

/// The whole `[connectors.mail]` table.
///
/// `MailConfig` is **not** denied unknown fields: it is the extension point,
/// and new additive sections (grants, per-agent policy) must keep older builds
/// loading. Its leaves are the strict ones.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MailConfig {
    /// Configured mailboxes, in owner order.
    pub accounts: Vec<MailAccount>,
    /// Effective hard bounds shared by every account.
    pub limits: MailLimits,
}

impl MailConfig {
    /// Parse the table, dropping load warnings.
    ///
    /// Prefer [`MailConfig::load`] when the caller can log them.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        Self::load(text).map(|(config, _warnings)| config)
    }

    /// Parse the table and report what the loader ignored.
    ///
    /// `send_mode` was removed in Phase 1 (sends are skill-only). A config that
    /// still carries it loads, and each occurrence adds one warning the caller
    /// should log; `deny_unknown_fields` still refuses everything else.
    ///
    /// Every account id must be a canonical lowercase slug
    /// (`[a-z0-9][a-z0-9_-]{0,31}`), and no two accounts may share an id or a
    /// [`MailAccount::secret_key`]. A violation is refused here — in English
    /// and French — rather than resolving a password under the wrong account.
    pub fn load(text: &str) -> Result<(Self, Vec<String>), toml::de::Error> {
        // Parse to a `Value` first so the removed `send_mode` key can be
        // dropped, with a warning, before the strict leaves see it. Everything
        // else still goes through `deny_unknown_fields`.
        let mut value: toml::Value = toml::from_str(text)?;
        let mut warnings = Vec::new();
        if let Some(accounts) = value
            .as_table_mut()
            .and_then(|table| table.get_mut("accounts"))
            .and_then(toml::Value::as_array_mut)
        {
            for (index, account) in accounts.iter_mut().enumerate() {
                let Some(table) = account.as_table_mut() else {
                    continue;
                };
                if let Some(legacy) = table.remove("send_mode") {
                    let id = table
                        .get("id")
                        .and_then(toml::Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("#{index}"));
                    warnings.push(format!(
                        "connectors.mail.accounts[{id}]: send_mode = {legacy} was ignored \
                         (sends are skill-only in Phase 1)"
                    ));
                }
            }
        }
        let config: Self = value.try_into()?;
        validate_accounts(&config.accounts)?;
        Ok((config, warnings))
    }

    /// Serialize the table (used by `aux connect add mail` and by the
    /// round-trip test).
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// The account with this id, if configured.
    pub fn account(&self, id: &str) -> Option<&MailAccount> {
        self.accounts.iter().find(|account| account.id == id)
    }
}

/// The contract's canonical account id: `[a-z0-9][a-z0-9_-]{0,31}`.
///
/// Public so a connector can refuse a non-slug `account` argument and keep the
/// `mail.call` Ledger row free of any raw model value.
pub fn is_account_slug(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && id.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Refuse an invalid account id, a duplicate id, or two ids that fold to the
/// same [`MailAccount::secret_key`]. The messages are English + French.
fn validate_accounts(accounts: &[MailAccount]) -> Result<(), toml::de::Error> {
    for account in accounts {
        if !is_account_slug(&account.id) {
            return Err(toml::de::Error::custom(format!(
                "[[accounts]] id {:?} is not a canonical lowercase slug \
                 [a-z0-9][a-z0-9_-]{{0,31}} / identifiant de compte invalide \
                 (slug en minuscules attendu)",
                account.id
            )));
        }
    }
    for (index, account) in accounts.iter().enumerate() {
        if accounts[..index].iter().any(|prior| prior.id == account.id) {
            return Err(toml::de::Error::custom(format!(
                "[[accounts]] duplicate id {:?} / identifiant de compte en double",
                account.id
            )));
        }
        let key = account.secret_key();
        if let Some(prior) = accounts[..index]
            .iter()
            .find(|prior| prior.secret_key() == key)
        {
            return Err(toml::de::Error::custom(format!(
                "[[accounts]] {:?} and {:?} share the secret key {key} / \
                 deux comptes partagent la même clé de mot de passe",
                prior.id, account.id
            )));
        }
    }
    Ok(())
}

fn fallback_usize(value: usize, fallback: usize) -> usize {
    if value == 0 {
        fallback
    } else {
        value
    }
}

fn fallback_days(value: u32, fallback: u32) -> u32 {
    if value == 0 {
        fallback
    } else {
        value
    }
}

fn fallback_secs(value: u64, fallback: u64) -> Duration {
    Duration::from_secs(if value == 0 { fallback } else { value })
}
