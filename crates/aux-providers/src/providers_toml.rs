//! `~/.auxesis/providers.toml`: the Phase 1 provider and brain configuration.
//!
//! This is the new home for providers (`docs/providers.md` §2). It is a
//! separate file from `config.toml`, it is strict (an unknown key, a missing
//! required key or a pasted secret is a load error), and a key is only ever an
//! `env:<NAME>` reference resolved from the process environment and then
//! `~/.auxesis/.env`.
//!
//! The legacy `[[providers]]` table in `config.toml` is migrated once by
//! [`migrate_legacy_config`], then commented out in place. The migration never
//! reads or copies a Keychain item: keys stay in the environment / `.env`.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{
    chat_completions_url, is_loopback_url, provider_name_is_key_shaped, shown_base_url, shown_id,
    shown_id_plain, ConfigError, KEY_SHAPED_PROVIDER_NAME,
};
use crate::key::{AgentEnvStore, KeyError, ENV_FILE};
use crate::types::ModelId;

/// File name of the provider configuration under the Auxesis home.
pub const PROVIDERS_FILE: &str = "providers.toml";

/// The only accepted prefix for a `key` value.
pub const ENV_REF_PREFIX: &str = "env:";

/// Local Ollama daemon root, before the `/v1/chat/completions` path.
pub const DEFAULT_OLLAMA_BASE_URL: &str = "http://127.0.0.1:11434";

/// Adapter named by `kind = ...`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// OpenAI `chat/completions` wire (DeepSeek, Ollama Cloud, LM Studio).
    Openai,
    /// Anthropic `v1/messages` wire.
    Anthropic,
    /// A local Ollama daemon (`/v1/chat/completions`, no key).
    Ollama,
    /// An ACP agent (OpenCode, …), a turn-level backend.
    Acp,
    /// Deterministic in-process adapter for tests.
    Fake,
}

impl EntryKind {
    /// Wire name used in `providers.toml`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::Ollama => "ollama",
            Self::Acp => "acp",
            Self::Fake => "fake",
        }
    }
}

/// Reasoning effort for the `anthropic` adapter (`output_config.effort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    /// Least effort.
    Low,
    /// Balanced effort (the adapter default).
    Medium,
    /// Most effort.
    High,
}

impl Effort {
    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One `[[provider]]` entry.
///
/// Strict: every field the schema does not name is rejected by serde, and
/// [`ProviderEntry::validate`] enforces the per-kind fields.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEntry {
    /// Stable provider id, `[a-z0-9-]{1,32}`, unique in the file.
    pub id: String,
    /// Adapter to use.
    pub kind: EntryKind,
    /// API root. Required for `openai` / `anthropic`; the local Ollama daemon
    /// defaults to [`DEFAULT_OLLAMA_BASE_URL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// `env:<NAME>` reference. Never a pasted secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Optional model allowlist for this provider; empty means "what the
    /// catalog lists".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// `openai` only: send DeepSeek's documented thinking-off toggle.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_thinking: bool,
    /// `anthropic` only: reasoning effort (default `medium`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
    /// `acp` only: names an `[acp.agents.*]` entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Permit a non-loopback `base_url` for the local `ollama` kind.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_remote_base_url: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// The `[brain]` table: which model answers, and what to try next.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrainConfig {
    /// Default brain, `<provider>/<model>` or a bare provider id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Fallback brains, tried in order only on a transport error or a 5xx.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<String>,
    /// Hint name (`cheap`, `strong`) to brain mapping for skill front matter.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub hints: std::collections::BTreeMap<String, String>,
}

/// A `<provider>/<model>` brain reference as `Debug` may show it.
///
/// The whole reference is classified first (a key may span the slash), then
/// each side on its own: a key-shaped provider or model is hidden.
fn shown_brain_reference(reference: &str) -> String {
    let whole = shown_id_plain(reference);
    if whole != reference {
        return whole;
    }
    match reference.split_once('/') {
        Some((provider, model)) => {
            format!("{}/{}", shown_id_plain(provider), shown_id_plain(model))
        }
        None => whole,
    }
}

impl fmt::Debug for BrainConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hints: std::collections::BTreeMap<String, String> = self
            .hints
            .iter()
            .map(|(hint, reference)| (shown_id_plain(hint), shown_brain_reference(reference)))
            .collect();
        f.debug_struct("BrainConfig")
            .field(
                "default",
                &self.default.as_deref().map(shown_brain_reference),
            )
            .field(
                "fallback",
                &self
                    .fallback
                    .iter()
                    .map(|reference| shown_brain_reference(reference))
                    .collect::<Vec<_>>(),
            )
            .field("hints", &hints)
            .finish()
    }
}

/// The whole `providers.toml` document.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersFile {
    /// `[[provider]]` entries, in file order.
    #[serde(default, rename = "provider")]
    pub providers: Vec<ProviderEntry>,
    /// `[brain]`.
    #[serde(default)]
    pub brain: BrainConfig,
}

impl fmt::Debug for ProviderEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderEntry")
            .field("id", &shown_id_plain(&self.id))
            .field("kind", &self.kind)
            .field("base_url", &self.base_url.as_deref().map(shown_base_url))
            // Never the value: a key is a credential (a literal or a reference).
            .field("key", &self.key.as_ref().map(|_| "[set]"))
            .field(
                "models",
                &self
                    .models
                    .iter()
                    .map(|model| shown_id_plain(model))
                    .collect::<Vec<_>>(),
            )
            .field("disable_thinking", &self.disable_thinking)
            .field("effort", &self.effort)
            .field("agent", &self.agent)
            .field("allow_remote_base_url", &self.allow_remote_base_url)
            .finish()
    }
}

impl fmt::Debug for ProvidersFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvidersFile")
            .field("providers", &self.providers)
            .field("brain", &self.brain)
            .finish()
    }
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// Validate a provider id: `[a-z0-9-]{1,32}`.
fn validate_id(id: &str) -> Result<(), ConfigError> {
    if provider_name_is_key_shaped(id) {
        return Err(invalid(KEY_SHAPED_PROVIDER_NAME));
    }
    if id.is_empty() || id.len() > 32 {
        return Err(invalid("provider id must be 1..=32 bytes of [a-z0-9-]"));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid("provider id must be [a-z0-9-]"));
    }
    Ok(())
}

/// The environment variable name a `key` reference points at, if the reference
/// is well formed. `None` means the reference is not `env:<NAME>`.
pub fn env_ref_name(reference: &str) -> Option<&str> {
    let name = reference.strip_prefix(ENV_REF_PREFIX)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    Some(name)
}

impl ProviderEntry {
    /// Check the entry against the `docs/providers.md` §2 rules. A
    /// secret-shaped id shows as `<id>` in every message.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.check().map_err(|err| match err {
            ConfigError::Invalid(message) => {
                invalid(message.replace(&format!("`{}`", self.id), &shown_id(&self.id)))
            }
            other => other,
        })
    }

    fn check(&self) -> Result<(), ConfigError> {
        validate_id(&self.id)?;
        if let Some(reference) = &self.key {
            if env_ref_name(reference).is_none() {
                return Err(invalid(format!(
                    "provider `{}`: `key` must be an env reference like `env:AUX_KEY_X`, never a value",
                    self.id
                )));
            }
        }
        for model in &self.models {
            ModelId::from_config(model).map_err(|err| {
                invalid(format!("provider `{}`: model id refused: {err}", self.id))
            })?;
        }

        match self.kind {
            EntryKind::Acp => {
                let agent = self.agent.as_deref().map(str::trim).unwrap_or("");
                if agent.is_empty() {
                    return Err(invalid(format!(
                        "provider `{}`: kind = \"acp\" needs an `agent` name",
                        self.id
                    )));
                }
                if self.base_url.is_some() || self.key.is_some() || !self.models.is_empty() {
                    return Err(invalid(format!(
                        "provider `{}`: an acp entry carries only `agent` (the CLI holds its login)",
                        self.id
                    )));
                }
                if self.effort.is_some() || self.disable_thinking {
                    return Err(invalid(format!(
                        "provider `{}`: an acp entry has no effort or thinking toggle",
                        self.id
                    )));
                }
            }
            EntryKind::Fake => {
                if self.key.is_some() {
                    return Err(invalid(format!(
                        "provider `{}`: a fake entry takes no key",
                        self.id
                    )));
                }
            }
            EntryKind::Ollama => {
                let base = self.base_url.as_deref().unwrap_or(DEFAULT_OLLAMA_BASE_URL);
                validate_url(base, &self.id)?;
                if !is_loopback_url(base) && !self.allow_remote_base_url {
                    return Err(invalid(format!(
                        "provider `{}`: `{}` is not loopback; set allow_remote_base_url = true \
                         to reach a remote Ollama",
                        self.id,
                        shown_base_url(base)
                    )));
                }
                if self.key.is_some() {
                    return Err(invalid(format!(
                        "provider `{}`: the local ollama kind takes no key",
                        self.id
                    )));
                }
                if self.effort.is_some() {
                    return Err(invalid(format!(
                        "provider `{}`: effort is anthropic-only",
                        self.id
                    )));
                }
            }
            EntryKind::Openai => {
                let base = self.require_base_url()?;
                validate_url(base, &self.id)?;
                if self.agent.is_some() || self.effort.is_some() {
                    return Err(invalid(format!(
                        "provider `{}`: `agent` and `effort` are not openai fields",
                        self.id
                    )));
                }
            }
            EntryKind::Anthropic => {
                let base = self.require_base_url()?;
                validate_url(base, &self.id)?;
                if self.key.is_none() {
                    return Err(invalid(format!(
                        "provider `{}`: kind = \"anthropic\" needs a `key` env reference",
                        self.id
                    )));
                }
                if self.agent.is_some() || self.disable_thinking {
                    return Err(invalid(format!(
                        "provider `{}`: `agent` and `disable_thinking` are not anthropic fields",
                        self.id
                    )));
                }
            }
        }
        Ok(())
    }

    fn require_base_url(&self) -> Result<&str, ConfigError> {
        let base = self.base_url.as_deref().map(str::trim).unwrap_or("");
        if base.is_empty() {
            return Err(invalid(format!(
                "provider `{}`: kind = \"{}\" needs a `base_url`",
                self.id,
                self.kind.as_str()
            )));
        }
        Ok(base)
    }

    /// The environment variable name this entry's key points at.
    pub fn key_env_name(&self) -> Option<&str> {
        self.key.as_deref().and_then(env_ref_name)
    }

    /// The model a bare-provider brain resolves to: the first allowlisted
    /// model, if any.
    pub fn first_model(&self) -> Option<&str> {
        self.models.first().map(String::as_str)
    }
}

/// URL hygiene shared with the legacy loader: http/https, no userinfo, no
/// query or fragment, and plain http only on loopback.
fn validate_url(base_url: &str, id: &str) -> Result<(), ConfigError> {
    // `chat_completions_url` enforces every rule and appends a path we ignore.
    chat_completions_url(base_url).map_err(|err| match err {
        ConfigError::Invalid(message) => invalid(format!("provider `{id}`: {message}")),
        other => other,
    })?;
    Ok(())
}

/// The `v1/messages` endpoint for an `anthropic` entry.
pub fn anthropic_messages_url(base_url: &str) -> Result<String, ConfigError> {
    validate_url(base_url, "anthropic")?;
    Ok(format!(
        "{}/v1/messages",
        base_url.trim().trim_end_matches('/')
    ))
}

/// The `v1/chat/completions` endpoint for a local `ollama` entry.
pub fn ollama_chat_url(base_url: &str) -> Result<String, ConfigError> {
    validate_url(base_url, "ollama")?;
    Ok(format!(
        "{}/v1/chat/completions",
        base_url.trim().trim_end_matches('/')
    ))
}

/// Parse and validate a `providers.toml` document.
pub fn parse_providers_toml(text: &str) -> Result<ProvidersFile, ConfigError> {
    let file: ProvidersFile = toml::from_str(text)
        .map_err(|err| kernel_core::redact_toml_error(&err, PROVIDERS_FILE, text))?;
    let mut seen = HashSet::new();
    for entry in &file.providers {
        entry.validate()?;
        if !seen.insert(entry.id.as_str()) {
            return Err(invalid(format!(
                "duplicate provider id {}",
                shown_id(&entry.id)
            )));
        }
    }
    Ok(file)
}

/// Load and validate `providers.toml`.
pub fn load_providers_toml(path: &Path) -> Result<ProvidersFile, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_providers_toml(&text)
}

/// Load `providers.toml` from an Auxesis home, treating a missing file as
/// empty (so a fresh install with no providers is not an error).
pub fn load_providers_for_home(home: &Path) -> Result<ProvidersFile, ConfigError> {
    match load_providers_toml(&home.join(PROVIDERS_FILE)) {
        Ok(file) => Ok(file),
        Err(ConfigError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(ProvidersFile::default())
        }
        Err(err) => Err(err),
    }
}

/// Resolve one entry's key: the process environment first, then
/// `~/.auxesis/.env` (`docs/providers.md` §2). The value is never logged.
pub fn resolve_entry_key(entry: &ProviderEntry, home: &Path) -> Result<Option<String>, KeyError> {
    let env_file = AgentEnvStore::load(&home.join(ENV_FILE))?;
    resolve_entry_key_with(entry, &env_file, |name| std::env::var(name).ok())
}

/// [`resolve_entry_key`] with injectable stores, for tests.
pub fn resolve_entry_key_with<F>(
    entry: &ProviderEntry,
    env_file: &AgentEnvStore,
    env: F,
) -> Result<Option<String>, KeyError>
where
    F: FnOnce(&str) -> Option<String>,
{
    let Some(name) = entry.key_env_name() else {
        return Ok(None);
    };
    if let Some(value) = env(name) {
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    if let Some(value) = env_file.get_var(name) {
        if !value.is_empty() {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

/// What a migration attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// `providers.toml` already existed (or there was nothing to migrate).
    Skipped,
    /// The legacy table was written to `providers.toml` and commented out.
    Migrated {
        /// Number of provider entries moved.
        providers: usize,
    },
}

impl MigrationOutcome {
    /// True when the legacy table was actually moved.
    pub fn migrated(&self) -> bool {
        matches!(self, Self::Migrated { .. })
    }
}

/// Legacy `[[providers]]` fields, permissive on purpose: the old file is read
/// once and then commented out.
#[derive(Debug, Deserialize)]
struct LegacyConfig {
    #[serde(default)]
    providers: Vec<LegacyProvider>,
}

#[derive(Debug, Deserialize)]
struct LegacyProvider {
    id: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    key_user: Option<String>,
    kind: LegacyKind,
    #[serde(default)]
    disable_thinking: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum LegacyKind {
    #[serde(rename = "openai-compat", alias = "openai")]
    OpenaiCompat,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "ollama")]
    Ollama,
    #[serde(rename = "acp")]
    Acp,
    #[serde(rename = "fake")]
    Fake,
}

fn legacy_to_entry(legacy: &LegacyProvider) -> Result<ProviderEntry, ConfigError> {
    let kind = match legacy.kind {
        LegacyKind::OpenaiCompat => EntryKind::Openai,
        LegacyKind::Anthropic => EntryKind::Anthropic,
        LegacyKind::Ollama => EntryKind::Ollama,
        LegacyKind::Acp => EntryKind::Acp,
        LegacyKind::Fake => EntryKind::Fake,
    };
    let key = legacy.key_user.as_deref().map(|account| {
        // `key_user = "x"` becomes `key = "env:AUX_KEY_X"`. The value
        // itself stays wherever it already lives.
        let name: String = account
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() {
                    ch.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();
        format!("{ENV_REF_PREFIX}AUX_KEY_{name}")
    });
    let models = if legacy.model.trim().is_empty() {
        Vec::new()
    } else {
        vec![legacy.model.clone()]
    };
    let entry = ProviderEntry {
        id: legacy.id.clone(),
        kind,
        base_url: (!legacy.base_url.trim().is_empty()).then(|| legacy.base_url.clone()),
        key,
        models,
        disable_thinking: legacy.disable_thinking,
        effort: None,
        agent: (kind == EntryKind::Acp && !legacy.id.is_empty()).then(|| legacy.id.clone()),
        allow_remote_base_url: false,
    };
    entry.validate()?;
    Ok(entry)
}

/// Comment out every `[[providers]]` block, leaving the rest of the file
/// untouched, and add a dated note above the first one.
fn comment_out_legacy_providers(config: &str, today: &str) -> Option<String> {
    let lines: Vec<&str> = config.lines().collect();
    let first = lines
        .iter()
        .position(|line| line.trim() == "[[providers]]")?;
    let mut out = Vec::with_capacity(lines.len() + 2);
    for (index, line) in lines.iter().enumerate() {
        if index == first {
            out.push(format!(
                "# [[providers]] migrated to providers.toml on {today}; keys stay in .env / Keychain"
            ));
        }
        if index >= first {
            let trimmed = line.trim();
            let is_new_table = (trimmed.starts_with('[') && trimmed.ends_with(']'))
                && trimmed != "[[providers]]"
                && !trimmed.starts_with("[[providers]");
            if is_new_table {
                // A different table starts; stop commenting from here on.
                out.extend(lines[index..].iter().map(|line| (*line).to_string()));
                break;
            }
            out.push(format!("# {line}"));
        } else {
            out.push((*line).to_string());
        }
    }
    let mut text = out.join("\n");
    if config.ends_with('\n') {
        text.push('\n');
    }
    Some(text)
}

/// Migrate a legacy `[[providers]]` table from `config.toml` into
/// `providers.toml` once.
///
/// Idempotent: when `providers.toml` already exists, nothing is read from the
/// legacy table and nothing is written. The migration never reads or copies a
/// Keychain item.
pub fn migrate_legacy_config(home: &Path, today: &str) -> Result<MigrationOutcome, ConfigError> {
    let providers_path = home.join(PROVIDERS_FILE);
    if providers_path.exists() {
        return Ok(MigrationOutcome::Skipped);
    }
    let config_path = home.join("config.toml");
    let text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MigrationOutcome::Skipped)
        }
        Err(source) => {
            return Err(ConfigError::Io {
                path: config_path.display().to_string(),
                source,
            })
        }
    };
    let legacy: LegacyConfig = toml::from_str(&text)
        .map_err(|err| kernel_core::redact_toml_error(&err, "config.toml", &text))?;
    if legacy.providers.is_empty() {
        return Ok(MigrationOutcome::Skipped);
    }

    let mut entries = Vec::with_capacity(legacy.providers.len());
    for provider in &legacy.providers {
        entries.push(legacy_to_entry(provider)?);
    }
    let file = ProvidersFile {
        providers: entries,
        brain: BrainConfig::default(),
    };
    let serialized = toml::to_string_pretty(&file).map_err(|err| invalid(err.to_string()))?;
    let commented = comment_out_legacy_providers(&text, today);
    // The write gateway: both files are written relative to the verified home
    // directory fd, never through the home path string, under the shared config
    // lock. `providers.toml` goes first: if the config rewrite failed after it,
    // the next start is already migrated (idempotent), so no entry is lost.
    kernel_core::with_config_lock(home, || -> Result<(), ConfigError> {
        let handle = kernel_core::SandboxHome::open(home)
            .map_err(|err| invalid(format!("opening home: {err}")))?;
        handle
            .write_atomic(
                std::path::Path::new(PROVIDERS_FILE),
                serialized.as_bytes(),
                0o600,
            )
            .map_err(|err| invalid(format!("writing {}: {err}", providers_path.display())))?;
        if let Some(commented) = &commented {
            handle
                .write_atomic(
                    std::path::Path::new("config.toml"),
                    commented.as_bytes(),
                    0o600,
                )
                .map_err(|err| invalid(format!("writing {}: {err}", config_path.display())))?;
        }
        Ok(())
    })
    .map_err(|err| invalid(format!("config lock: {err}")))??;
    let providers = file.providers.len();
    tracing::info!(providers, path = %providers_path.display(), "migrated legacy providers");
    Ok(MigrationOutcome::Migrated { providers })
}

/// The Auxesis home that owns `config.toml`, used to locate `providers.toml`.
pub fn home_for_config(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[[provider]]
id       = "deepseek"
kind     = "openai"
base_url = "https://api.deepseek.com/v1"
key      = "env:AUX_KEY_DEEPSEEK"
models   = ["deepseek-chat"]
disable_thinking = true

[[provider]]
id = "anthropic"
kind = "anthropic"
base_url = "https://api.anthropic.com"
key = "env:AUX_KEY_ANTHROPIC"
effort = "high"

[[provider]]
id = "ollama-cloud"
kind = "openai"
base_url = "https://ollama.com/v1"
key = "env:AUX_KEY_OLLAMA_CLOUD"

[[provider]]
id = "opencode"
kind = "acp"
agent = "opencode"

[brain]
default  = "deepseek/deepseek-chat"
fallback = ["anthropic/claude-haiku-5-5"]
hints = { cheap = "deepseek/deepseek-chat" }
"#;

    #[test]
    fn a_validation_error_never_quotes_a_secret_id_or_url_value() {
        // A key in the URL stays out of the error.
        let ollama = "kind = \"ollama\"\nbase_url";
        for (text, kept) in [
            (
                format!("id = \"o\"\n{ollama} = \"http://10.0.0.2:11434/v1?token=CANARY1\""),
                "provider `o`: base_url `http://10.0.0.2:11434/v1?<redacted>`",
            ),
            (
                format!("id = \"o\"\n{ollama} = \"http://u:CANARY1@10.0.0.2:11434\""),
                "provider `o`: base_url must not contain userinfo",
            ),
        ] {
            let text = format!("[[provider]]\n{text}\n");
            let err = parse_providers_toml(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(!leaked.to_lowercase().contains("canary"), "{leaked}");
            }
            assert!(shown.contains(kept), "{shown}");
        }
        // A provider id is a name: a key-shaped one is refused at load, never
        // echoed, including the security review's repro and its percent-encoded copies.
        for key in [
            "sk-proj-canary-7f3k9q",
            "%73k-proj-canary-7f3k9q",
            "%25252573k-proj-canary-7f3k9q",
        ] {
            let text = format!("[[provider]]\nid = \"{key}\"\nkind = \"fake\"\n");
            let err = parse_providers_toml(&text).unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            assert!(err.contains("looks like a key"), "{err}");
        }
        // A plain id is still quoted.
        let err = parse_providers_toml("[[provider]]\nid = \"deepseek\"\nkind = \"acp\"\n");
        assert!(err.unwrap_err().to_string().contains("provider `deepseek`"));
    }

    #[test]
    fn a_percent_encoded_key_never_shows_in_a_provider_url_or_id() {
        // `%73k-…` is the same key as `sk-…`, and
        // so are `%2573k-…` (encoded twice) and `%53K-…` (the same bytes,
        // another case). None of them may reach the error.
        for canary in [
            "sk-proj-CANARY-7f3k9q",
            "%73k-proj-CANARY-7f3k9q",
            "%2573k-proj-CANARY-7f3k9q",
            "%53K-PROJ-CANARY-7f3k9q",
        ] {
            let text = format!(
                "[[provider]]\nid = \"o\"\nkind = \"ollama\"\nbase_url = \"http://10.0.0.2:11434/{canary}\"\n"
            );
            let err = parse_providers_toml(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(
                    !leaked.to_lowercase().contains("canary"),
                    "the error echoed {canary}: {leaked}"
                );
            }
            assert!(shown.contains("<redacted>"), "{shown}");
            // The id is the same key: it is refused, never echoed.
            let text = format!("[[provider]]\nid = \"{canary}\"\nkind = \"fake\"\n");
            let err = parse_providers_toml(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(
                    !leaked.to_lowercase().contains("canary"),
                    "the error echoed the id: {leaked}"
                );
            }
        }
    }

    #[test]
    fn a_key_hidden_however_many_times_it_is_encoded_never_shows() {
        // `%25252573k-…` is the same key as `sk-…`,
        // four escape layers deep, and `%252525252573k-…` six layers deep. The
        // decoder peels every layer, so neither reaches the error, in the URL
        // or as the provider id.
        for canary in [
            "%25252573k-proj-CANARY-7f3k9q",
            "%252525252573k-proj-CANARY-7f3k9q",
        ] {
            let text = format!(
                "[[provider]]\nid = \"o\"\nkind = \"ollama\"\nbase_url = \"http://10.0.0.2:11434/{canary}\"\n"
            );
            let err = parse_providers_toml(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(
                    !leaked.to_lowercase().contains("canary"),
                    "the error echoed {canary}: {leaked}"
                );
            }
            assert!(shown.contains("<redacted>"), "{shown}");
            // The id is the same key: it is refused, never echoed.
            let text = format!("[[provider]]\nid = \"{canary}\"\nkind = \"fake\"\n");
            let err = parse_providers_toml(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(
                    !leaked.to_lowercase().contains("canary"),
                    "the error echoed the id: {leaked}"
                );
            }
        }
    }

    #[test]
    fn parses_the_contract_example() {
        let file = parse_providers_toml(FULL).unwrap();
        assert_eq!(file.providers.len(), 4);
        assert_eq!(file.providers[0].kind, EntryKind::Openai);
        assert_eq!(file.providers[0].key_env_name(), Some("AUX_KEY_DEEPSEEK"));
        assert_eq!(file.providers[1].effort, Some(Effort::High));
        assert_eq!(file.providers[3].agent.as_deref(), Some("opencode"));
        assert_eq!(
            file.brain.default.as_deref(),
            Some("deepseek/deepseek-chat")
        );
        assert_eq!(file.brain.fallback, ["anthropic/claude-haiku-5-5"]);
        assert_eq!(
            file.brain.hints.get("cheap").map(String::as_str),
            Some("deepseek/deepseek-chat")
        );
    }

    #[test]
    fn an_unknown_key_is_a_load_error() {
        let text = r#"
[[provider]]
id = "deepseek"
kind = "openai"
base_url = "https://api.deepseek.com/v1"
key = "env:AUX_KEY_DEEPSEEK"
pasted_secret = "sk-nope"
"#;
        let err = parse_providers_toml(text).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn a_parse_error_names_the_file_and_line_never_the_text() {
        // A broken line, a pasted key and a bad value.
        let base = "[[provider]]\nid = \"deepseek\"\nkind = \"openai\"\n";
        for line in [
            "api_key = \"sk-CANARY-1234567890abcdef\n",
            "sk-CANARY-1234567890abcdef = 1\n",
            "base_url = 7\nkey = \"CANARY-1234567890abcdef\"\n",
            "api_key = \"CANARY-1234567890abcdef\"\n",
        ] {
            let text = format!("{base}{line}");
            let err = parse_providers_toml(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            assert!(
                !shown.contains("CANARY") && !debug.contains("CANARY"),
                "{debug}"
            );
            assert!(shown.contains("providers.toml, line 4"), "{shown}");
        }
        // The legacy `[[providers]]` table in `config.toml`, both readers.
        let text = "[[providers]]\nid = \"x\"\napi_key = \"sk-CANARY-1234567890abcdef\n";
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("config.toml"), text).unwrap();
        let migrated = migrate_legacy_config(home.path(), "2026-10-29").unwrap_err();
        let parsed = crate::config::parse_providers(text).unwrap_err();
        for err in [migrated, parsed] {
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            assert!(
                !shown.contains("CANARY") && !debug.contains("CANARY"),
                "{debug}"
            );
            assert!(shown.contains("config.toml, line 3"), "{shown}");
        }
    }

    #[test]
    fn a_key_that_is_not_an_env_reference_is_refused() {
        for bad in ["sk-live-value", "env:", "env:lower", "file:/tmp/key"] {
            let text = format!(
                r#"
[[provider]]
id = "deepseek"
kind = "openai"
base_url = "https://api.deepseek.com/v1"
key = "{bad}"
"#
            );
            let err = parse_providers_toml(&text).unwrap_err();
            assert!(
                matches!(&err, ConfigError::Invalid(message) if message.contains("env reference")),
                "{bad}: got {err:?}"
            );
        }
    }

    #[test]
    fn id_charset_is_enforced() {
        for bad in ["DeepSeek", "a_b", "", "with space"] {
            let text = format!(
                r#"
[[provider]]
id = "{bad}"
kind = "fake"
"#
            );
            assert!(
                parse_providers_toml(&text).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn duplicate_ids_are_refused() {
        let text = r#"
[[provider]]
id = "deepseek"
kind = "fake"
[[provider]]
id = "deepseek"
kind = "fake"
"#;
        let err = parse_providers_toml(text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("duplicate")),
            "got {err:?}"
        );
    }

    #[test]
    fn per_kind_required_fields_are_enforced() {
        // anthropic without a key.
        let text = r#"
[[provider]]
id = "anthropic"
kind = "anthropic"
base_url = "https://api.anthropic.com"
"#;
        assert!(parse_providers_toml(text).is_err());

        // openai without a base_url.
        let text = r#"
[[provider]]
id = "deepseek"
kind = "openai"
"#;
        assert!(parse_providers_toml(text).is_err());

        // acp without an agent.
        let text = r#"
[[provider]]
id = "opencode"
kind = "acp"
"#;
        assert!(parse_providers_toml(text).is_err());

        // acp with a base_url.
        let text = r#"
[[provider]]
id = "opencode"
kind = "acp"
agent = "opencode"
base_url = "https://example.com"
"#;
        assert!(parse_providers_toml(text).is_err());
    }

    #[test]
    fn plain_http_is_loopback_only() {
        let text = r#"
[[provider]]
id = "deepseek"
kind = "openai"
base_url = "http://api.deepseek.com/v1"
key = "env:AUX_KEY_DEEPSEEK"
"#;
        assert!(parse_providers_toml(text).is_err());

        let text = r#"
[[provider]]
id = "local"
kind = "openai"
base_url = "http://127.0.0.1:1234/v1"
"#;
        assert!(parse_providers_toml(text).is_ok());
    }

    #[test]
    fn a_remote_ollama_needs_the_explicit_flag() {
        let text = r#"
[[provider]]
id = "ollama-remote"
kind = "ollama"
base_url = "https://ollama.example.com"
"#;
        let err = parse_providers_toml(text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("allow_remote_base_url")),
            "got {err:?}"
        );

        let text = r#"
[[provider]]
id = "ollama-remote"
kind = "ollama"
base_url = "https://ollama.example.com"
allow_remote_base_url = true
"#;
        assert!(parse_providers_toml(text).is_ok());
    }

    #[test]
    fn a_bad_model_id_is_refused() {
        let text = r#"
[[provider]]
id = "deepseek"
kind = "openai"
base_url = "https://api.deepseek.com/v1"
models = ["elise@example.invalid"]
"#;
        assert!(parse_providers_toml(text).is_err());
    }

    #[test]
    fn key_resolution_tries_the_process_then_the_env_file() {
        let entry = ProviderEntry {
            id: "deepseek".into(),
            kind: EntryKind::Openai,
            base_url: Some("https://api.deepseek.com/v1".into()),
            key: Some("env:AUX_KEY_DEEPSEEK".into()),
            models: vec![],
            disable_thinking: false,
            effort: None,
            agent: None,
            allow_remote_base_url: false,
        };
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(ENV_FILE);
        std::fs::write(&env_path, "AUX_KEY_DEEPSEEK=from-file\n").unwrap();
        let env_file = AgentEnvStore::load(&env_path).unwrap();

        // The process environment wins.
        let resolved =
            resolve_entry_key_with(&entry, &env_file, |_| Some("from-process".to_string()))
                .unwrap();
        assert_eq!(resolved.as_deref(), Some("from-process"));

        // An empty process value falls through to the file.
        let resolved = resolve_entry_key_with(&entry, &env_file, |_| Some(String::new())).unwrap();
        assert_eq!(resolved.as_deref(), Some("from-file"));

        // Neither source has it.
        let resolved = resolve_entry_key_with(&entry, &env_file, |_| None).unwrap();
        assert_eq!(resolved.as_deref(), Some("from-file"));
    }

    #[test]
    fn migration_moves_the_legacy_table_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let config = r#"
version = 1
[[providers]]
id = "deepseek"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
key_user = "deepseek"
kind = "openai-compat"

[[providers]]
id = "sandbox"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"

[brain]
preset = "ollama"
"#;
        std::fs::write(dir.path().join("config.toml"), config).unwrap();

        let outcome = migrate_legacy_config(dir.path(), "2026-10-12").unwrap();
        assert_eq!(outcome, MigrationOutcome::Migrated { providers: 2 });

        let file = load_providers_toml(&dir.path().join(PROVIDERS_FILE)).unwrap();
        assert_eq!(file.providers.len(), 2);
        assert_eq!(file.providers[0].kind, EntryKind::Openai);
        assert_eq!(
            file.providers[0].key.as_deref(),
            Some("env:AUX_KEY_DEEPSEEK")
        );
        assert_eq!(file.providers[0].models, ["deepseek-chat"]);

        // The legacy table is commented out, the [brain] preset is untouched.
        let rewritten = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert!(rewritten.contains("migrated to providers.toml on 2026-10-12"));
        assert!(rewritten.contains("# [[providers]]"));
        assert!(rewritten.contains("[brain]"));
        assert!(!rewritten.lines().any(|line| line.trim() == "[[providers]]"));

        // A second start does nothing.
        let outcome = migrate_legacy_config(dir.path(), "2026-10-13").unwrap();
        assert_eq!(outcome, MigrationOutcome::Skipped);
        let rewritten_again = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert_eq!(rewritten, rewritten_again);
    }

    #[test]
    fn migration_skips_a_config_without_providers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), "version = 1\n").unwrap();
        let outcome = migrate_legacy_config(dir.path(), "2026-10-12").unwrap();
        assert_eq!(outcome, MigrationOutcome::Skipped);
        assert!(!dir.path().join(PROVIDERS_FILE).exists());
    }

    #[test]
    fn debug_never_shows_a_key_in_a_provider_entry() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let mut file = parse_providers_toml(
            r#"
[[provider]]
id = "p"
kind = "openai"
base_url = "https://api.example.com/v1"
key = "env:AUX_KEY_X"
"#,
        )
        .unwrap();
        file.providers[0].id = key.clone();
        file.providers[0].base_url = Some(format!("https://api.example.com/v1/{key}"));
        let text = format!("{:?}", file.providers[0]);
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn debug_never_shows_a_key_in_a_providers_file() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let mut file = parse_providers_toml(
            r#"
[[provider]]
id = "p"
kind = "openai"
base_url = "https://api.example.com/v1"
key = "env:AUX_KEY_X"
"#,
        )
        .unwrap();
        file.providers[0].id = key.clone();
        file.providers[0].base_url = Some(format!("https://api.example.com/v1/{key}"));
        let text = format!("{file:?}");
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn debug_never_shows_a_key_in_a_brain_config() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let brain = BrainConfig {
            default: Some(format!("{key}/model")),
            fallback: vec![format!("provider/{key}")],
            hints: std::collections::BTreeMap::from([(
                "cheap".to_string(),
                format!("{key}/model"),
            )]),
        };
        let text = format!(
            "{:?}",
            ProvidersFile {
                providers: Vec::new(),
                brain
            }
        );
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn url_helpers_build_the_contract_paths() {
        assert_eq!(
            anthropic_messages_url("https://api.anthropic.com").unwrap(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            ollama_chat_url("http://127.0.0.1:11434").unwrap(),
            "http://127.0.0.1:11434/v1/chat/completions"
        );
    }
}
