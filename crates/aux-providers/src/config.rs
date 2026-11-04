//! Provider configuration: `[[providers]]` entries in `config.toml`.
//!
//! Config files never contain secrets — only a `key_user` reference used to
//! look the key up in the macOS Keychain (see [`crate::key`]).

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) use kernel_broker::is_secret_shaped;
use kernel_broker::{classify_echo, EchoState as Echo};

use crate::error::ProviderError;
use crate::fake::FakeProvider;
use crate::openai_compat::OpenAiCompat;
use crate::preset::{expand_brain, BrainSection, OLLAMA_MODEL_ENV};
use crate::provider::ChatProvider;

/// Errors while loading or validating the provider configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("reading provider config at {path}: {source}")]
    Io {
        /// Path that could not be read.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config file exists but does not parse. The error comes from
    /// [`kernel_core::redact_toml_error`]: file, line and column, never the text.
    #[error("parsing provider config: {}", .0.message())]
    Parse(#[from] toml::de::Error),
    /// The configuration parsed but is not usable.
    #[error("invalid provider config: {0}")]
    Invalid(String),
}

/// Which adapter serves a provider entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderKind {
    /// OpenAI `chat/completions` wire — DeepSeek, LM Studio,
    /// OpenRouter and every custom OpenAI-compatible endpoint.
    #[serde(rename = "openai-compat")]
    OpenAiCompat,
    /// Deterministic scripted adapter for tests and the sandbox.
    #[serde(rename = "fake")]
    Fake,
    /// An ACP agent (OpenCode, Claude Code, Codex, …). ACP is a **turn-level
    /// agent backend**, not a completion wire: this entry is resolved by
    /// `aux-acp` behind the `[acp] enabled` flag, and
    /// [`ProviderConfig::build_provider`] refuses it.
    #[serde(rename = "acp")]
    Acp,
}

impl ProviderKind {
    /// Wire name used in `config.toml`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenAiCompat => "openai-compat",
            Self::Fake => "fake",
            Self::Acp => "acp",
        }
    }
}

/// One `[[providers]]` entry.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Stable provider id, also used for `AUX_KEY_<UPPER_ID>`.
    pub id: String,
    /// API root, e.g. `https://api.deepseek.com/v1`. `/chat/completions` is
    /// appended when calling. Empty for `kind = "acp"` (the agent CLI talks
    /// to its own vendor).
    #[serde(default)]
    pub base_url: String,
    /// Default model for this provider. Empty for `kind = "acp"`: the ACP
    /// agent picks its own default.
    #[serde(default)]
    pub model: String,
    /// Keychain account, e.g. `deepseek`. Omit for local endpoints that need
    /// no key (LM Studio, Ollama) and for ACP entries (CLI login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_user: Option<String>,
    /// Adapter to use.
    pub kind: ProviderKind,
    /// Send DeepSeek's documented `thinking: {"type": "disabled"}` toggle
    /// (https://api-docs.deepseek.com/api/create-chat-completion). Thinking mode
    /// refuses a forced `tool_choice`, so a provider that forces a skill needs it
    /// off. Off by default: no other provider receives the field.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_thinking: bool,
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base_url = if self.base_url.is_empty() {
            String::new()
        } else {
            shown_base_url(&self.base_url)
        };
        f.debug_struct("ProviderConfig")
            .field("id", &shown_id_plain(&self.id))
            .field("base_url", &base_url)
            .field("model", &shown_id_plain(&self.model))
            .field("key_user", &self.key_user.as_deref().map(shown_id_plain))
            .field("kind", &self.kind)
            .field("disable_thinking", &self.disable_thinking)
            .finish()
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

impl ProviderConfig {
    /// Validate the entry: non-empty fields, valid HTTP(S) base URL, and a
    /// non-empty `key_user` when present.
    ///
    /// An ACP entry (`kind = "acp"`) carries no base URL or model: it names a
    /// CLI agent resolved through `[acp.agents.*]`, so only the id and the
    /// absence of `key_user` are checked (no pasted keys for login-based
    /// backends).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.trim().is_empty() {
            return Err(ConfigError::Invalid("provider id is empty".to_string()));
        }
        if provider_name_is_key_shaped(&self.id) {
            return Err(ConfigError::Invalid(KEY_SHAPED_PROVIDER_NAME.to_string()));
        }
        if self.kind == ProviderKind::Acp {
            if self.key_user.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "provider {}: ACP entries use the CLI's own login; \
                     `key_user` is not allowed",
                    shown_id(&self.id)
                )));
            }
            return Ok(());
        }
        if self.model.trim().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "provider {}: model is empty",
                shown_id(&self.id)
            )));
        }
        if let Some(key_user) = &self.key_user {
            if key_user.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "provider {}: key_user is empty",
                    shown_id(&self.id)
                )));
            }
        }
        chat_completions_url(&self.base_url).map_err(|err| match err {
            ConfigError::Invalid(message) => {
                ConfigError::Invalid(format!("provider {}: {message}", shown_id(&self.id)))
            }
            other => other,
        })?;
        Ok(())
    }

    /// Build the adapter for this entry, resolving the API key (Keychain
    /// first, `AUX_KEY_<UPPER_ID>` fallback).
    pub fn build_provider(&self) -> Result<Box<dyn ChatProvider>, ProviderError> {
        match self.kind {
            ProviderKind::OpenAiCompat => Ok(Box::new(OpenAiCompat::new(self)?)),
            ProviderKind::Fake => Ok(Box::new(FakeProvider::echo(&self.id))),
            ProviderKind::Acp => Err(ProviderError::AcpBackend {
                provider: shown_id_plain(&self.id),
            }),
        }
    }

    /// Build the adapter with an explicit API key, bypassing Keychain and
    /// environment lookups (tests and future key-onboarding flows).
    pub fn build_provider_with_key(
        &self,
        api_key: Option<String>,
    ) -> Result<Box<dyn ChatProvider>, ProviderError> {
        match self.kind {
            ProviderKind::OpenAiCompat => Ok(Box::new(OpenAiCompat::with_key(self, api_key)?)),
            ProviderKind::Fake => Ok(Box::new(FakeProvider::echo(&self.id))),
            ProviderKind::Acp => Err(ProviderError::AcpBackend {
                provider: shown_id_plain(&self.id),
            }),
        }
    }
}

/// Full URL for chat completions, appending `/chat/completions` to the
/// configured API root (a trailing slash on the root is tolerated).
///
/// Hygiene: a provider key may be sent to this URL, so a remote endpoint must
/// use `https`; plain `http` is only accepted for a loopback host (a local
/// LM Studio / Ollama). Userinfo, non-http schemes and query/fragment are
/// refused.
pub fn chat_completions_url(base_url: &str) -> Result<String, ConfigError> {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(ConfigError::Invalid("base_url is empty".to_string()));
    }
    // `ParseError` names the problem only; the text never shows.
    let url = reqwest::Url::parse(trimmed)
        .map_err(|err| ConfigError::Invalid(format!("base_url is not a valid URL: {err}")))?;
    let shown = shown_url(&url);
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Invalid(
            "base_url must not contain userinfo credentials (the provider key comes from the Keychain)"
                .to_string(),
        ));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ConfigError::Invalid(format!(
            "base_url `{shown}` must use http or https"
        )));
    }
    if url.host_str().is_none() {
        return Err(ConfigError::Invalid(format!(
            "base_url `{shown}` has no host"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError::Invalid(format!(
            "base_url `{shown}` must not contain a query or fragment"
        )));
    }
    if url.scheme() == "http" && !is_loopback_host(&url) {
        return Err(ConfigError::Invalid(format!(
            "base_url `{shown}` uses plain http for a remote host; a provider key may only be sent over https (or to a loopback endpoint)"
        )));
    }
    Ok(format!("{trimmed}/chat/completions"))
}

/// A base URL as an error may show it: scheme, host, port and path. Userinfo
/// is dropped, a query or fragment shows as `?<redacted>` / `#<redacted>`, and
/// a secret-shaped or unsettled part shows as `<redacted>` or `[hidden]`.
fn shown_url(url: &reqwest::Url) -> String {
    let part = |text: &str| match classify_echo(text) {
        Echo::Clean => text.to_string(),
        Echo::Secret => "<redacted>".to_string(),
        Echo::Unstable => HIDDEN.to_string(),
    };
    let mut out = part(url.scheme());
    if url.cannot_be_a_base() {
        out.push_str(":<redacted>");
    } else {
        // The userinfo is a credential: it never shows, and a URL that
        // carries a secret-shaped one shows as `<redacted>`.
        if is_secret_shaped(url.username()) || url.password().is_some_and(is_secret_shaped) {
            return "<redacted>".to_string();
        }
        out.push_str("://");
        out.push_str(&part(url.host_str().unwrap_or_default()));
        if let Some(port) = url.port() {
            out.push_str(&format!(":{port}"));
        }
        // Each path segment on its own: a key hidden in one segment is
        // hidden, the rest of the path stays readable.
        let path = url.path().trim_start_matches('/');
        if !path.is_empty() {
            for segment in path.split('/') {
                out.push('/');
                out.push_str(&part(segment));
            }
        }
    }
    if url.query().is_some() {
        out.push_str("?<redacted>");
    }
    if url.fragment().is_some() {
        out.push_str("#<redacted>");
    }
    out
}

/// [`shown_url`] for a base URL that already passed [`chat_completions_url`].
///
/// Public so a caller outside this crate (`auxd`, `aux-engine`, `aux-cli`)
/// can render a provider address without echoing a key hidden in its path.
pub fn shown_base_url(base_url: &str) -> String {
    reqwest::Url::parse(base_url.trim())
        .map_or_else(|_| "<invalid URL>".to_string(), |url| shown_url(&url))
}

/// The one refusal for a provider name that reads as a key. It never echoes
/// the name.
pub const KEY_SHAPED_PROVIDER_NAME: &str = "this provider name looks like a key; pick a plain name";

/// True when a provider id reads as a secret, raw or through any
/// percent-decoded copy.
///
/// A provider id is a name and a lookup handle, never a credential: every
/// entry point refuses a key-shaped one instead of storing or echoing it.
pub fn provider_name_is_key_shaped(name: &str) -> bool {
    is_secret_shaped(name)
}

/// What an echo shows when the decoder cannot settle a value.
const HIDDEN: &str = "[hidden]";

/// A provider id as an error may show it: quoted, or `<id>` when it is
/// secret-shaped (an id can be any slug, a pasted key included), or
/// `[hidden]` when the decoder cannot settle it.
pub(crate) fn shown_id(id: &str) -> String {
    if matches!(classify_echo(id), Echo::Clean) {
        format!("`{id}`")
    } else {
        shown_id_plain(id)
    }
}

/// [`shown_id`] without the quotes: for errors, `Debug` fields and logs.
///
/// Public for the same caller boundary as [`shown_base_url`].
pub fn shown_id_plain(id: &str) -> String {
    match classify_echo(id) {
        Echo::Clean => id.to_string(),
        Echo::Secret => "<id>".to_string(),
        Echo::Unstable => HIDDEN.to_string(),
    }
}

/// True when `base_url` parses and its host is loopback.
pub(crate) fn is_loopback_url(base_url: &str) -> bool {
    reqwest::Url::parse(base_url.trim())
        .map(|url| is_loopback_host(&url))
        .unwrap_or(false)
}

/// True for a loopback host (`127.0.0.0/8`, `::1`, `localhost`).
fn is_loopback_host(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some(host) => {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        }
        None => false,
    }
}

#[derive(Debug, Deserialize)]
struct ProvidersFile {
    #[serde(default)]
    providers: Vec<ProviderConfig>,
    /// `[brain]`: a preset (e.g. `ollama`) that adds one provider entry.
    #[serde(default)]
    brain: Option<BrainSection>,
}

/// Parse `[[providers]]` entries from TOML text. A `[brain] preset` adds the
/// entry it names. Unknown top-level fields (`version`, `log_level`,
/// `default_agent`, …) are ignored so the whole `~/.auxesis/config.toml` can be
/// passed in.
pub fn parse_providers(text: &str) -> Result<Vec<ProviderConfig>, ConfigError> {
    let env_model = std::env::var(OLLAMA_MODEL_ENV).ok();
    parse_providers_with_env(text, env_model.as_deref())
}

/// [`parse_providers`] with the Ollama model override passed in explicitly, so
/// callers and tests control the environment (`None` ignores it).
pub fn parse_providers_with_env(
    text: &str,
    env_model: Option<&str>,
) -> Result<Vec<ProviderConfig>, ConfigError> {
    let file: ProvidersFile = toml::from_str(text)
        .map_err(|err| kernel_core::redact_toml_error(&err, "config.toml", text))?;

    let mut providers = file.providers;
    if let Some(brain) = &file.brain {
        providers.extend(expand_brain(brain, env_model)?);
    }

    let mut seen = HashSet::new();
    for provider in &providers {
        provider.validate()?;
        if !seen.insert(provider.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate provider id {}",
                shown_id(&provider.id)
            )));
        }
    }
    Ok(providers)
}

/// Load and validate `[[providers]]` entries from a TOML config file.
pub fn load_providers(path: &Path) -> Result<Vec<ProviderConfig>, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_providers(&text)
}

#[cfg(test)]
mod tests {

    /// A gate that tokenises: C9 is the one covered row private mode allows.
    fn tokenising_gate(key: [u8; 32]) -> kernel_privacy::safetext::Gate {
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        kernel_privacy::safetext::Gate::for_tests(&grant, key, crate::test_gate::names_checked())
    }
    use super::*;
    use serde_json::json;

    fn minimal_toml(kind: &str) -> String {
        format!(
            r#"
            version = 1
            log_level = "info"
            default_agent = "main"

            [[providers]]
            id = "deepseek"
            base_url = "https://api.deepseek.com/v1"
            model = "deepseek-chat"
            key_user = "deepseek"
            kind = "{kind}"
            "#
        )
    }

    #[test]
    fn kind_wire_names_are_stable() {
        assert_eq!(
            serde_json::to_value(ProviderKind::OpenAiCompat).unwrap(),
            json!("openai-compat")
        );
        assert_eq!(
            serde_json::to_value(ProviderKind::Fake).unwrap(),
            json!("fake")
        );
        assert_eq!(
            serde_json::to_value(ProviderKind::Acp).unwrap(),
            json!("acp")
        );
        assert_eq!(ProviderKind::OpenAiCompat.as_str(), "openai-compat");
        assert_eq!(ProviderKind::Acp.as_str(), "acp");
    }

    #[test]
    fn parses_an_acp_provider_without_url_or_model() {
        let text = r#"
            version = 1
            [[providers]]
            id = "opencode-go"
            kind = "acp"
        "#;
        let providers = parse_providers(text).unwrap();
        assert_eq!(providers[0].kind, ProviderKind::Acp);
        assert_eq!(providers[0].base_url, "");
        assert_eq!(providers[0].model, "");
        assert_eq!(providers[0].key_user, None);

        // ACP entries never carry a key reference.
        let with_key = r#"
            [[providers]]
            id = "opencode-go"
            kind = "acp"
            key_user = "nope"
        "#;
        assert!(parse_providers(with_key).is_err());

        // ACP never builds a completion provider.
        let err = match providers[0].build_provider() {
            Ok(_) => panic!("an ACP entry must not build a ChatProvider"),
            Err(err) => err,
        };
        assert!(matches!(err, ProviderError::AcpBackend { .. }), "{err:?}");
    }

    #[test]
    fn parses_full_config_with_two_providers() {
        let text = format!(
            "{}{}",
            minimal_toml("openai-compat"),
            r#"
            [[providers]]
            id = "sandbox"
            base_url = "http://127.0.0.1:9/v1"
            model = "fake-model"
            kind = "fake"
            "#
        );
        let providers = parse_providers(&text).unwrap();
        assert_eq!(providers.len(), 2);

        assert_eq!(providers[0].id, "deepseek");
        assert_eq!(providers[0].base_url, "https://api.deepseek.com/v1");
        assert_eq!(providers[0].model, "deepseek-chat");
        assert_eq!(providers[0].key_user.as_deref(), Some("deepseek"));
        assert_eq!(providers[0].kind, ProviderKind::OpenAiCompat);

        assert_eq!(providers[1].kind, ProviderKind::Fake);
        assert_eq!(providers[1].key_user, None);
    }

    #[test]
    fn a_key_shaped_provider_id_is_refused_at_load() {
        // A provider id is a name, not a credential: the load fails closed and
        // the refusal never echoes the would-be key.
        let err = parse_providers(
            &minimal_toml("openai-compat")
                .replace("id = \"deepseek\"", "id = \"sk-proj-canary-7f3k9q\""),
        )
        .unwrap_err()
        .to_string();
        assert!(!err.to_lowercase().contains("canary"), "{err}");
        assert!(err.contains("looks like a key"), "{err}");
    }

    #[test]
    fn a_base_url_error_never_shows_userinfo_query_or_a_secret_id() {
        // A key in the URL stays out of the error; the
        // scheme, host and path stay readable.
        for (id, base_url, kept) in [
            (
                "p",
                "https://h.test/v1?api_key=CANARY1",
                "`https://h.test/v1?<redacted>`",
            ),
            (
                "p",
                "http://h.test:8080/v1#CANARY1",
                "`http://h.test:8080/v1#<redacted>`",
            ),
            ("p", "https://u:CANARY1@h.test:99999/v1", "not a valid URL"),
            ("p", "https://u:CANARY1@h.test/v1", "userinfo"),
            (
                "p",
                "http://h.test/sk-proj-CANARY-7f3k9q",
                "`http://h.test/<redacted>`",
            ),
        ] {
            let text = format!(
                "[[providers]]\nid = \"{id}\"\nkind = \"openai-compat\"\nbase_url = \"{base_url}\"\nmodel = \"m\"\n"
            );
            let err = parse_providers(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(!leaked.to_lowercase().contains("canary"), "{leaked}");
            }
            assert!(shown.contains(kept), "{shown}");
        }
    }

    #[test]
    fn a_percent_encoded_key_never_shows_in_a_base_url_error() {
        // `%73k-…` is the same key as `sk-…`, and
        // so are `%2573k-…` (encoded twice) and `%53K-…` (the same bytes,
        // another case). None of them may reach the error, in the URL, in the
        // userinfo or as the provider id.
        let canaries = [
            "sk-proj-CANARY-7f3k9q",
            "%73k-proj-CANARY-7f3k9q",
            "%2573k-proj-CANARY-7f3k9q",
            "%53K-PROJ-CANARY-7f3k9q",
        ];
        for canary in canaries {
            for base_url in [
                format!("http://h.test/{canary}"),
                format!("http://h.test/v1/{canary}/chat"),
                format!("http://u:{canary}@h.test/v1"),
                format!("https://h.test/{canary}?x=1"),
            ] {
                let text = format!(
                    "[[providers]]\nid = \"p\"\nkind = \"openai-compat\"\nbase_url = \"{base_url}\"\nmodel = \"m\"\n"
                );
                let err = parse_providers(&text).unwrap_err();
                let (shown, debug) = (err.to_string(), format!("{err:?}"));
                for leaked in [shown.as_str(), debug.as_str()] {
                    assert!(
                        !leaked.to_lowercase().contains("canary"),
                        "the error echoed {base_url}: {leaked}"
                    );
                }
            }
            // The id is the same key: it is refused, never echoed.
            let text = format!(
                "[[providers]]\nid = \"{canary}\"\nkind = \"openai-compat\"\nbase_url = \"https://h.test/v1?x=1\"\nmodel = \"m\"\n"
            );
            let err = parse_providers(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(
                    !leaked.to_lowercase().contains("canary"),
                    "the error echoed the id: {leaked}"
                );
            }
            assert!(shown.contains("looks like a key"), "{shown}");
        }
    }

    #[test]
    fn a_key_hidden_however_many_times_it_is_encoded_never_shows() {
        // `%25252573k-…` is the same key as `sk-…`,
        // four escape layers deep, and `%252525252573k-…` six layers deep. The
        // decoder peels every layer, so neither reaches the error, in the URL,
        // in the userinfo or as the provider id.
        for canary in [
            "%25252573k-proj-CANARY-7f3k9q",
            "%252525252573k-proj-CANARY-7f3k9q",
        ] {
            for base_url in [
                format!("http://h.test/{canary}"),
                format!("http://h.test/v1/{canary}/chat"),
                format!("http://u:{canary}@h.test/v1"),
            ] {
                let text = format!(
                    "[[providers]]\nid = \"p\"\nkind = \"openai-compat\"\nbase_url = \"{base_url}\"\nmodel = \"m\"\n"
                );
                let err = parse_providers(&text).unwrap_err();
                let (shown, debug) = (err.to_string(), format!("{err:?}"));
                for leaked in [shown.as_str(), debug.as_str()] {
                    assert!(
                        !leaked.to_lowercase().contains("canary"),
                        "the error echoed {base_url}: {leaked}"
                    );
                }
            }
            // The id is the same key: it is refused, never echoed.
            let text = format!(
                "[[providers]]\nid = \"{canary}\"\nkind = \"openai-compat\"\nbase_url = \"https://h.test/v1?x=1\"\nmodel = \"m\"\n"
            );
            let err = parse_providers(&text).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            for leaked in [shown.as_str(), debug.as_str()] {
                assert!(
                    !leaked.to_lowercase().contains("canary"),
                    "the error echoed the id: {leaked}"
                );
            }
            assert!(shown.contains("looks like a key"), "{shown}");
        }
    }

    #[test]
    fn a_key_encoded_once_four_or_ten_times_never_shows_in_a_url_or_id() {
        // The key stays out of the echo at 1, 4 and
        // 10 escape layers, in the query, the userinfo, the path and the id.
        for layers in [1usize, 4, 10] {
            // Built at runtime so no scanner sees a key literal.
            let raw = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
            let key = format!(
                "%{}{:02x}{}",
                "25".repeat(layers - 1),
                raw.as_bytes()[0],
                &raw[1..]
            );
            assert_eq!(shown_id(&key), "<id>");
            for (url, kept) in [
                (format!("https://h.test/v1?api_key={key}"), "?<redacted>"),
                (format!("https://u:{key}@h.test/v1"), "<redacted>"),
                (format!("http://h.test/v1/{key}/chat"), "<redacted>"),
            ] {
                let shown = shown_url(&reqwest::Url::parse(&url).unwrap());
                assert!(!shown.to_lowercase().contains("canary"), "{url}: {shown}");
                assert!(shown.contains(kept), "{url}: {shown}");
            }
        }
    }

    #[test]
    fn a_value_still_changing_at_the_cap_shows_the_placeholder() {
        // 40 nested escapes: 32 rounds are not enough to settle, so the value
        // is never quoted — a fixed "[hidden]" takes its place.
        let value = format!("%{}73", "25".repeat(39));
        // The kernel may now settle the value and hide it
        // as a key ("<id>"); either fixed placeholder keeps it unquoted.
        let id = shown_id(&value);
        assert!(id == "[hidden]" || id == "<id>", "{id}");
        let url = reqwest::Url::parse(&format!("http://h.test/{value}")).unwrap();
        let shown = shown_url(&url);
        assert!(
            shown == "http://h.test/[hidden]" || shown == "http://h.test/<redacted>",
            "{shown}"
        );
    }

    #[test]
    fn a_normal_url_and_id_still_show() {
        assert_eq!(shown_id("deepseek"), "`deepseek`");
        assert_eq!(
            shown_base_url("https://api.deepseek.com/v1"),
            "https://api.deepseek.com/v1"
        );
    }

    #[test]
    fn debug_never_shows_a_key_in_a_provider_config() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let config = ProviderConfig {
            id: key.clone(),
            base_url: format!("https://api.example.com/v1/{key}"),
            model: "m".to_string(),
            key_user: Some("k".to_string()),
            kind: ProviderKind::OpenAiCompat,
            disable_thinking: false,
        };
        let text = format!("{config:?}");
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn a_megabyte_of_nested_escapes_is_hidden_and_the_work_stays_bounded() {
        // A value that nests its escapes
        // deeply must not make the decoder work without bound. The decoder
        // stops at its budget while the text is still changing, so the value
        // is hidden — and it stops fast.
        let canary = format!("%25{}73k-proj-CANARY-7f3k9q", "25".repeat(98));
        let value = format!("{canary}{}", "x".repeat(1_000_000 - canary.len()));
        let started = std::time::Instant::now();
        let shown = shown_id(&value);
        let elapsed = started.elapsed();
        // Hidden either at the decode cap or as a key.
        assert!(shown == "[hidden]" || shown == "<id>", "{shown}");
        assert!(!shown.to_lowercase().contains("canary"), "{shown}");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the decoder took {elapsed:?} on a megabyte"
        );
    }

    #[test]
    fn missing_providers_section_is_empty() {
        let providers = parse_providers("version = 1\nlog_level = \"info\"\n").unwrap();
        assert!(providers.is_empty());
    }

    #[test]
    fn rejects_unknown_kind() {
        let err = parse_providers(&minimal_toml("anthropic")).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn rejects_missing_model() {
        let text = r#"
            [[providers]]
            id = "deepseek"
            base_url = "https://api.deepseek.com/v1"
            kind = "openai-compat"
        "#;
        let err = parse_providers(text).unwrap_err();
        // The field now defaults to empty; validation rejects it.
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("model")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_ids() {
        let text = format!("{}{}", minimal_toml("openai-compat"), minimal_toml("fake"));
        let err = parse_providers(&text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("duplicate")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_invalid_base_url() {
        let text =
            minimal_toml("openai-compat").replace("https://api.deepseek.com/v1", "not a url");
        let err = parse_providers(&text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("deepseek")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_http_base_url() {
        let text = minimal_toml("openai-compat")
            .replace("https://api.deepseek.com/v1", "ftp://example.com/v1");
        let err = parse_providers(&text).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
    }

    #[test]
    fn rejects_query_or_fragment_in_base_url() {
        for bad in [
            "https://api.deepseek.com/v1?x=1",
            "https://api.deepseek.com/v1#frag",
        ] {
            let text = minimal_toml("openai-compat").replace("https://api.deepseek.com/v1", bad);
            let err = parse_providers(&text).unwrap_err();
            assert!(
                matches!(&err, ConfigError::Invalid(message) if message.contains("query or fragment")),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_userinfo_in_base_url() {
        let text = minimal_toml("openai-compat").replace(
            "https://api.deepseek.com/v1",
            "https://user:pass@api.deepseek.com/v1",
        );
        let err = parse_providers(&text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("userinfo")),
            "got {err:?}"
        );
        let message = err.to_string();
        assert!(
            !message.contains("pass"),
            "error must not echo the password: {message}"
        );
    }

    /// Bite proof: without the scheme check a provider key is sent in
    /// cleartext to any remote host.
    #[test]
    fn remote_cleartext_base_url_is_refused_loopback_is_kept() {
        for bad in [
            "http://api.deepseek.com/v1",
            "http://192.168.1.10:8080/v1",
            "http://[2001:db8::1]:8080/v1",
        ] {
            let text = minimal_toml("openai-compat").replace("https://api.deepseek.com/v1", bad);
            let err = parse_providers(&text).unwrap_err();
            assert!(
                matches!(&err, ConfigError::Invalid(message) if message.contains("https")),
                "{bad}: got {err:?}"
            );
        }
        for good in [
            "http://127.0.0.1:9/v1",
            "http://localhost:11434/v1",
            "http://[::1]:11434/v1",
        ] {
            let text = minimal_toml("openai-compat").replace("https://api.deepseek.com/v1", good);
            let providers = parse_providers(&text)
                .unwrap_or_else(|err| panic!("{good} must be accepted: {err:?}"));
            assert_eq!(providers.len(), 1);
        }
        // Any remote endpoint stays usable over TLS.
        let text = chat_completions_url("https://api.deepseek.com/v1").unwrap();
        assert_eq!(text, "https://api.deepseek.com/v1/chat/completions");
    }

    #[test]
    fn config_errors_do_not_echo_control_characters() {
        // A bad base_url with TOML escapes must not split stderr.
        let text =
            minimal_toml("openai-compat").replace("https://api.deepseek.com/v1", "not\\turl");
        let err = parse_providers(&text).unwrap_err();
        let message = err.to_string();
        assert!(
            !message.contains('\t') && !message.contains('\n'),
            "control characters leaked: {message:?}"
        );
    }

    #[test]
    fn rejects_empty_id() {
        let text = minimal_toml("openai-compat").replace("id = \"deepseek\"", "id = \"  \"");
        let err = parse_providers(&text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("id")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_empty_key_user() {
        let text =
            minimal_toml("openai-compat").replace("key_user = \"deepseek\"", "key_user = \"\"");
        let err = parse_providers(&text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("key_user")),
            "got {err:?}"
        );
    }

    #[test]
    fn chat_completions_url_appends_path() {
        assert_eq!(
            chat_completions_url("https://api.deepseek.com/v1").unwrap(),
            "https://api.deepseek.com/v1/chat/completions"
        );
        assert_eq!(
            chat_completions_url("https://api.deepseek.com/v1/").unwrap(),
            "https://api.deepseek.com/v1/chat/completions"
        );
        assert_eq!(
            chat_completions_url("http://localhost:1234/v1").unwrap(),
            "http://localhost:1234/v1/chat/completions"
        );
    }

    #[test]
    fn load_providers_reads_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, minimal_toml("openai-compat")).unwrap();

        let providers = load_providers(&path).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, "deepseek");
    }

    #[test]
    fn load_providers_missing_file_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_providers(&dir.path().join("missing.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }), "got {err:?}");
    }

    #[test]
    fn build_provider_with_key_uses_configured_model_endpoint_and_name() {
        let providers = parse_providers(&minimal_toml("openai-compat")).unwrap();
        let provider = providers[0]
            .build_provider_with_key(Some("k".into()))
            .unwrap();
        assert_eq!(provider.name(), "deepseek");
    }

    #[tokio::test]
    async fn build_provider_for_fake_kind_echoes_deterministically() {
        let text = minimal_toml("fake").replace("key_user = \"deepseek\"\n", "");
        let providers = parse_providers(&text).unwrap();
        let provider = providers[0].build_provider().unwrap();
        assert_eq!(provider.name(), "deepseek");

        let ping = crate::types::SafeMessage::issue(
            &mut tokenising_gate([5u8; 32]),
            &crate::types::ChatMessage::user("ping"),
        )
        .unwrap();
        let request = crate::types::ChatRequest::new(vec![ping]);
        let first = provider.complete(&request).await.unwrap();
        let second = provider.complete(&request).await.unwrap();
        assert_eq!(first.content(), "[fake:deepseek] ping");
        assert_eq!(first, second);
    }
}
