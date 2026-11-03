//! Local brain presets: the `[brain]` table in `config.toml`.
//!
//! A preset expands to one pre-filled `[[providers]]` entry. The `ollama`
//! preset points the OpenAI-compatible adapter at the local Ollama server
//! (`/v1`, no key). The model comes from `[brain] model`, and
//! `AUXESIS_OLLAMA_MODEL` overrides it. The endpoint must be loopback unless
//! the owner sets `allow_remote_base_url = true` explicitly.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{
    chat_completions_url, is_loopback_url, shown_base_url, shown_id_plain, ConfigError,
    ProviderConfig, ProviderKind,
};

/// Provider id given to the Ollama preset. The adapter reads it to report a
/// refused connection as [`crate::ProviderError::OllamaNotRunning`].
pub const OLLAMA_PROVIDER_ID: &str = "ollama";

/// Ollama's OpenAI-compatible API root on this machine.
pub const OLLAMA_BASE_URL: &str = "http://127.0.0.1:11434/v1";

/// Default local model: `granite3.3:2b`, Apache-2.0, and listed with the
/// `tools` capability on ollama.com/library (checked 2026-10-10).
pub const OLLAMA_DEFAULT_MODEL: &str = "granite3.3:2b";

/// Environment variable that overrides the Ollama model.
pub const OLLAMA_MODEL_ENV: &str = "AUXESIS_OLLAMA_MODEL";

/// The `[brain]` table of `config.toml`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrainSection {
    /// Preset name, e.g. `"ollama"`. Absent means no preset.
    #[serde(default)]
    pub preset: Option<String>,
    /// Model for the preset. `AUXESIS_OLLAMA_MODEL` takes precedence.
    #[serde(default)]
    pub model: Option<String>,
    /// Endpoint override for the preset. Must be loopback unless
    /// `allow_remote_base_url` is set.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Permit a non-loopback `base_url` for the preset. Off by default.
    #[serde(default)]
    pub allow_remote_base_url: bool,
}

impl fmt::Debug for BrainSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrainSection")
            .field("preset", &self.preset)
            .field("model", &self.model.as_deref().map(shown_id_plain))
            .field("base_url", &self.base_url.as_deref().map(shown_base_url))
            .field("allow_remote_base_url", &self.allow_remote_base_url)
            .finish()
    }
}

/// Expand the `[brain]` table into the provider entry it names, if any.
pub(crate) fn expand_brain(
    brain: &BrainSection,
    env_model: Option<&str>,
) -> Result<Option<ProviderConfig>, ConfigError> {
    match brain.preset.as_deref() {
        None => Ok(None),
        Some("ollama") => ollama_entry(brain, env_model).map(Some),
        Some(other) => Err(ConfigError::Invalid(format!(
            "unknown brain preset `{other}` (known: ollama)"
        ))),
    }
}

fn ollama_entry(
    brain: &BrainSection,
    env_model: Option<&str>,
) -> Result<ProviderConfig, ConfigError> {
    let model = env_model
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_string)
        .or_else(|| brain.model.clone())
        .unwrap_or_else(|| OLLAMA_DEFAULT_MODEL.to_string());
    let base_url = brain
        .base_url
        .clone()
        .unwrap_or_else(|| OLLAMA_BASE_URL.to_string());

    // Scheme, query and userinfo are checked by the URL rules first. Then the
    // loopback rule: a remote Ollama must be asked for by name.
    chat_completions_url(&base_url)?;
    if !is_loopback_url(&base_url) && !brain.allow_remote_base_url {
        let shown = shown_base_url(&base_url);
        return Err(ConfigError::Invalid(format!(
            "[brain] base_url `{shown}` is not a loopback address; the ollama preset \
             refuses remote endpoints unless allow_remote_base_url = true"
        )));
    }

    Ok(ProviderConfig {
        disable_thinking: false,
        id: OLLAMA_PROVIDER_ID.to_string(),
        base_url,
        model,
        key_user: None,
        kind: ProviderKind::OpenAiCompat,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ollama(base_url: Option<&str>, model: Option<&str>) -> BrainSection {
        BrainSection {
            preset: Some("ollama".to_string()),
            model: model.map(str::to_string),
            base_url: base_url.map(str::to_string),
            allow_remote_base_url: false,
        }
    }

    #[test]
    fn no_preset_expands_to_nothing() {
        let brain = BrainSection::default();
        assert_eq!(expand_brain(&brain, None).unwrap(), None);
    }

    #[test]
    fn debug_never_shows_a_key_in_a_brain_section() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let brain = ollama(Some(&format!("https://api.example.com/v1/{key}")), None);
        let text = format!("{brain:?}");
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    #[test]
    fn ollama_defaults_to_loopback_keyless_and_the_default_model() {
        let entry = expand_brain(&ollama(None, None), None).unwrap().unwrap();
        assert_eq!(entry.id, OLLAMA_PROVIDER_ID);
        assert_eq!(entry.base_url, OLLAMA_BASE_URL);
        assert_eq!(entry.model, OLLAMA_DEFAULT_MODEL);
        assert_eq!(entry.key_user, None);
        assert_eq!(entry.kind, ProviderKind::OpenAiCompat);
    }

    #[test]
    fn config_model_is_used_and_env_overrides_it() {
        let brain = ollama(None, Some("qwen3:1.7b"));
        let entry = expand_brain(&brain, None).unwrap().unwrap();
        assert_eq!(entry.model, "qwen3:1.7b");

        let entry = expand_brain(&brain, Some("  llama3.2:3b  "))
            .unwrap()
            .unwrap();
        assert_eq!(entry.model, "llama3.2:3b");
    }

    #[test]
    fn blank_env_model_is_ignored() {
        let brain = ollama(None, Some("qwen3:1.7b"));
        let entry = expand_brain(&brain, Some("   ")).unwrap().unwrap();
        assert_eq!(entry.model, "qwen3:1.7b");
    }

    #[test]
    fn remote_base_url_is_refused_unless_explicitly_allowed() {
        let remote = "https://ollama.example.com/v1";
        let err = expand_brain(&ollama(Some(remote), None), None).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("allow_remote_base_url")),
            "got {err:?}"
        );

        let mut brain = ollama(Some(remote), None);
        brain.allow_remote_base_url = true;
        let entry = expand_brain(&brain, None).unwrap().unwrap();
        assert_eq!(entry.base_url, remote);
    }

    #[test]
    fn a_key_in_a_refused_remote_base_url_never_shows() {
        // A key in the path is the same key: the refusal must quote the
        // sanitized URL, never the raw base_url.
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let url = format!("https://ollama.example.com/v1/{key}");
        let err = expand_brain(&ollama(Some(&url), None), None).unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        for out in [&shown, &debug] {
            assert!(!out.to_lowercase().contains("canary"), "{out}");
        }
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn loopback_override_is_allowed_without_the_flag() {
        let entry = expand_brain(&ollama(Some("http://localhost:9999/v1"), None), None)
            .unwrap()
            .unwrap();
        assert_eq!(entry.base_url, "http://localhost:9999/v1");
    }

    #[test]
    fn unknown_preset_is_refused() {
        let brain = BrainSection {
            preset: Some("anthropic".to_string()),
            ..BrainSection::default()
        };
        let err = expand_brain(&brain, None).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid(message) if message.contains("unknown brain preset")),
            "got {err:?}"
        );
    }
}
