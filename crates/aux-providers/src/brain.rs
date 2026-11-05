//! Brain selection and the provider chain (`docs/providers.md` §3).
//!
//! Resolution order, first hit wins: skill front matter `brain:` → agent
//! `agent.md` `brain:` → `[brain] default`. A skill `brain:` may be a hint
//! (`cheap`, `strong`, `none`) mapped in `[brain.hints]`; an unmapped hint
//! falls through. `none` means the skill runs without a model.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::anthropic::AnthropicCompat;
use crate::catalog::{gate_skill_tools, Catalog, ChatOnly};
use crate::config::{build_fake, shown_id_plain, ConfigError, ProviderConfig, ProviderKind};
use crate::error::ProviderError;
use crate::fallback::{FallbackAdmission, FallbackLedger, FallbackProvider, NoopLedger};
use crate::openai_compat::OpenAiCompat;
use crate::provider::ChatProvider;
use crate::providers_toml::{
    resolve_entry_key, EntryKind, ProviderEntry, ProvidersFile, DEFAULT_OLLAMA_BASE_URL,
};

/// A resolved brain: a concrete provider/model, or "no model".
#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedBrain {
    /// Run against this provider and model.
    Model {
        /// Provider id.
        provider: String,
        /// Model id.
        model: String,
    },
    /// Run without a model (`brain: none`).
    None,
}

impl fmt::Debug for ResolvedBrain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model { provider, model } => f
                .debug_struct("Model")
                .field("provider", &shown_id_plain(provider))
                .field("model", &shown_id_plain(model))
                .finish(),
            Self::None => f.write_str("None"),
        }
    }
}

impl ResolvedBrain {
    /// The provider id, when there is one.
    pub fn provider(&self) -> Option<&str> {
        match self {
            Self::Model { provider, .. } => Some(provider),
            Self::None => None,
        }
    }

    /// The model id, when there is one.
    pub fn model(&self) -> Option<&str> {
        match self {
            Self::Model { model, .. } => Some(model),
            Self::None => None,
        }
    }
}

/// Why a brain reference could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum BrainError {
    /// The provider configuration is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The provider named by `<provider>/<model>` does not exist.
    #[error("brain reference names unknown provider `{0}`")]
    UnknownProvider(String),
    /// The model is not in the provider's allowlist.
    #[error("provider `{provider}` does not allow model `{model}`")]
    ModelNotAllowed {
        /// Provider id.
        provider: String,
        /// Refused model.
        model: String,
    },
    /// A bare provider id resolved but no model is known for it.
    #[error(
        "provider `{0}` has no model: name one as `<provider>/<model>` or add a models allowlist"
    )]
    NoModel(String),
    /// An ACP entry is not a completion provider.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The model cannot use tools but the skill needs them.
    #[error(transparent)]
    ChatOnly(#[from] ChatOnly),
}

/// Find a provider entry by id.
pub fn find_entry<'a>(file: &'a ProvidersFile, id: &str) -> Option<&'a ProviderEntry> {
    file.providers.iter().find(|entry| entry.id == id)
}

/// Resolve one brain reference. `Ok(None)` means "not a brain" (an unmapped
/// hint) and the caller falls through to the next level.
fn resolve_reference(
    file: &ProvidersFile,
    catalog: &Catalog,
    reference: &str,
) -> Result<Option<ResolvedBrain>, BrainError> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Ok(None);
    }
    if reference.eq_ignore_ascii_case("none") {
        return Ok(Some(ResolvedBrain::None));
    }
    if let Some(mapped) = file.brain.hints.get(reference) {
        return resolve_mapped(file, catalog, mapped);
    }
    resolve_mapped(file, catalog, reference)
}

fn resolve_mapped(
    file: &ProvidersFile,
    catalog: &Catalog,
    reference: &str,
) -> Result<Option<ResolvedBrain>, BrainError> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Ok(None);
    }
    if reference.eq_ignore_ascii_case("none") {
        return Ok(Some(ResolvedBrain::None));
    }
    if let Some((provider, model)) = reference.split_once('/') {
        let entry = find_entry(file, provider)
            .ok_or_else(|| BrainError::UnknownProvider(shown_id_plain(provider)))?;
        check_model_allowed(entry, model)?;
        return Ok(Some(ResolvedBrain::Model {
            provider: provider.to_string(),
            model: model.to_string(),
        }));
    }
    if let Some(entry) = find_entry(file, reference) {
        let model = entry
            .first_model()
            .map(str::to_string)
            .or_else(|| {
                catalog
                    .rows()
                    .iter()
                    .find(|row| row.provider == entry.id)
                    .map(|row| row.id.clone())
            })
            // An ACP entry has no model: the agent picks its own default, so a
            // bare provider id resolves with an empty model.
            .or_else(|| (entry.kind == EntryKind::Acp).then(String::new))
            .ok_or_else(|| BrainError::NoModel(shown_id_plain(&entry.id)))?;
        return Ok(Some(ResolvedBrain::Model {
            provider: entry.id.clone(),
            model,
        }));
    }
    // A bare word that is neither a provider nor a mapped hint: fall through.
    Ok(None)
}

fn check_model_allowed(entry: &ProviderEntry, model: &str) -> Result<(), BrainError> {
    if !entry.models.is_empty() && !entry.models.iter().any(|allowed| allowed == model) {
        return Err(BrainError::ModelNotAllowed {
            provider: shown_id_plain(&entry.id),
            model: shown_id_plain(model),
        });
    }
    Ok(())
}

/// Resolve the brain for one turn: skill → agent → `[brain] default`.
pub fn resolve_brain(
    file: &ProvidersFile,
    catalog: &Catalog,
    agent_brain: Option<&str>,
    skill_brain: Option<&str>,
) -> Result<ResolvedBrain, BrainError> {
    if let Some(skill) = skill_brain {
        if let Some(resolved) = resolve_reference(file, catalog, skill)? {
            return Ok(resolved);
        }
    }
    if let Some(agent) = agent_brain {
        if let Some(resolved) = resolve_reference(file, catalog, agent)? {
            return Ok(resolved);
        }
    }
    if let Some(default) = &file.brain.default {
        if let Some(resolved) = resolve_reference(file, catalog, default)? {
            return Ok(resolved);
        }
    }
    Ok(ResolvedBrain::None)
}

/// Build the adapter for one entry, resolving the key from its `env:` ref.
pub fn build_entry(
    entry: &ProviderEntry,
    model: &str,
    home: &Path,
) -> Result<Box<dyn ChatProvider>, ProviderError> {
    match entry.kind {
        EntryKind::Fake => build_fake(&entry.id),
        EntryKind::Acp => Err(ProviderError::AcpBackend {
            provider: shown_id_plain(&entry.id),
        }),
        EntryKind::Openai => {
            let base = entry.base_url.clone().unwrap_or_default();
            let config = legacy_config(entry, base, model);
            let key = resolve_entry_key(entry, home)?;
            Ok(Box::new(OpenAiCompat::with_key(&config, key)?))
        }
        EntryKind::Ollama => {
            let base = entry.base_url.as_deref().unwrap_or(DEFAULT_OLLAMA_BASE_URL);
            let config = legacy_config(entry, format!("{}/v1", base.trim_end_matches('/')), model);
            Ok(Box::new(
                OpenAiCompat::with_key(&config, None)?.local_runtime(),
            ))
        }
        EntryKind::Anthropic => Ok(Box::new(AnthropicCompat::new(entry, model, home)?)),
    }
}

fn legacy_config(entry: &ProviderEntry, base_url: String, model: &str) -> ProviderConfig {
    ProviderConfig {
        id: entry.id.clone(),
        base_url,
        model: model.to_string(),
        key_user: None,
        kind: ProviderKind::OpenAiCompat,
        disable_thinking: entry.disable_thinking,
    }
}

/// Build the completion provider for a resolved brain.
pub fn build_resolved(
    file: &ProvidersFile,
    resolved: &ResolvedBrain,
    home: &Path,
) -> Result<Option<Box<dyn ChatProvider>>, BrainError> {
    match resolved {
        ResolvedBrain::None => Ok(None),
        ResolvedBrain::Model { provider, model } => {
            let entry = find_entry(file, provider)
                .ok_or_else(|| BrainError::UnknownProvider(shown_id_plain(provider)))?;
            Ok(Some(build_entry(entry, model, home)?))
        }
    }
}

/// Resolve the brain, gate it for the skill's tool needs, and build the chain:
/// the resolved provider followed by `[brain] fallback` entries.
///
/// A tool-requiring skill is refused with `chat only` **before any request**,
/// and a fallback that cannot use tools is skipped for such a skill.
// One documented builder: file, catalog, home, ledger, admission, agent brain,
// skill brain, tool need.
#[allow(clippy::too_many_arguments)]
pub fn build_chain(
    file: &ProvidersFile,
    catalog: &Catalog,
    home: &Path,
    ledger: Arc<dyn FallbackLedger>,
    admission: Option<Arc<dyn FallbackAdmission>>,
    agent_brain: Option<&str>,
    skill_brain: Option<&str>,
    needs_tools: bool,
) -> Result<Option<Box<dyn ChatProvider>>, BrainError> {
    let resolved = resolve_brain(file, catalog, agent_brain, skill_brain)?;
    let ResolvedBrain::Model { provider, model } = &resolved else {
        return Ok(None);
    };
    gate_skill_tools(catalog, provider, model, needs_tools)?;

    let entry = find_entry(file, provider)
        .ok_or_else(|| BrainError::UnknownProvider(shown_id_plain(provider)))?;
    let mut chain: Vec<Box<dyn ChatProvider>> = vec![build_entry(entry, model, home)?];

    for fallback in &file.brain.fallback {
        let Some(ResolvedBrain::Model { provider, model }) =
            resolve_reference(file, catalog, fallback)?
        else {
            continue;
        };
        if needs_tools && !catalog.has_tools(&provider, &model) {
            continue;
        }
        let Some(entry) = find_entry(file, &provider) else {
            continue;
        };
        chain.push(build_entry(entry, &model, home)?);
    }

    if chain.len() == 1 {
        Ok(Some(chain.pop().expect("one provider")))
    } else {
        // A gated chain admits every fallback destination live before its hop
        // `None` keeps the Open-only chain.
        let provider: Box<dyn ChatProvider> = match admission {
            Some(admission) => Box::new(FallbackProvider::with_admission(chain, ledger, admission)),
            None => Box::new(FallbackProvider::with_ledger(chain, ledger)),
        };
        Ok(Some(provider))
    }
}

/// A chain with no Ledger sink, for callers that do not write one.
pub fn build_chain_noop(
    file: &ProvidersFile,
    catalog: &Catalog,
    home: &Path,
    agent_brain: Option<&str>,
    skill_brain: Option<&str>,
    needs_tools: bool,
) -> Result<Option<Box<dyn ChatProvider>>, BrainError> {
    build_chain(
        file,
        catalog,
        home,
        Arc::new(NoopLedger),
        None,
        agent_brain,
        skill_brain,
        needs_tools,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers_toml::parse_providers_toml;

    fn file() -> ProvidersFile {
        let text = r#"
[[provider]]
id = "deepseek"
kind = "openai"
base_url = "https://api.deepseek.com/v1"
key = "env:AUX_KEY_DEEPSEEK"
models = ["deepseek-chat"]

[[provider]]
id = "anthropic"
kind = "anthropic"
base_url = "https://api.anthropic.com"
key = "env:AUX_KEY_ANTHROPIC"
models = ["claude-haiku-5-5"]

[[provider]]
id = "opencode"
kind = "acp"
agent = "opencode"

[[provider]]
id = "chatty"
kind = "openai"
base_url = "http://127.0.0.1:9/v1"
models = ["no-tools-model"]

[brain]
default = "deepseek/deepseek-chat"
fallback = ["anthropic/claude-haiku-5-5"]
hints = { strong = "anthropic/claude-haiku-5-5" }
"#;
        parse_providers_toml(text).unwrap()
    }

    fn catalog() -> Catalog {
        Catalog::parse(
            r#"
[[model]]
provider = "deepseek"
id = "deepseek-chat"
tools = true
[[model]]
provider = "anthropic"
id = "claude-haiku-5-5"
tools = true
[[model]]
provider = "chatty"
id = "no-tools-model"
tools = false
"#,
        )
        .unwrap()
    }

    #[test]
    fn skill_beats_agent_beats_default() {
        let file = file();
        let catalog = catalog();
        assert_eq!(
            resolve_brain(&file, &catalog, Some("anthropic/claude-haiku-5-5"), None).unwrap(),
            ResolvedBrain::Model {
                provider: "anthropic".into(),
                model: "claude-haiku-5-5".into()
            }
        );
        assert_eq!(
            resolve_brain(&file, &catalog, None, None).unwrap(),
            ResolvedBrain::Model {
                provider: "deepseek".into(),
                model: "deepseek-chat".into()
            }
        );
    }

    #[test]
    fn a_hint_maps_and_an_unmapped_hint_falls_through() {
        let file = file();
        let catalog = catalog();
        assert_eq!(
            resolve_brain(&file, &catalog, None, Some("strong")).unwrap(),
            ResolvedBrain::Model {
                provider: "anthropic".into(),
                model: "claude-haiku-5-5".into()
            }
        );
        // `cheap` is not mapped: fall through to the default.
        assert_eq!(
            resolve_brain(&file, &catalog, None, Some("cheap")).unwrap(),
            ResolvedBrain::Model {
                provider: "deepseek".into(),
                model: "deepseek-chat".into()
            }
        );
    }

    #[test]
    fn none_means_no_model() {
        let file = file();
        let catalog = catalog();
        assert_eq!(
            resolve_brain(&file, &catalog, None, Some("none")).unwrap(),
            ResolvedBrain::None
        );
    }

    #[test]
    fn an_unknown_provider_in_an_explicit_reference_is_an_error() {
        let file = file();
        let catalog = catalog();
        let err = resolve_brain(&file, &catalog, None, Some("ghost/model")).unwrap_err();
        assert!(matches!(err, BrainError::UnknownProvider(id) if id == "ghost"));
    }

    #[test]
    fn a_model_outside_the_allowlist_is_refused() {
        let file = file();
        let catalog = catalog();
        let err = resolve_brain(&file, &catalog, None, Some("deepseek/other")).unwrap_err();
        assert!(
            matches!(err, BrainError::ModelNotAllowed { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_refused_key_shaped_model_never_shows_in_the_error() {
        let file = file();
        let catalog = catalog();
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let err =
            resolve_brain(&file, &catalog, None, Some(&format!("deepseek/{key}"))).unwrap_err();
        assert!(
            matches!(err, BrainError::ModelNotAllowed { .. }),
            "got {err:?}"
        );
        for text in [format!("{err}"), format!("{err:?}")] {
            assert!(!text.contains("CANARY"), "{text}");
        }
    }

    #[test]
    fn debug_never_shows_a_key_in_a_resolved_brain() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let brain = ResolvedBrain::Model {
            provider: key,
            model: "m".to_string(),
        };
        let text = format!("{brain:?}");
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn a_bare_provider_id_uses_its_first_allowlisted_model() {
        let file = file();
        let catalog = catalog();
        assert_eq!(
            resolve_brain(&file, &catalog, None, Some("deepseek")).unwrap(),
            ResolvedBrain::Model {
                provider: "deepseek".into(),
                model: "deepseek-chat".into()
            }
        );
    }

    #[test]
    fn a_tool_skill_on_a_tools_less_brain_is_refused_before_building() {
        let file = file();
        let catalog = catalog();
        let result = build_chain(
            &file,
            &catalog,
            Path::new("/nonexistent"),
            Arc::new(NoopLedger),
            None,
            None,
            Some("chatty/no-tools-model"),
            true,
        );
        let Err(err) = result else {
            panic!("expected a chat-only refusal");
        };
        assert!(matches!(err, BrainError::ChatOnly(_)), "got {err:?}");
    }
}
