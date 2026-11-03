//! BRAINCONFIG-DEBUG: a provider config never prints a raw endpoint URL, a
//! provider id or a model id through `Debug`.
//!
//! Every provider `Debug` impl renders its values through the public helpers
//! (`shown_base_url`, `shown_id_plain`). A key pasted in a URL, in an id or in
//! a model id therefore never reaches a log line, and a plain provider stays
//! readable.

use aux_providers::providers_toml::{BrainConfig, EntryKind, ProviderEntry, ProvidersFile};
use aux_providers::{
    AnthropicCompat, BrainSection, FakeProvider, OpenAiCompat, ProviderConfig, ProviderKind,
    ResolvedBrain,
};

/// A key-shaped value, built in pieces so this file never holds one.
fn key_shaped() -> String {
    ["sk", "-proj-", "CANARY-", "7f3k9q"].concat()
}

/// A base URL that carries a password and a key in its query.
fn leaky_base_url() -> String {
    ["https://user:", "secret", "@host/v1?key=", "abc"].concat()
}

/// A `providers.toml` entry whose URL and model a key can be pasted into.
fn entry(base_url: Option<&str>, models: &[&str]) -> ProviderEntry {
    ProviderEntry {
        id: "acme".to_string(),
        kind: EntryKind::Openai,
        base_url: base_url.map(str::to_string),
        key: Some("env:AUX_KEY_ACME".to_string()),
        models: models.iter().map(|model| (*model).to_string()).collect(),
        disable_thinking: false,
        effort: None,
        agent: None,
        allow_remote_base_url: false,
    }
}

/// The legacy `config.toml` entry, with the same values.
fn legacy_config() -> ProviderConfig {
    ProviderConfig {
        id: "acme".to_string(),
        base_url: leaky_base_url(),
        model: key_shaped(),
        key_user: None,
        kind: ProviderKind::OpenAiCompat,
        disable_thinking: false,
    }
}

/// The URL of a key never shows: no password, no query value.
#[test]
fn a_provider_config_debug_shows_neither_a_password_nor_a_query_key() {
    let file = ProvidersFile {
        providers: vec![entry(Some(&leaky_base_url()), &[&key_shaped()])],
        brain: BrainConfig::default(),
    };
    let text = format!("{file:?}");
    assert!(!text.contains("secret"), "{text}");
    assert!(!text.contains("abc"), "{text}");
    // The host stays readable: a sanitised URL is still a usable URL.
    assert!(text.contains("host"), "{text}");
}

/// A model id is a name, never a key: one pasted in the wrong field never
/// reaches a log line.
#[test]
fn a_provider_config_debug_never_shows_a_key_shaped_model_id() {
    let file = ProvidersFile {
        providers: vec![entry(Some(&leaky_base_url()), &[&key_shaped()])],
        brain: BrainConfig {
            default: Some(format!("acme/{}", key_shaped())),
            fallback: vec![format!("acme/{}", key_shaped())],
            hints: std::collections::BTreeMap::from([(
                "cheap".to_string(),
                format!("acme/{}", key_shaped()),
            )]),
        },
    };
    let text = format!("{file:?}");
    assert!(!text.to_lowercase().contains("canary"), "{text}");
}

/// The legacy `config.toml` entry behaves like the `providers.toml` one.
#[test]
fn a_legacy_provider_config_debug_never_shows_a_key_or_a_raw_url() {
    let text = format!("{:?}", legacy_config());
    assert!(!text.to_lowercase().contains("canary"), "{text}");
    assert!(!text.contains("secret"), "{text}");
    assert!(!text.contains("abc"), "{text}");
}

/// The `[brain]` preset of the legacy file is a provider config too.
#[test]
fn a_brain_preset_debug_never_shows_a_key_shaped_model_id() {
    let section = BrainSection {
        preset: Some("ollama".to_string()),
        model: Some(key_shaped()),
        base_url: Some(leaky_base_url()),
        allow_remote_base_url: false,
    };
    let text = format!("{section:?}");
    assert!(!text.to_lowercase().contains("canary"), "{text}");
    assert!(!text.contains("secret"), "{text}");
    assert!(!text.contains("abc"), "{text}");
}

/// The resolved brain names a provider and a model: both go through the
/// helpers.
#[test]
fn a_resolved_brain_debug_never_shows_a_key_shaped_model_id() {
    let brain = ResolvedBrain::Model {
        provider: "acme".to_string(),
        model: key_shaped(),
    };
    let text = format!("{brain:?}");
    assert!(!text.to_lowercase().contains("canary"), "{text}");
}

/// The live adapters print the same values: a key pasted as the model never
/// reaches a log line.
#[test]
fn an_adapter_debug_never_shows_a_key_shaped_model_id() {
    let config = ProviderConfig {
        base_url: "https://api.example.com/v1".to_string(),
        ..legacy_config()
    };
    let openai = OpenAiCompat::with_key(&config, Some("k".to_string())).unwrap();
    let text = format!("{openai:?}");
    assert!(!text.to_lowercase().contains("canary"), "{text}");

    let anthropic = AnthropicCompat::with_key(
        &ProviderEntry {
            kind: EntryKind::Anthropic,
            base_url: Some("https://api.anthropic.com".to_string()),
            models: Vec::new(),
            ..entry(None, &[])
        },
        &key_shaped(),
        Some("k".to_string()),
    )
    .unwrap();
    let text = format!("{anthropic:?}");
    assert!(!text.to_lowercase().contains("canary"), "{text}");

    let fake = FakeProvider::echo("acme").with_model(key_shaped());
    let text = format!("{fake:?}");
    assert!(!text.to_lowercase().contains("canary"), "{text}");
}

/// A plain provider stays readable: the host, the id and the model are what
/// makes a log line useful.
#[test]
fn a_plain_provider_stays_readable_in_a_debug_print() {
    let text = format!(
        "{:?}",
        entry(Some("https://api.example.com/v1"), &["acme-1"])
    );
    assert!(text.contains("acme"), "{text}");
    assert!(text.contains("https://api.example.com/v1"), "{text}");
    assert!(text.contains("acme-1"), "{text}");

    let config = ProviderConfig {
        base_url: "https://api.example.com/v1".to_string(),
        model: "acme-1".to_string(),
        ..legacy_config()
    };
    let text = format!("{config:?}");
    assert!(text.contains("acme"), "{text}");
    assert!(text.contains("https://api.example.com/v1"), "{text}");
    assert!(text.contains("acme-1"), "{text}");
}

/// No URL at all is a normal state (an ACP entry): the print must not panic.
#[test]
fn an_empty_base_url_never_panics_in_a_debug_print() {
    let without_url = ProviderEntry {
        kind: EntryKind::Acp,
        key: None,
        agent: Some("opencode".to_string()),
        ..entry(None, &[])
    };
    let text = format!("{without_url:?}");
    assert!(text.contains("base_url"), "{text}");

    let legacy = ProviderConfig {
        base_url: String::new(),
        model: String::new(),
        ..legacy_config()
    };
    let text = format!("{legacy:?}");
    assert!(text.contains("base_url"), "{text}");
}

/// The `key` field is a credential reference, but a literal can be pasted or
/// built directly: `Debug` says only that a key is set.
#[test]
fn a_provider_entry_debug_never_shows_its_key() {
    let mut pasted = entry(Some("https://api.example.com/v1"), &["acme-1"]);
    pasted.key = Some(key_shaped());
    let text = format!("{pasted:?}");
    assert!(!text.contains("CANARY"), "{text}");
    assert!(text.contains("[set]"), "{text}");

    let reference = format!("{:?}", entry(None, &[]));
    assert!(!reference.contains("AUX_KEY_ACME"), "{reference}");
}
