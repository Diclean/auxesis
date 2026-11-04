//! Provider adapters for Auxesis — chat providers (OpenAI-compatible + fake).
//!
//! The interface contract lives in `docs/providers.md`.
//!
//! The crate is built around the object-safe [`ChatProvider`] trait. Two
//! adapters ship:
//!
//! - [`OpenAiCompat`] — the OpenAI `chat/completions` wire, used for DeepSeek,
//!   LM Studio, OpenRouter and every other OpenAI-compatible
//!   endpoint. Implements SSE streaming (`complete_streaming`) with a
//!   non-streaming fallback when the endpoint refuses it.
//! - The `ollama` [`preset`] — the same adapter pointed at the local Ollama
//!   server (`/v1`, no key), selected with `[brain] preset = "ollama"`.
//! - [`FakeProvider`] — deterministic scripted responses for tests and the
//!   sandbox. No network, no keys.
//!
//! API keys are never stored in config files: [`ProviderConfig`] only carries
//! a `key_user` reference. [`resolve_key`] looks up the macOS Keychain first
//! (service `auxesis`) and falls back to `AUX_KEY_<UPPER_ID>` for dev/tests.
//!
//! Requests carry only gated text: a [`SafeMessage`] is issued from a local
//! [`ChatMessage`] through the privacy gate, never from a raw `String`.
//!
//! ```
//! use aux_providers::{ChatMessage, ChatProvider, ChatRequest, ChatResponse, FakeProvider, SafeMessage};
//! use kernel_core::privacy::{admit_call, Destination, PathId, PrivacyMode};
//! use kernel_privacy::safetext::Gate;
//!
//! let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));
//! assert_eq!(provider.name(), "fake");
//! let grant = admit_call(PathId::A2, PrivacyMode::Open, Destination::Vendor("fake".into())).unwrap();
//! let mut gate = Gate::for_grant(&grant, [3u8; 32]);
//! let hello = SafeMessage::issue(&mut gate, &ChatMessage::user("hello")).unwrap();
//! let _request = ChatRequest::new(vec![hello]);
//! ```

pub mod anthropic;
pub mod brain;
pub mod catalog;
pub mod config;
pub mod error;
pub mod fake;
pub mod fallback;
pub mod key;
pub mod openai_compat;
pub mod preset;
mod privacy_wiring;
pub mod provider;
pub mod providers_toml;
#[cfg(any(test, feature = "test-util"))]
pub mod test_gate;
pub mod types;

pub use anthropic::AnthropicCompat;
pub use async_trait::async_trait;
pub use brain::{
    build_chain, build_chain_noop, build_entry, build_resolved, find_entry, resolve_brain,
    BrainError, ResolvedBrain,
};
pub use catalog::{gate_skill_tools, Catalog, ChatOnly, ModelRow};
pub use config::{
    chat_completions_url, load_providers, parse_providers, provider_name_is_key_shaped,
    shown_base_url, shown_id_plain, ConfigError, ProviderConfig, ProviderKind,
    KEY_SHAPED_PROVIDER_NAME,
};
pub use error::ProviderError;
pub use fake::FakeProvider;
pub use fallback::{
    fallback_reason, is_fallback_eligible, FallbackAdmission, FallbackHop, FallbackLedger,
    FallbackProvider, KernelFallbackAdmission, NoopAdmission, NoopLedger, RecordingLedger,
};
pub use key::{
    env_var_name, resolve_key, resolve_key_full, resolve_key_with, set_in_env_file, AgentEnvStore,
    KeyError, KeychainStore, SecretStore, ENV_FILE, KEYCHAIN_SERVICE,
};
pub use openai_compat::{OpenAiCompat, DEFAULT_TIMEOUT};
pub use preset::{
    BrainSection, OLLAMA_BASE_URL, OLLAMA_DEFAULT_MODEL, OLLAMA_MODEL_ENV, OLLAMA_PROVIDER_ID,
};
pub use privacy_wiring::GatedChat;
pub use provider::{ChatProvider, Contact};
pub use providers_toml::{
    load_providers_for_home, load_providers_toml, migrate_legacy_config, parse_providers_toml,
    resolve_entry_key, BrainConfig, Effort, EntryKind, MigrationOutcome, ProviderEntry,
    ProvidersFile, PROVIDERS_FILE,
};
pub use types::{
    ChatDelta, ChatMessage, ChatRequest, ChatResponse, ChatRole, ModelId, ModelIdError,
    SafeMessage, SafeToolCall, SafeToolSpec, ToolCall, ToolSpec, Usage,
};
