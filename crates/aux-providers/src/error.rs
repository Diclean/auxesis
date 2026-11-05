//! Provider errors shared by every adapter.

use std::time::Duration;

use thiserror::Error;

use crate::config::ConfigError;
use crate::key::KeyError;

/// Errors returned by [`crate::ChatProvider`] implementations.
///
/// HTTP statuses are mapped to dedicated variants so callers can react to
/// them (retry on 429, surface an auth problem on 401, …) without parsing
/// strings. The provider id is sanitized before it enters a message, never the
/// secret.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// The provider rejected the API key (HTTP 401).
    #[error("provider `{provider}` rejected the API key (HTTP 401)")]
    Unauthorized {
        /// Provider id from the configuration.
        provider: String,
    },
    /// The provider rate limited the request (HTTP 429).
    #[error("provider `{provider}` rate limited the request (HTTP 429)")]
    RateLimited {
        /// Provider id from the configuration.
        provider: String,
        /// Value of the `Retry-After` header, when it was a number of seconds.
        retry_after: Option<Duration>,
    },
    /// The provider returned a server error (HTTP 5xx).
    #[error("provider `{provider}` returned a server error (HTTP {status})")]
    Server {
        /// Provider id from the configuration.
        provider: String,
        /// HTTP status code.
        status: u16,
    },
    /// The provider returned any other non-success status (usually 4xx).
    #[error("provider `{provider}` request failed (HTTP {status}): {message}")]
    Client {
        /// Provider id from the configuration.
        provider: String,
        /// HTTP status code.
        status: u16,
        /// Error message extracted from the response body.
        message: String,
    },
    /// The request failed before a valid HTTP response was received.
    #[error("provider `{provider}` request failed: {source}")]
    Request {
        /// Provider id from the configuration.
        provider: String,
        /// Underlying transport error, with its URL stripped.
        #[source]
        source: reqwest::Error,
    },
    /// The request exceeded the configured timeout.
    #[error("provider `{provider}` timed out")]
    Timeout {
        /// Provider id from the configuration.
        provider: String,
    },
    /// The local Ollama server is not listening. The message is bilingual
    /// (EN/FR) because it is shown to the owner as-is.
    #[error(
        "Ollama is not running. Start it (`ollama serve`) and try again. \
         / Ollama n'est pas lancé. Démarrez-le (`ollama serve`) puis réessayez."
    )]
    OllamaNotRunning {
        /// Provider id from the configuration.
        provider: String,
    },
    /// The response was successful but not parseable as a chat completion.
    #[error("provider `{provider}` returned an invalid response: {message}")]
    InvalidResponse {
        /// Provider id from the configuration.
        provider: String,
        /// What could not be parsed.
        message: String,
    },
    /// The fake provider ran out of scripted responses.
    #[error("provider `{provider}` script exhausted: no scripted response left")]
    ScriptExhausted {
        /// Provider id from the configuration.
        provider: String,
    },
    /// A `fake` provider was configured, but this build has no fake adapter.
    #[error(
        "provider `{provider}` is a fake provider, and this build does not include \
         the fake adapter (the `test-fake` feature is off); configure a real \
         AI service instead"
    )]
    FakeDisabled {
        /// Provider id from the configuration.
        provider: String,
    },
    /// The provider configuration is invalid.
    /// The privacy gate refused this call in the current mode.
    #[error("provider `{provider}` is disabled in private mode ({path})")]
    PrivacyDisabled {
        /// Provider id from the configuration.
        provider: String,
        /// Privacy path id that refused the call (`A1` or `A2`).
        path: &'static str,
    },

    /// The provider refused to answer on safety grounds (Anthropic
    /// `stop_reason: "refusal"`). A typed error, never a fallback trigger
    /// (`docs/providers.md` §5.1/§6). The message carries only the category,
    /// never the content.
    #[error("provider `{provider}` refused the request ({category})")]
    Refused {
        /// Provider id from the configuration.
        provider: String,
        /// Refusal category reported by the provider.
        category: String,
    },

    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The API key could not be looked up.
    #[error("key lookup failed: {0}")]
    Key(#[from] KeyError),
    /// The entry is an ACP agent: it runs as a turn-level backend, never as a
    /// completion [`crate::ChatProvider`].
    #[error(
        "provider `{provider}` is an ACP agent: it runs as a turn-level backend, \
         not as a ChatProvider"
    )]
    AcpBackend {
        /// Provider id from the configuration.
        provider: String,
    },
}

/// Redact the adapter's own resolved key from an upstream-supplied string
/// before it becomes part of a [`ProviderError`].
///
/// A provider that echoes its `x-api-key` or `Authorization` value in an error
/// body or an SSE `error` event must not have that value copied into an error
/// message, a `Display`, a `Debug` or a log. The adapter's key is replaced by
/// its exact value first (deterministic, independent of the global scrubber
/// state), then the kernel's registered-secret scrubber is applied for any
/// other known secret the upstream echoed.
pub(crate) fn redact_upstream(text: &str, key: Option<&str>) -> String {
    let direct = match key {
        Some(key) if !key.is_empty() => text.replace(key, "[REDACTED]"),
        _ => text.to_string(),
    };
    kernel_broker::scrub::redact_known_secrets(&direct).unwrap_or(direct)
}
