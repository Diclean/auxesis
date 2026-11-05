//! The chat provider trait every adapter implements.

use async_trait::async_trait;

use crate::error::ProviderError;
use crate::types::{ChatDelta, ChatRequest, ChatResponse};

/// A chat completion backend.
///
/// The trait is object-safe (`Box<dyn ChatProvider>` works) and async via
/// [`async_trait`]. Implementations must never log or store API keys.
///
/// ```
/// use aux_providers::{ChatProvider, FakeProvider};
///
/// let provider: Box<dyn ChatProvider> = Box::new(FakeProvider::echo("main"));
/// assert_eq!(provider.name(), "main");
/// ```
#[async_trait]
pub trait ChatProvider: Send + Sync {
    /// Run one chat completion without streaming. See [`Self::complete_streaming`]
    /// for the streaming entry point; this stays the exact same call it always
    /// was (SSE false, one response body).
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError>;

    /// Run one chat completion, reporting incremental text as it arrives.
    ///
    /// `sink` is called zero or more times while the completion streams; every
    /// call is advisory, and the returned [`ChatResponse`] is the complete,
    /// authoritative result. This default implementation is the non-streaming
    /// fallback for providers that do not support SSE: it runs [`Self::complete`]
    /// and reports the whole answer as one [`ChatDelta::Text`] (then the
    /// assembled tool calls and usage, in that order), so a streaming front
    /// sees the same contract from every adapter.
    async fn complete_streaming(
        &self,
        req: &ChatRequest,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        let response = self.complete(req).await?;
        report_response(&response, sink);
        Ok(response)
    }

    /// Stable provider id (matches the `id` in the configuration).
    fn name(&self) -> &str;

    /// The provider's configured default model, when it has one.
    ///
    /// Used by the engine to price a completion against `[prices]` when the
    /// request does not carry an explicit model override. Adapters that do
    /// not model a completion (the fake) answer `None`.
    fn model(&self) -> Option<&str> {
        None
    }

    /// Host of this provider's configured HTTP endpoint, if it has one.
    fn endpoint_host(&self) -> Option<String> {
        None
    }

    /// Endpoint hosts contacted by this provider, in request order. Providers
    /// that make a single request can use the default; chains can report each
    /// destination they actually tried.
    fn endpoint_hosts(&self) -> Vec<String> {
        self.endpoint_host().into_iter().collect()
    }

    /// Every attempt this provider made, in order and never deduplicated, so
    /// a caller can slice out one round. `None` when it keeps no such log.
    fn contact_log(&self) -> Option<Vec<Contact>> {
        None
    }

    /// True only for a brain positively known to run on this Mac: a local
    /// runtime on a loopback endpoint serving a model with no cloud marker.
    fn on_this_mac(&self) -> bool {
        false
    }

    /// True only for the trusted subscription backend itself (Ollama Cloud
    /// at `https://ollama.com`), where a model the catalog marks as billed by
    /// subscription costs 0 cents per call. Any other endpoint sending the
    /// same model id is billed per call.
    fn subscription_billed(&self) -> bool {
        false
    }
}

/// One provider attempt: the host it went to (`None` when unknown) and
/// whether that brain is known to run on this Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub host: Option<String>,
    pub on_this_mac: bool,
}

/// Report a fully assembled response to a streaming sink, in the order the
/// trait's default [`ChatProvider::complete_streaming`] documents: the whole
/// text as one delta, then the assembled tool calls, then usage. Used by the
/// default implementation and by adapters that fall back to a non-streaming
/// call mid-flight, so both paths have the same observable contract.
pub fn report_response(response: &ChatResponse, sink: &(dyn Fn(ChatDelta) + Send + Sync)) {
    if !response.message.content.is_empty() {
        sink(ChatDelta::Text(response.message.content.clone()));
    }
    for call in &response.message.tool_calls {
        sink(ChatDelta::ToolCall(call.clone()));
    }
    if let Some(usage) = response.usage {
        sink(ChatDelta::Usage(usage));
    }
}
