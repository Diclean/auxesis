//! Deterministic fake chat provider for tests and the sandbox.
//!
//! Compiled only with the off-by-default `test-fake` feature (tests and
//! sandbox builds). A release build has no fake adapter: a `fake` provider
//! entry is refused with [`crate::ProviderError::FakeDisabled`].
//!
//! No network, no keys. Three modes:
//!
//! - [`FakeProvider::scripted`] — returns the given responses in order, then
//!   fails with [`ProviderError::ScriptExhausted`].
//! - [`FakeProvider::repeating`] — always returns the same response.
//! - [`FakeProvider::echo`] — answers `[fake:<name>] <last user message>`,
//!   which is what the sandbox config uses.
//!
//! Streaming (`complete_streaming`) is deterministic too: by default the fake
//! reports the whole answer as one text delta (the provider-agnostic fallback
//! shape); [`FakeProvider::with_stream_chunks`] splits the answer into fixed
//! character chunks so front-ends and the coalescer can be tested without a
//! network or a timer.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::config::shown_id_plain;
use crate::error::ProviderError;
use crate::provider::ChatProvider;
use crate::types::{ChatDelta, ChatRequest, ChatResponse, ChatRole, Usage};

/// A deterministic in-process chat provider.
///
/// Every received request is recorded so tests can assert what the chat loop
/// sent (see [`FakeProvider::requests`]).
pub struct FakeProvider {
    name: String,
    /// Optional model id an adapter would use; exposed through
    /// [`ChatProvider::model`] so budget pricing can be exercised in tests.
    model: Option<String>,
    /// When set, `complete_streaming` splits the answer text into chunks of
    /// this many characters; `None` reports the whole answer as one delta.
    stream_chunk_size: Option<usize>,
    inner: Mutex<Inner>,
}

impl fmt::Debug for FakeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeProvider")
            .field("name", &shown_id_plain(&self.name))
            .field("model", &self.model.as_deref().map(shown_id_plain))
            .field("stream_chunk_size", &self.stream_chunk_size)
            .field("inner", &self.inner)
            .finish()
    }
}

#[derive(Debug)]
struct Inner {
    behavior: Behavior,
    requests: Vec<ChatRequest>,
}

#[derive(Debug)]
enum Behavior {
    Script(VecDeque<ChatResponse>),
    Repeat(ChatResponse),
    Echo,
}

impl FakeProvider {
    /// Return the given responses in order, then fail with
    /// [`ProviderError::ScriptExhausted`].
    pub fn scripted(name: impl Into<String>, responses: Vec<ChatResponse>) -> Self {
        Self {
            name: name.into(),
            model: None,
            stream_chunk_size: None,
            inner: Mutex::new(Inner {
                behavior: Behavior::Script(responses.into()),
                requests: Vec::new(),
            }),
        }
    }

    /// Always return `response`.
    pub fn repeating(name: impl Into<String>, response: ChatResponse) -> Self {
        Self {
            name: name.into(),
            model: None,
            stream_chunk_size: None,
            inner: Mutex::new(Inner {
                behavior: Behavior::Repeat(response),
                requests: Vec::new(),
            }),
        }
    }

    /// Echo the last user message as `[fake:<name>] <content>`.
    pub fn echo(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            model: None,
            stream_chunk_size: None,
            inner: Mutex::new(Inner {
                behavior: Behavior::Echo,
                requests: Vec::new(),
            }),
        }
    }

    /// Announce a model id (pricing/budget tests).
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Stream the answer in chunks of `size` characters (deterministic, no
    /// delay). Size 0 (or unset) reports the whole answer as one delta.
    pub fn with_stream_chunks(mut self, size: usize) -> Self {
        self.stream_chunk_size = (size > 0).then_some(size);
        self
    }

    /// Number of completions served so far.
    pub fn request_count(&self) -> usize {
        self.inner
            .lock()
            .expect("fake provider lock poisoned")
            .requests
            .len()
    }

    /// Snapshot of every request received so far, oldest first.
    pub fn requests(&self) -> Vec<ChatRequest> {
        self.inner
            .lock()
            .expect("fake provider lock poisoned")
            .requests
            .clone()
    }
}

#[async_trait]
impl ChatProvider for FakeProvider {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let mut inner = self.inner.lock().expect("fake provider lock poisoned");
        inner.requests.push(req.clone());

        let mut response = match &mut inner.behavior {
            Behavior::Script(queue) => {
                queue
                    .pop_front()
                    .ok_or_else(|| ProviderError::ScriptExhausted {
                        provider: shown_id_plain(&self.name),
                    })?
            }
            Behavior::Repeat(response) => response.clone(),
            Behavior::Echo => ChatResponse::assistant(echo_body(&self.name, req)),
        };
        // Deterministic counts unless the script pinned its own.
        if response.usage.is_none() {
            response.usage = Some(fake_usage(req, &response));
        }
        Ok(response)
    }

    async fn complete_streaming(
        &self,
        req: &ChatRequest,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        let response = self.complete(req).await?;
        let content = &response.message.content;
        match self.stream_chunk_size {
            Some(size) => {
                for chunk in content.chars().collect::<Vec<char>>().chunks(size) {
                    sink(ChatDelta::Text(chunk.iter().collect()));
                }
            }
            None if !content.is_empty() => sink(ChatDelta::Text(content.clone())),
            None => {}
        }
        for call in &response.message.tool_calls {
            sink(ChatDelta::ToolCall(call.clone()));
        }
        if let Some(usage) = response.usage {
            sink(ChatDelta::Usage(usage));
        }
        Ok(response)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }
}

/// Deterministic, obviously-fake usage: one "token" per character of the
/// prompt (every message) and of the completion text.
///
/// Deliberately different from the engine's `chars/4` estimate so tests can
/// tell provider-reported usage apart from the fallback.
fn fake_usage(request: &ChatRequest, response: &ChatResponse) -> Usage {
    Usage {
        prompt_tokens: request
            .messages
            .iter()
            .map(|message| message.content().as_str().chars().count() as u64)
            .sum(),
        completion_tokens: response.message.content.chars().count() as u64,
        cost_usd: None,
        cached_prompt_tokens: None,
    }
}

fn echo_body(provider: &str, req: &ChatRequest) -> String {
    match req
        .messages
        .iter()
        .rev()
        .find(|m| m.role() == ChatRole::User)
    {
        Some(message) => format!(
            "[fake:{}] {}",
            shown_id_plain(provider),
            message.content().as_str()
        ),
        None => format!("[fake:{}] no user message", shown_id_plain(provider)),
    }
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
    use crate::types::{ChatMessage, SafeMessage, ToolCall};
    use std::sync::Arc;

    /// Gate local messages into a request, as the engine does.
    fn gated(messages: Vec<ChatMessage>) -> ChatRequest {
        let mut gate = tokenising_gate([4u8; 32]);
        ChatRequest::new(
            messages
                .iter()
                .map(|message| SafeMessage::issue(&mut gate, message).unwrap())
                .collect(),
        )
    }

    fn user(content: &str) -> ChatRequest {
        gated(vec![ChatMessage::user(content)])
    }

    #[tokio::test]
    async fn scripted_returns_responses_in_order() {
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::assistant("one"),
                ChatResponse::assistant("two"),
            ],
        );

        assert_eq!(
            provider.complete(&user("a")).await.unwrap().content(),
            "one"
        );
        assert_eq!(
            provider.complete(&user("b")).await.unwrap().content(),
            "two"
        );
        assert_eq!(provider.request_count(), 2);
    }

    #[tokio::test]
    async fn scripted_exhaustion_is_an_error() {
        let provider = FakeProvider::scripted("fake", vec![ChatResponse::assistant("one")]);
        provider.complete(&user("a")).await.unwrap();

        let err = provider.complete(&user("b")).await.unwrap_err();
        assert!(
            matches!(&err, ProviderError::ScriptExhausted { provider } if provider == "fake"),
            "got {err:?}"
        );
        assert_eq!(provider.request_count(), 2);
    }

    #[tokio::test]
    async fn repeating_always_returns_the_same_response() {
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("steady"));
        assert_eq!(
            provider.complete(&user("a")).await.unwrap().content(),
            "steady"
        );
        assert_eq!(
            provider.complete(&user("b")).await.unwrap().content(),
            "steady"
        );
        assert_eq!(provider.request_count(), 2);
    }

    #[tokio::test]
    async fn echo_is_deterministic_and_uses_the_last_user_message() {
        let provider = FakeProvider::echo("main");
        let request = gated(vec![
            ChatMessage::system("be nice"),
            ChatMessage::user("first"),
            ChatMessage::assistant("reply"),
            ChatMessage::user("second"),
        ]);

        let first = provider.complete(&request).await.unwrap();
        let second = provider.complete(&request).await.unwrap();
        assert_eq!(first.content(), "[fake:main] second");
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn echo_without_user_message_is_still_deterministic() {
        let provider = FakeProvider::echo("main");
        let request = gated(vec![ChatMessage::system("only system")]);
        assert_eq!(
            provider.complete(&request).await.unwrap().content(),
            "[fake:main] no user message"
        );
    }

    #[tokio::test]
    async fn requests_are_recorded_verbatim() {
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("ok"));
        let request = user("hello");
        provider.complete(&request).await.unwrap();

        let recorded = provider.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], request);
    }

    #[tokio::test]
    async fn responses_carry_deterministic_usage() {
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("done"));
        let response = provider.complete(&user("hello")).await.unwrap();

        assert_eq!(
            response.usage,
            Some(Usage {
                prompt_tokens: "hello".chars().count() as u64,
                completion_tokens: "done".chars().count() as u64,
                cost_usd: None,
                cached_prompt_tokens: None,
            })
        );
        // Same input, same counts — the fake stays deterministic.
        let again = provider.complete(&user("hello")).await.unwrap();
        assert_eq!(response.usage, again.usage);
    }

    #[tokio::test]
    async fn usage_counts_every_message_of_the_prompt() {
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("ok"));
        let request = gated(vec![
            ChatMessage::system("be nice"),
            ChatMessage::user("hi"),
        ]);
        let response = provider.complete(&request).await.unwrap();

        assert_eq!(
            response.usage.unwrap().prompt_tokens,
            ("be nice".chars().count() + "hi".chars().count()) as u64
        );
    }

    #[tokio::test]
    async fn scripted_usage_is_preserved() {
        let usage = Usage {
            prompt_tokens: 42,
            completion_tokens: 7,
            cost_usd: None,
            cached_prompt_tokens: None,
        };
        let provider =
            FakeProvider::scripted("fake", vec![ChatResponse::assistant("x").with_usage(usage)]);
        let response = provider.complete(&user("hello")).await.unwrap();
        assert_eq!(response.usage, Some(usage));
    }

    #[tokio::test]
    async fn echo_usage_tracks_the_echoed_completion() {
        let provider = FakeProvider::echo("main");
        let response = provider.complete(&user("hello")).await.unwrap();
        let echoed = "[fake:main] hello";
        assert_eq!(
            response.usage,
            Some(Usage {
                prompt_tokens: "hello".chars().count() as u64,
                completion_tokens: echoed.chars().count() as u64,
                cost_usd: None,
                cached_prompt_tokens: None,
            })
        );
    }

    #[tokio::test]
    async fn two_instances_with_the_same_script_are_identical() {
        let script = || {
            FakeProvider::scripted(
                "fake",
                vec![ChatResponse::assistant("a"), ChatResponse::assistant("b")],
            )
        };
        let first = script();
        let second = script();
        for input in ["x", "y"] {
            assert_eq!(
                first.complete(&user(input)).await.unwrap(),
                second.complete(&user(input)).await.unwrap()
            );
        }
    }

    #[tokio::test]
    async fn fake_providers_are_object_safe() {
        let provider: Box<dyn ChatProvider> = Box::new(FakeProvider::echo("boxed"));
        assert_eq!(provider.name(), "boxed");
        assert_eq!(
            provider.complete(&user("hi")).await.unwrap().content(),
            "[fake:boxed] hi"
        );
    }

    /// Records every [`ChatDelta`] as a compact string (test sink).
    fn sink_log() -> (Arc<Mutex<Vec<String>>>, impl Fn(ChatDelta) + Send + Sync) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink_log = Arc::clone(&log);
        let sink = move |delta: ChatDelta| {
            let entry = match delta {
                ChatDelta::Text(text) => format!("text:{text}"),
                ChatDelta::ToolCall(call) => format!("call:{}:{}", call.name, call.id),
                ChatDelta::Usage(usage) => {
                    format!("usage:{}/{}", usage.prompt_tokens, usage.completion_tokens)
                }
            };
            sink_log.lock().unwrap().push(entry);
        };
        (log, sink)
    }

    #[tokio::test]
    async fn streaming_reports_text_chunks_in_order() {
        let provider = FakeProvider::echo("main").with_stream_chunks(4);
        let (log, sink) = sink_log();

        let response = provider
            .complete_streaming(&user("hi"), &sink)
            .await
            .unwrap();

        let entries = log.lock().unwrap().clone();
        let texts: Vec<&str> = entries
            .iter()
            .filter_map(|entry| entry.strip_prefix("text:"))
            .collect();
        assert_eq!(texts.concat(), "[fake:main] hi");
        assert_eq!(texts.len(), 4, "15 chars in chunks of 4: {entries:?}");
        assert_eq!(
            entries.last().unwrap().as_str(),
            format!(
                "usage:{}/{}",
                "hi".chars().count(),
                response.message.content.chars().count()
            ),
            "usage is reported after the text: {entries:?}"
        );
        let again = provider
            .complete_streaming(&user("hi"), &sink)
            .await
            .unwrap();
        assert_eq!(again, response, "streaming stays deterministic");
    }

    #[tokio::test]
    async fn streaming_without_a_chunk_size_emits_one_delta() {
        let provider = FakeProvider::echo("main");
        let (log, sink) = sink_log();
        provider
            .complete_streaming(&user("hi"), &sink)
            .await
            .unwrap();
        let entries = log.lock().unwrap().clone();
        assert_eq!(entries[0], "text:[fake:main] hi");
    }

    #[tokio::test]
    async fn streaming_emits_assembled_tool_calls_then_usage() {
        let call = ToolCall::new("call_1", "shell", serde_json::json!({ "cmd": "ls" }));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(crate::types::ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![call],
                ))
                .with_usage(Usage {
                    prompt_tokens: 3,
                    completion_tokens: 0,
                    cost_usd: None,
                    cached_prompt_tokens: None,
                }),
            ],
        )
        .with_stream_chunks(2);
        let (log, sink) = sink_log();

        let response = provider
            .complete_streaming(&user("hello"), &sink)
            .await
            .unwrap();

        assert_eq!(
            log.lock().unwrap().clone(),
            vec!["call:shell:call_1".to_string(), "usage:3/0".to_string()],
            "tool calls and usage trail the (empty) text"
        );
        assert_eq!(response.tool_calls().len(), 1);
    }

    /// A provider that implements only `complete`: the trait's default
    /// `complete_streaming` must report the whole answer as one delta.
    struct PlainProvider(FakeProvider);

    #[async_trait]
    impl ChatProvider for PlainProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.0.complete(req).await
        }

        fn name(&self) -> &str {
            self.0.name()
        }
    }

    #[tokio::test]
    async fn the_default_streaming_fallback_reports_the_whole_answer() {
        let provider = PlainProvider(FakeProvider::echo("main"));
        let (log, sink) = sink_log();

        let streamed = provider
            .complete_streaming(&user("hi"), &sink)
            .await
            .unwrap();

        assert_eq!(streamed.content(), "[fake:main] hi");
        let entries = log.lock().unwrap().clone();
        assert_eq!(
            entries.len(),
            2,
            "one text delta + one usage event: {entries:?}"
        );
        assert_eq!(entries[0], "text:[fake:main] hi");
        assert!(entries[1].starts_with("usage:"), "{entries:?}");
    }
}
