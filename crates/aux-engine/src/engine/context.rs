//! The model context: the bounded window of stored rows, the metadata
//! a row carries, and the reasoning text that travels with it.

use super::budget::estimate_tokens;
use super::tools::CallOutcome;
use aux_providers::{ChatMessage, SafeMessage, ToolCall};
use aux_store::Message;
use kernel_core::ContextConfig;

pub(super) fn role_str(role: aux_providers::ChatRole) -> &'static str {
    match role {
        aux_providers::ChatRole::System => "system",
        aux_providers::ChatRole::User => "user",
        aux_providers::ChatRole::Assistant => "assistant",
        aux_providers::ChatRole::Tool => "tool",
    }
}

/// A daemon-written state line (Resume released): it reaches the model; the
/// session's one stored prompt row stays out of the bounded window.
pub(super) fn is_state_line(message: &Message) -> bool {
    message.role == "system"
        && message.meta.as_deref().is_some_and(|raw| {
            serde_json::from_str::<serde_json::Value>(raw)
                .ok()
                .and_then(|value| value["kind"].as_str().map(str::to_string))
                .is_some_and(|kind| kind == "state")
        })
}

pub(super) fn hydrate_message(message: &aux_store::Message) -> Option<ChatMessage> {
    let meta = message
        .meta
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
    match message.role.as_str() {
        "system" => Some(ChatMessage::system(message.content.clone())),
        "user" => Some(ChatMessage::user(message.content.clone())),
        "assistant" => {
            let tool_calls = meta
                .as_ref()
                .and_then(|value| value.get("tool_calls"))
                .and_then(|calls| {
                    serde_json::from_value::<Vec<aux_providers::ToolCall>>(calls.clone()).ok()
                })
                .unwrap_or_default();
            // Reasoning goes back only on a message that carries tool calls
            // (where the provider requires it) and only with the id of the
            // provider that produced it; a row without that id sends nothing.
            let text = |key: &str| {
                meta.as_ref()
                    .filter(|_| !tool_calls.is_empty())
                    .and_then(|value| value.get(key))
                    .and_then(|text| text.as_str())
                    .map(str::to_string)
            };
            let mut restored =
                ChatMessage::assistant_with_tool_calls(message.content.clone(), tool_calls.clone());
            if let Some(provider) = text(REASONING_PROVIDER_META_KEY) {
                restored = restored
                    .with_reasoning_content(text(REASONING_META_KEY))
                    .with_reasoning_provider(provider);
            }
            Some(restored)
        }
        "tool" => {
            let call_id = meta
                .as_ref()
                .and_then(|value| value.get("tool_call_id"))
                .and_then(|id| id.as_str())
                .unwrap_or_default()
                .to_string();
            Some(ChatMessage::tool_result(call_id, message.content.clone()))
        }
        _ => None,
    }
}

/// Meta key holding the provider's reasoning text on an assistant row. Local
/// only: the API, the event stream, the snapshot and the CLI never read it.
const REASONING_META_KEY: &str = "reasoning_content";

/// Meta key naming the provider that produced the stored reasoning.
const REASONING_PROVIDER_META_KEY: &str = "reasoning_provider";

/// Most reasoning bytes kept on one message. A stored row weighs on the
/// 32,000-token context window and on every input reservation, so the cap is
/// 64 KiB (about 16k tokens), not the 1 MiB a stream may carry: DeepSeek needs
/// the field present, not whole, and one row must never fill the window.
const MAX_REASONING_BYTES: usize = 64 * 1024;

/// The meta of an assistant row: its tool calls, plus the reasoning text the
/// provider returned with them and that provider's id, so a rebuilt thread can
/// send it back to the same provider only.
pub(super) fn assistant_meta(message: &ChatMessage) -> Option<String> {
    let (Some(reasoning), Some(provider)) = (
        message
            .reasoning_content
            .as_deref()
            .filter(|_| !message.tool_calls.is_empty()),
        message.reasoning_provider.as_deref(),
    ) else {
        return tool_calls_meta(&message.tool_calls);
    };
    serde_json::to_string(&serde_json::json!({
        "tool_calls": message.tool_calls,
        REASONING_META_KEY: reasoning,
        REASONING_PROVIDER_META_KEY: provider,
    }))
    .ok()
}

/// Cut the reasoning of a reply to [`MAX_REASONING_BYTES`], on a character
/// boundary, before it is gated, stored or sent again.
pub(super) fn cap_reasoning(message: &mut ChatMessage) {
    if let Some(reasoning) = message.reasoning_content.as_mut() {
        if reasoning.len() > MAX_REASONING_BYTES {
            let mut end = MAX_REASONING_BYTES;
            while !reasoning.is_char_boundary(end) {
                end -= 1;
            }
            reasoning.truncate(end);
        }
    }
}

/// The meta of a private assistant row: its tool calls as the provider read
/// them, tokens and all.
pub(super) fn safe_tool_calls_meta(message: &SafeMessage) -> Option<String> {
    let calls: Vec<ToolCall> = message
        .tool_calls()
        .iter()
        .map(|call| {
            ToolCall::new(
                call.id().as_str(),
                call.name().as_str(),
                call.arguments().as_value().clone(),
            )
        })
        .collect();
    tool_calls_meta(&calls)
}

pub(super) fn tool_result_meta(call: &ToolCall, outcome: &CallOutcome) -> String {
    let mut meta = serde_json::json!({
        "tool_call_id": call.id,
        "tool": call.name,
        "status": outcome.status,
        "tainted": outcome.taint.is_some(),
    });
    if let Some(kind) = outcome.error_kind {
        meta["error_kind"] = serde_json::Value::String(kind.to_string());
    }
    if let Some(source) = &outcome.taint {
        meta["taint_source"] = serde_json::to_value(source).unwrap_or(serde_json::Value::Null);
    }
    meta.to_string()
}

pub(super) fn tool_calls_meta(calls: &[ToolCall]) -> Option<String> {
    if calls.is_empty() {
        None
    } else {
        serde_json::to_string(&serde_json::json!({ "tool_calls": calls })).ok()
    }
}

pub(super) fn bounded_window(mut window: Vec<Message>, context: &ContextConfig) -> Vec<Message> {
    strip_leading_tool_rows(&mut window);

    let mut tokens = 0u64;
    let mut keep_from = window.len();
    for (index, message) in window.iter().enumerate().rev() {
        tokens += estimate_store_message_tokens(message);
        if tokens > context.max_tokens && index + 1 < window.len() {
            break;
        }
        keep_from = index;
    }
    window.drain(..keep_from);

    // The trim above can start on a `tool` row and can cut a
    // `tool_call`/`tool_result` pair; normalise until stable.
    loop {
        let before = window.len();
        strip_leading_tool_rows(&mut window);
        drop_dangling_tool_calls(&mut window);
        strip_leading_tool_rows(&mut window);
        if window.len() == before {
            break;
        }
    }
    window
}

fn strip_leading_tool_rows(window: &mut Vec<Message>) {
    let start = window
        .iter()
        .position(|message| message.role != "tool")
        .unwrap_or(window.len());
    window.drain(..start);
}

fn drop_dangling_tool_calls(window: &mut Vec<Message>) {
    let mut index = 0;
    while index < window.len() {
        if window[index].role != "assistant" {
            index += 1;
            continue;
        }
        let Some(call_ids) = persisted_tool_call_ids(&window[index]) else {
            index += 1;
            continue;
        };
        if call_ids.is_empty() {
            index += 1;
            continue;
        }
        let all_answered = {
            let mut answered = std::collections::HashSet::new();
            let mut cursor = index + 1;
            while cursor < window.len() && window[cursor].role == "tool" {
                if let Some(id) = persisted_tool_call_id(&window[cursor]) {
                    answered.insert(id);
                }
                cursor += 1;
            }
            call_ids.iter().all(|id| answered.contains(id))
        };
        if all_answered {
            index += 1;
        } else {
            window.remove(index);
        }
    }
}

fn persisted_tool_call_ids(message: &Message) -> Option<Vec<String>> {
    let meta = message
        .meta
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())?;
    let calls =
        serde_json::from_value::<Vec<aux_providers::ToolCall>>(meta.get("tool_calls")?.clone())
            .ok()?;
    Some(calls.into_iter().map(|call| call.id).collect())
}

fn persisted_tool_call_id(message: &Message) -> Option<String> {
    let meta = message
        .meta
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())?;
    meta.get("tool_call_id")
        .and_then(|id| id.as_str())
        .map(str::to_string)
}

fn estimate_store_message_tokens(message: &Message) -> u64 {
    estimate_tokens(&message.content) + 4 + stored_reasoning_tokens(message)
}

fn stored_reasoning_tokens(message: &Message) -> u64 {
    if message.role != "assistant" {
        return 0;
    }
    let Some(meta) = message
        .meta
        .as_deref()
        .filter(|meta| meta.contains(REASONING_META_KEY))
    else {
        return 0;
    };
    serde_json::from_str::<serde_json::Value>(meta)
        .ok()
        .and_then(|value| {
            value
                .get(REASONING_META_KEY)
                .and_then(|text| text.as_str())
                .map(estimate_tokens)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::super::budget::{estimate_request_tokens, estimate_tokens};
    use super::super::testsupport::*;
    use super::*;
    use async_trait::async_trait;
    use aux_providers::{
        ChatMessage, ChatProvider, ChatRequest, ChatResponse, FakeProvider, ProviderError,
        SafeMessage, ToolCall,
    };
    use aux_store::Message;
    use kernel_broker::{Action, Rule};
    use kernel_core::ContextConfig;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn reasoning_content_returns_to_the_provider_within_the_turn() {
        let harness = Harness::new();
        let provider = reasoning_tool_then_text("I will write the note.");
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));

        session.send("write a note").await.unwrap();

        let requests = provider.requests();
        let second = serde_json::to_value(&requests[1].messages).unwrap();
        assert_eq!(
            second[2]["reasoning_content"], "I will write the note.",
            "round two carries round one's reasoning: {second}"
        );
        let first = serde_json::to_string(&requests[0].messages).unwrap();
        assert!(!first.contains("reasoning_content"));
    }

    #[tokio::test]
    async fn reasoning_is_stored_in_meta_only_and_restored_when_the_thread_is_rebuilt() {
        let harness = Harness::new();
        let provider = reasoning_tool_then_text("I will write the note.");
        let session_id = {
            let mut first = harness.start(&provider, vec![], RecordingApprover::new(true));
            first.send("write a note").await.unwrap();
            first.session().id
        };

        let rows = harness.store().list_messages(session_id).unwrap();
        for row in &rows {
            assert!(
                !row.content.contains("I will write the note."),
                "reasoning is never message content"
            );
        }
        let call_row = rows.iter().find(|row| row.role == "assistant").unwrap();
        let meta: serde_json::Value =
            serde_json::from_str(call_row.meta.as_deref().unwrap()).unwrap();
        assert_eq!(meta["reasoning_content"], "I will write the note.");
        assert_eq!(meta["tool_calls"][0]["id"], "call_1");

        // A new process rebuilds the thread from the store.
        let echo = FakeProvider::echo("fake");
        let mut second = harness.start_resumed(&echo, RecordingApprover::new(true), session_id);
        second.send("thanks").await.unwrap();

        let sent = serde_json::to_value(&echo.requests()[0].messages).unwrap();
        let with_calls: Vec<&serde_json::Value> = sent
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message.get("tool_calls").is_some())
            .collect();
        assert_eq!(with_calls.len(), 1, "{sent}");
        assert_eq!(with_calls[0]["reasoning_content"], "I will write the note.");
        let others = sent
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message.get("reasoning_content").is_some())
            .count();
        assert_eq!(others, 1, "only the tool-call message carries it: {sent}");
    }

    #[tokio::test]
    async fn a_legacy_row_without_reasoning_rebuilds_without_the_key() {
        let harness = Harness::new();
        let provider = scripted_tool_then_text();
        let session_id = {
            let mut first = harness.start(&provider, vec![], RecordingApprover::new(true));
            first.send("write a note").await.unwrap();
            first.session().id
        };
        let rows = harness.store().list_messages(session_id).unwrap();
        let call_row = rows.iter().find(|row| row.role == "assistant").unwrap();
        assert!(!call_row.meta.as_deref().unwrap().contains("reasoning"));

        let echo = FakeProvider::echo("fake");
        let mut second = harness.start_resumed(&echo, RecordingApprover::new(true), session_id);
        second.send("again").await.unwrap();

        let sent = serde_json::to_string(&echo.requests()[0].messages).unwrap();
        assert!(
            sent.contains("tool_calls"),
            "the call row is rebuilt: {sent}"
        );
        assert!(!sent.contains("reasoning_content"), "{sent}");
    }

    /// ERASE-ECHO-ESCAPED: the store keeps a tool call's arguments as a
    /// JSON-encoded string inside `meta`. After an erase rewrites a quote with
    /// a newline and a double quote, `hydrate_message` must still rebuild the
    /// call, with the marker in its arguments.
    #[test]
    fn a_scrubbed_escaped_tool_call_meta_still_hydrates_after_an_erase() {
        const ERASED: &str = "Clause 4:\nThe tenant pays \"1 250 EUR\" on the first.";
        const KEPT: &str = "Delivery is due within thirty days of signature.";
        let harness = Harness::new();
        let hash = "c".repeat(64);
        let (session_id, row_id) = {
            let store = harness.store();
            let document = append_test_document(&store, &hash, "lease.txt");
            let session_id = store.create_session("main", None).unwrap().id;
            let result = format!(
                "[untrusted document content]\n{}",
                json!({"document_id": document, "excerpt": ERASED})
            );
            store
                .append_message(
                    session_id,
                    "tool",
                    &result,
                    Some(r#"{"tool_call_id":"call_1","tool":"docs_ingest"}"#),
                )
                .unwrap();
            let arguments = json!({"brief": ERASED, "note": KEPT}).to_string();
            let meta = json!({"tool_calls":[{
                "id":"call_2","type":"function",
                "function":{"name":"delegate","arguments":arguments}
            }]})
            .to_string();
            let row = store
                .append_message(session_id, "assistant", "", Some(&meta))
                .unwrap();
            store.erase_document_by_hash_prefix(&hash[..12]).unwrap();
            (session_id, row.id)
        };
        let row = harness
            .store()
            .list_messages(session_id)
            .unwrap()
            .into_iter()
            .find(|message| message.id == row_id)
            .expect("the assistant row survived the erase");

        let rebuilt = hydrate_message(&row).expect("the scrubbed row still replays");
        assert_eq!(rebuilt.tool_calls.len(), 1, "{rebuilt:?}");
        assert_eq!(rebuilt.tool_calls[0].name, "delegate");
        assert_eq!(
            rebuilt.tool_calls[0].arguments["brief"],
            aux_store::DOCUMENT_UNAVAILABLE_TEXT
        );
        assert_eq!(rebuilt.tool_calls[0].arguments["note"], KEPT);
        let sent = serde_json::to_string(&rebuilt).unwrap();
        assert!(!sent.contains(ERASED), "{sent}");
    }

    #[tokio::test]
    async fn a_private_turn_stores_no_reasoning() {
        let mut harness = Harness::new();
        harness.private(aux_runtime::known_names::Contacts::default());
        let provider = reasoning_tool_then_text("I will write the note.");
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));
        let session_id = session.session().id;

        session.send("write a note").await.unwrap();

        for row in harness.store().list_messages(session_id).unwrap() {
            let stored = format!("{} {}", row.content, row.meta.unwrap_or_default());
            assert!(!stored.contains("I will write the note."), "{stored}");
        }
    }

    #[test]
    fn reasoning_is_capped_on_a_character_boundary() {
        let mut message = ChatMessage::assistant_with_tool_calls(
            "",
            vec![write_file_call("call_1", "a.txt", "x")],
        )
        .with_reasoning_content(Some("é".repeat(MAX_REASONING_BYTES)))
        .with_reasoning_provider("fake");
        cap_reasoning(&mut message);
        let kept = message.reasoning_content.as_deref().unwrap();
        assert!(kept.len() <= MAX_REASONING_BYTES && kept.len() > MAX_REASONING_BYTES - 2);
        let meta: serde_json::Value =
            serde_json::from_str(&assistant_meta(&message).unwrap()).unwrap();
        assert_eq!(meta["reasoning_content"], kept);
        assert_eq!(meta["reasoning_provider"], "fake");
        assert!(
            assistant_meta(
                &ChatMessage::assistant("no calls")
                    .with_reasoning_content(Some("r".into()))
                    .with_reasoning_provider("fake")
            )
            .is_none(),
            "no tool calls, no reasoning kept"
        );
    }

    #[tokio::test]
    async fn an_oversized_reply_reasoning_is_cut_before_it_is_sent_or_stored() {
        let harness = Harness::new();
        let provider = reasoning_tool_then_text(&"r".repeat(MAX_REASONING_BYTES * 4));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));
        let session_id = session.session().id;

        session.send("write a note").await.unwrap();

        let second = serde_json::to_value(&provider.requests()[1].messages).unwrap();
        let sent = second[2]["reasoning_content"].as_str().unwrap();
        assert_eq!(sent.len(), MAX_REASONING_BYTES);
        let rows = harness.store().list_messages(session_id).unwrap();
        let meta = rows.iter().find(|row| row.role == "assistant").unwrap();
        assert!(meta.meta.as_deref().unwrap().len() < MAX_REASONING_BYTES + 1024);
    }

    #[tokio::test]
    async fn a_stored_reasoning_keeps_its_producer_and_a_row_without_one_sends_nothing() {
        let harness = Harness::new();
        let provider = reasoning_tool_then_text("I will write the note.");
        let session_id = {
            let mut first = harness.start(&provider, vec![], RecordingApprover::new(true));
            first.send("write a note").await.unwrap();
            first.session().id
        };
        let rows = harness.store().list_messages(session_id).unwrap();
        let call_row = rows.iter().find(|row| row.role == "assistant").unwrap();
        let meta: serde_json::Value =
            serde_json::from_str(call_row.meta.as_deref().unwrap()).unwrap();
        assert_eq!(meta["reasoning_provider"], "fake");

        let rebuilt = hydrate_message(call_row).unwrap();
        assert_eq!(rebuilt.reasoning_provider.as_deref(), Some("fake"));
        assert_eq!(
            rebuilt.reasoning_content.as_deref(),
            Some("I will write the note.")
        );

        // The same row without a producer id (written by an earlier build).
        let mut anonymous = call_row.clone();
        let mut value = meta.clone();
        value.as_object_mut().unwrap().remove("reasoning_provider");
        anonymous.meta = Some(value.to_string());
        let rebuilt = hydrate_message(&anonymous).unwrap();
        assert_eq!(rebuilt.reasoning_content, None);
        assert!(!rebuilt.tool_calls.is_empty());
    }

    #[test]
    fn a_reasoning_heavy_history_stays_under_the_window_and_the_reservation() {
        let context = ContextConfig::default();
        let reasoning = "r".repeat(MAX_REASONING_BYTES);
        let mut rows = Vec::new();
        for turn in 0..12i64 {
            let call = ToolCall::new(format!("c{turn}"), "write_file", json!({"path": "a"}));
            let message = ChatMessage::assistant_with_tool_calls("", vec![call])
                .with_reasoning_content(Some(reasoning.clone()))
                .with_reasoning_provider("fake");
            rows.push(store_message(
                turn * 2 + 1,
                "assistant",
                "",
                assistant_meta(&message),
            ));
            rows.push(store_message(
                turn * 2 + 2,
                "tool",
                "ok",
                Some(json!({"tool_call_id": format!("c{turn}")}).to_string()),
            ));
        }
        rows.push(store_message(99, "user", "and now?", None));

        let kept = bounded_window(rows, &context);

        let window: u64 = kept.iter().map(estimate_store_message_tokens).sum();
        assert!(window <= context.max_tokens, "window {window}");
        assert!(
            kept.len() < 10,
            "reasoning rows were trimmed: {}",
            kept.len()
        );
        // The request built from the kept rows reserves at least what it sends.
        let mut gate = tokenising_gate([5u8; 32]);
        let messages: Vec<SafeMessage> = kept
            .iter()
            .filter_map(hydrate_message)
            .map(|message| SafeMessage::issue(&mut gate, &message).unwrap())
            .collect();
        let sent_reasoning: u64 = messages
            .iter()
            .filter_map(|message| message.reasoning_content())
            .map(|text| estimate_tokens(text.as_str()))
            .sum();
        assert!(sent_reasoning > 0);
        let reserved = estimate_request_tokens(&ChatRequest::new(messages));
        assert!(reserved >= sent_reasoning, "reserved {reserved}");
        assert!(reserved <= context.max_tokens, "reserved {reserved}");
    }

    #[test]
    fn role_strings_match_the_store_convention() {
        use aux_providers::ChatRole;
        assert_eq!(role_str(ChatRole::System), "system");
        assert_eq!(role_str(ChatRole::User), "user");
        assert_eq!(role_str(ChatRole::Assistant), "assistant");
        assert_eq!(role_str(ChatRole::Tool), "tool");
    }

    /// Records the address of every request's conversation buffer. Does not
    /// retain the request (unlike `FakeProvider`), so `Arc::make_mut` in the
    /// engine can reuse the allocation — which is exactly what is measured.
    struct PointerProvider {
        responses: Mutex<Vec<ChatResponse>>,
        pointers: Mutex<Vec<usize>>,
    }

    #[async_trait]
    impl ChatProvider for PointerProvider {
        async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.pointers
                .lock()
                .unwrap()
                .push(Arc::as_ptr(&request.messages) as usize);
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                panic!("PointerProvider: no scripted response left");
            }
            Ok(responses.remove(0))
        }

        fn name(&self) -> &str {
            "pointer"
        }
    }

    #[tokio::test]
    async fn a_multi_round_turn_reuses_one_conversation_buffer() {
        // Every round's request shares the session's buffer (no
        // `messages.clone()` per round).
        let harness = Harness::new();
        let provider = PointerProvider {
            responses: Mutex::new(vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![write_file_call("call_1", "note.txt", "hello")],
                )),
                ChatResponse::assistant("done"),
            ]),
            pointers: Mutex::new(Vec::new()),
        };
        let rules = vec![Rule::new("main", "write_file", Action::Allow)];
        let mut session = harness.start(&provider, rules, RecordingApprover::new(false));

        session.send("do it").await.unwrap();

        let pointers = provider.pointers.lock().unwrap().clone();
        assert!(pointers.len() >= 2, "two provider rounds: {pointers:?}");
        let shared = session.context_arc_ptr();
        assert!(
            pointers.iter().all(|pointer| *pointer == shared),
            "each round must reuse the same allocation: {pointers:?} vs {shared:x}"
        );
    }

    // ---- Turn-health regressions ----

    /// A persisted message row, for `bounded_window` tests.
    fn store_message(id: i64, role: &str, content: &str, meta: Option<String>) -> Message {
        Message {
            id,
            session_id: 1,
            role: role.to_string(),
            content: content.to_string(),
            created_at: "2026-10-03 00:00:00".to_string(),
            meta,
        }
    }

    #[test]
    fn bounded_window_strips_a_leading_orphan_after_the_token_trim() {
        // The token trim can start on a `tool` row even though the count
        // bound stripped the leading orphan first.
        let window = vec![
            store_message(1, "system", &"s".repeat(4000), None),
            store_message(
                2,
                "tool",
                "orphan result",
                Some(json!({"tool_call_id": "c1"}).to_string()),
            ),
            store_message(3, "user", "newest", None),
        ];
        let context = ContextConfig {
            max_messages: 100,
            max_tokens: 20,
        };

        let trimmed = bounded_window(window, &context);

        assert_eq!(trimmed.len(), 1, "{trimmed:?}");
        assert_eq!(
            trimmed[0].role, "user",
            "the token trim must not re-expose a leading orphan tool result"
        );
    }

    #[test]
    fn bounded_window_drops_an_unanswered_assistant_tool_calls_row() {
        // A batch cancelled before the writer-side repair left this shape;
        // every provider rejects it.
        let call_meta =
            tool_calls_meta(&[ToolCall::new("c1", "shell", json!({"command": "echo hi"}))]);
        let window = vec![
            store_message(1, "assistant", "", call_meta),
            store_message(2, "user", "carry on", None),
        ];

        let trimmed = bounded_window(window, &ContextConfig::default());

        assert_eq!(trimmed.len(), 1, "{trimmed:?}");
        assert_eq!(trimmed[0].role, "user");
    }

    #[test]
    fn bounded_window_keeps_an_answered_assistant_tool_calls_row() {
        let call_meta =
            tool_calls_meta(&[ToolCall::new("c1", "shell", json!({"command": "echo hi"}))]);
        let window = vec![
            store_message(1, "assistant", "", call_meta),
            store_message(
                2,
                "tool",
                "hi",
                Some(json!({"tool_call_id": "c1", "tool": "shell"}).to_string()),
            ),
            store_message(3, "user", "next", None),
        ];

        let trimmed = bounded_window(window, &ContextConfig::default());

        assert_eq!(trimmed.len(), 3, "{trimmed:?}");
        assert_eq!(trimmed[0].role, "assistant");
        assert_eq!(trimmed[1].role, "tool");
    }
}
