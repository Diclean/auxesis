//! Shared scrubbing for agent-originated ACP text.
//!
//! An ACP agent is untrusted input. Everything it emits — message chunks,
//! thoughts, tool payloads, plans — passes the same two secret layers the
//! supervisor already applies to stderr (`kernel_broker::redact_secrets` plus the
//! registered-known-value layer) before it is stored, returned, or forwarded
//! to an observer.

use serde_json::Value;

use crate::protocol::{PlanEntry, ToolCallUpdate};

/// Run `text` through the shared scrubbers: the pattern/structured layers
/// first, then every registered known value (the exact-value layer).
pub fn scrub_agent_text(text: &str) -> String {
    let mut scrubbed = kernel_broker::redact_secrets(text);
    if let Some(known) = kernel_broker::scrub::redact_known_secrets(&scrubbed) {
        scrubbed = known;
    }
    scrubbed
}

/// Prefix agent text with the untrusted tag exactly once, so a consumer that
/// sees it in a model context can never mistake it for instructions.
pub fn tagged_agent_text(text: &str) -> String {
    if text.is_empty() || text.starts_with(crate::ACP_UNTRUSTED_TAG) {
        text.to_string()
    } else {
        format!("{}\n{text}", crate::ACP_UNTRUSTED_TAG)
    }
}

/// Deep-scrub every string in a JSON value (tool inputs/outputs and content
/// blocks can carry secrets the agent saw).
pub fn scrub_agent_value(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(scrub_agent_text(text)),
        Value::Array(items) => Value::Array(items.iter().map(scrub_agent_value).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), scrub_agent_value(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Scrub the free-text fields of one tool-call update.
pub fn scrub_tool_call(call: &mut ToolCallUpdate) {
    if let Some(title) = call.title.as_deref() {
        call.title = Some(scrub_agent_text(title));
    }
    call.raw_input = call.raw_input.as_ref().map(scrub_agent_value);
    call.raw_output = call.raw_output.as_ref().map(scrub_agent_value);
    call.content = call.content.iter().map(scrub_agent_value).collect();
    call.locations = call.locations.iter().map(scrub_agent_value).collect();
}

/// Scrub one plan's entry text.
pub fn scrub_plan(entries: &mut [PlanEntry]) {
    for entry in entries {
        entry.content = scrub_agent_text(&entry.content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    #[test]
    fn ordinary_text_is_returned_byte_for_byte() {
        let text = "hello world\nsecond line with  two spaces";
        assert_eq!(scrub_agent_text(text), text);
    }

    #[test]
    fn shared_secret_redaction_canaries_are_redacted() {
        redaction_canaries::assert_no_canaries(scrub_agent_text);
    }

    #[test]
    fn known_and_pattern_secrets_are_both_redacted() {
        let _guard = crate::known_secret_test_lock();
        let canary = "CANARY_ACP_SCRUB_0123456789abcdef";
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret(canary);
        let scrubbed = scrub_agent_text(&format!(
            "token=sk-abcdefghijklmnopqrstuvwxyz012345 known={canary}"
        ));
        kernel_broker::scrub::clear_known_secrets();
        assert!(!scrubbed.contains(canary), "{scrubbed}");
        assert!(
            !scrubbed.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
            "{scrubbed}"
        );
        assert!(scrubbed.contains("<redacted>"), "{scrubbed}");
    }

    #[test]
    fn known_secret_split_across_a_newline_is_redacted() {
        let _guard = crate::known_secret_test_lock();
        let canary = "CANARY_ACP_STREAM_0123456789abcdef";
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret(canary);
        let scrubbed = scrub_agent_text("split\nCANARY_ACP_STREAM_0123\n456789abcdef");
        kernel_broker::scrub::clear_known_secrets();
        assert!(!scrubbed.contains(canary), "{scrubbed}");
        assert!(scrubbed.contains("<redacted>"), "{scrubbed}");
    }

    #[test]
    fn tagged_agent_text_prefixes_exactly_once() {
        let once = tagged_agent_text("answer");
        assert!(once.starts_with(crate::ACP_UNTRUSTED_TAG));
        assert_eq!(tagged_agent_text(&once), once);
        assert_eq!(tagged_agent_text(""), "");
    }

    #[test]
    fn nested_tool_values_are_scrubbed() {
        let mut call = ToolCallUpdate {
            id: "t1".to_string(),
            title: Some("run token=sk-abcdefghijklmnopqrstuvwxyz012345".to_string()),
            raw_output: Some(
                json!({"nested": ["ok", "token=sk-abcdefghijklmnopqrstuvwxyz012345"]}),
            ),
            ..ToolCallUpdate::default()
        };
        scrub_tool_call(&mut call);
        let text = format!("{:?}", call);
        assert!(
            !text.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
            "{text}"
        );
        assert!(text.contains("<redacted>"), "{text}");
    }
}
