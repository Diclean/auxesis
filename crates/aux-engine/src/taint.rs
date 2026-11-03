//! Per-conversation taint tracking (WS-C).
//!
//! Once a tool whose output is untrusted (`shell`, `http_fetch`, connector
//! and mail tools, or anything unclassified) is dispatched, its content may
//! enter the model's context and the conversation is **tainted**: every
//! consequential tool call must be approved, and "always allow" cannot widen
//! that.
//!
//! Taint is sticky for the life of the conversation. It survives turns and
//! restarts because it is persisted *before* the untrusted call runs: the
//! engine writes a `session_taint` mark (write-ahead, so a cancelled or
//! crashed turn still resumes tainted) and a `workspace_taint` mark (every
//! conversation that starts in a touched workspace is tainted until the
//! owner clears it). Completed tool results also carry their trust state in
//! the message `meta`, and a resumed session rebuilds the state from that
//! history. Message content is never inspected, so nothing the model says
//! can clear it. Rows whose provenance cannot be established fail closed as
//! [`Taint::Unknown`].

use aux_store::Message;
use kernel_broker::{Taint, TaintSource, ToolRegistry};

/// Rebuild the taint state of a conversation from its persisted messages.
///
/// Only `tool` rows carry trust metadata; every other role is ignored, so
/// nothing the user or the model writes can clear (or set) taint.
pub fn from_history(messages: &[Message], registry: &ToolRegistry) -> Taint {
    let mut taint = Taint::Clean;
    for message in messages.iter().filter(|message| message.role == "tool") {
        match classify(message, registry) {
            Row::Clean => {}
            Row::Tainted(source) => taint.record(source),
            Row::Unknown => taint.mark_unknown(),
        }
    }
    taint
}

enum Row {
    Clean,
    Tainted(TaintSource),
    Unknown,
}

fn classify(message: &Message, registry: &ToolRegistry) -> Row {
    let Some(meta) = message
        .meta
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
    else {
        return Row::Unknown;
    };
    let tool = meta.get("tool").and_then(|value| value.as_str());
    match meta.get("tainted").and_then(|value| value.as_bool()) {
        // Written by this engine for a result that actually entered context.
        Some(true) => {
            let source = meta
                .get("taint_source")
                .and_then(|value| serde_json::from_value::<TaintSource>(value.clone()).ok())
                .or_else(|| tool.map(|name| TaintSource::new(name, None)));
            source.map(Row::Tainted).unwrap_or(Row::Unknown)
        }
        // The label says clean, but it lives in the same writable row as the
        // rest of the metadata. Re-check it against the tool class: a
        // `tainted: false` label on an untrusted-output tool (or a row whose
        // tool name cannot be checked) contradicts what we know and fails
        // closed. Rows for trusted tools stay clean.
        Some(false) => match tool {
            Some(name) if registry.is_untrusted_output(name) => Row::Unknown,
            Some(_) => Row::Clean,
            None => Row::Unknown,
        },
        // Rows persisted before taint tracking existed: classify by name. A
        // registered tool's explicit class decides; anything not in the
        // registry fails closed as unknown (we cannot tell what it was).
        None => match tool {
            Some(name) if registry.get(name).is_some() && registry.is_untrusted_output(name) => {
                Row::Tainted(TaintSource::new(name, None))
            }
            Some(name) if registry.get(name).is_some() => Row::Clean,
            _ => Row::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    /// The kernel's tool classes with the app's built-in tools registered, as
    /// `registry_from_config` builds them.
    fn builtin_registry() -> kernel_broker::ToolRegistry {
        let sandbox = kernel_broker::ShellSandbox::default();
        let web = kernel_core::WebConfig::default();
        let mut registry =
            kernel_broker::ToolRegistry::with_shell_web(sandbox.clone(), web.clone());
        aux_runtime::tools::register_builtins(&mut registry, sandbox, web);
        registry
    }
    use super::*;

    fn message(role: &str, meta: Option<&str>) -> Message {
        Message {
            id: 1,
            session_id: 1,
            role: role.to_string(),
            content: "content".to_string(),
            created_at: "2026-10-04 00:00:00".to_string(),
            meta: meta.map(str::to_string),
        }
    }

    fn tool_row(meta: serde_json::Value) -> Message {
        message("tool", Some(&meta.to_string()))
    }

    #[test]
    fn taint_is_rebuilt_from_tool_rows_only() {
        let registry = builtin_registry();
        let history = vec![
            tool_row(serde_json::json!({"tool": "read_file", "status": "ok", "tainted": false})),
            tool_row(serde_json::json!({
                "tool": "http_fetch",
                "status": "ok",
                "tainted": true,
                "taint_source": {"tool": "http_fetch", "detail": "https://example.com"},
            })),
            message("assistant", None),
            message("user", None),
        ];
        assert_eq!(
            from_history(&history, &registry).summary().as_deref(),
            Some("http_fetch: https://example.com")
        );
        assert!(!from_history(&history[..1], &registry).forces_ask());
        // Text-only history stays clean no matter what it says.
        let text = vec![message("assistant", None), message("user", None)];
        assert!(!from_history(&text, &registry).forces_ask());
    }

    #[test]
    fn a_forged_clean_label_on_an_untrusted_tool_fails_closed() {
        let registry = builtin_registry();
        // A tampered row can claim `tainted: false` for anything; the tool
        // class has the last word.
        let laundered = vec![tool_row(serde_json::json!({
            "tool": "http_fetch",
            "status": "ok",
            "tainted": false,
        }))];
        assert!(from_history(&laundered, &registry).forces_ask());
        let shell = vec![tool_row(serde_json::json!({
            "tool": "shell",
            "status": "ok",
            "tainted": false,
        }))];
        assert!(from_history(&shell, &registry).forces_ask());
        // A clean label with no readable tool name also fails closed.
        let nameless = vec![tool_row(
            serde_json::json!({"status": "ok", "tainted": false}),
        )];
        assert!(from_history(&nameless, &registry).forces_ask());
        // A genuine clean row for a trusted tool is still clean.
        let trusted = vec![tool_row(serde_json::json!({
            "tool": "read_file",
            "status": "ok",
            "tainted": false,
        }))];
        assert!(!from_history(&trusted, &registry).forces_ask());
    }

    #[test]
    fn legacy_and_unknown_rows_fail_closed() {
        let registry = builtin_registry();
        // A pre-WS-C fetch row (no taint field) is classified by tool name.
        let legacy = vec![tool_row(
            serde_json::json!({"tool": "http_fetch", "status": "ok"}),
        )];
        assert!(from_history(&legacy, &registry).forces_ask());
        // Missing/unreadable metadata or an unknown tool: fail closed.
        for history in [
            vec![message("tool", None)],
            vec![message("tool", Some("not json"))],
            vec![tool_row(serde_json::json!({"status": "ok"}))],
            vec![tool_row(
                serde_json::json!({"tool": "vanished", "status": "ok"}),
            )],
        ] {
            let taint = from_history(&history, &registry);
            assert!(taint.summary().unwrap().contains("fail closed"));
        }
    }
}
