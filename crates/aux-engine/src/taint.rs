//! Per-conversation taint tracking.
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
                .map(|mut source| {
                    source.detail = host_only(source.detail.take());
                    source
                })
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

/// Schemes whose body is never a host (READS-8 rev 2, view-source READS-9),
/// as shown: the scheme and its colon.
const BODY_ONLY: [&str; 6] = [
    "javascript:",
    "data:",
    "vbscript:",
    "about:",
    "blob:",
    "view-source:",
];

/// The [`BODY_ONLY`] entry a scheme names, case-insensitively, once the tabs
/// and newlines WHATWG drops from a URL are removed (`java\tscript`).
fn body_only(scheme: &str) -> Option<&'static str> {
    BODY_ONLY.iter().copied().find(|shown| {
        let mut cleaned = scheme.chars().filter(|c| !matches!(c, '\t' | '\n' | '\r'));
        let name = shown.trim_end_matches(':');
        name.chars()
            .all(|n| cleaned.next().is_some_and(|c| c.eq_ignore_ascii_case(&n)))
            && cleaned.next().is_none()
    })
}

/// The host (and port) of a model-chosen URL: never its user info, path,
/// query or fragment, which can carry what the page was asked (READS-6).
/// A URL with no host (`file:///etc/passwd`) gives its scheme, never the
/// path (READS-7), and an opaque one (`javascript:alert(1)`, `data:,x`)
/// gives `javascript:` / `data:`, never its body (READS-8). Leading C0
/// controls and spaces are dropped first, as WHATWG does (READS-9); text
/// before `://` that no scheme can hold gives nothing. Every taint row,
/// Activity entry and card shows this.
pub(crate) fn url_host(raw: &str) -> &str {
    let rest = raw.trim_start_matches(|c: char| c <= '\u{20}' || c.is_whitespace());
    // Schemes that never name a host: their scheme only, whatever follows
    // (`javascript://token`, `data:x@token` would otherwise parse a host).
    if let Some((scheme, _)) = rest.split_once(':') {
        if let Some(shown) = body_only(scheme) {
            // No tab or newline dropped: show the scheme as written.
            return if scheme.len() + 1 == shown.len() {
                &rest[..=scheme.len()]
            } else {
                shown
            };
        }
    }
    if let Some(scheme) = opaque_scheme(rest) {
        return scheme;
    }
    let (separated, (scheme, rest)) = match rest.split_once("://") {
        Some(parts) => (true, parts),
        None => (false, ("", rest)),
    };
    let authority = rest
        .split(|c: char| matches!(c, '/' | '?' | '#' | '\\') || c.is_whitespace())
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    // Before `://` a scheme starts with a letter (`1x://`, `://` hold none).
    let scheme_ok = scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        && (!separated || scheme.starts_with(|c: char| c.is_ascii_alphabetic()));
    // A real host is letters, digits and `.-_:[]%`; anything else is the
    // body of a URL with no host (`javascript://alert(1)`), not shown.
    // A colon outside `[...]` is a port: 0-5 digits, once (`a.example:8443`,
    // `[::1]:80`); `x:s3cr3t` is an opaque body, never a host (READS-9).
    let unbracketed = host.rsplit_once(']').map_or(host, |(_, tail)| tail);
    let port_ok = unbracketed
        .split_once(':')
        .is_none_or(|(_, port)| port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()));
    let host_ok = port_ok
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || ".-_:[]%".contains(c));
    if !scheme_ok {
        // `java%73cript://token`: no scheme, so what follows is a body.
        ""
    } else if host.is_empty() || !host_ok {
        scheme
    } else {
        host
    }
}

/// `scheme:` of a URL with no `//` after the colon and no port (`scheme:`
/// then 1-5 digits ends the text or a path), which has a body and no host.
/// `host:8443/x` and `user:pw@host` are not opaque.
fn opaque_scheme(url: &str) -> Option<&str> {
    let (scheme, after) = url.split_once(':')?;
    let mut chars = scheme.chars();
    if !chars.next()?.is_ascii_alphabetic()
        || !chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        || after.starts_with("//")
    {
        return None;
    }
    let authority = after
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') {
        return None;
    }
    let digits = after.bytes().take_while(u8::is_ascii_digit).count();
    let ends = after[digits..]
        .chars()
        .next()
        .is_none_or(|c| matches!(c, '/' | '?' | '#' | '\\') || c.is_whitespace());
    if (1..=5).contains(&digits) && ends {
        return None;
    }
    Some(&url[..=scheme.len()])
}

/// A stored taint detail as the host only: rows written before READS-6 kept
/// the whole URL, and resume shows them again (READS-7). A detail with
/// nothing a URL could cut away (a host, `acp (timed out)`) is kept as
/// written; one that leaves nothing, or is empty, is dropped.
pub(crate) fn host_only(detail: Option<String>) -> Option<String> {
    let detail = detail.filter(|detail| !detail.is_empty())?;
    if !detail.contains(['/', '?', '#', '@', '\\', ':']) {
        return Some(detail);
    }
    Some(url_host(&detail).to_string()).filter(|host| !host.is_empty())
}

/// A stored workspace mark (`tool: detail`, see [`TaintSource::summary`])
/// with its detail cut to the host, as [`host_only`]. A mark with no prefix
/// is a bare tool name: shown as is, escaped (READS-8), unless it looks like
/// a URL or path (it has a `/`, `:`, `@`, `?`, `#` or `\\` in it), which is cut
/// as above, as main did: `http_fetch/S3CRET/tok` shows `http_fetch`.
pub(crate) fn host_only_reason(reason: String) -> Option<String> {
    match reason.split_once(": ") {
        Some((tool, detail)) => Some(match host_only(Some(detail.to_string())) {
            Some(host) => format!("{tool}: {host}"),
            None => tool.to_string(),
        }),
        None if reason.contains(['/', ':', '@', '?', '#', '\\']) => host_only(Some(reason)),
        None => Some(kernel_broker::sanitize_text(&reason))
            .map(|name| name.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|name| !name.is_empty()),
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
            Some("http_fetch: example.com")
        );
        assert!(!from_history(&history[..1], &registry).forces_ask());
        // Text-only history stays clean no matter what it says.
        let text = vec![message("assistant", None), message("user", None)];
        assert!(!from_history(&text, &registry).forces_ask());
    }

    /// READS-7: a row stored before READS-6 with the whole URL comes back
    /// as its host only; a URL with no host gives its scheme, never a path.
    #[test]
    fn stored_taint_details_come_back_as_the_host_only() {
        let registry = builtin_registry();
        let source = |detail: &str| serde_json::json!({"tool": "http_fetch", "detail": detail});
        let row = |detail: &str| {
            tool_row(serde_json::json!({"tainted": true, "taint_source": source(detail)}))
        };
        for (detail, shown) in [
            (
                "https://u:p@a.example:8443/i?t=x",
                "http_fetch: a.example:8443",
            ),
            ("a.example/inbox?q=secret", "http_fetch: a.example"),
            ("file:///etc/passwd", "http_fetch: file"),
            ("/etc/passwd", "http_fetch"),
            ("a.example:8443", "http_fetch: a.example:8443"),
        ] {
            let taint = from_history(&[row(detail)], &registry);
            assert!(taint.forces_ask(), "{detail}");
            assert_eq!(taint.summary().as_deref(), Some(shown), "{detail}");
        }
        assert_eq!(
            url_host("a/b:///etc"),
            "",
            "a scheme with a path is no scheme"
        );
        let acp = Some("acp (timed out)".to_string());
        assert_eq!(host_only(acp.clone()), acp);
        assert_eq!(host_only_reason("shell".into()).as_deref(), Some("shell"));
        assert_eq!(host_only_reason("/etc/passwd".into()), None);
    }

    /// READS-8: an opaque URL gives its scheme, never its body; an empty
    /// host is no host; a bare tool name is shown as is, escaped.
    #[test]
    fn opaque_urls_and_bare_names_never_show_a_body() {
        for (url, shown) in [
            ("data:,x", "data:"),
            ("data:text/html;base64,AAAA", "data:"),
            ("javascript:alert(1)", "javascript:"),
            (" JavaScript:alert(1)", "JavaScript:"),
            ("javascript:alert('a@b')", "javascript:"),
            ("javascript://alert(1)", "javascript:"),
            ("javascript://s3cr3t-token", "javascript:"),
            ("javascript:letmein@s3cr3t-token", "javascript:"),
            ("JAVASCRIPT://s3cr3t-token", "JAVASCRIPT:"),
            ("data://s3cr3t-token", "data:"),
            ("vbscript:x@s3cr3t-token", "vbscript:"),
            ("blob:https://evil.example/x", "blob:"),
            ("mailto:a@b.example", "b.example"),
            ("user:pw@a.example/x", "a.example"),
            ("a.example:8443/x", "a.example:8443"),
            ("[::1]:80/x", "[::1]:80"),
            // READS-9: C0 controls, tabs and newlines, escapes, view-source.
            ("\u{1}javascript://s3cr3t-token", "javascript:"),
            ("\u{0}data://tok", "data:"),
            ("\u{1c}JAVASCRIPT://tok", "JAVASCRIPT:"),
            ("\u{1}\t javascript:x@tok", "javascript:"),
            ("java\tscript:x", "javascript:"),
            ("jav\na\r\tscript://tok", "javascript:"),
            ("java%73cript://s3cr3t-token", ""),
            ("vbscript:x@tok", "vbscript:"),
            (
                "view-source:javascript:letmein@s3cr3t-token",
                "view-source:",
            ),
            ("VIEW-SOURCE:https://u:p@a.example/x", "VIEW-SOURCE:"),
            // READS-9 rev 2: an opaque body never parses as host:port, and
            // text before `://` must start with a letter.
            ("\u{0}java%73cript:s3cr3t", ""),
            ("java%73cript:s3cr3t", ""),
            ("\u{0}java%73cript:USER:PASS", ""),
            ("a:s3cr3t:80", ""),
            ("1javascript://s3cr3t-token", ""),
            ("-javascript://s3cr3t-token", ""),
            ("://s3cr3t-token", ""),
            ("https://a.example:8443/x", "a.example:8443"),
            ("https://münchen.example/x", "münchen.example"),
            ("http://[::1]:80/x", "[::1]:80"),
            ("localhost:3000", "localhost:3000"),
        ] {
            assert_eq!(url_host(url), shown, "{url}");
        }
        for body in [
            "data:,x",
            "data:text/html;base64,AAAA",
            "javascript:alert(1)",
        ] {
            let shown = host_only(Some(body.to_string()));
            assert!(shown.as_deref().is_some_and(|s| s.ends_with(':')), "{body}");
            let reason = host_only_reason(format!("http_fetch: {body}"));
            assert!(reason.is_some_and(|r| r.ends_with(": data:") || r.ends_with(": javascript:")));
            let bare = host_only_reason(body.to_string());
            assert!(bare.is_some_and(|r| r.ends_with(':')), "{body}");
        }
        for url in [
            "\u{1}javascript://s3cr3t-token",
            "java\tscript:x@s3cr3t-token",
            "java%73cript://s3cr3t-token",
            "view-source:javascript:letmein@s3cr3t-token",
        ] {
            let shown = host_only(Some(url.to_string())).unwrap_or_default();
            assert!(!shown.contains("s3cr3t") && !shown.contains('x'), "{url}");
            let reason = host_only_reason(format!("http_fetch: {url}")).unwrap_or_default();
            assert!(!reason.contains("s3cr3t"), "{url}: {reason}");
            let bare = host_only_reason(url.to_string()).unwrap_or_default();
            assert!(!bare.contains("s3cr3t"), "{url}: {bare}");
        }
        assert_eq!(host_only(Some(String::new())), None);
        assert_eq!(host_only(None), None);
        let name = host_only_reason("mcp/files\u{7}  tool".into());
        assert_eq!(name.as_deref(), Some("mcp"));
        let path = host_only_reason("http_fetch/S3CRET/tok".into());
        assert_eq!(path.as_deref(), Some("http_fetch"));
        let name = host_only_reason("search\u{7}  web".into());
        assert_eq!(name.as_deref(), Some("search web"));
        assert_eq!(host_only_reason(String::new()), None);
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
