//! Grep-style guard: every display surface must route text through the one
//! shared scrubber.
//!
//! F-03 made `error::scrub_preview` / `snapshot::scrub_field` the single choke
//! point for activity, WS frames, messages, instructions, notifications and
//! error bodies; `logging` scrubs with the same `redact_secrets` core. This
//! test reads the surface modules' own source and asserts each known
//! display function still calls a scrub entry point. It fails the moment a
//! surface starts formatting store or upstream text directly — the
//! regression class the fix exists to prevent.

/// The body of the first function whose signature contains `signature`.
///
/// The end is the first line that closes the function at the signature's own
/// indentation, so nested blocks do not cut it short.
fn body_of<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("surface signature `{signature}` not found"));
    let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let indent: String = source[line_start..start]
        .chars()
        .take_while(|c| *c == ' ')
        .collect();
    let close = format!("\n{indent}}}");
    let rest = &source[start..];
    let end = rest.find(&close).unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn every_display_surface_routes_through_the_shared_scrubber() {
    use std::fmt::Write as _;

    // (module file, source, function signature, entry point it must call)
    let surfaces: &[(&str, &str, &str, &str)] = &[
        // activity + messages + instructions + activity digest
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "pub fn scrub_field(",
            "scrub_preview",
        ),
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "fn read_events(",
            "event_summary",
        ),
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "fn read_messages(",
            "preview(",
        ),
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "pub fn message_json_scrubbed(",
            "scrub_preview",
        ),
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "fn instructions_view(",
            "scrub_preview",
        ),
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "pub fn event_summary(",
            "preview(",
        ),
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "fn kind_display(",
            "scrub_field",
        ),
        (
            "snapshot.rs",
            include_str!("snapshot.rs"),
            "fn preview_capped(",
            "scrub_field",
        ),
        // WS journal (audit rows) frames
        (
            "events.rs",
            include_str!("events.rs"),
            "pub fn journal_message(",
            "scrub_field",
        ),
        (
            "events.rs",
            include_str!("events.rs"),
            "fn sanitize_json(",
            "scrub_external_preview",
        ),
        (
            "events.rs",
            include_str!("events.rs"),
            "fn payload_agent(",
            "scrub_field",
        ),
        // live WS turn frames
        (
            "wire.rs",
            include_str!("wire.rs"),
            "pub fn message_new(",
            "message_json_scrubbed",
        ),
        (
            "wire.rs",
            include_str!("wire.rs"),
            "pub fn tool_end(",
            "scrub_preview",
        ),
        (
            "wire.rs",
            include_str!("wire.rs"),
            "fn tool_call(",
            "scrub_preview",
        ),
        // approvals
        (
            "approval.rs",
            include_str!("approval.rs"),
            "async fn decide(",
            "scrub_preview",
        ),
        // error bodies
        (
            "error.rs",
            include_str!("error.rs"),
            "pub fn sanitize_detail(",
            "sanitize_error_detail",
        ),
        (
            "error.rs",
            include_str!("error.rs"),
            "pub fn scrub_preview(",
            "scrub_external_preview",
        ),
        // notifications + run summaries
        (
            "../agent_job.rs",
            include_str!("../agent_job.rs"),
            "fn fail(",
            "scrub_external_preview",
        ),
        (
            "../agent_job.rs",
            include_str!("../agent_job.rs"),
            "fn notify(",
            "scrub_external_preview",
        ),
        (
            "../agent_job.rs",
            include_str!("../agent_job.rs"),
            "fn success_summary(",
            "scrub_external_preview",
        ),
        (
            "../agent_job.rs",
            include_str!("../agent_job.rs"),
            "fn run(&self, _store",
            "scrub_external_preview",
        ),
        // daemon log records: the writer runs the kernel's log entry point
        // (`redact_secrets` plus the identity layer). The kernel's own body is
        // checked by kernel-broker's tests; here the call is held to its path,
        // and `logging.rs` tests a token-shaped secret through the writer.
        (
            "../logging.rs",
            include_str!("../logging.rs"),
            "fn write(&mut self",
            "kernel_broker::redact_log_line_guarded",
        ),
    ];

    let mut failures = String::new();
    for (file, source, signature, expected) in surfaces {
        let body = body_of(source, signature);
        if !body.contains(expected) {
            let _ = writeln!(
                failures,
                "{file}: `{signature}` no longer calls `{expected}`"
            );
        }
    }
    assert!(
        failures.is_empty(),
        "a display surface bypasses the shared scrubber:\n{failures}"
    );
}
