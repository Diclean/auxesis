//! Log-filter defaults shared by the Auxesis binaries.
//!
//! A hostile web page is parsed by the fetch stack in the daemon's process,
//! and the HTML parser crates log through the `log` facade. At the default
//! levels those records reach the subscriber and, for the daemon, are redirected
//! by launchd into `~/.auxesis/logs/auxd.log` — so parser noise is a
//! disk-fill vector, not just noise (RV4-02: html5ever logs one `WARN` per
//! foster-parented token; 99,360 records / 8.85 MiB on disk for a single
//! 512 KiB unauthenticated fetch).

/// `EnvFilter` directives that silence the HTML/XML parser crates by
/// default: `html5ever` (foster-parenting warnings in the tree builder,
/// char-reference `debug!` in the tokenizer), `markup5ever`, and `xml5ever`
/// (reached through `markup5ever_rcdom`).
///
/// These are *defaults*, not a lock: [`with_parser_logs_silenced`] places
/// them before the caller's filter, and `EnvFilter` keeps the last directive
/// for a given target, so an explicit later directive — `RUST_LOG=html5ever=warn`
/// — re-enables the crate for debugging.
pub const NOISY_PARSER_LOG_DIRECTIVES: &str = "html5ever=off,markup5ever=off,xml5ever=off";

/// `EnvFilter` directives that cap the WhatsApp transport stack at `warn`
/// by default.
///
/// `whatsapp-rust` and its `wacore*`/`waproto` dependencies log peer
/// identities at `INFO` — for example `Identity change for <number> …` — and
/// a phone number or JID in `~/.auxesis/logs/auxd.log` violates the project's
/// log-hygiene rules. Capping those targets at `warn` keeps errors and
/// warnings visible while dropping the identity-carrying `info!`/`debug!`
/// records. Like the parser defaults these are overridable: the directives
/// are prepended and `EnvFilter` keeps the last directive for a target, so
/// `RUST_LOG=whatsapp_rust=info` re-enables the stack for debugging (the
/// writer-level redaction the binaries install still applies).
///
/// Every crate of the transport graph is named explicitly: `EnvFilter` only
/// matches a target on a `::` boundary, so `wacore=warn` does not cover
/// `wacore_binary`, and the hyphenated crate names (`whatsapp-rust`, `wacore-*`)
/// appear as underscores in `tracing` targets.
pub const NOISY_TRANSPORT_LOG_DIRECTIVES: &str = "whatsapp_rust=warn,wacore=warn,wacore_appstate=warn,wacore_binary=warn,wacore_derive=warn,wacore_libsignal=warn,wacore_noise=warn,waproto=warn,whatsapp_rust_sqlite_storage=warn,whatsapp_rust_tokio_transport=warn,whatsapp_rust_ureq_http_client=warn";

/// Prepend [`NOISY_PARSER_LOG_DIRECTIVES`] to `base`.
///
/// `base` is the operator's filter (a `RUST_LOG` value or the configured
/// level); a directive in it for one of the silenced targets replaces the
/// default because directives with the same target are deduplicated in
/// favour of the last one parsed.
pub fn with_parser_logs_silenced(base: &str) -> String {
    format!("{NOISY_PARSER_LOG_DIRECTIVES},{base}")
}

/// Prepend both default-silence groups ([`NOISY_TRANSPORT_LOG_DIRECTIVES`]
/// then [`NOISY_PARSER_LOG_DIRECTIVES`]) to `base`.
///
/// This is the filter the long-running binaries build: parser noise and the
/// WhatsApp transport's identity-carrying records are both capped unless the
/// operator opts back in through `RUST_LOG`/the configured level.
pub fn with_noisy_logs_silenced(base: &str) -> String {
    format!("{NOISY_TRANSPORT_LOG_DIRECTIVES},{NOISY_PARSER_LOG_DIRECTIVES},{base}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_directives_come_first() {
        let filter = with_parser_logs_silenced("info");
        assert_eq!(filter, "html5ever=off,markup5ever=off,xml5ever=off,info");
        // A caller directive for the same target is parsed later, which is
        // what lets an explicit `RUST_LOG=html5ever=warn` win.
        let overridden = with_parser_logs_silenced("html5ever=warn");
        assert!(overridden.ends_with("html5ever=warn"));
    }

    #[test]
    fn transport_defaults_cap_the_whole_whatsapp_stack_at_warn() {
        let filter = with_noisy_logs_silenced("info");
        // Every transport crate is capped before the caller's `info`, so a
        // `whatsapp_rust` INFO record is dropped by default.
        for target in [
            "whatsapp_rust",
            "wacore",
            "wacore_binary",
            "wacore_libsignal",
            "wacore_noise",
            "waproto",
        ] {
            assert!(
                filter.contains(&format!("{target}=warn")),
                "missing {target}: {filter}"
            );
        }
        assert!(filter.ends_with(",info"), "{filter}");
        // The caller's later directive still wins for a given target.
        let overridden = with_noisy_logs_silenced("whatsapp_rust=debug");
        assert!(overridden.ends_with("whatsapp_rust=debug"), "{overridden}");
        let parser_overridden = with_noisy_logs_silenced("info,html5ever=warn");
        assert!(
            parser_overridden.ends_with("html5ever=warn"),
            "{parser_overridden}"
        );
    }
}
