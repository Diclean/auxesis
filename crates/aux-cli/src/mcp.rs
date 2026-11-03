//! `aux mcp` — inspect the user's configured MCP servers.
//!
//! Read-only and bounded: `list` discovers each enabled server (isolated
//! failures, per-server timeout) and prints a status line; `tools <id>` prints
//! one server's discovered wire names and risk. Neither prints a tool
//! description, a schema or any other server-supplied content.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use kernel_core::i18n::{format, text};
use kernel_core::{Lang, Message};
use kernel_mcp::{McpConfig, McpConfigError, McpRuntime, McpServerState};

/// `aux mcp <list|tools>`.
#[derive(Debug, Args)]
pub struct McpArgs {
    #[command(subcommand)]
    action: McpAction,
}

#[derive(Debug, Subcommand)]
enum McpAction {
    /// List configured MCP servers, their state and tool count.
    List,
    /// List one server's discovered tool names and risk.
    Tools {
        /// Server id from `~/.auxesis/mcp.toml`.
        id: String,
    },
}

/// Run `aux mcp`.
pub fn run(args: McpArgs, lang: Lang) -> ExitCode {
    let home = kernel_core::auxesis_home();
    let config = match load(&home) {
        Ok(config) => config,
        Err(err) => {
            let message = format(Message::McpConfigUnusable, lang, &[&err.to_string()]);
            let _ = writeln!(std::io::stderr(), "{message}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = discover(&home, &config);
    match args.action {
        McpAction::List => print_list(&runtime, lang),
        McpAction::Tools { id } => print_tools(&runtime, &id, lang),
    }
    ExitCode::SUCCESS
}

/// Load `mcp.toml` through the verified home.
fn load(home: &Path) -> Result<McpConfig, McpConfigError> {
    let path = kernel_core::verified_home_or_verify(home)
        .and_then(|verified| verified.real_path())
        .map_err(McpConfigError::Io)?
        .join("mcp.toml");
    McpConfig::load_from_path(&path)
}

/// Discover the enabled servers, applying the same web deny-domain gate as the
/// daemon, plus its stdio confirmation and M6-2 install-approval policy, and
/// its sandbox (item 13).
///
/// The CLI is read-only, but it must not spawn a `stdio` server or contact an
/// `http` one that the daemon would refuse: a server is listed only when it
/// carries the owner's approval, checked by the daemon's own predicate in
/// [`kernel_mcp::McpServerConfig::is_install_approved`]. A `stdio` server also
/// needs its launch confirmation. If the daemon token cannot be read, nothing
/// is approved or confirmed (item 5, fail closed). Never fails: a runtime that
/// cannot start yields an empty report.
fn discover(home: &Path, config: &McpConfig) -> McpRuntime {
    discover_with(home, config, true)
}

/// [`discover`] with the SSRF guard made explicit so the gate itself can be
/// driven against a loopback fixture in a unit test. Production always passes
/// `true`.
fn discover_with(home: &Path, config: &McpConfig, network_guard: bool) -> McpRuntime {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return McpRuntime::empty();
    };
    let names: BTreeSet<String> = config
        .enabled_servers()
        .flat_map(|server| server.env.iter().cloned())
        .collect();
    let secrets = kernel_core::env_file::read_values(home, &names);
    let web = kernel_core::Config::load_or_create(&kernel_core::config_path(home))
        .map(|config| config.web)
        .unwrap_or_default();
    let deny = deny_domain_gate(web);
    let token = read_daemon_token(home);
    let options = kernel_mcp::McpStartOptions {
        network_guard,
        // The stdio sandbox is attached by the launch path, not by a flag.
        confirmation_secret: token.clone(),
    };
    runtime.block_on(McpRuntime::start_with(
        config.clone(),
        &secrets,
        options,
        &move |server| server_gate(server, token.as_deref(), &deny),
    ))
}

/// The daemon's per-server gate, in the daemon's order: the old uncurated
/// `stdio` confirmation first, then the M6-2 install approval, then the `[web]`
/// egress gate.
///
/// The approval predicate is `kernel_mcp`'s, not a copy, and the catalog pin
/// comes from the same catalog the daemon uses.
fn server_gate(
    server: &kernel_mcp::McpServerConfig,
    token: Option<&[u8]>,
    deny: &dyn Fn(&str) -> Option<&'static str>,
) -> Result<(), kernel_mcp::McpServerRefusal> {
    use kernel_mcp::{McpServerRefusal, McpTransport};
    if server.catalog_id.is_none()
        && server.transport == McpTransport::Stdio
        && !token.is_some_and(|token| server.stdio_is_confirmed_with(token))
    {
        return Err(McpServerRefusal::needs_confirmation(
            "stdio_confirmation_required",
        ));
    }
    let pin = auxd::mcp::catalog_pin(server);
    if !server.is_install_approved(token, pin.as_deref()) {
        return Err(McpServerRefusal::needs_approval("approval_required"));
    }
    if server.transport == McpTransport::Http {
        if let Some(label) = server.url.as_deref().and_then(deny) {
            return Err(McpServerRefusal::failed(label));
        }
    }
    Ok(())
}

/// Read the daemon token (`<home>/api.token`) without creating it.
///
/// Any failure (missing, unreadable, oversized, empty) means no confirmation
/// or approval can be honoured: an uncatalogued `stdio` server is reported
/// `needs_confirmation` and every other enabled server `needs_approval`.
fn read_daemon_token(home: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let verified = kernel_core::verified_home_or_verify(home).ok()?;
    let mut file = verified
        .open_read_existing(Path::new("api.token"), 4096)
        .ok()?;
    let mut token = String::new();
    file.read_to_string(&mut token).ok()?;
    let token = token.trim();
    if token.is_empty() || token.len() > 256 {
        return None;
    }
    Some(token.as_bytes().to_vec())
}

/// A minimal `[web].deny_domains` matcher, so the read-only CLI listing does
/// not pull the whole fetch stack in.
fn deny_domain_gate(web: kernel_core::WebConfig) -> impl Fn(&str) -> Option<&'static str> {
    move |url: &str| {
        let host = url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split(['/', ':']).next())
            .unwrap_or("");
        let denied = web.deny_domains.iter().any(|pattern| {
            let pattern = pattern.trim_start_matches("*.").trim_start_matches('.');
            !pattern.is_empty() && (host == pattern || host.ends_with(&format!(".{pattern}")))
        });
        denied.then_some("denied_domain")
    }
}

fn print_list(runtime: &McpRuntime, lang: Lang) {
    let mut out = std::io::stdout();
    if runtime.statuses().is_empty() {
        let _ = writeln!(out, "{}", text(Message::McpNoServers, lang));
        return;
    }
    let _ = writeln!(out, "{}", text(Message::McpServersHeader, lang));
    for status in runtime.statuses() {
        let state = match status.state {
            McpServerState::Ready => text(Message::McpStateReady, lang),
            McpServerState::Disabled => text(Message::McpStateDisabled, lang),
            McpServerState::NeedsConfirmation => text(Message::McpStateNeedsConfirmation, lang),
            McpServerState::NeedsApproval => text(Message::McpStateNeedsApproval, lang),
            McpServerState::Quarantined => text(Message::McpStateQuarantined, lang),
            McpServerState::Failed => text(Message::McpStateFailed, lang),
        };
        let count = format(
            Message::McpToolCount,
            lang,
            &[&status.tool_count.to_string()],
        );
        let _ = writeln!(
            out,
            "  {}  {}  {}  {}",
            status.id, status.transport, state, count
        );
    }
}

fn print_tools(runtime: &McpRuntime, id: &str, lang: Lang) {
    let mut out = std::io::stdout();
    let descriptors = runtime.descriptors_for(id);
    let known = runtime.statuses().iter().any(|status| status.id == id);
    if descriptors.is_empty() && !known {
        let _ = writeln!(out, "{}", format(Message::McpUnknownServer, lang, &[id]));
        return;
    }
    let _ = writeln!(out, "{}", format(Message::McpToolsHeader, lang, &[id]));
    for descriptor in descriptors {
        let _ = writeln!(
            out,
            "  {}  ({})",
            descriptor.wire_name,
            descriptor.risk().as_str()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_deny_gate_matches_domains_and_subdomains() {
        let mut web = kernel_core::WebConfig::default();
        web.deny_domains.push("mcp.example.invalid".to_string());
        web.deny_domains.push("*.blocked.invalid".to_string());
        let deny = deny_domain_gate(web);
        assert_eq!(
            deny("https://mcp.example.invalid/mcp"),
            Some("denied_domain")
        );
        assert_eq!(
            deny("https://sub.blocked.invalid/mcp"),
            Some("denied_domain")
        );
        assert_eq!(deny("https://mcp.data.gouv.fr/mcp"), None);
    }

    #[test]
    fn a_missing_file_is_an_empty_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let config = McpConfig::load_from_path(&dir.path().join("mcp.toml")).unwrap();
        assert!(config.is_empty());
    }

    #[test]
    fn the_cli_refuses_a_stdio_server_that_is_not_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // No daemon token: nothing can be confirmed, so the stdio server is
        // never spawned (item 13, fail closed).
        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"stdio-one\"\ntransport = \"stdio\"\n\
             command = \"/bin/true\"\nenabled = true\n[server.agents]\nmain = [\"X\"]\n",
        )
        .unwrap();
        let runtime = discover(home, &config);
        assert_eq!(runtime.statuses().len(), 1);
        assert_eq!(
            runtime.statuses()[0].state,
            kernel_mcp::McpServerState::NeedsConfirmation
        );
        assert_eq!(runtime.tool_count(), 0);
    }

    #[test]
    fn the_cli_gate_contacts_an_http_server_only_after_approval() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = "mcp-cli-approval-token-0123456789";
        std::fs::write(home.join("api.token"), token).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let mut config = McpConfig::parse(
            "t",
            &format!(
                "[[server]]\nid = \"local\"\ntransport = \"http\"\nurl = \"{url}\"\n\
                 enabled = true\n[server.agents]\nmain = [\"HTTP_TOOL\"]\n"
            ),
        )
        .unwrap();

        // No approval: the gate refuses before any transport is built.
        let before = discover_with(home, &config, false);
        assert_eq!(
            before.statuses()[0].state,
            kernel_mcp::McpServerState::NeedsApproval
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // The same keyed binding the owner's approve writes: the CLI now
        // reaches the transport (the fake closes the connection, the hit is
        // the proof it was contacted).
        config.server[0].approval = Some(
            config.server[0]
                .approval_binding(token.as_bytes(), None)
                .expect("approval binding"),
        );
        let after = discover_with(home, &config, false);
        assert_ne!(
            after.statuses()[0].state,
            kernel_mcp::McpServerState::NeedsApproval
        );
        let contacted = hits.load(Ordering::SeqCst);
        assert!(contacted > 0);

        // With the production SSRF guard the approval gate still releases the
        // server; the loopback address is refused before any connection, as it
        // always was.
        let guarded = discover_with(home, &config, true);
        assert_eq!(
            guarded.statuses()[0].state,
            kernel_mcp::McpServerState::Failed
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            contacted,
            "the SSRF guard refuses the loopback fixture before connecting"
        );
    }
}
