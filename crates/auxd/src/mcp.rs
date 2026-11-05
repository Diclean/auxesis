//! P2 in the daemon: the user's `~/.auxesis/mcp.toml` and its runtime.
//!
//! Nothing here is enabled by default. An **absent** file means no server; a
//! present but invalid file is logged as a clear error and the daemon boots
//! without MCP, exactly like a config that only has some servers enabled. A
//! server that fails discovery is isolated: its id and a content-free reason
//! are logged, and every other server still mounts its tools.
//!
//! # Egress
//!
//! There is no dedicated MCP egress allowlist yet. The client's own
//! [`kernel_mcp::HttpTransport`] pins the exact configured origin and refuses a
//! non-`https` public host, which is the scoped "allowed only for this client"
//! guarantee. On top of that, an `http` server is passed through the existing
//! `[web]` egress gate (`deny_domains`/`https_only`/shape), so a host the owner
//! already denied for `http_fetch` is refused here too. A first-class MCP host
//! allowlist is noted as P3.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use kernel_core::privacy::PrivacyMode;
use kernel_mcp::{
    McpConfig, McpConfigError, McpRuntime, McpServerConfig, McpServerRefusal, McpStartOptions,
    McpTransport,
};

use crate::privacy_wiring;

/// Name of the user MCP configuration inside the Auxesis home.
pub const MCP_CONFIG_FILE: &str = "mcp.toml";

/// The daemon's MCP runtime, shared by the turn runner, the job runner and the
/// API. The privacy watch swaps the runtime inside it when the mode changes.
pub type McpSlot = Arc<RwLock<Arc<McpRuntime>>>;

/// The ordering shared by every MCP config write and the privacy rebuild.
///
/// A mutation holds [`Self::mutation`] while it rewrites `mcp.toml` and
/// installs the replacement runtime, and bumps [`Self::generation`] for each
/// committed write. The privacy watch takes the same lock, so a rebuild can
/// never install a runtime built from a config that a revoke, shrink or delete
/// has already replaced.
#[derive(Clone)]
pub struct McpOrdering {
    /// Serialises MCP config writes and runtime replacement.
    pub mutation: Arc<tokio::sync::Mutex<()>>,
    /// Monotone generation of the persisted MCP configuration.
    pub generation: Arc<std::sync::atomic::AtomicU64>,
}

impl McpOrdering {
    /// A fresh, unshared ordering.
    pub fn new() -> Self {
        Self {
            mutation: Arc::new(tokio::sync::Mutex::new(())),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl Default for McpOrdering {
    fn default() -> Self {
        Self::new()
    }
}

/// Keep the runtime in step with the live mode (`README.md`, "The two modes").
/// MCP servers run in both modes. On a switch open → private every running
/// child is stopped, even one that a mounted tool still holds, and the runtime
/// is rebuilt, so no open-mode state survives into private. A plain
/// private → private tick does nothing. A switch that lands during a rebuild
/// drops the new runtime, which kills its children, and the rebuild is retried.
pub fn spawn_privacy_watch(
    home: PathBuf,
    slot: McpSlot,
    ordering: McpOrdering,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(privacy_wiring::WATCH_INTERVAL);
        let mut was_private = privacy_wiring::private_now(&home);
        let mut restart = false;
        loop {
            tick.tick().await;
            let private = privacy_wiring::private_now(&home);
            if private && !was_private {
                current(&slot).stop_child_processes().await;
                restart = true;
            }
            was_private = private;
            if restart {
                let mode = privacy_wiring::current_mode(&home);
                restart = !rebuild(&home, &slot, mode, &ordering).await;
            }
        }
    })
}

/// The runtime currently in `slot`.
pub fn current(slot: &McpSlot) -> Arc<McpRuntime> {
    Arc::clone(&slot.read().unwrap_or_else(|poisoned| poisoned.into_inner()))
}

/// Whether the new runtime was installed (`false`: retry on the next tick).
async fn rebuild(home: &Path, slot: &McpSlot, mode: PrivacyMode, ordering: &McpOrdering) -> bool {
    // Read, discover and swap as one operation, under the same lock as every
    // MCP mutation. A revoke that lands while a rebuild is discovering either
    // waits and rebuilds the runtime from the new config, or lands before the
    // read; the pre-revoke runtime can never be installed over it.
    let _mutation = ordering.mutation.lock().await;
    let generation = ordering
        .generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let Ok(config) = crate::api::load_config_verified(home) else {
        return false;
    };
    let sandbox = aux_engine::shell_sandbox(&config.shell);
    let runtime = start(home, &config.web, &sandbox).await;
    // The mode may have moved while discovery ran. A runtime built for the old
    // mode is dropped here, and dropping it kills the children it started.
    if privacy_wiring::current_mode(home) != mode {
        return false;
    }
    // Defense in depth: a writer that only bumps the generation (without the
    // lock) also refuses this runtime instead of installing a stale one.
    if ordering
        .generation
        .load(std::sync::atomic::Ordering::SeqCst)
        != generation
    {
        return false;
    }
    let old = {
        let mut current = slot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut *current, runtime)
    };
    drop(old);
    true
}

/// Read and validate the user's MCP configuration, through the verified home.
///
/// A missing file is an empty configuration. The caller decides whether an
/// invalid file is fatal (it is not: the daemon logs and keeps running).
pub fn load(home: &Path) -> Result<McpConfig, McpConfigError> {
    read_config(&kernel_core::verified_home_or_verify(home)?)
}

/// `mcp.toml` opened once through `home`'s fd (`O_NOFOLLOW | O_NONBLOCK`): a
/// link, a FIFO or a file over `MAX_MCP_CONFIG_BYTES` is an error at once,
/// never followed nor waited on. Missing is an empty configuration.
pub fn read_config(home: &kernel_core::SandboxHome) -> Result<McpConfig, McpConfigError> {
    use std::io::Read;
    let max = kernel_mcp::MAX_MCP_CONFIG_BYTES;
    let path = home.real_path()?.join(MCP_CONFIG_FILE);
    let file = match home.open_read_existing(Path::new(MCP_CONFIG_FILE), max) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(McpConfig::default()),
        file => file?,
    };
    let mut text = String::new();
    file.take(max + 1).read_to_string(&mut text)?;
    McpConfig::parse(&path.display().to_string(), &text)
}

/// The curated catalog pin for one configured server, if its claimed entry
/// resolves.
///
/// The CLI applies the daemon's install-approval predicate, and the pin is
/// part of the approval binding; exposing it keeps the CLI's answer exactly
/// the daemon's instead of a fail-closed guess.
pub fn catalog_pin(server: &McpServerConfig) -> Option<String> {
    crate::api::mcp_plugins::catalog_pin(server)
}

/// Every declared `env` name across the enabled servers.
pub fn declared_env_names(config: &McpConfig) -> BTreeSet<String> {
    config
        .enabled_servers()
        .flat_map(|server| server.env.iter().cloned())
        .collect()
}

/// Read the requested values from the protected `<home>/.env`.
///
/// Delegates to the shared reader; values are returned to the caller and never
/// logged.
pub fn read_secrets(home: &Path, names: &BTreeSet<String>) -> BTreeMap<String, String> {
    kernel_core::env_file::read_values(home, names)
}

/// Load, policy-check and discover the configured servers.
///
/// Never fails: a single unusable, unconfirmed or unreachable server is
/// quarantined in isolation, and every other server still loads.
pub async fn start(
    home: &Path,
    web: &kernel_core::WebConfig,
    _sandbox: &kernel_broker::ShellSandbox,
) -> Arc<McpRuntime> {
    let config = match load(home) {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "MCP configuration is unusable; starting without MCP servers"
            );
            return Arc::new(McpRuntime::empty());
        }
    };
    if config.is_empty() {
        return Arc::new(McpRuntime::empty());
    }
    let names = declared_env_names(&config);
    let secrets = read_secrets(home, &names);
    // Defense in depth: register every injected value with the exact-value
    // scrubber, so a value can never survive into a log even by accident.
    // Nothing here logs the value or its length.
    for value in secrets.values() {
        let _ = kernel_broker::scrub::register_known_secret(value);
    }
    let gate = kernel_net::WebGate::new(web.clone());
    // The API token keys every stdio confirmation. If it cannot be read or
    // created, no confirmation can be valid, so every uncurated stdio server
    // is reported `needs_confirmation` (item 5, fail closed).
    let confirmation_secret = crate::api::ApiToken::load_or_create(home)
        .map(|token| token.confirmation_key().to_vec())
        .ok();
    if confirmation_secret.is_none() {
        tracing::warn!(
            "daemon token unavailable; no stdio MCP server can be confirmed (fail closed)"
        );
    }
    let options = McpStartOptions {
        network_guard: true,
        // Item 8: the stdio sandbox is not an option — the launch path always
        // attaches it. On macOS a missing `sandbox-exec` refuses the spawn, and
        // there is no `sandbox_stdio` switch to turn it off.
        confirmation_secret: confirmation_secret.clone(),
    };
    // Both transports run in private mode (TOK-7): the arguments keep session
    // tokens and the replies pass the session gate. `spawn_privacy_watch`
    // restarts the children when the mode turns private.
    let runtime = McpRuntime::start_with(config, &secrets, options, &move |server| {
        // Catalog/confirmation/hard-refusal policy first: an unconfirmed or
        // mismatched server is quarantined, never spawned.
        if let Some(refusal) =
            crate::api::mcp_plugins::server_policy_refusal(server, confirmation_secret.as_deref())
        {
            return Err(refusal);
        }
        egress_refusal(&gate, server).map_err(McpServerRefusal::failed)
    })
    .await;
    let ready = runtime
        .statuses()
        .iter()
        .filter(|status| status.state == kernel_mcp::McpServerState::Ready)
        .count();
    tracing::info!(
        servers = runtime.statuses().len(),
        ready,
        tools = runtime.tool_count(),
        "MCP runtime started"
    );
    Arc::new(runtime)
}

/// Apply the existing `[web]` egress gate to one configured server.
fn egress_refusal(
    gate: &kernel_net::WebGate,
    server: &McpServerConfig,
) -> Result<(), &'static str> {
    if server.transport != McpTransport::Http {
        return Ok(());
    }
    let Some(url) = server.url.as_deref() else {
        return Ok(());
    };
    gate.check(url)
        .map(|_| ())
        .map_err(|reason| reason.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_enabled_servers_contribute_env_names() {
        let config = McpConfig::parse(
            "mcp.toml",
            r#"
[[server]]
id = "on"
transport = "http"
url = "https://a.invalid/mcp"
env = ["DATAGOUV_KEY"]
enabled = true

[[server]]
id = "off"
transport = "http"
url = "https://b.invalid/mcp"
env = ["UNUSED_KEY"]
enabled = false
"#,
        )
        .unwrap();
        let names = declared_env_names(&config);
        assert!(names.contains("DATAGOUV_KEY"));
        assert!(!names.contains("UNUSED_KEY"));
    }

    #[test]
    fn a_missing_env_file_yields_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let names: BTreeSet<String> = ["DATAGOUV_KEY".to_owned()].into_iter().collect();
        assert!(read_secrets(dir.path(), &names).is_empty());
    }

    /// The owner's config for these tests: open mode.
    fn open_config(home: &std::path::Path) {
        std::fs::write(
            kernel_core::config_path(home),
            "version = 1\nprivacy.mode = \"open\"\n",
        )
        .unwrap();
    }

    fn no_sandbox() -> kernel_broker::ShellSandbox {
        kernel_broker::ShellSandbox::new(false, false, true)
    }

    #[test]
    fn a_denied_or_malformed_http_endpoint_is_refused_by_the_web_gate() {
        let mut web = kernel_core::WebConfig::default();
        web.deny_domains.push("mcp.example.invalid".to_string());
        let gate = kernel_net::WebGate::new(web);
        let denied = McpServerConfig {
            id: "denied".to_string(),
            catalog_id: None,
            data_class: kernel_mcp::McpDataClass::Sensitive,
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: McpTransport::Http,
            url: Some("https://mcp.example.invalid/mcp".to_string()),
            command: None,
            args: Vec::new(),
            env: Vec::new(),
            enabled: true,
            agents: BTreeMap::new(),
        };
        assert!(egress_refusal(&gate, &denied).is_err());

        let allowed = McpServerConfig {
            url: Some("https://mcp.data.gouv.fr/mcp".to_string()),
            ..denied.clone()
        };
        assert!(egress_refusal(&gate, &allowed).is_ok());

        let stdio = McpServerConfig {
            transport: McpTransport::Stdio,
            url: None,
            command: Some("/bin/true".to_string()),
            ..denied.clone()
        };
        assert!(egress_refusal(&gate, &stdio).is_ok());
    }

    #[test]
    fn an_unconfirmed_stdio_server_is_quarantined_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        kernel_core::ensure_home(home).unwrap();
        open_config(home);
        std::fs::write(
            home.join("mcp.toml"),
            r#"
[[server]]
id = "legacy"
transport = "stdio"
command = "/nonexistent/mcp-server-does-not-exist"
enabled = true
[server.agents]
main = ["X"]
"#,
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let web = kernel_core::WebConfig::default();
        let mcp = runtime.block_on(start(home, &web, &no_sandbox()));
        assert_eq!(mcp.statuses().len(), 1);
        assert_eq!(
            mcp.statuses()[0].state,
            kernel_mcp::McpServerState::NeedsConfirmation
        );
        assert_eq!(
            mcp.statuses()[0].reason,
            Some("stdio_confirmation_required")
        );
        assert_eq!(mcp.tool_count(), 0);
    }

    /// A real, readable program file that is not an MCP server.
    ///
    /// The confirmation binds the program's SHA-256, so the file must exist
    /// and be readable: a program that cannot be hashed gets no binding at
    /// all (and is never confirmed).
    fn broken_program() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("mcp-server-does-not-speak-mcp");
        std::fs::write(&program, b"not an mcp server\n").unwrap();
        (dir, program.to_string_lossy().into_owned())
    }

    #[test]
    fn a_confirmed_but_broken_server_is_failed_and_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        kernel_core::ensure_home(home).unwrap();
        let (_program_dir, command) = broken_program();
        // Both records are keyed by the daemon token, so the test must mint
        // the same bindings the approve endpoint would: the launch
        // confirmation and the install approval (a confirmation alone is not
        // an approval since kernel v0.1.2).
        let token = "mcp-unit-token-0123456789";
        std::fs::write(crate::api::token_path(home), token).unwrap();
        let draft = format!(
            "[[server]]\nid = \"broken\"\ntransport = \"stdio\"\ncommand = \"{command}\"\n\
             enabled = true\n[server.agents]\nmain = [\"X\"]\n"
        );
        let parsed = kernel_mcp::McpConfig::parse("mcp.toml", &draft).unwrap();
        let hash = parsed.server[0]
            .confirmation_binding(token.as_bytes())
            .unwrap();
        let approval = parsed.server[0]
            .approval_binding(token.as_bytes(), None)
            .unwrap();
        open_config(home);
        std::fs::write(
            home.join("mcp.toml"),
            format!(
                "[[server]]\nid = \"broken\"\ntransport = \"stdio\"\ncommand = \"{command}\"\n\
                 enabled = true\nstdio_confirmed = true\nstdio_confirmation = \"{hash}\"\n\
                 approval = \"{approval}\"\n[server.agents]\nmain = [\"X\"]\n"
            ),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let web = kernel_core::WebConfig::default();
        let mcp = runtime.block_on(start(home, &web, &no_sandbox()));
        assert_eq!(mcp.statuses().len(), 1);
        assert_eq!(mcp.statuses()[0].state, kernel_mcp::McpServerState::Failed);
        assert_eq!(mcp.tool_count(), 0);
    }

    #[test]
    fn an_invalid_server_is_quarantined_not_a_boot_failure() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        kernel_core::ensure_home(home).unwrap();
        open_config(home);
        std::fs::write(
            home.join("mcp.toml"),
            "[[server]]\nid = \"UPPER\"\ntransport = \"stdio\"\ncommand = \"/bin/true\"\nenabled = true\n",
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let web = kernel_core::WebConfig::default();
        let mcp = runtime.block_on(start(home, &web, &no_sandbox()));
        assert_eq!(mcp.statuses().len(), 1);
        assert_eq!(
            mcp.statuses()[0].state,
            kernel_mcp::McpServerState::Quarantined
        );
        assert_eq!(mcp.statuses()[0].reason, Some("invalid_server_id"));
        assert_eq!(mcp.tool_count(), 0);
    }

    #[test]
    fn a_catalog_mismatch_is_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        kernel_core::ensure_home(home).unwrap();
        open_config(home);
        std::fs::write(
            home.join("mcp.toml"),
            "[[server]]\nid = \"datagouv-mcp\"\ncatalog_id = \"datagouv-mcp\"\n\
             transport = \"http\"\nurl = \"https://attacker.invalid/mcp\"\nenabled = true\n",
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let web = kernel_core::WebConfig::default();
        let mcp = runtime.block_on(start(home, &web, &no_sandbox()));
        assert_eq!(
            mcp.statuses()[0].state,
            kernel_mcp::McpServerState::Quarantined
        );
        assert_eq!(mcp.statuses()[0].reason, Some("catalog_mismatch"));
    }

    #[test]
    fn a_stdio_server_cannot_shadow_a_catalog_id() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        kernel_core::ensure_home(home).unwrap();
        let (_program_dir, command) = broken_program();
        let token = "mcp-unit-token-0123456789";
        std::fs::write(crate::api::token_path(home), token).unwrap();
        // Even a fully confirmed stdio server that claims a catalog id is
        // quarantined (item 7): the catalog publishes no stdio command, so the
        // claim can never match and the tools are never registered under the
        // catalog toolkit name.
        let draft = format!(
            "[[server]]\nid = \"shadow\"\ncatalog_id = \"mcp-insee-entreprises\"\n\
             transport = \"stdio\"\ncommand = \"{command}\"\nenabled = true\n\
             [server.agents]\nmain = [\"X\"]\n"
        );
        let parsed = kernel_mcp::McpConfig::parse("mcp.toml", &draft).unwrap();
        let hash = parsed.server[0]
            .confirmation_binding(token.as_bytes())
            .unwrap();
        open_config(home);
        std::fs::write(
            home.join("mcp.toml"),
            format!(
                "[[server]]\nid = \"shadow\"\ncatalog_id = \"mcp-insee-entreprises\"\n\
                 transport = \"stdio\"\ncommand = \"{command}\"\nenabled = true\n\
                 stdio_confirmed = true\nstdio_confirmation = \"{hash}\"\n\
                 [server.agents]\nmain = [\"X\"]\n"
            ),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let web = kernel_core::WebConfig::default();
        let mcp = runtime.block_on(start(home, &web, &no_sandbox()));
        assert_eq!(
            mcp.statuses()[0].state,
            kernel_mcp::McpServerState::Quarantined
        );
        assert_eq!(mcp.statuses()[0].reason, Some("catalog_stdio_unverifiable"));
        assert_eq!(mcp.tool_count(), 0);
    }

    /// A FIFO nobody writes to, a link or a dangling link at mcp.toml is an
    /// error at once: never a wait, and the link's server list is never read.
    #[cfg(unix)]
    #[test]
    fn a_fifo_or_linked_mcp_toml_is_refused_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (path, other) = (dir.path().join(MCP_CONFIG_FILE), dir.path().join("o.toml"));
        let server = "[[server]]\nid = \"on\"\ntransport = \"http\"\nenabled = true\n";
        std::fs::write(&other, format!("{server}url = \"https://a.invalid/mcp\"\n")).unwrap();
        // Unregistered: no other test can reach this home.
        let home = kernel_core::SandboxHome::open(dir.path()).unwrap();
        for kind in ["fifo", "link", "dangling"] {
            match kind {
                "fifo" => {
                    let made = std::process::Command::new("mkfifo").arg(&path).status();
                    assert!(made.unwrap().success());
                }
                "link" => std::os::unix::fs::symlink(&other, &path).unwrap(),
                _ => std::os::unix::fs::symlink(dir.path().join("gone"), &path).unwrap(),
            }
            let (moved, (sent, got)) = (home.clone(), std::sync::mpsc::channel());
            std::thread::spawn(move || sent.send(read_config(&moved).is_err()));
            let wait = std::time::Duration::from_secs(10);
            assert!(got.recv_timeout(wait).expect("blocked"), "{kind}");
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::rename(&other, &path).unwrap();
        assert_eq!(read_config(&home).unwrap().enabled_servers().count(), 1);
    }
}
