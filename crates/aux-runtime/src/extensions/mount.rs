//! Mounts, freezing and registration.
//!
//! A mount is per agent. Mounting records the extension in
//! `~/.auxesis/extensions/mounts.json`; the daemon then registers each tool as
//! `mcp__<name>__<tool>` on the agent's `kernel-broker` registry, where the
//! default is `ask` because an MCP tool requires an exact-name rule.
//!
//! Identity drift freezes the extension: it is unmounted from every agent, a
//! `ext.frozen` Ledger row is written, and only `aux ext verify --accept`
//! (owner re-approval) clears the flag.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kernel_broker::ToolRegistry;
use kernel_mcp::{McpTool, McpTransport};
use serde::{Deserialize, Serialize};

use super::extensions_dir;
use super::install::{load_installed, InstalledExtension};
use super::ledger;
use super::session::{session_for, verify_identity, ExtensionSession, SessionOptions};

/// Everything a mount needs to know about one extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionState {
    /// Extension name.
    pub name: String,
    /// Pinned version.
    pub version: String,
    /// `mcp` in slice 1.
    pub kind: String,
    /// True once identity drift froze it.
    #[serde(default)]
    pub frozen: bool,
    /// Tool name → hex blake3 identity, pinned at install.
    #[serde(default)]
    pub tools: BTreeMap<String, String>,
    /// Declared `host:port` allowlist.
    #[serde(default)]
    pub network: Vec<String>,
    /// Declared secret env names.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// The `[oauth]` table pinned at approval; `None` when the extension has
    /// none. A state written before this pin existed has no field, so an
    /// extension that now carries `[oauth]` fails closed until re-approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<super::catalog::OAuthConfig>,
}

/// Everything that can refuse a mount.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// The extension is not installed.
    #[error("extension `{0}` is not installed")]
    NotInstalled(String),
    /// The extension is installed but has no pinned identity row.
    #[error("extension `{0}` has no pinned identity; reinstall or verify it")]
    MissingState(String),
    /// The extension is frozen until the owner re-approves it.
    #[error("extension `{0}` is frozen")]
    Frozen(String),
    /// A sensitive extension is not mountable in Private mode.
    #[error("extension `{0}` is sensitive and cannot be mounted in Private mode")]
    PrivateMode(String),
    /// The installed version, network allowlist or secret names differ from
    /// what the owner approved; only `aux ext verify --accept` clears it.
    #[error("approval_required: extension `{name}` changed since approval ({reason}); run `aux ext verify --accept {name}`")]
    ApprovalRequired {
        /// Extension name.
        name: String,
        /// Content-free reason: what changed.
        reason: String,
    },
    /// The agent name is empty.
    #[error("agent name is empty")]
    InvalidAgent,
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The `[privacy]` table of a `config.toml`, ignoring every other section.
#[derive(Debug, Default, serde::Deserialize)]
struct PrivacyFile {
    #[serde(default)]
    privacy: kernel_core::privacy::PrivacyConfig,
}

/// The live privacy mode of `home`, re-read on every call.
///
/// A config that cannot be read or parsed is [`PrivacyMode::Private`], so a
/// broken file fails toward refusing the mount. config.toml is opened once
/// and never waited on: a FIFO, a symlink, a directory or another user's file
/// is refused at once, and so is Private too.
pub fn current_mode(home: &Path) -> kernel_core::privacy::PrivacyMode {
    let read = crate::known_names::read_config(home)
        .ok()
        .and_then(|text| toml::from_str::<PrivacyFile>(&text).ok());
    read.map(|file| file.privacy.mode)
        .unwrap_or(kernel_core::privacy::PrivacyMode::Private)
}

/// The persisted mount table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MountTable {
    #[serde(default)]
    agents: BTreeMap<String, Vec<String>>,
}

fn state_path(home: &Path, name: &str) -> PathBuf {
    extensions_dir(home)
        .join("state")
        .join(format!("{name}.json"))
}

fn mounts_path(home: &Path) -> PathBuf {
    extensions_dir(home).join("mounts.json")
}

/// Persist one extension's state (0600).
pub fn store_state(home: &Path, state: &ExtensionState) -> std::io::Result<()> {
    let path = state_path(home, &state.name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        super::install::set_mode(parent, 0o700)?;
    }
    let text = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;
    std::fs::write(&path, text)?;
    super::install::set_mode(&path, 0o600)?;
    Ok(())
}

/// Load one extension's state, when it exists.
pub fn load_state(home: &Path, name: &str) -> Option<ExtensionState> {
    let text = std::fs::read_to_string(state_path(home, name)).ok()?;
    serde_json::from_str(&text).ok()
}

fn load_mounts(home: &Path) -> MountTable {
    std::fs::read_to_string(mounts_path(home))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn store_mounts(home: &Path, mounts: &MountTable) -> std::io::Result<()> {
    let path = mounts_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        super::install::set_mode(parent, 0o700)?;
    }
    let text = serde_json::to_string_pretty(mounts).map_err(std::io::Error::other)?;
    std::fs::write(&path, text)?;
    super::install::set_mode(&path, 0o600)?;
    Ok(())
}

/// The `host:port` allowlist of an entry, in the form the state pins.
pub fn network_pins(entry: &super::catalog::Entry) -> Vec<String> {
    entry
        .network_allowlist()
        .into_iter()
        .map(|(host, port)| format!("{host}:{port}"))
        .collect()
}

/// The `[oauth]` fields that differ between the pin and the installed entry.
///
/// Field names only, never values: the reason is content-free.
fn changed_oauth_fields(
    pinned: &super::catalog::OAuthConfig,
    now: &super::catalog::OAuthConfig,
) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if pinned.authorization_url != now.authorization_url {
        changed.push("authorization_url");
    }
    if pinned.token_url != now.token_url {
        changed.push("token_url");
    }
    if pinned.client_id != now.client_id {
        changed.push("client_id");
    }
    if pinned.scopes != now.scopes {
        changed.push("scopes");
    }
    if pinned.client_secret_env != now.client_secret_env {
        changed.push("client_secret_env");
    }
    // `OAuthConfig` derives `PartialEq`: a field added after this list is
    // still caught here, so it can never be silently unpinned.
    unlisted_oauth_change(&mut changed, pinned == now);
    changed
}

/// The whole-struct fallback in [`changed_oauth_fields`].
///
/// Split out so the branch is testable without adding a field to
/// `OAuthConfig` just for a test. It never overwrites a named field.
fn unlisted_oauth_change(changed: &mut Vec<&'static str>, equal: bool) {
    if changed.is_empty() && !equal {
        changed.push("other");
    }
}

/// Refuse an installed build the owner did not approve.
///
/// It must carry the pinned version, and its network hosts and secret names
/// must each be in the pinned sets. A narrower or equal set passes. Its
/// `[oauth]` table must equal the pinned one: a changed authorize/token URL,
/// client id, client secret name, scopes or any other table field is refused,
/// and an extension that gained `[oauth]` after a pin written without one
/// fails closed.
pub fn check_approval(
    state: &ExtensionState,
    installed: &InstalledExtension,
) -> Result<(), MountError> {
    let refuse = |reason: String| {
        Err(MountError::ApprovalRequired {
            name: installed.name.clone(),
            reason,
        })
    };
    if installed.version != state.version || installed.entry.version != state.version {
        return refuse(format!(
            "version {} is not the approved {}",
            installed.version, state.version
        ));
    }
    let wider: Vec<String> = network_pins(&installed.entry)
        .into_iter()
        .filter(|host| !state.network.contains(host))
        .collect();
    if !wider.is_empty() {
        return refuse(format!("new network hosts: {}", wider.join(", ")));
    }
    let new_secrets: Vec<String> = installed
        .entry
        .secret_names()
        .into_iter()
        .filter(|name| !state.secrets.contains(name))
        .collect();
    if !new_secrets.is_empty() {
        return refuse(format!("new secret names: {}", new_secrets.join(", ")));
    }
    match (&state.oauth, &installed.entry.oauth) {
        (Some(pinned), Some(now)) => {
            let changed = changed_oauth_fields(pinned, now);
            if !changed.is_empty() {
                return refuse(format!("changed oauth fields: {}", changed.join(", ")));
            }
        }
        (None, None) => {}
        (None, Some(_)) => {
            return refuse("the oauth configuration is not pinned".to_owned());
        }
        (Some(_), None) => {
            return refuse("the pinned oauth configuration was removed".to_owned());
        }
    }
    Ok(())
}

/// Load the pinned state of `installed` and check it covers this build.
/// A missing or unreadable state is [`MountError::MissingState`].
pub fn require_approval(
    home: &Path,
    installed: &InstalledExtension,
) -> Result<ExtensionState, MountError> {
    let state = load_state(home, &installed.name)
        .ok_or_else(|| MountError::MissingState(installed.name.clone()))?;
    check_approval(&state, installed)?;
    Ok(state)
}

/// Mount `name` for `agent`.
///
/// The extension must be installed **and** carry a pinned identity row; a
/// `sensitive` entry is refused while `home` is in Private mode.
pub fn mount(home: &Path, name: &str, agent: &str) -> Result<(), MountError> {
    if agent.trim().is_empty() {
        return Err(MountError::InvalidAgent);
    }
    let installed =
        load_installed(home, name).ok_or_else(|| MountError::NotInstalled(name.to_owned()))?;
    let state = load_state(home, name).ok_or_else(|| MountError::MissingState(name.to_owned()))?;
    if state.frozen {
        return Err(MountError::Frozen(name.to_owned()));
    }
    check_approval(&state, &installed)?;
    if !may_mount_in_mode(&installed.entry, current_mode(home)) {
        return Err(MountError::PrivateMode(name.to_owned()));
    }
    let mut mounts = load_mounts(home);
    let list = mounts.agents.entry(agent.to_owned()).or_default();
    if !list.iter().any(|entry| entry == name) {
        list.push(name.to_owned());
    }
    store_mounts(home, &mounts)?;
    ledger::log(
        home,
        "ext.mount",
        &serde_json::json!({"name": name, "version": state.version, "agent": agent}),
    );
    Ok(())
}

/// Unmount `name` from `agent`.
pub fn unmount(home: &Path, name: &str, agent: &str) -> Result<(), MountError> {
    let mut mounts = load_mounts(home);
    if let Some(list) = mounts.agents.get_mut(agent) {
        list.retain(|entry| entry != name);
        if list.is_empty() {
            mounts.agents.remove(agent);
        }
    }
    store_mounts(home, &mounts)?;
    ledger::log(
        home,
        "ext.unmount",
        &serde_json::json!({"name": name, "agent": agent}),
    );
    Ok(())
}

/// Whether `name` is mounted for `agent`.
pub fn is_mounted(home: &Path, name: &str, agent: &str) -> bool {
    load_mounts(home)
        .agents
        .get(agent)
        .map(|list| list.iter().any(|entry| entry == name))
        .unwrap_or(false)
}

/// Every extension mounted for `agent`, sorted.
pub fn mounted_extensions(home: &Path, agent: &str) -> Vec<String> {
    let mut list = load_mounts(home)
        .agents
        .get(agent)
        .cloned()
        .unwrap_or_default();
    list.sort();
    list
}

/// Drop `name` from every agent's mount list.
pub fn remove_from_all_mounts(home: &Path, name: &str) -> std::io::Result<()> {
    let mut mounts = load_mounts(home);
    let mut changed = false;
    for list in mounts.agents.values_mut() {
        let before = list.len();
        list.retain(|entry| entry != name);
        changed |= list.len() != before;
    }
    mounts.agents.retain(|_, list| !list.is_empty());
    if changed {
        store_mounts(home, &mounts)?;
    }
    Ok(())
}

/// Whether the extension is frozen.
pub fn is_frozen(home: &Path, name: &str) -> bool {
    load_state(home, name)
        .map(|state| state.frozen)
        .unwrap_or(false)
}

/// Freeze `name`: unmount everywhere, persist the flag and write the Ledger row.
pub fn freeze(home: &Path, name: &str, reason: &str) -> Result<(), MountError> {
    let mut state =
        load_state(home, name).ok_or_else(|| MountError::NotInstalled(name.to_owned()))?;
    state.frozen = true;
    store_state(home, &state)?;
    remove_from_all_mounts(home, name)?;
    ledger::log(
        home,
        "ext.frozen",
        &serde_json::json!({"name": name, "version": state.version, "reason": reason}),
    );
    Ok(())
}

/// Clear a freeze after the owner re-approves (`aux ext verify --accept`).
pub fn accept(home: &Path, name: &str) -> Result<(), MountError> {
    let mut state =
        load_state(home, name).ok_or_else(|| MountError::NotInstalled(name.to_owned()))?;
    state.frozen = false;
    store_state(home, &state)?;
    ledger::log(
        home,
        "ext.verify",
        &serde_json::json!({"name": name, "version": state.version, "accepted": true}),
    );
    Ok(())
}

/// Whether an entry may be mounted in `mode`.
///
/// A `public` extension mounts in either mode. A `sensitive` one follows its
/// privacy path: every stdio extension runs on `B14`, which the registry marks
/// Covered (arguments keep session tokens, replies pass the session gate), so it
/// mounts in Private mode too.
pub fn may_mount_in_mode(
    entry: &super::catalog::Entry,
    mode: kernel_core::privacy::PrivacyMode,
) -> bool {
    match entry.sensitivity {
        super::catalog::Sensitivity::Public => true,
        super::catalog::Sensitivity::Sensitive => {
            kernel_core::privacy::may_mount(kernel_mcp::transport_path(McpTransport::Stdio), mode)
        }
    }
}

/// Every live session of a daemon, keyed by extension name.
pub struct ExtensionHost {
    home: PathBuf,
    sessions: BTreeMap<String, Arc<ExtensionSession>>,
}

impl std::fmt::Debug for ExtensionHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionHost")
            .field("sessions", &self.sessions.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ExtensionHost {
    /// An empty host.
    pub fn empty(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
            sessions: BTreeMap::new(),
        }
    }

    /// Start every mounted, unfrozen extension and verify its identity.
    pub async fn start(home: &Path) -> Self {
        let mut host = Self::empty(home);
        let mounts = load_mounts(home);
        let names: Vec<String> = mounts
            .agents
            .values()
            .flatten()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        for name in names {
            if is_frozen(home, &name) {
                continue;
            }
            let Some(installed) = load_installed(home, &name) else {
                continue;
            };
            // A sensitive extension is never started in Private mode.
            if !may_mount_in_mode(&installed.entry, current_mode(home)) {
                continue;
            }
            // An upgraded build with a new version, host or secret name never
            // starts before the owner's new yes; a missing state never starts.
            if let Err(err) = require_approval(home, &installed) {
                tracing::warn!(extension = %name, reason = %err, "extension did not start");
                continue;
            }
            match session_for(home, &installed, &SessionOptions::default()).await {
                Ok(session) => {
                    let session = Arc::new(session);
                    if verify_identity(home, &name, &session.tools).is_ok() {
                        host.sessions.insert(name, session);
                    }
                }
                Err(err) => {
                    tracing::warn!(extension = %name, reason = %err, "extension did not start");
                }
            }
        }
        host
    }

    /// The home the host is rooted at.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The live session for `name`, when it is running.
    pub fn session(&self, name: &str) -> Option<&Arc<ExtensionSession>> {
        self.sessions.get(name)
    }

    /// Names with a live session.
    pub fn running(&self) -> Vec<&str> {
        self.sessions.keys().map(String::as_str).collect()
    }

    /// Register `agent`'s mounted extension tools on `registry`.
    ///
    /// Every tool is registered as a [`McpTool`], whose class requires an
    /// exact-name rule, so the broker default is `ask`.
    pub fn register_for_agent(&self, agent: &str, registry: &mut ToolRegistry) -> usize {
        // The live mode is re-read here on every turn, so a switch to Private
        // stops offering a sensitive extension without a restart.
        let mode = current_mode(&self.home);
        let mut registered = 0usize;
        for name in mounted_extensions(&self.home, agent) {
            let Some(state) = load_state(&self.home, &name) else {
                continue;
            };
            if state.frozen {
                continue;
            }
            let Some(installed) = load_installed(&self.home, &name) else {
                continue;
            };
            if !may_mount_in_mode(&installed.entry, mode) {
                continue;
            }
            if check_approval(&state, &installed).is_err() {
                continue;
            }
            let Some(session) = self.sessions.get(&name) else {
                continue;
            };
            for tool in &session.tools {
                let wire = kernel_mcp::wire_name(&name, &tool.name);
                let Some(descriptor) =
                    kernel_mcp::McpToolDescriptor::from_remote(&name, "", wire.clone(), tool)
                else {
                    continue;
                };
                if registry.get(&wire).is_some() {
                    continue;
                }
                registry.register(Box::new(McpTool::new(
                    descriptor,
                    Arc::clone(&session.client),
                    kernel_mcp::MCP_CALL_TIMEOUT,
                    kernel_mcp::transport_path(McpTransport::Stdio),
                )));
                registry.mark_untrusted_output(wire);
                registered += 1;
            }
        }
        registered
    }

    /// Stop every child and proxy.
    pub async fn stop(&self) {
        for session in self.sessions.values() {
            session.stop().await;
        }
    }
}

/// The call timeout used when registering extension tools.
pub const CALL_TIMEOUT: Duration = kernel_mcp::MCP_CALL_TIMEOUT;

#[cfg(test)]
mod tests {
    use super::*;

    fn state(name: &str) -> ExtensionState {
        ExtensionState {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            kind: "mcp".to_owned(),
            frozen: false,
            tools: BTreeMap::new(),
            network: Vec::new(),
            secrets: Vec::new(),
            oauth: None,
        }
    }

    #[test]
    fn mount_and_unmount_round_trip() {
        let home = tempfile::tempdir().unwrap();
        install_entry(
            home.path(),
            "demo",
            super::super::catalog::Sensitivity::Public,
        );
        store_state(home.path(), &state("demo")).unwrap();
        assert!(!is_mounted(home.path(), "demo", "alice"));
        mount(home.path(), "demo", "alice").unwrap();
        assert!(is_mounted(home.path(), "demo", "alice"));
        assert_eq!(mounted_extensions(home.path(), "alice"), vec!["demo"]);
        unmount(home.path(), "demo", "alice").unwrap();
        assert!(!is_mounted(home.path(), "demo", "alice"));
    }

    #[test]
    fn freeze_unmounts_everywhere_and_blocks_mounts() {
        let home = tempfile::tempdir().unwrap();
        install_entry(
            home.path(),
            "demo",
            super::super::catalog::Sensitivity::Public,
        );
        store_state(home.path(), &state("demo")).unwrap();
        mount(home.path(), "demo", "alice").unwrap();
        mount(home.path(), "demo", "bob").unwrap();
        freeze(home.path(), "demo", "tool changed").unwrap();
        assert!(is_frozen(home.path(), "demo"));
        assert!(!is_mounted(home.path(), "demo", "alice"));
        assert!(!is_mounted(home.path(), "demo", "bob"));
        assert!(matches!(
            mount(home.path(), "demo", "alice"),
            Err(MountError::Frozen(_))
        ));
        accept(home.path(), "demo").unwrap();
        assert!(!is_frozen(home.path(), "demo"));
    }

    #[test]
    fn an_installed_extension_without_an_identity_row_is_refused() {
        let home = tempfile::tempdir().unwrap();
        install_entry(
            home.path(),
            "demo",
            super::super::catalog::Sensitivity::Public,
        );
        // No `store_state`: the identity row is missing.
        assert!(matches!(
            mount(home.path(), "demo", "alice"),
            Err(MountError::MissingState(_))
        ));
    }

    #[test]
    fn mounting_an_unknown_extension_is_refused() {
        let home = tempfile::tempdir().unwrap();
        assert!(matches!(
            mount(home.path(), "ghost", "alice"),
            Err(MountError::NotInstalled(_))
        ));
    }

    fn install_entry(home: &Path, name: &str, sensitivity: super::super::catalog::Sensitivity) {
        let entry = test_entry(name, sensitivity);
        let dir = super::super::install_dir(home, name, "1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("entry.toml"), toml::to_string(&entry).unwrap()).unwrap();
    }

    fn test_entry(
        name: &str,
        sensitivity: super::super::catalog::Sensitivity,
    ) -> super::super::catalog::Entry {
        super::super::catalog::Entry {
            name: name.to_owned(),
            kind: super::super::catalog::EntryKind::Mcp,
            version: "1.0.0".to_owned(),
            licence: "MIT".to_owned(),
            reviewed: true,
            sensitivity,
            summary_en: String::new(),
            summary_fr: String::new(),
            source: super::super::catalog::Source {
                kind: super::super::catalog::SourceType::Binary,
                package: "server".to_owned(),
                sha256: "a".repeat(64),
            },
            run: super::super::catalog::Run {
                transport: super::super::catalog::Transport::Stdio,
                command: "server".to_owned(),
                args: Vec::new(),
            },
            tools: Vec::new(),
            oauth: None,
            meta: None,
        }
    }

    fn installed(version: &str, network: &[&str], secrets: &[&str]) -> InstalledExtension {
        let tool = |network: Vec<String>, secrets: Vec<String>| super::super::catalog::EntryTool {
            name: "ping".to_owned(),
            description: String::new(),
            network,
            secrets,
            auth: "none".to_owned(),
            fs: Vec::new(),
        };
        let mut entry = test_entry("demo", super::super::catalog::Sensitivity::Public);
        entry.version = version.to_owned();
        entry.tools = vec![tool(
            network.iter().map(|s| (*s).to_owned()).collect(),
            secrets.iter().map(|s| (*s).to_owned()).collect(),
        )];
        InstalledExtension {
            name: "demo".to_owned(),
            version: version.to_owned(),
            dir: PathBuf::from("/nonexistent"),
            entry,
        }
    }

    #[test]
    fn approval_refuses_a_new_version_host_or_secret_and_passes_a_narrower_set() {
        let mut pinned = state("demo");
        pinned.network = vec!["a.example:443".to_owned(), "c.example:443".to_owned()];
        pinned.secrets = vec!["EXT_DEMO__TOKEN".to_owned()];
        let label = |result: Result<(), MountError>| {
            let err = result.expect_err("must be refused");
            assert!(matches!(err, MountError::ApprovalRequired { .. }), "{err}");
            assert!(err.to_string().starts_with("approval_required"), "{err}");
        };
        label(check_approval(
            &pinned,
            &installed("2.0.0", &["a.example:443"], &[]),
        ));
        label(check_approval(
            &pinned,
            &installed("1.0.0", &["a.example:443", "b.example:443"], &[]),
        ));
        label(check_approval(
            &pinned,
            &installed("1.0.0", &[], &["EXT_DEMO__TOKEN", "EXT_DEMO__OTHER"]),
        ));
        // Equal and narrower sets with the same version pass.
        check_approval(
            &pinned,
            &installed(
                "1.0.0",
                &["a.example:443", "c.example:443"],
                &["EXT_DEMO__TOKEN"],
            ),
        )
        .unwrap();
        check_approval(&pinned, &installed("1.0.0", &["a.example:443"], &[])).unwrap();
    }

    #[test]
    fn approval_refuses_a_changed_oauth_scope_and_fails_closed_without_a_pin() {
        let oauth = |scopes: &[&str]| super::super::catalog::OAuthConfig {
            authorization_url: "https://auth.example/authorize".to_owned(),
            token_url: "https://auth.example/token".to_owned(),
            client_id: "client".to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            client_secret_env: None,
        };
        // Same version, hosts and secrets: only `[oauth]` moves.
        let mut pinned = state("demo");
        pinned.oauth = Some(oauth(&["read"]));
        let mut entry = installed("1.0.0", &[], &[]);
        entry.entry.oauth = Some(oauth(&["read"]));
        check_approval(&pinned, &entry).unwrap();

        entry.entry.oauth = Some(oauth(&["read", "write"]));
        let err = check_approval(&pinned, &entry).expect_err("wider scopes must be refused");
        assert!(matches!(err, MountError::ApprovalRequired { .. }), "{err}");
        assert!(err.to_string().contains("scopes"), "{err}");
        entry.entry.oauth = Some(oauth(&[]));
        let err = check_approval(&pinned, &entry).expect_err("narrowed scopes are still a change");
        assert!(err.to_string().contains("scopes"), "{err}");

        let mut moved = oauth(&["read"]);
        moved.token_url = "https://relay.example/token".to_owned();
        entry.entry.oauth = Some(moved);
        let err = check_approval(&pinned, &entry).expect_err("a moved token URL is refused");
        assert!(err.to_string().contains("token_url"), "{err}");

        // A pin written before the OAuth pin existed carries no table: a build
        // that now has `[oauth]` fails closed, and `aux ext verify --accept`
        // records the table once.
        pinned.oauth = None;
        entry.entry.oauth = Some(oauth(&["read"]));
        let err = check_approval(&pinned, &entry).expect_err("missing pin must fail closed");
        assert!(matches!(err, MountError::ApprovalRequired { .. }), "{err}");
        // An extension without `[oauth]` is unaffected.
        entry.entry.oauth = None;
        check_approval(&pinned, &entry).unwrap();
    }

    #[test]
    fn an_unlisted_oauth_field_change_is_refused_as_other() {
        // `OAuthConfig` has five fields today and the named list covers them
        // all, so no real value can reach the whole-struct fallback. Test the
        // branch through its helper: an unlisted difference becomes `other`,
        // an equal struct adds nothing, and a named change keeps its name.
        let mut changed = Vec::new();
        unlisted_oauth_change(&mut changed, false);
        assert_eq!(changed, vec!["other"]);
        changed.clear();
        unlisted_oauth_change(&mut changed, true);
        assert!(changed.is_empty());
        changed.push("token_url");
        unlisted_oauth_change(&mut changed, false);
        assert_eq!(changed, vec!["token_url"]);
    }

    #[test]
    fn approval_without_a_state_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        assert!(matches!(
            require_approval(home.path(), &installed("1.0.0", &[], &[])),
            Err(MountError::MissingState(_))
        ));
    }

    fn set_mode(home: &Path, mode: &str) {
        std::fs::write(
            home.join("config.toml"),
            format!("[privacy]\nmode = \"{mode}\"\n"),
        )
        .unwrap();
    }

    /// Any config.toml that cannot be read safely, a FIFO above all, gives
    /// Private (the most restrictive mode) at once and never blocks.
    #[cfg(unix)]
    #[test]
    fn a_special_config_file_gives_private_at_once_and_never_blocks() {
        use kernel_core::privacy::PrivacyMode;
        let home = tempfile::tempdir().unwrap();
        let (home, config) = (home.path().to_path_buf(), home.path().join("config.toml"));
        let open = home.join("open.toml");
        std::fs::write(&open, "[privacy]\nmode = \"open\"\n").unwrap();
        set_mode(&home, "open");
        assert_eq!(current_mode(&home), PrivacyMode::Open);
        std::fs::remove_file(&config).unwrap();
        for kind in ["fifo", "symlink", "directory"] {
            match kind {
                "fifo" => {
                    let made = std::process::Command::new("mkfifo").arg(&config).status();
                    assert!(made.unwrap().success());
                }
                "symlink" => std::os::unix::fs::symlink(&open, &config).unwrap(),
                _ => std::fs::create_dir(&config).unwrap(),
            }
            let (moved, (sent, got)) = (home.clone(), std::sync::mpsc::channel());
            std::thread::spawn(move || sent.send(current_mode(&moved)));
            let mode = got.recv_timeout(Duration::from_secs(10));
            assert_eq!(
                mode.expect("current_mode blocked"),
                PrivacyMode::Private,
                "{kind}"
            );
            std::fs::remove_file(&config)
                .or_else(|_| std::fs::remove_dir(&config))
                .unwrap();
        }
        assert_eq!(current_mode(&home), PrivacyMode::Private, "no config");
    }

    #[test]
    fn a_sensitive_extension_mounts_in_private_mode() {
        let home = tempfile::tempdir().unwrap();
        install_entry(
            home.path(),
            "demo",
            super::super::catalog::Sensitivity::Sensitive,
        );
        store_state(home.path(), &state("demo")).unwrap();
        set_mode(home.path(), "private");
        assert!(mount(home.path(), "demo", "alice").is_ok());
        assert!(is_mounted(home.path(), "demo", "alice"));
    }

    #[test]
    fn a_public_extension_mounts_in_private_mode() {
        let home = tempfile::tempdir().unwrap();
        install_entry(
            home.path(),
            "demo",
            super::super::catalog::Sensitivity::Public,
        );
        store_state(home.path(), &state("demo")).unwrap();
        set_mode(home.path(), "private");
        assert!(mount(home.path(), "demo", "alice").is_ok());
    }
}
