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
    /// The approved artefact's sha256 ([`artefact_pin`]), pinned at approval:
    /// the approval binds these bytes, not the version name. A row written
    /// before this pin has none and is never the approved build: it fails
    /// closed until the owner names the build (`--accept --downgrade-to`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artefact: Option<String>,
    /// What runs and where ([`launch_pin`]), pinned at approval: source type,
    /// entry kind, sensitivity and the whole `[run]` table. entry.toml sits in
    /// the install tree, so a row without this pin fails closed until
    /// `aux ext verify --accept` re-pins it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<LaunchPin>,
}

/// The launch-deciding fields of an approved entry (EXT-ANCHOR-7 r2): a flip
/// of the source type skips the binary re-hash, a new command or args run
/// other code with the extension's secrets, and a lowered sensitivity mounts
/// in Private mode, so each must match the owner's yes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPin {
    /// `[source].type`.
    pub source: super::catalog::SourceType,
    /// Entry `kind`.
    pub kind: super::catalog::EntryKind,
    /// Entry `sensitivity`.
    pub sensitivity: super::catalog::Sensitivity,
    /// The whole `[run]` table (transport, command, args, and any field added
    /// to it later).
    pub run: super::catalog::Run,
}

/// The [`LaunchPin`] an approval of `entry` records.
pub fn launch_pin(entry: &super::catalog::Entry) -> LaunchPin {
    LaunchPin {
        source: entry.source.kind,
        kind: entry.kind,
        sensitivity: entry.sensitivity,
        run: entry.run.clone(),
    }
}

/// The names of the fields that differ between two launch pins.
pub(crate) fn changed_launch_fields(pinned: &LaunchPin, now: &LaunchPin) -> Vec<&'static str> {
    let mut changed = Vec::new();
    let mut check = |differs: bool, field| {
        if differs {
            changed.push(field);
        }
    };
    check(pinned.source != now.source, "source.type");
    check(pinned.kind != now.kind, "kind");
    check(pinned.sensitivity != now.sensitivity, "sensitivity");
    check(pinned.run.transport != now.run.transport, "run.transport");
    check(pinned.run.command != now.run.command, "run.command");
    check(pinned.run.args != now.run.args, "run.args");
    // A `[run]` field added later is still covered, by name of its table.
    if changed.is_empty() && pinned != now {
        changed.push("run");
    }
    changed
}

/// Every field an owner must name to re-trust `entry` over `state`
/// (`--accept-change`): the changed launch fields, plus `network` for a new
/// host, `secrets` for a new secret name and `oauth` for any `[oauth]` change.
/// A narrower host or secret set is not a change.
pub fn changed_trust_fields(
    state: &ExtensionState,
    entry: &super::catalog::Entry,
) -> Vec<&'static str> {
    let mut changed = state.launch.as_ref().map_or_else(Vec::new, |pinned| {
        changed_launch_fields(pinned, &launch_pin(entry))
    });
    if network_pins(entry)
        .iter()
        .any(|host| !state.network.contains(host))
    {
        changed.push("network");
    }
    if entry
        .secret_names()
        .iter()
        .any(|name| !state.secrets.contains(name))
    {
        changed.push("secrets");
    }
    if state.oauth != entry.oauth {
        changed.push("oauth");
    }
    changed
}

/// The exact `aux ext verify` command that re-trusts `installed` over `state`:
/// `--downgrade-to` for another build, `--accept-legacy` for a row without a
/// launch pin, `--accept-change` with every changed trust field.
pub fn accept_command(state: &ExtensionState, installed: &InstalledExtension) -> String {
    let name = &installed.name;
    // A directory name is not a catalog version: it never enters a command.
    if !super::catalog::valid_version(&installed.version) {
        return format!("aux ext remove {name} && aux ext install {name}");
    }
    let mut command = format!("aux ext verify {name} --accept");
    let same_bytes = state.artefact.as_deref() == Some(artefact_pin(&installed.entry).as_str());
    if installed.version != state.version || !same_bytes {
        command.push_str(&format!(" --downgrade-to {}", installed.version));
    }
    if state.launch.is_none() {
        command.push_str(" --accept-legacy");
    }
    let changed = changed_trust_fields(state, &installed.entry);
    if !changed.is_empty() {
        command.push_str(&format!(" --accept-change {}", changed.join(",")));
    }
    command
}

/// Each host and secret name `entry` adds over `state`, JSON-quoted and
/// escaped: the owner sees every new value, not only its field.
pub fn new_trust_values(state: &ExtensionState, entry: &super::catalog::Entry) -> Vec<String> {
    let hosts = network_pins(entry)
        .into_iter()
        .filter(|host| !state.network.contains(host));
    let hosts = hosts.map(|host| format!("network {}", super::quoted(&host)));
    let secrets = entry.secret_names().into_iter();
    let secrets = secrets.filter(|name| !state.secrets.contains(name));
    hosts
        .chain(secrets.map(|name| format!("secrets {}", super::quoted(&name))))
        .collect()
}

/// The artefact sha256 an approval pins: the entry's `source.sha256`,
/// lowercase. For a binary it is the re-hashed file's (`verify_installed`
/// refuses any other bytes); for an npm/uv tree it is the tarball's, checked
/// at install (the unpacked tree is not re-hashed, see `verify_installed`).
pub fn artefact_pin(entry: &super::catalog::Entry) -> String {
    entry.source.sha256.to_ascii_lowercase()
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
    #[error(
        "approval_required: extension `{name}` changed since approval ({reason}); run `{fix}`"
    )]
    ApprovalRequired {
        /// Extension name.
        name: String,
        /// Content-free reason: what changed.
        reason: String,
        /// The exact command that re-trusts it ([`accept_command`]).
        fix: String,
    },
    /// The install could not be checked for another reason than other bytes:
    /// no `--accept` fixes it, so none is suggested.
    #[error("extension `{name}` failed its install check: {reason}")]
    Unverified {
        /// Extension name.
        name: String,
        /// What failed.
        reason: String,
    },
    /// The agent name is empty.
    #[error("agent name is empty")]
    InvalidAgent,
    #[error("extensions/mounts.json is unreadable; refusing to change mounts")]
    MountsUnreadable,
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

const MAX_STATE_BYTES: u64 = 256 * 1024;
const MAX_MOUNTS_BYTES: u64 = 1024 * 1024;

fn state_rel(name: &str) -> PathBuf {
    Path::new("extensions")
        .join("state")
        .join(format!("{name}.json"))
}

fn mounts_rel() -> PathBuf {
    Path::new("extensions").join("mounts.json")
}

pub fn store_state(home: &Path, state: &ExtensionState) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;
    let handle = kernel_core::SandboxHome::open(home)?;
    let dirs = Path::new("extensions/state");
    handle.create_dir_all(dirs)?;
    super::install::force_private_dir(&handle, dirs)?;
    handle.write_atomic(&state_rel(&state.name), text.as_bytes(), 0o600)
}

pub(crate) fn read_state(
    home: &Path,
    name: &str,
) -> Result<Option<ExtensionState>, std::io::Error> {
    let handle = match kernel_core::SandboxHome::open_existing(home) {
        Ok(handle) => handle,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(std::io::ErrorKind::InvalidData.into()),
    };
    match super::read_text_at_checked(&handle, &state_rel(name), MAX_STATE_BYTES) {
        super::ReadAt::Absent => Ok(None),
        super::ReadAt::Unreadable => Err(std::io::ErrorKind::InvalidData.into()),
        // A row naming another extension is never this one's approval.
        super::ReadAt::Text(text) => match serde_json::from_str::<ExtensionState>(&text) {
            Ok(state) if state.name == name => Ok(Some(state)),
            _ => Err(std::io::ErrorKind::InvalidData.into()),
        },
    }
}

/// Whether the state row holds text that is not a valid state: a record that
/// exists but cannot be read back (absent or a non-regular file is not one).
pub(crate) fn state_row_is_corrupt(home: &Path, name: &str) -> bool {
    let Ok(handle) = kernel_core::SandboxHome::open_existing(home) else {
        return false;
    };
    matches!(
        super::read_text_at_checked(&handle, &state_rel(name), MAX_STATE_BYTES),
        super::ReadAt::Text(text) if !serde_json::from_str::<ExtensionState>(&text)
            .is_ok_and(|state| state.name == name)
    )
}

pub fn load_state(home: &Path, name: &str) -> Option<ExtensionState> {
    read_state(home, name).ok().flatten()
}

pub fn is_frozen(home: &Path, name: &str) -> bool {
    match read_state(home, name) {
        Ok(None) => false,
        Ok(Some(state)) => state.frozen,
        Err(_) => true,
    }
}

fn load_mounts(home: &Path) -> Result<MountTable, MountError> {
    let handle = match kernel_core::SandboxHome::open_existing(home) {
        Ok(handle) => handle,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(MountTable::default()),
        Err(err) => return Err(err.into()),
    };
    match super::read_text_at_checked(&handle, &mounts_rel(), MAX_MOUNTS_BYTES) {
        super::ReadAt::Absent => Ok(MountTable::default()),
        super::ReadAt::Unreadable => Err(MountError::MountsUnreadable),
        super::ReadAt::Text(text) => {
            serde_json::from_str(&text).map_err(|_| MountError::MountsUnreadable)
        }
    }
}

fn store_mounts(home: &Path, mounts: &MountTable) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(mounts).map_err(std::io::Error::other)?;
    let handle = kernel_core::SandboxHome::open(home)?;
    let dirs = Path::new("extensions");
    handle.create_dir_all(dirs)?;
    super::install::force_private_dir(&handle, dirs)?;
    handle.write_atomic(&mounts_rel(), text.as_bytes(), 0o600)
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
/// fails closed. Its artefact sha256 must be the pinned one, and so must its
/// source type, kind, sensitivity and `[run]` table ([`launch_pin`]); a row
/// without either pin fails closed too.
pub fn check_approval(
    state: &ExtensionState,
    installed: &InstalledExtension,
) -> Result<(), MountError> {
    let refuse = |reason: String| {
        Err(MountError::ApprovalRequired {
            name: installed.name.clone(),
            reason,
            fix: accept_command(state, installed),
        })
    };
    if installed.version != state.version || installed.entry.version != state.version {
        return refuse(format!(
            "version {} is not the approved {}",
            super::escape_text(&installed.version),
            super::escape_text(&state.version)
        ));
    }
    let pin = artefact_pin(&installed.entry);
    match state.artefact.as_deref() {
        Some(approved) if approved == pin => {}
        Some(approved) => {
            return refuse(format!(
                "artefact sha256 {pin} is not the approved {approved}"
            ))
        }
        None => return refuse("no approved artefact sha256 is pinned".to_owned()),
    }
    match &state.launch {
        Some(pinned) => {
            let changed = changed_launch_fields(pinned, &launch_pin(&installed.entry));
            if !changed.is_empty() {
                return refuse(format!("changed launch fields: {}", changed.join(", ")));
            }
        }
        None => {
            return refuse("no approved launch (command, type, sensitivity) is pinned".to_owned())
        }
    }
    let wider: Vec<String> = network_pins(&installed.entry)
        .into_iter()
        .filter(|host| !state.network.contains(host))
        .map(|host| super::quoted(&host))
        .collect();
    if !wider.is_empty() {
        return refuse(format!("new network hosts: {}", wider.join(", ")));
    }
    let new_secrets: Vec<String> = installed
        .entry
        .secret_names()
        .into_iter()
        .filter(|name| !state.secrets.contains(name))
        .map(|name| super::quoted(&name))
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

/// A re-hash refusal as a mount error. Only other bytes ask the owner for a
/// reinstall (the reason carries both hashes); a read failure is IO and never
/// does, since a reinstall cannot fix it.
fn install_refusal(name: &str, err: super::install::InstallError) -> MountError {
    use super::install::InstallError;
    match err {
        InstallError::NotInstalled(_) => MountError::NotInstalled(name.to_owned()),
        // `--accept` re-hashes first and refuses the same bytes: only a
        // reinstall of the catalog build puts the approved bytes back.
        InstallError::HashMismatch { .. } => MountError::ApprovalRequired {
            name: name.to_owned(),
            reason: err.to_string(),
            fix: format!("aux ext install {name}"),
        },
        InstallError::Io(err) => MountError::Io(err),
        other => MountError::Unverified {
            name: name.to_owned(),
            reason: other.to_string(),
        },
    }
}

/// Mount `name` for `agent`.
///
/// The extension must be installed **and** carry a pinned identity row; a
/// `sensitive` entry is refused while `home` is in Private mode.
pub fn mount(home: &Path, name: &str, agent: &str) -> Result<(), MountError> {
    if agent.trim().is_empty() {
        return Err(MountError::InvalidAgent);
    }
    // Re-hashed like a start: a binary rewritten in place is never mounted.
    let installed =
        super::install::verify_installed(home, name).map_err(|err| install_refusal(name, err))?;
    let state = load_state(home, name).ok_or_else(|| MountError::MissingState(name.to_owned()))?;
    if state.frozen {
        return Err(MountError::Frozen(name.to_owned()));
    }
    check_approval(&state, &installed)?;
    if !may_mount_in_mode(&installed.entry, current_mode(home)) {
        return Err(MountError::PrivateMode(name.to_owned()));
    }
    let mut mounts = load_mounts(home)?;
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
    let mut mounts = load_mounts(home)?;
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
        .ok()
        .and_then(|mounts| {
            mounts
                .agents
                .get(agent)
                .map(|list| list.iter().any(|entry| entry == name))
        })
        .unwrap_or(false)
}

/// Every extension mounted for `agent`, sorted.
pub fn mounted_extensions(home: &Path, agent: &str) -> Vec<String> {
    let mut list = load_mounts(home)
        .ok()
        .and_then(|mounts| mounts.agents.get(agent).cloned())
        .unwrap_or_default();
    list.sort();
    list
}

/// Drop `name` from every agent's mount list.
pub fn remove_from_all_mounts(home: &Path, name: &str) -> std::io::Result<()> {
    let mut mounts = load_mounts(home).map_err(|err| std::io::Error::other(err.to_string()))?;
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

/// Freeze `name`: unmount everywhere, persist the flag and write the Ledger row.
///
/// The table is read first, the flag written first (fail closed): an unreadable
/// table mounts nothing and is never rewritten; the freeze is logged, the table reported.
pub fn freeze(home: &Path, name: &str, reason: &str) -> Result<(), MountError> {
    let mut state =
        load_state(home, name).ok_or_else(|| MountError::NotInstalled(name.to_owned()))?;
    let table = load_mounts(home);
    state.frozen = true;
    store_state(home, &state)?;
    ledger::log(
        home,
        "ext.frozen",
        &serde_json::json!({"name": name, "version": state.version, "reason": reason}),
    );
    table?;
    remove_from_all_mounts(home, name)?;
    Ok(())
}

/// Clear a freeze with no re-hash, diff or print: a test shortcut only. The
/// owner's path is `session::accept_with` (`aux ext verify --accept`).
#[cfg(test)]
pub(crate) fn accept(home: &Path, name: &str) -> Result<(), MountError> {
    let mut state =
        load_state(home, name).ok_or_else(|| MountError::NotInstalled(name.to_owned()))?;
    state.frozen = false;
    store_state(home, &state)?;
    ledger::log(
        home,
        "ext.verify",
        &serde_json::json!({"name": name, "version": state.version, "accepted": true, "sha256": state.artefact}),
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
        let mounts = load_mounts(home).unwrap_or_default();
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
            // Re-hashed before it starts: a binary rewritten in place never runs.
            let installed = match super::install::verify_installed(home, &name) {
                Ok(installed) => installed,
                Err(err) => {
                    tracing::warn!(extension = %name, reason = %err, "extension did not start");
                    continue;
                }
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
            artefact: Some(server_sha()),
            launch: Some(launch_pin(&test_entry(
                name,
                super::super::catalog::Sensitivity::Public,
            ))),
        }
    }

    /// The test binary's bytes; a mount re-hashes them like a start.
    const SERVER: &[u8] = b"#!test-server";

    fn server_sha() -> String {
        use sha2::Digest;
        super::super::hex(&sha2::Sha256::digest(SERVER))
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
    fn an_unreadable_mounts_json_is_never_overwritten() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("extensions").join("mounts.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json").unwrap();
        assert!(unmount(home.path(), "demo", "alice").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not json");
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

    // EXT-ANCHOR-9: a row naming another extension is never this one's pin.
    #[test]
    fn a_state_row_naming_another_extension_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let public = super::super::catalog::Sensitivity::Public;
        install_entry(home.path(), "demo", public);
        store_state(home.path(), &state("other")).unwrap();
        let dir = home.path().join("extensions/state");
        std::fs::copy(dir.join("other.json"), dir.join("demo.json")).unwrap();
        assert!(load_state(home.path(), "demo").is_none());
        assert!(is_frozen(home.path(), "demo"), "fails closed");
        assert!(state_row_is_corrupt(home.path(), "demo"));
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

    #[cfg(unix)]
    #[test]
    fn store_mounts_reforces_a_private_extensions_dir() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("extensions");
        std::fs::create_dir_all(&root).unwrap();
        super::super::install::set_mode(&root, 0o777).unwrap();
        store_mounts(home.path(), &MountTable::default()).unwrap();
        let mode = std::fs::metadata(&root).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    fn unreadable_table(home: &Path) -> PathBuf {
        install_entry(home, "demo", super::super::catalog::Sensitivity::Public);
        store_state(home, &state("demo")).unwrap();
        let path = home.join("extensions").join("mounts.json");
        std::fs::write(&path, b"not json").unwrap();
        path
    }

    #[test]
    fn an_unreadable_table_refuses_mounts_and_still_freezes() {
        let home = tempfile::tempdir().unwrap();
        let path = unreadable_table(home.path());
        let mounted = mount(home.path(), "demo", "alice");
        assert!(matches!(mounted, Err(MountError::MountsUnreadable)));
        let frozen = freeze(home.path(), "demo", "drift");
        assert!(matches!(frozen, Err(MountError::MountsUnreadable)));
        assert!(is_frozen(home.path(), "demo"));
        assert_eq!(std::fs::read(&path).unwrap(), b"not json");
    }

    #[test]
    fn an_oversized_state_row_reads_as_frozen() {
        let home = tempfile::tempdir().unwrap();
        unreadable_table(home.path());
        let row = home.path().join("extensions/state/demo.json");
        std::fs::write(&row, vec![b' '; MAX_STATE_BYTES as usize + 1]).unwrap();
        assert!(is_frozen(home.path(), "demo"));
    }

    #[test]
    fn an_oversized_state_row_freezes_and_refuses_mounts_without_a_table() {
        let home = tempfile::tempdir().unwrap();
        install_entry(
            home.path(),
            "demo",
            super::super::catalog::Sensitivity::Public,
        );
        store_state(home.path(), &state("demo")).unwrap();
        // A valid row, padded past the cap: only the size limit can refuse it.
        let row = home.path().join("extensions/state/demo.json");
        let mut text = std::fs::read(&row).unwrap();
        text.resize(MAX_STATE_BYTES as usize + 1, b' ');
        std::fs::write(&row, text).unwrap();
        assert!(!home.path().join("extensions/mounts.json").exists());
        assert!(is_frozen(home.path(), "demo"));
        assert!(matches!(
            mount(home.path(), "demo", "alice"),
            Err(MountError::MissingState(_))
        ));
        assert!(!is_mounted(home.path(), "demo", "alice"));
    }

    fn install_entry(home: &Path, name: &str, sensitivity: super::super::catalog::Sensitivity) {
        let entry = test_entry(name, sensitivity);
        let dir = super::super::install_dir(home, name, "1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("entry.toml"), toml::to_string(&entry).unwrap()).unwrap();
        std::fs::write(dir.join("server"), SERVER).unwrap();
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
                sha256: server_sha(),
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

    // EXT-ANCHOR-9 r2: a directory version is never put in a command, and a
    // bidi character in it is shown as `\u{..}`.
    #[test]
    fn a_bad_directory_version_is_escaped_and_never_suggested() {
        let build = installed("2.0.0\u{202e}x", &[], &[]);
        let fix = "aux ext remove demo && aux ext install demo";
        assert_eq!(accept_command(&state("demo"), &build), fix);
        let err = check_approval(&state("demo"), &build)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("2.0.0\\u{202e}x") && !err.contains('\u{202e}'),
            "{err}"
        );
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

    // EXT-ANCHOR-7: approval binds the artefact sha256: other bytes at the
    // approved version, or a row written before the pin, fail closed.
    #[test]
    fn approval_refuses_other_bytes_and_a_row_without_an_artefact_pin() {
        let mut pinned = state("demo");
        let mut build = installed("1.0.0", &[], &[]);
        build.entry.source.sha256 = server_sha().to_ascii_uppercase();
        check_approval(&pinned, &build).unwrap();
        build.entry.source.sha256 = "b".repeat(64);
        let err = check_approval(&pinned, &build).expect_err("other bytes");
        assert!(err.to_string().contains("sha256"), "{err}");
        pinned.artefact = None;
        let err = check_approval(&pinned, &installed("1.0.0", &[], &[])).expect_err("no pin");
        let err = err.to_string();
        assert!(err.contains("no approved artefact sha256"), "{err}");
    }

    // EXT-ANCHOR-7 r2: each launch field is named when it changes.
    #[test]
    fn approval_names_each_changed_launch_field() {
        use super::super::catalog::{Sensitivity, SourceType};
        let pinned = state("demo");
        let mut build = installed("1.0.0", &[], &[]);
        check_approval(&pinned, &build).unwrap();
        build.entry.source.kind = SourceType::Uv;
        build.entry.sensitivity = Sensitivity::Sensitive;
        build.entry.run.args = vec!["-c".to_owned()];
        let err = check_approval(&pinned, &build).expect_err("launch changed");
        let err = err.to_string();
        assert!(
            err.contains("changed launch fields: source.type, sensitivity, run.args"),
            "{err}"
        );
    }

    // EXT-ANCHOR-8: changed bytes at the approved build are refused at mount
    // with both hashes; a read failure is IO and never suggests `--accept`.
    #[test]
    fn a_mount_refuses_changed_bytes_and_maps_a_read_failure_to_io() {
        let home = tempfile::tempdir().unwrap();
        install_entry(
            home.path(),
            "demo",
            super::super::catalog::Sensitivity::Public,
        );
        store_state(home.path(), &state("demo")).unwrap();
        let server = super::super::install_dir(home.path(), "demo", "1.0.0").join("server");
        std::fs::write(&server, b"#!other-bytes").unwrap();
        let err = mount(home.path(), "demo", "alice").unwrap_err();
        assert!(matches!(err, MountError::ApprovalRequired { .. }), "{err}");
        let other = {
            use sha2::Digest;
            super::super::hex(&sha2::Sha256::digest(b"#!other-bytes"))
        };
        let text = err.to_string();
        assert!(
            text.contains(&server_sha()) && text.contains(&other),
            "{text}"
        );
        assert!(!is_mounted(home.path(), "demo", "alice"));
        std::fs::remove_file(&server).unwrap();
        std::fs::create_dir(&server).unwrap();
        let err = mount(home.path(), "demo", "alice").unwrap_err();
        assert!(matches!(err, MountError::Io(_)), "{err}");
        assert!(!err.to_string().contains("--accept"), "{err}");
        assert!(!is_mounted(home.path(), "demo", "alice"));
    }

    #[test]
    fn an_unverified_install_never_asks_for_accept() {
        let other = super::super::install::InstallError::Unpack("bad".to_owned());
        let err = install_refusal("demo", other);
        assert!(matches!(err, MountError::Unverified { .. }), "{err}");
        assert!(!err.to_string().contains("--accept"), "{err}");
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
        let mut pinned = state("demo");
        pinned.launch = Some(launch_pin(&test_entry(
            "demo",
            super::super::catalog::Sensitivity::Sensitive,
        )));
        store_state(home.path(), &pinned).unwrap();
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
