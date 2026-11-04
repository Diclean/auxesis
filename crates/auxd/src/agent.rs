//! Per-agent state owned by the daemon: the `<home>/agents/<agent>/agent.toml`
//! sidecar and the `PAUSED` / `KILLED` markers.
//!
//! The engine reads an agent's soul (`soul.md`) and the global `[[rules]]`; it
//! has no notion of a per-agent provider or of a paused agent. This module adds
//! exactly that, **without widening any right**:
//!
//! - `agent.toml` only ever *restricts*: it names a provider/model the agent
//!   runs with (selected from the entries already configured in
//!   `config.toml`) and an optional tools allowlist that the turn path turns
//!   into per-agent `deny` rules for every other registered tool. It can never
//!   grant a tool, a budget or a sandbox exception.
//! - `PAUSED` refuses new turns and scheduled jobs for that agent until
//!   `POST /v1/agents/{id}/resume` removes it; an installed `PAUSED`/`KILLED`
//!   marker also aborts an in-flight API turn at its next step boundary.
//!   `KILLED` is the same hard stop and also blocks resume until the owner
//!   clears the kill.
//!
//! Writes are atomic (sibling temp file, fsync, rename), private (`0600`)
//! and serialized in-process, so a concurrent PUT can never tear the file or
//! lose a field.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aux_engine::{agent_dir, default_soul, soul_path, MAX_SOUL_BYTES};
use aux_providers::provider_name_is_key_shaped;
use serde::{Deserialize, Serialize};

/// Sidecar file holding the daemon-owned part of an agent's configuration.
pub const AGENT_CONFIG_FILE: &str = "agent.toml";

/// Older name of the sidecar, read only while `agent.toml` is absent; it
/// is never written again.
pub const LEGACY_AGENT_CONFIG_FILE: &str = "dot.toml";

/// Marker file that pauses an agent (turns and jobs refuse to start).
pub const PAUSED_MARKER: &str = "PAUSED";

/// Marker file that stops an agent until the owner resumes it.
pub const KILLED_MARKER: &str = "KILLED";

/// Refuse to read a sidecar larger than this (runaway write, device file).
const MAX_AGENT_CONFIG_BYTES: u64 = 64 * 1024;

/// Serializes every sidecar/soul write of the process.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Why an agent operation failed.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// A filesystem operation failed.
    #[error("{0}")]
    Io(String),
    /// The sidecar exists but cannot be parsed: fail closed rather than run
    /// without the allowlist the owner wrote.
    #[error("the agent configuration file is unreadable: {0}")]
    Config(String),
}

/// The daemon-owned part of an agent, persisted as `agent.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Provider id from `[[providers]]`; `None` keeps the daemon's default
    /// selection rule (exactly one provider configured, or the turn fails).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Model override for the selected provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Tools this agent may use. `None` = every registered tool follows the
    /// global rules; `Some(list)` = every tool not listed is denied for this
    /// agent. The list never grants anything: listed tools still obey the
    /// global rules and approvals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// Owner-selected local instruction skills; this grants no permissions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,
}

/// The default agent's old name (`default_agent`/`default_dot = "main"`).
pub const LEGACY_DEFAULT_AGENT: &str = "main";

/// The agent the owner's chat runs (iMessage, the channel turns): the
/// configured `default_agent`, as written. A config that cannot be read falls
/// back to the default a fresh config writes (the chief).
pub fn default_chat_agent(home: &Path) -> String {
    crate::api::load_config_verified(home)
        .map(|config| config.default_agent)
        .unwrap_or_else(|_| kernel_core::Config::default().default_agent)
}

/// The run state of an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Normal: turns and jobs may run.
    Active,
    /// Turns and jobs refuse to start until resumed.
    Paused,
    /// Same stop, sticky: resume is refused until the owner clears the kill.
    Killed,
}

impl AgentState {
    /// Whether new work must be refused.
    pub fn blocks_work(self) -> bool {
        !matches!(self, AgentState::Active)
    }
}

/// True when a directory for `agent` exists under `<home>/agents`.
pub fn exists(home: &Path, agent: &str) -> bool {
    agent_dir(home, agent).is_dir()
}

/// The agent's current state, from its marker files (killed wins).
pub fn state(home: &Path, agent: &str) -> AgentState {
    let dir = agent_dir(home, agent);
    if dir.join(KILLED_MARKER).exists() {
        AgentState::Killed
    } else if dir.join(PAUSED_MARKER).exists() {
        AgentState::Paused
    } else {
        AgentState::Active
    }
}

/// The sidecar a read should use: `agent.toml`, or the legacy `dot.toml` while
/// `agent.toml` does not exist yet. Writes always use `agent.toml`.
fn config_read_path(home: &Path, agent: &str) -> PathBuf {
    let current = agent_dir(home, agent).join(AGENT_CONFIG_FILE);
    let legacy = agent_dir(home, agent).join(LEGACY_AGENT_CONFIG_FILE);
    if !current.exists() && legacy.exists() {
        legacy
    } else {
        current
    }
}

/// Read the sidecar; a missing file yields defaults.
///
/// A present-but-unusable file is an error (fail closed): silently ignoring
/// it would drop a tools allowlist.
pub fn config(home: &Path, agent: &str) -> Result<AgentConfig, AgentError> {
    let path = config_read_path(home, agent);
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AgentConfig::default());
        }
        Err(err) => {
            return Err(AgentError::Config(format!(
                "could not read {}: {err}",
                path.display()
            )));
        }
    };
    if !meta.is_file() {
        return Err(AgentError::Config(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_AGENT_CONFIG_BYTES {
        return Err(AgentError::Config(format!(
            "{} is unexpectedly large ({} bytes)",
            path.display(),
            meta.len()
        )));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|err| AgentError::Config(format!("could not read {}: {err}", path.display())))?;
    let mut config: AgentConfig = toml::from_str(&text).map_err(|err| {
        let file = path.display().to_string();
        AgentError::Config(
            kernel_core::redact_toml_error(&err, &file, &text)
                .message()
                .to_string(),
        )
    })?;
    // A pre-upgrade sidecar may hold a key-shaped provider. It is a name, so
    // fail closed: clear it (the agent falls back to the default brain) and
    // never echo the value. The next save writes `provider` absent.
    if config
        .provider
        .as_deref()
        .is_some_and(provider_name_is_key_shaped)
    {
        tracing::warn!("an agent's provider name looked like a key and was cleared");
        config.provider = None;
    }
    Ok(config)
}

/// Write the sidecar atomically (`0600`, last writer wins under the lock).
///
/// The write goes through the verified home directory fd.
pub fn write_config(home: &Path, agent: &str, config: &AgentConfig) -> Result<(), AgentError> {
    let mut clean = config.clone();
    if clean
        .provider
        .as_deref()
        .is_some_and(provider_name_is_key_shaped)
    {
        tracing::warn!("an agent's provider name looked like a key and was cleared");
        clean.provider = None;
    }
    let text = toml::to_string(&clean)
        .map_err(|err| AgentError::Config(format!("could not serialize the agent: {err}")))?;
    let rel = Path::new("agents").join(agent).join(AGENT_CONFIG_FILE);
    write_private_atomically(home, &rel, text.as_bytes()).map_err(AgentError::Io)
}

/// Read the soul for display/update; `None` when it is missing or unusable.
///
/// Never writes and never creates: a read must not fabricate the default the
/// engine would use only at turn time.
pub fn read_soul(home: &Path, agent: &str) -> Option<String> {
    read_soul_checked(home, agent).ok().flatten()
}

/// Read an agent's soul through the verified home handle, or `None` when no soul
/// file exists.
///
/// The read is fd-relative: `agents`, then the agent
/// directory, then `soul.md` — every component opened with `O_NOFOLLOW`
/// (`O_DIRECTORY` for the directories), so a symlinked agent directory or soul
/// is refused instead of followed, and the leaf additionally with
/// `O_NONBLOCK` so a FIFO can never block the daemon. The final descriptor is
/// `fstat`ed: it must be a regular file owned by this process's uid, and the
/// read is bounded to [`MAX_SOUL_BYTES`] + 1 bytes, so an oversized file is
/// refused rather than silently truncated.
fn read_soul_checked(home: &Path, agent: &str) -> Result<Option<String>, AgentError> {
    let path = soul_path(home, agent);
    let handle = match kernel_core::SandboxHome::open_existing(home) {
        Ok(handle) => handle,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(AgentError::Io(err.to_string())),
    };
    let rel = Path::new("agents").join(agent).join("soul.md");
    let mut file = match handle.open_read_existing(&rel, MAX_SOUL_BYTES) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(AgentError::Io(format!(
                "could not read {}: {err}",
                path.display()
            )))
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .map_err(|err| AgentError::Io(format!("could not stat {}: {err}", path.display())))?;
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(AgentError::Io(format!(
                "{} is not owned by this user",
                path.display()
            )));
        }
    }
    let mut bytes = Vec::new();
    Read::take(&mut file, MAX_SOUL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| AgentError::Io(format!("could not read {}: {err}", path.display())))?;
    if bytes.len() as u64 > MAX_SOUL_BYTES {
        return Err(AgentError::Io(format!(
            "{} is unexpectedly large (>{} bytes)",
            path.display(),
            MAX_SOUL_BYTES
        )));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| AgentError::Io(format!("{} is not valid UTF-8", path.display())))
}

/// Read an agent's soul **for the editor**: the exact bytes the owner wrote.
///
/// Unlike [`read_soul`], a present-but-unusable file is an error rather than
/// `None`: the editor must never show a truncated soul (which a save would
/// then persist) nor silently fall back to the default and overwrite a
/// corrupt file on the next click. `Ok(None)` means no soul file exists yet
/// and the engine would use its built-in default.
pub fn read_soul_for_edit(home: &Path, agent: &str) -> Result<Option<String>, AgentError> {
    read_soul_checked(home, agent)
}

/// Write the instructions (`soul.md`) atomically (`0600`).
///
/// This is the **only** writer of a soul, and the one path both `POST
/// /v1/agents` and `PUT /v1/agents/{id}` use: a sibling temp file created
/// `O_EXCL|O_NOFOLLOW` and renamed over `soul.md`, relative to the verified
/// home handle. An existing symlink is replaced, never followed.
///
/// The write goes through the verified home directory fd.
pub fn write_soul(home: &Path, agent: &str, text: &str) -> Result<(), AgentError> {
    let rel = Path::new("agents").join(agent).join("soul.md");
    write_private_atomically(home, &rel, text.as_bytes()).map_err(AgentError::Io)
}

/// The default soul for an agent that was created without instructions.
pub fn default_instructions(agent: &str) -> String {
    default_soul(agent)
}

/// Create the agent directory; `Ok(true)` when this call created it, `Ok(false)`
/// when it already existed. `create_dir` is atomic, which is what makes
/// concurrent creates of the same name race safely.
pub fn claim_dir(home: &Path, agent: &str) -> Result<bool, AgentError> {
    // The write goes through the verified home directory fd.
    let handle =
        kernel_core::SandboxHome::open(home).map_err(|err| AgentError::Io(err.to_string()))?;
    let rel = Path::new("agents").join(agent);
    if let Some(parent) = rel.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        handle
            .create_dir_all(parent)
            .map_err(|err| AgentError::Io(err.to_string()))?;
    }
    handle
        .create_dir(&rel)
        .map_err(|err| AgentError::Io(err.to_string()))
}

/// Remove an agent directory created by a failed create (best effort, empty or
/// daemon-written files only; never follows into unrelated content).
pub fn abandon_dir(home: &Path, agent: &str) {
    // Deletes are fd-relative on the verified home handle.
    let Ok(handle) = kernel_core::SandboxHome::open_existing(home) else {
        return;
    };
    let dir = Path::new("agents").join(agent);
    let _ = handle.remove_file(&dir.join(AGENT_CONFIG_FILE));
    let _ = handle.remove_file(&dir.join(LEGACY_AGENT_CONFIG_FILE));
    let _ = handle.remove_file(&dir.join("soul.md"));
    let _ = handle.remove_dir(&dir);
}

/// Create a marker; `Ok(true)` when it was created, `Ok(false)` when present.
pub fn set_marker(home: &Path, agent: &str, marker: &str) -> Result<bool, AgentError> {
    // The write goes through the verified home directory fd.
    let handle =
        kernel_core::SandboxHome::open(home).map_err(|err| AgentError::Io(err.to_string()))?;
    let rel_dir = Path::new("agents").join(agent);
    handle
        .create_dir_all(&rel_dir)
        .map_err(|err| AgentError::Io(err.to_string()))?;
    handle
        .write_new(&rel_dir.join(marker), b"", 0o600)
        .map_err(|err| AgentError::Io(err.to_string()))
}

/// Remove a marker; `Ok(true)` when it was present.
pub fn clear_marker(home: &Path, agent: &str, marker: &str) -> Result<bool, AgentError> {
    // The delete is fd-relative on the verified home handle.
    let handle = match kernel_core::SandboxHome::open_existing(home) {
        Ok(handle) => handle,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(AgentError::Io(err.to_string())),
    };
    let rel = Path::new("agents").join(agent).join(marker);
    match handle.remove_file(&rel) {
        Ok(found) => Ok(found),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(AgentError::Io(err.to_string())),
    }
}

/// Path used by tests and error messages.
pub fn dir_of(home: &Path, agent: &str) -> PathBuf {
    agent_dir(home, agent)
}

/// Write bytes through a sibling temp file, fsync and rename.
///
/// The temp file and `renameat` live in the verified parent directory fd,
/// never through a home path string.
fn write_private_atomically(home: &Path, rel: &Path, bytes: &[u8]) -> Result<(), String> {
    let _guard = WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let handle = kernel_core::SandboxHome::open(home).map_err(|err| err.to_string())?;
    handle
        .write_atomic(rel, bytes, 0o600)
        .map_err(|err| format!("writing {}: {err}", rel.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_sidecar_yields_defaults() {
        let dir = tempdir().unwrap();
        let config = config(dir.path(), "scout").unwrap();
        assert_eq!(config, AgentConfig::default());
    }

    #[test]
    fn sidecar_round_trips_provider_model_and_tools() {
        let dir = tempdir().unwrap();
        let written = AgentConfig {
            provider: Some("deepseek".to_string()),
            model: Some("deepseek-chat".to_string()),
            tools: Some(vec!["read_file".to_string(), "web_search".to_string()]),
            skills: vec!["writing".to_string()],
        };
        write_config(dir.path(), "scout", &written).unwrap();

        let again = config(dir.path(), "scout").unwrap();
        assert_eq!(again, written);
        let text =
            std::fs::read_to_string(dir_of(dir.path(), "scout").join(AGENT_CONFIG_FILE)).unwrap();
        assert!(text.contains("provider = \"deepseek\""));
        assert!(!text.contains("KEY"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir_of(dir.path(), "scout").join(AGENT_CONFIG_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_legacy_dot_toml_is_read_while_agent_toml_is_absent() {
        let dir = tempdir().unwrap();
        let dir_path = dir_of(dir.path(), "scout");
        std::fs::create_dir_all(&dir_path).unwrap();
        std::fs::write(
            dir_path.join(LEGACY_AGENT_CONFIG_FILE),
            "provider = \"deepseek\"\n",
        )
        .unwrap();

        let read = config(dir.path(), "scout").unwrap();
        assert_eq!(read.provider.as_deref(), Some("deepseek"));
    }

    #[test]
    fn agent_toml_wins_over_a_legacy_dot_toml_and_writes_use_the_new_name() {
        let dir = tempdir().unwrap();
        let dir_path = dir_of(dir.path(), "scout");
        std::fs::create_dir_all(&dir_path).unwrap();
        std::fs::write(
            dir_path.join(LEGACY_AGENT_CONFIG_FILE),
            "provider = \"deepseek\"\n",
        )
        .unwrap();
        std::fs::write(dir_path.join(AGENT_CONFIG_FILE), "provider = \"mistral\"\n").unwrap();
        assert_eq!(
            config(dir.path(), "scout").unwrap().provider.as_deref(),
            Some("mistral")
        );

        let fresh = tempdir().unwrap();
        let written = AgentConfig {
            provider: Some("deepseek".to_string()),
            ..AgentConfig::default()
        };
        write_config(fresh.path(), "scout", &written).unwrap();
        assert!(dir_of(fresh.path(), "scout")
            .join(AGENT_CONFIG_FILE)
            .is_file());
        assert!(!dir_of(fresh.path(), "scout")
            .join(LEGACY_AGENT_CONFIG_FILE)
            .exists());
    }

    #[test]
    fn a_key_shaped_provider_in_a_sidecar_is_cleared_on_load_and_write() {
        let key = "sk-proj-canary-7f3k9q"; // gitleaks:allow
        for file in [AGENT_CONFIG_FILE, LEGACY_AGENT_CONFIG_FILE] {
            let dir = tempdir().unwrap();
            let dir_path = dir_of(dir.path(), "scout");
            std::fs::create_dir_all(&dir_path).unwrap();
            std::fs::write(
                dir_path.join(file),
                format!("provider = \"{key}\"\nmodel = \"m\"\ntools = [\"read_file\"]\n"),
            )
            .unwrap();
            let read = config(dir.path(), "scout").unwrap();
            assert_eq!(read.provider, None, "{file}");
            assert_eq!(read.model.as_deref(), Some("m"), "{file}");
            assert_eq!(read.tools, Some(vec!["read_file".to_string()]), "{file}");
        }

        // A save never writes a raw value even when a caller passes one.
        let dir = tempdir().unwrap();
        let raw = AgentConfig {
            provider: Some(key.to_string()),
            ..AgentConfig::default()
        };
        write_config(dir.path(), "writer", &raw).unwrap();
        let text =
            std::fs::read_to_string(dir_of(dir.path(), "writer").join(AGENT_CONFIG_FILE)).unwrap();
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(!text.contains("provider"), "{text}");
    }

    #[test]
    fn a_corrupt_sidecar_fails_closed() {
        let dir = tempdir().unwrap();
        let dir_path = dir_of(dir.path(), "scout");
        std::fs::create_dir_all(&dir_path).unwrap();
        std::fs::write(dir_path.join(AGENT_CONFIG_FILE), "not = [toml").unwrap();

        assert!(matches!(
            config(dir.path(), "scout"),
            Err(AgentError::Config(_))
        ));
    }

    #[test]
    fn soul_round_trips_and_stays_private() {
        let dir = tempdir().unwrap();
        assert_eq!(read_soul(dir.path(), "scout"), None);
        write_soul(dir.path(), "scout", "# scout\nbe terse\n").unwrap();
        assert_eq!(
            read_soul(dir.path(), "scout").as_deref(),
            Some("# scout\nbe terse\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(soul_path(dir.path(), "scout"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_missing_soul_reads_as_none_without_creating_anything() {
        let dir = tempdir().unwrap();
        assert_eq!(read_soul_for_edit(dir.path(), "ghost").unwrap(), None);
        assert_eq!(read_soul(dir.path(), "ghost"), None);
        assert!(
            !dir_of(dir.path(), "ghost").exists(),
            "a read must not create the agent directory"
        );
    }

    #[test]
    fn a_normal_soul_reads_back_verbatim() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "scout");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"# scout\nbe terse\n").unwrap();

        assert_eq!(
            read_soul_for_edit(dir.path(), "scout").unwrap().as_deref(),
            Some("# scout\nbe terse\n")
        );
        assert_eq!(
            read_soul(dir.path(), "scout").as_deref(),
            Some("# scout\nbe terse\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_agent_directory_is_refused() {
        let dir = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        let stolen = elsewhere.path().join("soul.md");
        std::fs::write(&stolen, "# another home\n").unwrap();
        std::fs::create_dir_all(dir.path().join("agents")).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("agents/scout")).unwrap();

        assert!(read_soul_for_edit(dir.path(), "scout").is_err());
        assert_eq!(read_soul(dir.path(), "scout"), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_soul_is_refused() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("elsewhere.md");
        std::fs::write(&target, "# elsewhere\n").unwrap();
        let path = soul_path(dir.path(), "scout");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert!(read_soul_for_edit(dir.path(), "scout").is_err());
        assert_eq!(read_soul(dir.path(), "scout"), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_soul_is_refused_without_blocking() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "scout");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        assert!(read_soul_for_edit(dir.path(), "scout").is_err());
        assert_eq!(read_soul(dir.path(), "scout"), None);
    }

    #[test]
    fn an_oversized_soul_is_refused_not_truncated() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "scout");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'x'; (MAX_SOUL_BYTES + 1) as usize]).unwrap();

        assert!(read_soul_for_edit(dir.path(), "scout").is_err());
        assert_eq!(read_soul(dir.path(), "scout"), None);
    }

    #[test]
    fn a_soul_exactly_at_the_ceiling_is_still_read() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "scout");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let content = "x".repeat(MAX_SOUL_BYTES as usize);
        std::fs::write(&path, &content).unwrap();

        assert_eq!(
            read_soul_for_edit(dir.path(), "scout").unwrap().as_deref(),
            Some(content.as_str())
        );
    }

    #[test]
    fn markers_drive_state_with_kill_winning() {
        let dir = tempdir().unwrap();
        assert_eq!(state(dir.path(), "scout"), AgentState::Active);
        assert!(set_marker(dir.path(), "scout", PAUSED_MARKER).unwrap());
        assert_eq!(state(dir.path(), "scout"), AgentState::Paused);
        assert!(!set_marker(dir.path(), "scout", PAUSED_MARKER).unwrap());
        assert!(set_marker(dir.path(), "scout", KILLED_MARKER).unwrap());
        assert_eq!(state(dir.path(), "scout"), AgentState::Killed);
        assert!(clear_marker(dir.path(), "scout", PAUSED_MARKER).unwrap());
        assert_eq!(
            state(dir.path(), "scout"),
            AgentState::Killed,
            "kill is sticky"
        );
        assert!(clear_marker(dir.path(), "scout", KILLED_MARKER).unwrap());
        assert_eq!(state(dir.path(), "scout"), AgentState::Active);
        assert!(!clear_marker(dir.path(), "scout", KILLED_MARKER).unwrap());
    }

    #[test]
    fn claim_dir_is_atomic_and_abandon_only_removes_ours() {
        let dir = tempdir().unwrap();
        assert!(claim_dir(dir.path(), "scout").unwrap());
        assert!(!claim_dir(dir.path(), "scout").unwrap());
        write_config(dir.path(), "scout", &AgentConfig::default()).unwrap();
        abandon_dir(dir.path(), "scout");
        assert!(!exists(dir.path(), "scout"));
    }

    #[test]
    fn default_instructions_name_the_agent() {
        assert!(default_instructions("scout").contains("You are scout"));
    }
}
