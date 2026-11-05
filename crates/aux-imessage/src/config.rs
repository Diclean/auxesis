//! `gateways.toml` and the `[imessage]` section (G2).
//!
//! Disabled by default. An enabled section that is invalid — no owner handle,
//! no pinned chat GUID, no agent handle, the agent among the owner handles, or
//! a pacing gap under the 15 s floor — reads back disabled, so a typo can never
//! open a channel.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The pacing floor: at least 15 s after the owner's last inbound, and at
/// least 15 s between two sends (G2; the iPhone thread-jumping lesson).
pub const MIN_PACING_SECS: i64 = 15;

/// Our own file name under the verified home.
pub const GATEWAYS_FILE: &str = "gateways.toml";

/// Where the reader looks when the section does not set `chat_db`.
pub const DEFAULT_CHAT_DB: &str = "Library/Messages/chat.db";

/// The persisted cursor file, relative to the verified home.
pub const DEFAULT_CURSOR_FILE: &str = "imessage_cursor.json";

/// Most owner handles one pinned chat may name.
pub const MAX_OWNER_HANDLES: usize = 8;

/// Longest handle or chat GUID the config will hold.
pub const MAX_HANDLE_LEN: usize = 320;

/// How the agent reaches the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The agent's own Apple ID is signed in to Messages; the owner reads on
    /// the iPhone.
    #[default]
    AppleId,
    /// Fallback: RCS from line 2 (the agent) to line 1 (the owner), locked to
    /// exactly one chat.
    RcsFallback,
}

impl Mode {
    /// The AppleScript `service type` this mode targets. RCS is carried by
    /// Messages' SMS service.
    pub fn service_type(self) -> &'static str {
        match self {
            Self::AppleId => "iMessage",
            Self::RcsFallback => "SMS",
        }
    }
}

/// The `[imessage]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImessageConfig {
    /// Off unless the owner turns it on.
    pub enabled: bool,
    /// The owner's handle(s), exactly as Messages spells them. Only these may
    /// be read from and sent to.
    pub owner_handles: Vec<String>,
    /// The one pinned chat GUID (`iMessage;-;+33600000001`).
    pub chat_guid: String,
    /// The agent's own Apple ID (or line 2 in fallback mode). Never a send
    /// target.
    pub agent_handle: String,
    /// Apple-ID mode or the RCS fallback.
    pub mode: Mode,
    /// Override for `~/Library/Messages/chat.db` (tests point at a fake).
    pub chat_db: Option<PathBuf>,
    /// Override for the persisted ROWID cursor file (a name relative to the
    /// verified `AUXESIS_HOME`, never an absolute path).
    pub cursor_file: Option<String>,
    /// Pacing floor in seconds; may be raised, never lowered past
    /// [`MIN_PACING_SECS`].
    pub min_gap_secs: i64,
}

impl Default for ImessageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            owner_handles: Vec::new(),
            chat_guid: String::new(),
            agent_handle: String::new(),
            mode: Mode::AppleId,
            chat_db: None,
            cursor_file: None,
            min_gap_secs: MIN_PACING_SECS,
        }
    }
}

/// Why an enabled `[imessage]` section is not usable. Carries no handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// No owner handle is configured.
    #[error("no owner handle is configured")]
    NoOwnerHandles,
    /// More owner handles than one chat may name.
    #[error("too many owner handles")]
    TooManyOwnerHandles,
    /// A handle is empty, too long, or carries a control byte.
    #[error("an owner handle is invalid")]
    BadHandle,
    /// The pinned chat GUID is missing or invalid.
    #[error("the pinned chat GUID is invalid")]
    BadChatGuid,
    /// The agent handle is missing or invalid.
    #[error("the agent handle is invalid")]
    BadAgentHandle,
    /// The agent handle is also an owner handle: that is iMessage-to-self.
    #[error("the agent handle is one of the owner handles")]
    AgentIsOwner,
    /// The pacing gap is below the 15 s floor.
    #[error("the pacing gap is below the 15 s floor")]
    MinGapTooSmall,
    /// The cursor file is not a plain name under the verified home.
    #[error("the cursor file is not a plain name under the verified home")]
    BadCursorFile,
}

impl ImessageConfig {
    /// Validate an enabled section. Disabled sections are not validated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.owner_handles.is_empty() {
            return Err(ConfigError::NoOwnerHandles);
        }
        if self.owner_handles.len() > MAX_OWNER_HANDLES {
            return Err(ConfigError::TooManyOwnerHandles);
        }
        for handle in &self.owner_handles {
            validate_handle(handle).map_err(|_| ConfigError::BadHandle)?;
        }
        validate_handle(&self.agent_handle).map_err(|_| ConfigError::BadAgentHandle)?;
        if self
            .owner_handles
            .iter()
            .any(|h| same_handle(h, &self.agent_handle))
        {
            return Err(ConfigError::AgentIsOwner);
        }
        if !valid_text(&self.chat_guid, MAX_HANDLE_LEN) {
            return Err(ConfigError::BadChatGuid);
        }
        if let Some(file) = &self.cursor_file {
            if !safe_relative_name(file) {
                return Err(ConfigError::BadCursorFile);
            }
        }
        if self.min_gap_secs < MIN_PACING_SECS {
            return Err(ConfigError::MinGapTooSmall);
        }
        Ok(())
    }

    /// The `chat.db` to read: the configured path, else the standard one under
    /// the real user home (the kernel's accessor, never a raw `HOME` read).
    pub fn chat_db_path(&self) -> PathBuf {
        if let Some(path) = &self.chat_db {
            return path.clone();
        }
        kernel_core::real_user_home()
            .map(|home| home.join(DEFAULT_CHAT_DB))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CHAT_DB))
    }

    /// The persisted ROWID cursor file, a plain name under the verified
    /// `AUXESIS_HOME`.
    pub fn cursor_file(&self) -> PathBuf {
        self.cursor_file
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CURSOR_FILE))
    }
}

/// A single-component relative file name: no root, no `..`, no separators, no
/// control byte.
fn safe_relative_name(name: &str) -> bool {
    use std::path::Component;
    if name.is_empty() || name.contains('\0') || name.len() > MAX_HANDLE_LEN {
        return false;
    }
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

/// Anything else in `gateways.toml` (Telegram keeps its own config today, so
/// this is only the section this crate owns).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewaysConfig {
    /// The Messages gateway.
    pub imessage: ImessageConfig,
}

impl GatewaysConfig {
    /// The section is enabled and valid: the only state in which the daemon
    /// may build the Messages gateway.
    pub fn imessage_usable(&self) -> bool {
        self.imessage.enabled && self.imessage.validate().is_ok()
    }
}

/// Read `<home>/gateways.toml`. A missing file is the default (disabled); an
/// unreadable, linked or FIFO file is logged and reads back disabled.
pub fn load(home: &Path) -> GatewaysConfig {
    load_file(&home.join(GATEWAYS_FILE))
}

/// Read an explicit `gateways.toml` (test seam and the helper binary).
pub fn load_file(path: &Path) -> GatewaysConfig {
    let bytes = match read_bounded(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return GatewaysConfig::default();
        }
        Err(err) => {
            tracing::warn!(error = %err, "gateways.toml is unreadable; gateways stay disabled");
            return GatewaysConfig::default();
        }
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        tracing::warn!("gateways.toml is not UTF-8; gateways stay disabled");
        return GatewaysConfig::default();
    };
    match toml::from_str::<GatewaysConfig>(text) {
        Ok(mut config) => {
            if config.imessage.enabled {
                if let Err(err) = config.imessage.validate() {
                    tracing::warn!(error = %err, "[imessage] is invalid; it stays disabled");
                    config.imessage.enabled = false;
                }
            }
            config
        }
        Err(err) => {
            let err = kernel_core::redact_toml_error(&err, "gateways.toml", text);
            tracing::warn!(
                error = err.message(),
                "gateways.toml is invalid; gateways stay disabled"
            );
            GatewaysConfig::default()
        }
    }
}

/// The bytes at `path`, read as the kernel reads a config file (`O_NOFOLLOW |
/// O_NONBLOCK`, bounded): never through a link nor waiting on a FIFO.
fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    use kernel_core::config::MAX_CONFIG_BYTES;
    use std::io::Read;
    let path = std::path::absolute(path)?;
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    let dir = kernel_core::SandboxHome::open_existing(dir)?;
    let file = dir.open_read_existing(Path::new(name), MAX_CONFIG_BYTES)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    Ok(bytes)
}

/// True when two handles name the same principal: email handles compare
/// case-insensitively, phone handles exactly.
pub fn same_handle(a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a.contains('@') && b.contains('@') {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn validate_handle(handle: &str) -> Result<(), ConfigError> {
    if !valid_text(handle, MAX_HANDLE_LEN) {
        return Err(ConfigError::BadHandle);
    }
    Ok(())
}

/// Non-empty, within `max`, and free of NUL and other control bytes.
fn valid_text(value: &str, max: usize) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed.len() <= max && !trimmed.chars().any(|c| c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> ImessageConfig {
        ImessageConfig {
            enabled: true,
            owner_handles: vec!["+33600000001".to_string()],
            chat_guid: "iMessage;-;+33600000001".to_string(),
            agent_handle: "agent@example.test".to_string(),
            ..ImessageConfig::default()
        }
    }

    #[test]
    fn the_default_is_disabled() {
        let config = ImessageConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.min_gap_secs, MIN_PACING_SECS);
    }

    #[test]
    fn a_valid_section_passes() {
        valid().validate().unwrap();
    }

    #[test]
    fn the_agent_may_not_be_an_owner() {
        let mut config = valid();
        config.owner_handles.push("AGENT@example.test".to_string());
        assert_eq!(config.validate(), Err(ConfigError::AgentIsOwner));
    }

    #[test]
    fn the_pacing_floor_can_not_be_lowered() {
        let mut config = valid();
        config.min_gap_secs = MIN_PACING_SECS - 1;
        assert_eq!(config.validate(), Err(ConfigError::MinGapTooSmall));
        config.min_gap_secs = 60;
        config.validate().unwrap();
    }

    #[test]
    fn a_control_byte_in_a_handle_is_refused() {
        let mut config = valid();
        config.owner_handles = vec!["+33600\n00001".to_string()];
        assert_eq!(config.validate(), Err(ConfigError::BadHandle));
    }

    #[test]
    fn an_invalid_enabled_file_reads_back_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GATEWAYS_FILE);
        std::fs::write(
            &path,
            "[imessage]\nenabled = true\nowner_handles = []\nchat_guid = \"x\"\nagent_handle = \"a@example.test\"\n",
        )
        .unwrap();
        let config = load_file(&path);
        assert!(!config.imessage.enabled);
        assert!(!config.imessage_usable());
    }

    #[test]
    fn an_unknown_key_disables_the_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GATEWAYS_FILE);
        std::fs::write(
            &path,
            "[imessage]\nenabled = true\nowner_handles = [\"+33600000001\"]\nchat_guid = \"iMessage;-;+33600000001\"\nagent_handle = \"a@example.test\"\ntypo = 1\n",
        )
        .unwrap();
        let config = load_file(&path);
        assert!(!config.imessage.enabled);
    }

    #[test]
    fn a_missing_file_is_the_disabled_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = load(dir.path());
        assert!(!config.imessage.enabled);
    }

    /// A link or a FIFO at gateways.toml reads back disabled at once.
    #[cfg(unix)]
    #[test]
    fn a_fifo_or_linked_gateways_file_reads_disabled_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (path, other) = (dir.path().join(GATEWAYS_FILE), dir.path().join("o.toml"));
        std::fs::write(&other, "[imessage]\nenabled = true\n").unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(!load(dir.path()).imessage.enabled, "a link is refused");
        std::fs::remove_file(&path).unwrap();
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        assert!(made.unwrap().success());
        let (home, (sent, got)) = (dir.path().to_path_buf(), std::sync::mpsc::channel());
        std::thread::spawn(move || sent.send(load(&home).imessage.enabled));
        let wait = std::time::Duration::from_secs(10);
        assert!(!got.recv_timeout(wait).expect("blocked"));
    }
}
