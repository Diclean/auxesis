//! The agent loader: `agent.md`, with `soul.md` / `dot.toml` as legacy aliases.
//!
//! The skills contract moved out of this repository (see `docs/README.md`).
//! `agent.md` wins when it exists; when it is absent an equivalent is built
//! from the `soul.md` body and the `dot.toml` sidecar. Any unknown
//! front-matter key is a load error: the loader fails to load, it never
//! degrades.
//!
//! The old `budget.daily_usd` front-matter key is gone: daily caps come only
//! from `[budgets]` in `config.toml`. An older `agent.md` that still carries
//! it loads normally and is told, once, where the cap now lives.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::frontmatter::{self, Value};
use super::{tool_map, RecipientPolicy};

/// Refuse to read an `agent.md` larger than this.
pub const MAX_AGENT_BYTES: u64 = 1024 * 1024;

/// Which provider class the agent runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Brain {
    /// A configured cloud provider.
    Cloud,
    /// A local model.
    Local,
    /// A test double.
    Fake,
}

/// The agent's default privacy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentMode {
    /// Values leave only as tokens.
    Private,
    /// Values may leave as themselves.
    Open,
}

/// Where the loaded agent definition came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSource {
    /// A front-matter `agent.md`.
    AgentMd,
    /// The legacy `soul.md` + `dot.toml` pair.
    Legacy,
}

/// An `agent.md` (or legacy) load failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLoadError {
    /// File the error is about (`agent.md`, `soul.md`, `dot.toml`).
    pub file: String,
    /// Human-readable reason, safe to log.
    pub reason: String,
}

impl fmt::Display for AgentLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.reason)
    }
}

impl std::error::Error for AgentLoadError {}

fn error(file: &str, reason: impl Into<String>) -> AgentLoadError {
    AgentLoadError {
        file: file.to_string(),
        reason: reason.into(),
    }
}

/// One agent's identity and capabilities.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedAgent {
    /// Agent name; always equals the directory name.
    pub name: String,
    /// Provider class.
    pub brain: Brain,
    /// Default privacy mode.
    pub default_mode: AgentMode,
    /// Channels the agent may be reached on.
    pub channels: Vec<String>,
    /// Allowed tools, canonical logical names.
    pub tools: Vec<String>,
    /// Default recipient policy for skills.
    pub recipients_policy: RecipientPolicy,
    /// E.164 phones / emails used by policy `allowlist`.
    pub recipients_allowlist: Vec<String>,
    /// Instruction body.
    pub body: String,
    /// Which file(s) the definition came from.
    pub source: AgentSource,
    /// Directory the agent was loaded from.
    pub dir: PathBuf,
}

impl LoadedAgent {
    /// True when `tool` is in the agent's allowlist (short forms expanded).
    pub fn allows(&self, tool: &str) -> bool {
        let canonical = tool_map::canonical_name(tool).unwrap_or_else(|| tool.to_string());
        self.tools.contains(&canonical)
            || (self.name == crate::grants::CHIEF_AGENT
                && self.source == AgentSource::Legacy
                && self.tools.iter().any(|tool| tool == "*"))
    }
}

const AGENT_KEYS: &[&str] = &[
    "name",
    "brain",
    "default_mode",
    "channels",
    "tools",
    "recipients",
];

/// Load the agent rooted at `agent_dir`.
pub fn load_agent(agent_dir: &Path) -> Result<LoadedAgent, AgentLoadError> {
    let name = agent_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| error("agent.md", "agent directory has no usable name"))?
        .to_string();
    let agent_md = agent_dir.join("agent.md");
    match read_bounded(&agent_md) {
        Ok(bytes) => parse_agent_md(&bytes, agent_dir, &name),
        Err(ReadError::NotFound) => load_legacy(agent_dir, &name),
        Err(ReadError::TooLarge) => Err(error("agent.md", "agent.md is larger than 1 MiB")),
        Err(ReadError::Symlink) => Err(error("agent.md", "agent.md is a symbolic link")),
        Err(ReadError::Io(err)) => {
            Err(error("agent.md", format!("could not read agent.md: {err}")))
        }
    }
}

/// The privacy mode `agent.md` sets for its agent: one layer of the effective
/// mode (`README.md`, "The two modes"). `None` when the agent has no agent.md,
/// since a legacy agent sets no layer. An agent.md that cannot be read is
/// private, so the mode fails toward masking.
pub fn agent_mode_layer(agent_dir: &Path) -> Option<kernel_core::privacy::PrivacyMode> {
    use kernel_core::privacy::PrivacyMode;
    match load_agent(agent_dir) {
        Ok(agent) if agent.source == AgentSource::AgentMd => Some(match agent.default_mode {
            AgentMode::Private => PrivacyMode::Private,
            AgentMode::Open => PrivacyMode::Open,
        }),
        Ok(_) => None,
        Err(_) => Some(PrivacyMode::Private),
    }
}

/// The effective mode of a turn: the global mode, tightened by one layer. The
/// most private layer wins, so private on either side makes the turn private.
pub fn effective_mode(
    global: kernel_core::privacy::PrivacyMode,
    layer: Option<kernel_core::privacy::PrivacyMode>,
) -> kernel_core::privacy::PrivacyMode {
    use kernel_core::privacy::PrivacyMode;
    if global == PrivacyMode::Private || layer == Some(PrivacyMode::Private) {
        PrivacyMode::Private
    } else {
        PrivacyMode::Open
    }
}

fn parse_agent_md(bytes: &[u8], dir: &Path, name: &str) -> Result<LoadedAgent, AgentLoadError> {
    if bytes.len() as u64 > MAX_AGENT_BYTES {
        return Err(error("agent.md", "agent.md is larger than 1 MiB"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| error("agent.md", "agent.md is not valid UTF-8"))?;
    let (meta, body) = frontmatter::parse(text)
        .map_err(|err| error("agent.md", format!("front matter: {err}")))?;
    let entries = meta
        .as_map()
        .ok_or_else(|| error("agent.md", "front matter must be a mapping"))?;
    let file = dir.join("agent.md");
    for (key, _) in entries {
        // Dead config, kept loadable: the daily cap lives in `[budgets]`, so
        // an older agent.md is told once where it moved rather than failing
        // the whole agent (or dropping the key in silence).
        if key == "budget" {
            tracing::warn!(
                file = %file.display(),
                agent = %name,
                "agent.md `budget.daily_usd` is ignored; set the daily cap in config.toml under [budgets.agents.{name}]"
            );
            continue;
        }
        if !AGENT_KEYS.contains(&key.as_str()) {
            return Err(error(
                "agent.md",
                format!("unknown front-matter key `{key}`"),
            ));
        }
    }

    let declared = require_str(&meta, "name", "agent.md")?;
    if declared != name {
        return Err(error(
            "agent.md",
            format!("name `{declared}` does not match the directory `{name}`"),
        ));
    }

    let brain = match meta.get("brain") {
        None | Some(Value::Null) => Brain::Cloud,
        Some(value) => match value.as_str() {
            Some("cloud") => Brain::Cloud,
            Some("local") => Brain::Local,
            Some("fake") => Brain::Fake,
            _ => return Err(error("agent.md", "brain must be one of cloud, local, fake")),
        },
    };

    let default_mode = match meta.get("default_mode") {
        None | Some(Value::Null) => AgentMode::Private,
        Some(value) => match value.as_str() {
            Some("private") => AgentMode::Private,
            Some("open") => AgentMode::Open,
            _ => return Err(error("agent.md", "default_mode must be private or open")),
        },
    };

    let channels = string_list(&meta, "channels", "agent.md")?;

    let raw_tools = string_list(&meta, "tools", "agent.md")?;
    let mut tools = Vec::new();
    for tool in raw_tools {
        let canonical = tool_map::canonical_name(&tool).unwrap_or(tool);
        if !tools.contains(&canonical) {
            tools.push(canonical);
        }
    }

    let mut recipients_policy = RecipientPolicy::KnownContacts;
    let mut recipients_allowlist = Vec::new();
    if let Some(value) = meta.get("recipients") {
        let entries = value
            .as_map()
            .ok_or_else(|| error("agent.md", "recipients must be a mapping"))?;
        for (key, _) in entries {
            if key != "policy" && key != "allowlist" {
                return Err(error("agent.md", format!("unknown recipients key `{key}`")));
            }
        }
        if let Some(policy) = value.get("policy") {
            let name = policy
                .as_str()
                .ok_or_else(|| error("agent.md", "recipients.policy must be a string"))?;
            recipients_policy = RecipientPolicy::parse(name)
                .ok_or_else(|| error("agent.md", format!("unknown recipients.policy `{name}`")))?;
        }
        recipients_allowlist = string_list(value, "allowlist", "agent.md")?;
    }

    Ok(LoadedAgent {
        name: name.to_string(),
        brain,
        default_mode,
        channels,
        tools,
        recipients_policy,
        recipients_allowlist,
        body,
        source: AgentSource::AgentMd,
        dir: dir.to_path_buf(),
    })
}

fn load_legacy(dir: &Path, name: &str) -> Result<LoadedAgent, AgentLoadError> {
    let soul = dir.join("soul.md");
    let body = match read_bounded(&soul) {
        Ok(bytes) => {
            String::from_utf8(bytes).map_err(|_| error("soul.md", "soul.md is not valid UTF-8"))?
        }
        Err(ReadError::NotFound) => String::new(),
        Err(ReadError::TooLarge) => {
            return Err(error("soul.md", "soul.md is larger than 1 MiB"));
        }
        Err(ReadError::Symlink) => return Err(error("soul.md", "soul.md is a symbolic link")),
        Err(ReadError::Io(err)) => {
            return Err(error("soul.md", format!("could not read soul.md: {err}")));
        }
    };

    // The daemon writes `agent.toml`; the pre-WO-07 `dot.toml` is read only
    // while `agent.toml` is absent.
    let (sidecar_name, sidecar_read) = match read_bounded(&dir.join("agent.toml")) {
        Err(ReadError::NotFound) => ("dot.toml", read_bounded(&dir.join("dot.toml"))),
        other => ("agent.toml", other),
    };
    let tools = match sidecar_read {
        Ok(bytes) => {
            let text = String::from_utf8(bytes)
                .map_err(|_| error(sidecar_name, format!("{sidecar_name} is not valid UTF-8")))?;
            let sidecar: Sidecar = toml::from_str(&text).map_err(|err| {
                let err = kernel_core::redact_toml_error(&err, sidecar_name, &text);
                error(
                    sidecar_name,
                    format!("{sidecar_name} is unreadable: {}", err.message()),
                )
            })?;
            let unrestricted_chief = name == crate::grants::CHIEF_AGENT && sidecar.tools.is_none();
            let mut tools = Vec::new();
            for tool in sidecar.tools.unwrap_or_default() {
                let canonical = tool_map::canonical_name(&tool).unwrap_or(tool);
                if !tools.contains(&canonical) {
                    tools.push(canonical);
                }
            }
            if unrestricted_chief {
                tools.push("*".into());
            }
            tools
        }
        Err(ReadError::NotFound) if name == crate::grants::CHIEF_AGENT => vec!["*".into()],
        Err(ReadError::NotFound) => Vec::new(),
        Err(ReadError::TooLarge) => {
            return Err(error(
                sidecar_name,
                format!("{sidecar_name} is larger than 1 MiB"),
            ));
        }
        Err(ReadError::Symlink) => {
            return Err(error(
                sidecar_name,
                format!("{sidecar_name} is a symbolic link"),
            ));
        }
        Err(ReadError::Io(err)) => {
            return Err(error(
                sidecar_name,
                format!("could not read {sidecar_name}: {err}"),
            ));
        }
    };

    Ok(LoadedAgent {
        name: name.to_string(),
        brain: Brain::Cloud,
        default_mode: AgentMode::Private,
        channels: Vec::new(),
        tools,
        recipients_policy: RecipientPolicy::KnownContacts,
        recipients_allowlist: Vec::new(),
        body,
        source: AgentSource::Legacy,
        dir: dir.to_path_buf(),
    })
}

/// The subset of the `agent.toml` sidecar the loader reads.
#[derive(Debug, serde::Deserialize)]
struct Sidecar {
    #[serde(default)]
    tools: Option<Vec<String>>,
}

enum ReadError {
    NotFound,
    TooLarge,
    Symlink,
    Io(std::io::Error),
}

/// Read at most [`MAX_AGENT_BYTES`], refusing a final symlink.
fn read_bounded(path: &Path) -> Result<Vec<u8>, ReadError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(ReadError::Symlink),
        Ok(meta) if !meta.is_file() => {
            return Err(ReadError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a regular file",
            )));
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReadError::NotFound);
        }
        Err(err) => return Err(ReadError::Io(err)),
    }
    let file = fs::File::open(path).map_err(ReadError::Io)?;
    let mut bytes = Vec::new();
    file.take(MAX_AGENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(ReadError::Io)?;
    if bytes.len() as u64 > MAX_AGENT_BYTES {
        return Err(ReadError::TooLarge);
    }
    Ok(bytes)
}

fn require_str(value: &Value, key: &str, file: &str) -> Result<String, AgentLoadError> {
    match value.get(key) {
        Some(Value::Str(text)) if !text.is_empty() => Ok(text.clone()),
        Some(_) => Err(error(file, format!("`{key}` must be a non-empty string"))),
        None => Err(error(file, format!("missing required field `{key}`"))),
    }
}

fn string_list(value: &Value, key: &str, file: &str) -> Result<Vec<String>, AgentLoadError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::List(items)) => {
            let mut out = Vec::new();
            for item in items {
                let text = item
                    .as_str()
                    .ok_or_else(|| error(file, format!("`{key}` entries must be strings")))?;
                if text.is_empty() {
                    return Err(error(file, format!("`{key}` entries must not be empty")));
                }
                out.push(text.to_string());
            }
            Ok(out)
        }
        Some(_) => Err(error(file, format!("`{key}` must be a sequence"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn chief_skills_use_all_tools_by_default_but_respect_an_empty_ceiling() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("main");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load_agent(&dir).unwrap().allows("mail.send"));
        std::fs::write(dir.join("agent.toml"), "tools = []\n").unwrap();
        assert!(!load_agent(&dir).unwrap().allows("mail.send"));
    }

    fn write(dir: &Path, name: &str, contents: &str) {
        fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn loads_agent_md_front_matter() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        write(
            &agent_dir,
            "agent.md",
            "---\nname: assistant\nbrain: cloud\ndefault_mode: private\nchannels: [mac, telegram]\ntools: [google.gmail.search]\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nBody text.\n",
        );
        let agent = load_agent(&agent_dir).unwrap();
        assert_eq!(agent.name, "assistant");
        assert_eq!(agent.brain, Brain::Cloud);
        assert_eq!(agent.default_mode, AgentMode::Private);
        assert_eq!(agent.channels, vec!["mac", "telegram"]);
        assert_eq!(agent.tools, vec!["google.gmail.search"]);
        assert!(agent.allows("google.gmail.search"));
        assert_eq!(agent.source, AgentSource::AgentMd);
        assert_eq!(agent.body, "Body text.\n");
    }

    /// WO-BUD-6: the removed `budget.daily_usd` key no longer fails the load
    /// and no longer has anywhere to be stored; one warning names the file
    /// and points at the config.toml section that replaced it.
    #[test]
    fn a_legacy_budget_key_is_ignored_once_with_a_pointer_to_config_toml() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        write(
            &agent_dir,
            "agent.md",
            "---\nname: assistant\ndefault_mode: open\nbudget: { daily_usd: 2.00 }\n---\nBody text.\n",
        );

        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let agent = load_agent(&agent_dir).expect("an old budget key must not stop the load");

        drop(guard);
        assert_eq!(agent.name, "assistant");
        assert_eq!(agent.default_mode, AgentMode::Open);
        assert_eq!(agent.body, "Body text.\n");

        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("budget.daily_usd"), "{logs}");
        assert!(
            logs.contains(&agent_dir.join("agent.md").display().to_string()),
            "the warning names the file: {logs}"
        );
        assert!(
            logs.contains("[budgets.agents.assistant]"),
            "the warning points at config.toml: {logs}"
        );
        assert!(logs.contains("config.toml"), "{logs}");
        assert_eq!(
            logs.lines()
                .filter(|line| line.contains("budget.daily_usd"))
                .count(),
            1,
            "exactly one warning per load: {logs}"
        );
    }

    #[test]
    fn unknown_key_fails_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        write(
            &agent_dir,
            "agent.md",
            "---\nname: assistant\nmystery: true\n---\n",
        );
        let err = load_agent(&agent_dir).unwrap_err();
        assert!(err.reason.contains("unknown front-matter key `mystery`"));
    }

    #[test]
    fn name_must_match_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        write(&agent_dir, "agent.md", "---\nname: other\n---\n");
        assert!(load_agent(&agent_dir).is_err());
    }

    #[test]
    fn agent_toml_tools_are_read_and_win_over_a_legacy_dot_toml() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        write(&agent_dir, "soul.md", "legacy body");
        write(&agent_dir, "dot.toml", "tools = [\"gmail.send\"]\n");
        write(
            &agent_dir,
            "agent.toml",
            "tools = [\"google.gmail.search\"]\n",
        );
        let agent = load_agent(&agent_dir).unwrap();
        assert_eq!(agent.tools, vec!["google.gmail.search"]);
    }

    #[test]
    fn agent_md_wins_over_soul_and_dot_toml() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        write(&agent_dir, "soul.md", "legacy body");
        write(
            &agent_dir,
            "dot.toml",
            "provider = \"p\"\ntools = [\"google.gmail.send\"]\n",
        );
        write(
            &agent_dir,
            "agent.md",
            "---\nname: assistant\ntools: [google.gmail.search]\n---\nnew body",
        );
        let agent = load_agent(&agent_dir).unwrap();
        assert_eq!(agent.source, AgentSource::AgentMd);
        assert_eq!(agent.tools, vec!["google.gmail.search"]);
        assert_eq!(agent.body, "new body");
    }

    #[test]
    fn falls_back_to_soul_and_dot_toml() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        write(&agent_dir, "soul.md", "legacy body");
        write(
            &agent_dir,
            "dot.toml",
            "provider = \"p\"\ntools = [\"gmail.send\"]\n",
        );
        let agent = load_agent(&agent_dir).unwrap();
        assert_eq!(agent.source, AgentSource::Legacy);
        assert_eq!(agent.default_mode, AgentMode::Private);
        assert_eq!(agent.recipients_policy, RecipientPolicy::KnownContacts);
        assert_eq!(agent.tools, vec!["google.gmail.send"]);
        assert_eq!(agent.body, "legacy body");
    }

    #[test]
    fn missing_agent_files_yields_an_empty_legacy_agent() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        let agent = load_agent(&agent_dir).unwrap();
        assert_eq!(agent.source, AgentSource::Legacy);
        assert!(agent.tools.is_empty());
        assert!(agent.body.is_empty());
    }

    #[test]
    fn oversized_agent_md_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        let mut file = fs::File::create(agent_dir.join("agent.md")).unwrap();
        file.write_all(b"---\nname: assistant\n---\n").unwrap();
        file.write_all(&vec![b'x'; MAX_AGENT_BYTES as usize])
            .unwrap();
        assert!(load_agent(&agent_dir).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_agent_soul_and_sidecar_are_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();

        fs::write(
            dir.path().join("real-agent.md"),
            "---\nname: assistant\n---\n",
        )
        .unwrap();
        symlink(dir.path().join("real-agent.md"), agent_dir.join("agent.md")).unwrap();
        let err = load_agent(&agent_dir).unwrap_err();
        assert!(err.reason.contains("symbolic link"), "{err}");

        fs::remove_file(agent_dir.join("agent.md")).unwrap();
        fs::write(dir.path().join("real-soul.md"), "body").unwrap();
        symlink(dir.path().join("real-soul.md"), agent_dir.join("soul.md")).unwrap();
        let err = load_agent(&agent_dir).unwrap_err();
        assert!(err.reason.contains("symbolic link"), "{err}");

        fs::remove_file(agent_dir.join("soul.md")).unwrap();
        fs::write(dir.path().join("real-dot.toml"), "tools = []\n").unwrap();
        symlink(dir.path().join("real-dot.toml"), agent_dir.join("dot.toml")).unwrap();
        let err = load_agent(&agent_dir).unwrap_err();
        assert!(err.reason.contains("symbolic link"), "{err}");
    }

    #[test]
    fn oversized_soul_and_sidecar_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("assistant");
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(
            agent_dir.join("soul.md"),
            vec![b'x'; MAX_AGENT_BYTES as usize + 1],
        )
        .unwrap();
        let err = load_agent(&agent_dir).unwrap_err();
        assert!(err.reason.contains("larger than 1 MiB"), "{err}");

        fs::remove_file(agent_dir.join("soul.md")).unwrap();
        fs::write(
            agent_dir.join("dot.toml"),
            vec![b'x'; MAX_AGENT_BYTES as usize + 1],
        )
        .unwrap();
        let err = load_agent(&agent_dir).unwrap_err();
        assert!(err.reason.contains("larger than 1 MiB"), "{err}");
    }
}
