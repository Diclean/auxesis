//! Skill file parsing and the fail-to-load loader.
//!
//! One file is one skill. Every rejection is a [`SkillLoadError`] and a
//! `skill.load_error` Ledger row; a skill with any error is never loaded.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use kernel_broker::AuditSink;

use super::agent::LoadedAgent;
use super::frontmatter::{self, Value};
use super::{tool_map, RecipientPolicy};

/// Refuse to read a skill file larger than this.
pub const MAX_SKILL_BYTES: u64 = 64 * 1024;

/// Maximum accepted skill-name length.
pub const MAX_SKILL_NAME_LEN: usize = 40;

const SKILL_KEYS: &[&str] = &[
    "name",
    "version",
    "command",
    "brain",
    "trigger",
    "tools",
    "inputs",
    "recipients",
    "approval",
    "on_failure",
];

/// The tokenisation tier of an input value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Confidential: tokenised like confidential text.
    C,
    /// High: tokenised like high-sensitivity text.
    H,
    /// Normal.
    N,
}

impl Tier {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "C" => Some(Tier::C),
            "H" => Some(Tier::H),
            "N" => Some(Tier::N),
            _ => None,
        }
    }
}

/// The declared value type of an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValueType {
    /// Free string (the default).
    #[default]
    String,
    /// An ISO date-time.
    DateTime,
    /// A duration such as `30m`.
    Duration,
    /// An email address.
    Email,
}

impl ValueType {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "string" => Some(ValueType::String),
            "datetime" => Some(ValueType::DateTime),
            "duration" => Some(ValueType::Duration),
            "email" => Some(ValueType::Email),
            _ => None,
        }
    }

    /// The contract spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ValueType::String => "string",
            ValueType::DateTime => "datetime",
            ValueType::Duration => "duration",
            ValueType::Email => "email",
        }
    }
}

/// One declared input slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillInput {
    /// Slot name.
    pub name: String,
    /// Tokenisation tier, when declared.
    pub tier: Option<Tier>,
    /// Value type (`string` by default).
    pub value_type: ValueType,
    /// Default the runtime fills when the model omits the slot.
    pub default: Option<String>,
    /// The slot this input is derived from: `from: contact(<slot>)`
    /// (`docs/phase1.md` §7). `Some` means the model never fills this slot;
    /// the runtime resolves it from the named `tier: H` input after the fill.
    pub from: Option<String>,
}

/// The skill's trigger block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trigger {
    /// Startable by hand (`/command` or the model).
    pub manual: bool,
    /// A 5-field cron, allowed only when every tool is read-only.
    pub schedule: Option<String>,
    /// Phase 1 (`email.received`); refused in Phase 0.
    pub on: Option<String>,
}

/// The approval level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// One approval per call, in order.
    EachAction,
    /// One approval for the whole run.
    EachRun,
    /// No card: every tool is read-only, so the run observes and writes nothing.
    None,
}

impl Approval {
    /// The contract spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Approval::EachAction => "each_action",
            Approval::EachRun => "each_run",
            Approval::None => "none",
        }
    }
}

/// What happens when a call fails. The only Phase 0 value is `stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailure {
    /// Stop the run; remaining calls do not execute.
    Stop,
}

/// The brain a skill asks for (`docs/providers.md` §3).
///
/// `none` is the deterministic, local case: the skill's calls are dispatched to
/// a local connector and no model runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SkillBrain {
    /// Inherit the agent's brain (the default when the key is absent).
    #[default]
    Agent,
    /// No model: the skill runs deterministically.
    None,
    /// A configured cloud provider.
    Cloud,
    /// A local model.
    Local,
    /// A test double.
    Fake,
}

impl SkillBrain {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "none" => Some(SkillBrain::None),
            "cloud" => Some(SkillBrain::Cloud),
            "local" => Some(SkillBrain::Local),
            "fake" => Some(SkillBrain::Fake),
            _ => None,
        }
    }
}

/// A skill that parsed and passed every rule.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedSkill {
    /// Skill name (equals the file stem).
    pub name: String,
    /// Version declared in the file.
    pub version: u32,
    /// Optional slash command, unique per agent.
    pub command: Option<String>,
    /// Which brain runs the skill; `none` is the deterministic local case.
    pub brain: SkillBrain,
    /// The trigger block.
    pub trigger: Trigger,
    /// Tools declared by the skill (canonical logical names).
    pub tools: Vec<String>,
    /// Effective tools: the agent's `tools` ∩ the skill's `tools`.
    pub effective_tools: Vec<String>,
    /// Declared inputs, in file order.
    pub inputs: Vec<SkillInput>,
    /// Effective recipient policy (the stricter of agent and skill).
    pub recipients_policy: RecipientPolicy,
    /// Approval level.
    pub approval: Approval,
    /// Failure policy.
    pub on_failure: OnFailure,
    /// Instruction body.
    pub body: String,
    /// blake3 of the file bytes, hex.
    pub hash: String,
    /// File the skill was read from.
    pub file: String,
}

impl LoadedSkill {
    /// The broker's skill context for this exact file.
    pub fn skill_ref(&self) -> kernel_broker::SkillRef {
        kernel_broker::SkillRef {
            name: self.name.clone(),
            version: self.version.to_string(),
            hash: self.hash.clone(),
        }
    }

    /// True when every effective tool is read-only.
    pub fn all_tools_read_only(&self) -> bool {
        self.effective_tools.iter().all(|tool| {
            tool_map::lookup(tool)
                .map(|info| info.is_read_only())
                .unwrap_or(false)
        })
    }
}

/// One rejected skill file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillLoadError {
    /// File the error is about.
    pub file: String,
    /// Human-readable reason, safe to log.
    pub reason: String,
    /// Skill name: the parsed front-matter name, else the file stem.
    pub skill_name: String,
    /// Skill version when the front matter parsed far enough to know it.
    pub skill_version: Option<u32>,
    /// blake3 of the file bytes, when any were read.
    pub skill_hash: Option<String>,
}

impl SkillLoadError {
    fn new(file: impl Into<String>, reason: impl Into<String>) -> Self {
        SkillLoadError {
            file: file.into(),
            reason: reason.into(),
            skill_name: String::new(),
            skill_version: None,
            skill_hash: None,
        }
    }

    fn with_identity(
        mut self,
        skill_name: String,
        skill_version: Option<u32>,
        skill_hash: Option<String>,
    ) -> Self {
        self.skill_name = skill_name;
        self.skill_version = skill_version;
        self.skill_hash = skill_hash;
        self
    }
}

impl fmt::Display for SkillLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.reason)
    }
}

impl std::error::Error for SkillLoadError {}

/// The result of loading one agent's skills: what loaded, what did not.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SkillLoad {
    /// Skills that passed every rule.
    pub skills: Vec<LoadedSkill>,
    /// Every rejected file, in the order it was read.
    pub errors: Vec<SkillLoadError>,
}

/// Read, validate and return every skill below `<agent dir>/skills`.
pub fn load_skills(
    agent_dir: &Path,
    agent: &LoadedAgent,
    sink: Option<&dyn AuditSink>,
) -> SkillLoad {
    let mut load = SkillLoad::default();
    let skills_dir = agent_dir.join("skills");
    let mut files: Vec<PathBuf> = Vec::new();
    match fs::read_dir(&skills_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                match path.file_name().and_then(|name| name.to_str()) {
                    Some(name) => {
                        if Path::new(name).extension().and_then(|ext| ext.to_str()) == Some("md") {
                            files.push(path);
                        }
                    }
                    None => {
                        let lossy = path
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if lossy.ends_with(".md") {
                            push_error(
                                &mut load,
                                sink,
                                &agent.name,
                                &lossy,
                                "skill file name is not valid UTF-8",
                            );
                        }
                    }
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            push_error(
                &mut load,
                sink,
                &agent.name,
                &skills_dir.display().to_string(),
                format!("could not read the skills directory: {err}"),
            );
            return load;
        }
    }
    files.sort();

    let mut candidates: Vec<LoadedSkill> = Vec::new();
    for path in files {
        let file = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<non-utf8>")
            .to_string();
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("<non-utf8>")
            .to_string();
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                record_error(
                    &mut load,
                    sink,
                    &agent.name,
                    load_error(&file, "skill file is a symbolic link").with_identity(
                        stem.clone(),
                        None,
                        None,
                    ),
                );
                continue;
            }
            Ok(meta) if !meta.is_file() => continue,
            Ok(_) => {}
            Err(err) => {
                record_error(
                    &mut load,
                    sink,
                    &agent.name,
                    load_error(&file, format!("could not stat the skill file: {err}"))
                        .with_identity(stem.clone(), None, None),
                );
                continue;
            }
        }
        let bytes = match read_bounded(&path) {
            Ok(bytes) => bytes,
            Err(ReadSkillError::TooLarge) => {
                record_error(
                    &mut load,
                    sink,
                    &agent.name,
                    load_error(&file, "skill file is larger than 64 KiB").with_identity(
                        stem.clone(),
                        None,
                        None,
                    ),
                );
                continue;
            }
            Err(ReadSkillError::Io(err)) => {
                record_error(
                    &mut load,
                    sink,
                    &agent.name,
                    load_error(&file, format!("could not read the skill file: {err}"))
                        .with_identity(stem.clone(), None, None),
                );
                continue;
            }
        };
        let hash = blake3::hash(&bytes).to_hex().to_string();
        match parse_skill(&bytes, &file, &stem, agent) {
            Ok(skill) => candidates.push(skill),
            Err(err) => {
                let (name, version) = best_effort_identity(&bytes, &stem);
                record_error(
                    &mut load,
                    sink,
                    &agent.name,
                    err.with_identity(name, version, Some(hash)),
                );
            }
        }
    }

    reject_duplicates(&mut load, sink, &agent.name, candidates);
    load
}

/// Reject every file that shares a `name` or `command` with another.
pub(super) fn reject_duplicates(
    load: &mut SkillLoad,
    sink: Option<&dyn AuditSink>,
    agent: &str,
    candidates: Vec<LoadedSkill>,
) {
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    let mut command_counts: HashMap<String, usize> = HashMap::new();
    for skill in &candidates {
        *name_counts.entry(skill.name.clone()).or_insert(0) += 1;
        if let Some(command) = skill.command.clone() {
            *command_counts.entry(command).or_insert(0) += 1;
        }
    }
    for skill in candidates {
        let duplicate_name = name_counts.get(&skill.name).copied().unwrap_or(0) > 1;
        let duplicate_command = skill
            .command
            .as_ref()
            .map(|command| command_counts.get(command).copied().unwrap_or(0) > 1)
            .unwrap_or(false);
        if duplicate_name {
            record_error(
                load,
                sink,
                agent,
                load_error(
                    &skill.file,
                    format!("duplicate skill name `{}`", skill.name),
                )
                .with_identity(
                    skill.name.clone(),
                    Some(skill.version),
                    Some(skill.hash.clone()),
                ),
            );
        } else if duplicate_command {
            record_error(
                load,
                sink,
                agent,
                load_error(
                    &skill.file,
                    format!(
                        "duplicate command `{}`",
                        skill.command.as_deref().unwrap_or_default()
                    ),
                )
                .with_identity(
                    skill.name.clone(),
                    Some(skill.version),
                    Some(skill.hash.clone()),
                ),
            );
        } else {
            load.skills.push(skill);
        }
    }
}

/// Parse and validate one skill file. `bytes` are the exact file bytes, so the
/// hash is computed over them.
pub fn parse_skill(
    bytes: &[u8],
    file: &str,
    stem: &str,
    agent: &LoadedAgent,
) -> Result<LoadedSkill, SkillLoadError> {
    let hash = blake3::hash(bytes).to_hex().to_string();
    let text = std::str::from_utf8(bytes)
        .map_err(|_| load_error(file, "skill file is not valid UTF-8"))?;
    let (meta, body) =
        frontmatter::parse(text).map_err(|err| load_error(file, format!("front matter: {err}")))?;
    let entries = meta
        .as_map()
        .ok_or_else(|| load_error(file, "front matter must be a mapping"))?;
    for (key, _) in entries {
        if !SKILL_KEYS.contains(&key.as_str()) {
            return Err(load_error(
                file,
                format!("unknown front-matter key `{key}`"),
            ));
        }
    }

    let name = require_str(&meta, "name", file)?;
    validate_skill_name(&name).map_err(|reason| load_error(file, reason))?;
    if name != stem {
        return Err(load_error(
            file,
            format!("name `{name}` does not match the file stem `{stem}`"),
        ));
    }

    let version = match meta.get("version") {
        Some(Value::Int(version)) if *version >= 1 && *version <= u32::MAX as i64 => {
            *version as u32
        }
        Some(Value::Int(_)) => {
            return Err(load_error(
                file,
                "version must be an integer between 1 and 4294967295",
            ));
        }
        Some(_) => return Err(load_error(file, "version must be an integer >= 1")),
        None => return Err(load_error(file, "missing required field `version`")),
    };

    let command = match meta.get("command") {
        None | Some(Value::Null) => None,
        Some(Value::Str(command)) if !command.is_empty() => {
            if command.chars().any(char::is_whitespace) || command.contains('/') {
                return Err(load_error(
                    file,
                    "command must be a single word without `/`",
                ));
            }
            Some(command.clone())
        }
        Some(_) => return Err(load_error(file, "command must be a non-empty string")),
    };

    let brain = match meta.get("brain") {
        None | Some(Value::Null) => SkillBrain::Agent,
        Some(Value::Str(value)) => SkillBrain::parse(value)
            .ok_or_else(|| load_error(file, format!("unknown brain `{value}`")))?,
        Some(_) => return Err(load_error(file, "`brain` must be a string")),
    };

    let declared = match meta.get("tools") {
        Some(Value::List(_)) => string_list(&meta, "tools", file)?,
        Some(_) => return Err(load_error(file, "`tools` must be a sequence")),
        None => return Err(load_error(file, "missing required field `tools`")),
    };
    let mut tools: Vec<String> = Vec::new();
    for tool in &declared {
        let info = tool_map::lookup(tool)
            .ok_or_else(|| load_error(file, format!("unknown tool `{tool}`")))?;
        if !agent.allows(&info.logical) {
            return Err(load_error(
                file,
                format!("tool `{tool}` is not in the agent's tools"),
            ));
        }
        if !tools.contains(&info.logical) {
            tools.push(info.logical);
        }
    }
    let effective_tools: Vec<String> = tools
        .iter()
        .filter(|tool| agent.allows(tool))
        .cloned()
        .collect();

    let trigger = parse_trigger(&meta, file, &effective_tools)?;
    let inputs = parse_inputs(&meta, file)?;
    let skill_policy = parse_recipients(&meta, file)?;
    let recipients_policy = match skill_policy {
        Some(policy) => policy.strictest(agent.recipients_policy),
        None => agent.recipients_policy,
    };

    let approval = match meta.get("approval") {
        Some(Value::Str(value)) => match value.as_str() {
            "each_action" => Approval::EachAction,
            "each_run" => Approval::EachRun,
            "none" => Approval::None,
            "once_per_recipient" => {
                return Err(load_error(
                    file,
                    "`approval: once_per_recipient` is Phase 1",
                ));
            }
            _ => return Err(load_error(file, format!("unknown approval `{value}`"))),
        },
        Some(_) => return Err(load_error(file, "`approval` must be a string")),
        None => return Err(load_error(file, "missing required field `approval`")),
    };

    if approval == Approval::None {
        // `none` is only safe because the run can write nothing but the local
        // ingest: every other tool it may call is a read (M5-5).
        for tool in &effective_tools {
            let read_only = tool_map::lookup(tool)
                .map(|info| info.runs_without_card())
                .unwrap_or(false);
            if !read_only {
                return Err(load_error(
                    file,
                    format!(
                        "`approval: none` is only allowed when every tool is read-only (found `{tool}`)"
                    ),
                ));
            }
        }
    }

    let on_failure = match meta.get("on_failure") {
        None | Some(Value::Null) => OnFailure::Stop,
        Some(Value::Str(value)) if value == "stop" => OnFailure::Stop,
        Some(_) => return Err(load_error(file, "`on_failure` must be `stop`")),
    };

    Ok(LoadedSkill {
        name,
        version,
        command,
        brain,
        trigger,
        tools,
        effective_tools,
        inputs,
        recipients_policy,
        approval,
        on_failure,
        body,
        hash,
        file: file.to_string(),
    })
}

fn parse_trigger(
    meta: &Value,
    file: &str,
    effective_tools: &[String],
) -> Result<Trigger, SkillLoadError> {
    let mut trigger = Trigger {
        manual: false,
        schedule: None,
        on: None,
    };
    let Some(value) = meta.get("trigger") else {
        return Ok(trigger);
    };
    if value.is_null() {
        return Ok(trigger);
    }
    let entries = value
        .as_map()
        .ok_or_else(|| load_error(file, "`trigger` must be a mapping"))?;
    for (key, _) in entries {
        if !["manual", "schedule", "on"].contains(&key.as_str()) {
            return Err(load_error(file, format!("unknown trigger key `{key}`")));
        }
    }
    if let Some(manual) = value.get("manual") {
        trigger.manual = manual
            .as_bool()
            .ok_or_else(|| load_error(file, "trigger.manual must be a boolean"))?;
    }
    if let Some(schedule) = value.get("schedule") {
        match schedule {
            Value::Null => {}
            Value::Str(expression) => {
                validate_cron(expression)
                    .map_err(|reason| load_error(file, format!("invalid cron: {reason}")))?;
                trigger.schedule = Some(expression.clone());
            }
            _ => {
                return Err(load_error(
                    file,
                    "trigger.schedule must be a cron string or null",
                ));
            }
        }
    }
    if let Some(on) = value.get("on") {
        match on {
            Value::Null => {}
            _ => {
                return Err(load_error(
                    file,
                    "triggered skills (`trigger.on`) are Phase 1",
                ));
            }
        }
    }
    if trigger.schedule.is_some() {
        for tool in effective_tools {
            let read_only = tool_map::lookup(tool)
                .map(|info| info.is_read_only())
                .unwrap_or(false);
            if !read_only {
                return Err(load_error(
                    file,
                    format!(
                        "`trigger.schedule` is only allowed when every tool is read-only (found `{tool}`)"
                    ),
                ));
            }
        }
    }
    Ok(trigger)
}

/// Whether `name` is an identifier-like skill input name,
/// `^[a-z][a-z0-9_]{0,63}$`.
///
/// An input name is emitted as a JSON Schema property key and reaches the
/// provider as tool metadata, so it must not be able to carry personal data
/// (an e-mail address or a phone number, for instance). The loader rejects
/// anything outside this shape.
fn is_valid_input_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= 64
        && first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn parse_inputs(meta: &Value, file: &str) -> Result<Vec<SkillInput>, SkillLoadError> {
    let Some(value) = meta.get("inputs") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let entries = value
        .as_map()
        .ok_or_else(|| load_error(file, "`inputs` must be a mapping"))?;
    let mut inputs = Vec::new();
    for (name, input) in entries {
        if !is_valid_input_name(name) {
            return Err(load_error(
                file,
                format!("input `{name}` is not a valid name: use `^[a-z][a-z0-9_]{{0,63}}$`"),
            ));
        }
        let fields = input
            .as_map()
            .ok_or_else(|| load_error(file, format!("input `{name}` must be a mapping")))?;
        for (key, _) in fields {
            if !["tier", "type", "default", "from"].contains(&key.as_str()) {
                return Err(load_error(
                    file,
                    format!("input `{name}` has unknown key `{key}`"),
                ));
            }
        }
        let tier = match input.get("tier") {
            None | Some(Value::Null) => None,
            Some(Value::Str(value)) => Some(Tier::parse(value).ok_or_else(|| {
                load_error(file, format!("input `{name}` has unknown tier `{value}`"))
            })?),
            Some(_) => {
                return Err(load_error(
                    file,
                    format!("input `{name}` tier must be C, H or N"),
                ));
            }
        };
        let value_type = match input.get("type") {
            None | Some(Value::Null) => ValueType::String,
            Some(Value::Str(value)) => ValueType::parse(value).ok_or_else(|| {
                load_error(file, format!("input `{name}` has unknown type `{value}`"))
            })?,
            Some(_) => {
                return Err(load_error(
                    file,
                    format!("input `{name}` type must be a string"),
                ));
            }
        };
        let default = match input.get("default") {
            None | Some(Value::Null) => None,
            Some(Value::Str(value)) => Some(value.clone()),
            Some(Value::Int(value)) => Some(value.to_string()),
            Some(Value::Float(value)) => Some(value.to_string()),
            Some(Value::Bool(value)) => Some(value.to_string()),
            Some(_) => {
                return Err(load_error(
                    file,
                    format!("input `{name}` default must be a scalar"),
                ));
            }
        };
        let from = match input.get("from") {
            None | Some(Value::Null) => None,
            Some(Value::Str(value)) => Some(parse_contact_source(name, value, file)?),
            Some(_) => {
                return Err(load_error(
                    file,
                    format!("input `{name}` from must be a string"),
                ));
            }
        };
        inputs.push(SkillInput {
            name: name.clone(),
            tier,
            value_type,
            default,
            from,
        });
    }
    for input in &inputs {
        let Some(source) = &input.from else {
            continue;
        };
        if input.value_type != ValueType::Email {
            return Err(load_error(
                file,
                format!(
                    "input `{}` from is only allowed on `type: email`",
                    input.name
                ),
            ));
        }
        if source == &input.name {
            return Err(load_error(
                file,
                format!("input `{}` from names itself", input.name),
            ));
        }
        let Some(source_input) = inputs.iter().find(|candidate| &candidate.name == source) else {
            return Err(load_error(
                file,
                format!("input `{}` from names unknown input `{source}`", input.name),
            ));
        };
        if source_input.tier != Some(Tier::H) {
            return Err(load_error(
                file,
                format!(
                    "input `{}` from names `{source}`, which is not tier H",
                    input.name
                ),
            ));
        }
        if source_input.from.is_some() {
            return Err(load_error(
                file,
                format!("input `{}` from names derived input `{source}`", input.name),
            ));
        }
    }
    Ok(inputs)
}

/// Parse the only accepted derivation form, `contact(<slot>)`, returning the
/// input name it references (`docs/phase1.md` §7). Any other form is a load
/// error.
fn parse_contact_source(name: &str, value: &str, file: &str) -> Result<String, SkillLoadError> {
    let slot = value
        .strip_prefix("contact(")
        .and_then(|rest| rest.strip_suffix(')'))
        .filter(|slot| {
            !slot.is_empty()
                && !slot
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch == '(' || ch == ')')
        });
    slot.map(str::to_string).ok_or_else(|| {
        load_error(
            file,
            format!("input `{name}` from must be `contact(<slot>)`"),
        )
    })
}

fn parse_recipients(meta: &Value, file: &str) -> Result<Option<RecipientPolicy>, SkillLoadError> {
    let Some(value) = meta.get("recipients") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let entries = value
        .as_map()
        .ok_or_else(|| load_error(file, "`recipients` must be a mapping"))?;
    for (key, _) in entries {
        if key != "policy" {
            return Err(load_error(file, format!("unknown recipients key `{key}`")));
        }
    }
    match value.get("policy") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(policy)) => RecipientPolicy::parse(policy)
            .map(Some)
            .ok_or_else(|| load_error(file, format!("unknown recipients.policy `{policy}`"))),
        Some(_) => Err(load_error(file, "recipients.policy must be a string")),
    }
}

fn validate_skill_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_SKILL_NAME_LEN {
        return Err(format!(
            "name must contain 1 to {MAX_SKILL_NAME_LEN} characters"
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("name may contain only lowercase letters, digits and `-`".to_string());
    }
    Ok(())
}

/// Validate a 5-field cron expression.
pub fn validate_cron(expression: &str) -> Result<(), String> {
    let fields: Vec<&str> = expression.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!("expected 5 fields, found {}", fields.len()));
    }
    let ranges: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];
    let names = ["minute", "hour", "day-of-month", "month", "day-of-week"];
    for ((field, (low, high)), name) in fields.iter().zip(ranges).zip(names) {
        validate_cron_field(field, low, high).map_err(|reason| format!("{name}: {reason}"))?;
    }
    Ok(())
}

fn validate_cron_field(field: &str, low: u32, high: u32) -> Result<(), String> {
    if field.is_empty() {
        return Err("empty field".to_string());
    }
    for part in field.split(',') {
        if part.is_empty() {
            return Err("empty list item".to_string());
        }
        let range = match part.split_once('/') {
            Some((range, step)) => {
                let step: u32 = step.parse().map_err(|_| format!("invalid step `{step}`"))?;
                if step == 0 {
                    return Err("step must be greater than zero".to_string());
                }
                range
            }
            None => part,
        };
        if range == "*" {
            continue;
        }
        let (start, end) = match range.split_once('-') {
            Some((start, end)) => {
                let start: u32 = start
                    .parse()
                    .map_err(|_| format!("invalid value `{start}`"))?;
                let end: u32 = end.parse().map_err(|_| format!("invalid value `{end}`"))?;
                if start > end {
                    return Err(format!("reversed range `{range}`"));
                }
                (start, end)
            }
            None => {
                let value: u32 = range
                    .parse()
                    .map_err(|_| format!("invalid value `{range}`"))?;
                (value, value)
            }
        };
        if start < low || end > high {
            return Err(format!("value out of range {low}-{high}"));
        }
    }
    Ok(())
}

fn require_str(value: &Value, key: &str, file: &str) -> Result<String, SkillLoadError> {
    match value.get(key) {
        Some(Value::Str(text)) if !text.is_empty() => Ok(text.clone()),
        Some(_) => Err(load_error(
            file,
            format!("`{key}` must be a non-empty string"),
        )),
        None => Err(load_error(file, format!("missing required field `{key}`"))),
    }
}

fn string_list(value: &Value, key: &str, file: &str) -> Result<Vec<String>, SkillLoadError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::List(items)) => {
            let mut out = Vec::new();
            for item in items {
                let text = item
                    .as_str()
                    .ok_or_else(|| load_error(file, format!("`{key}` entries must be strings")))?;
                if text.is_empty() {
                    return Err(load_error(
                        file,
                        format!("`{key}` entries must not be empty"),
                    ));
                }
                out.push(text.to_string());
            }
            Ok(out)
        }
        Some(_) => Err(load_error(file, format!("`{key}` must be a sequence"))),
    }
}

fn load_error(file: &str, reason: impl Into<String>) -> SkillLoadError {
    SkillLoadError::new(file, reason)
}

/// Best-effort identity for a load error: the front-matter name/version when
/// they parse, else the file stem and `None`.
fn best_effort_identity(bytes: &[u8], stem: &str) -> (String, Option<u32>) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return (stem.to_string(), None);
    };
    let Ok((meta, _)) = frontmatter::parse(text) else {
        return (stem.to_string(), None);
    };
    let name = meta
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| stem.to_string());
    let version = match meta.get("version") {
        Some(Value::Int(version)) if *version >= 1 && *version <= u32::MAX as i64 => {
            Some(*version as u32)
        }
        _ => None,
    };
    (name, version)
}

/// Log and record one load error.
fn record_error(
    load: &mut SkillLoad,
    sink: Option<&dyn AuditSink>,
    agent: &str,
    mut error: SkillLoadError,
) {
    if error.skill_name.is_empty() {
        error.skill_name = Path::new(&error.file)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(&error.file)
            .to_string();
    }
    log_load_error(sink, agent, &error);
    load.errors.push(error);
}

fn push_error(
    load: &mut SkillLoad,
    sink: Option<&dyn AuditSink>,
    agent: &str,
    file: &str,
    reason: impl Into<String>,
) {
    record_error(load, sink, agent, load_error(file, reason));
}

fn log_load_error(sink: Option<&dyn AuditSink>, agent: &str, error: &SkillLoadError) {
    let Some(sink) = sink else {
        return;
    };
    let payload = serde_json::json!({
        "agent": agent,
        "skill_name": error.skill_name,
        "skill_version": error.skill_version,
        "skill_hash": error.skill_hash,
        "run_id": serde_json::Value::Null,
        "file": error.file,
        "reason": error.reason,
    });
    let _ = sink.log_event("skill.load_error", &payload);
}

enum ReadSkillError {
    TooLarge,
    Io(std::io::Error),
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ReadSkillError> {
    let file = fs::File::open(path).map_err(ReadSkillError::Io)?;
    let mut bytes = Vec::new();
    file.take(MAX_SKILL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(ReadSkillError::Io)?;
    if bytes.len() as u64 > MAX_SKILL_BYTES {
        return Err(ReadSkillError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(tools: &[&str]) -> LoadedAgent {
        LoadedAgent {
            name: "assistant".to_string(),
            brain: super::super::agent::Brain::Cloud,
            default_mode: super::super::agent::AgentMode::Private,
            channels: Vec::new(),
            tools: tools.iter().map(|tool| tool.to_string()).collect(),
            recipients_policy: RecipientPolicy::KnownContacts,
            recipients_allowlist: Vec::new(),
            body: String::new(),
            source: super::super::agent::AgentSource::AgentMd,
            dir: PathBuf::from("/tmp/assistant"),
        }
    }

    fn skill_text(front: &str) -> Vec<u8> {
        format!("---\n{front}---\nBody.\n").into_bytes()
    }

    const VALID: &str = "\
name: send-invite
version: 1
tools: [google.calendar.create_event, google.gmail.send]
approval: each_run
";

    #[test]
    fn parses_brain_none_and_rejects_an_unknown_brain() {
        let agent = agent(&["google.gmail.send"]);
        let skill = parse_skill(
            &skill_text("name: send-invite\nversion: 1\nbrain: none\ntools: [google.gmail.send]\napproval: each_run\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap();
        assert_eq!(skill.brain, SkillBrain::None);

        let err = parse_skill(
            &skill_text("name: send-invite\nversion: 1\nbrain: quantum\ntools: [google.gmail.send]\napproval: each_run\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("unknown brain"), "{}", err.reason);
    }

    #[test]
    fn parses_a_valid_skill() {
        let agent = agent(&["google.calendar.create_event", "google.gmail.send"]);
        let skill =
            parse_skill(&skill_text(VALID), "send-invite.md", "send-invite", &agent).unwrap();
        assert_eq!(skill.name, "send-invite");
        assert_eq!(skill.version, 1);
        assert_eq!(skill.approval, Approval::EachRun);
        assert_eq!(skill.effective_tools.len(), 2);
        assert_eq!(skill.skill_ref().version, "1");
        assert_eq!(skill.hash.len(), 64);
    }

    #[test]
    fn rejects_unknown_tool_missing_field_and_unknown_key() {
        let agent = agent(&["google.gmail.send"]);
        let err = parse_skill(
            &skill_text("name: send-invite\nversion: 1\ntools: [google.gmail.archive]\napproval: each_run\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("unknown tool"));

        let err = parse_skill(
            &skill_text("name: send-invite\ntools: [google.gmail.send]\napproval: each_run\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("missing required field `version`"));

        let err = parse_skill(
            &skill_text("name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\nmystery: 1\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("unknown front-matter key `mystery`"));
    }

    #[test]
    fn rejects_a_version_above_u32_max() {
        let agent = agent(&["google.gmail.send"]);
        let err = parse_skill(
            &skill_text(
                "name: send-invite\nversion: 4294967296\ntools: [google.gmail.send]\napproval: each_run\n",
            ),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("4294967295"), "{}", err.reason);
    }

    #[test]
    fn rejects_a_tool_outside_the_agents_tools() {
        let agent = agent(&["google.gmail.search"]);
        let err =
            parse_skill(&skill_text(VALID), "send-invite.md", "send-invite", &agent).unwrap_err();
        assert!(err.reason.contains("not in the agent's tools"));
    }

    #[test]
    fn rejects_bad_cron_and_schedule_on_a_write_tool() {
        let agent = agent(&["google.gmail.search", "google.gmail.send"]);
        let err = parse_skill(
            &skill_text("name: brief\nversion: 1\ntools: [google.gmail.search]\napproval: each_run\ntrigger:\n  schedule: \"61 * * * *\"\n"),
            "brief.md",
            "brief",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("invalid cron"));

        let err = parse_skill(
            &skill_text("name: brief\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ntrigger:\n  schedule: \"0 8 * * *\"\n"),
            "brief.md",
            "brief",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("read-only"));
    }

    #[test]
    fn rejects_phase_one_approval_and_trigger() {
        let agent = agent(&["google.gmail.send"]);
        let err = parse_skill(
            &skill_text("name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: once_per_recipient\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("Phase 1"));

        let err = parse_skill(
            &skill_text("name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ntrigger:\n  on: email.received\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("Phase 1"));
    }

    #[test]
    fn rejects_unknown_input_tier_or_type() {
        let agent = agent(&["google.gmail.send"]);
        let err = parse_skill(
            &skill_text("name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ninputs:\n  person: { tier: X }\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("unknown tier"));

        let err = parse_skill(
            &skill_text("name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ninputs:\n  when: { type: date }\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap_err();
        assert!(err.reason.contains("unknown type"));
    }

    #[test]
    fn rejects_name_that_does_not_match_the_stem() {
        let agent = agent(&["google.gmail.send"]);
        let err = parse_skill(&skill_text(VALID), "other.md", "other", &agent).unwrap_err();
        assert!(err.reason.contains("does not match the file stem"));
    }

    #[test]
    fn parses_a_contact_derived_email_input() {
        let agent = agent(&["google.gmail.send"]);
        let skill = parse_skill(
            &skill_text("name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ninputs:\n  person: { tier: H }\n  email: { type: email, tier: C, from: contact(person) }\n"),
            "send-invite.md",
            "send-invite",
            &agent,
        )
        .unwrap();
        let email = skill
            .inputs
            .iter()
            .find(|input| input.name == "email")
            .unwrap();
        assert_eq!(email.from.as_deref(), Some("person"));
        let person = skill
            .inputs
            .iter()
            .find(|input| input.name == "person")
            .unwrap();
        assert_eq!(person.from, None);
    }

    #[test]
    fn rejects_bad_contact_derivations() {
        let agent = agent(&["google.gmail.send"]);
        let reason = |inputs: &str| {
            parse_skill(
                &skill_text(&format!(
                    "name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ninputs:\n{inputs}"
                )),
                "send-invite.md",
                "send-invite",
                &agent,
            )
            .unwrap_err()
            .reason
        };

        let unknown = reason(
            "  person: { tier: H }\n  email: { type: email, tier: C, from: contact(missing) }\n",
        );
        assert!(unknown.contains("unknown input"), "{unknown}");

        let not_high = reason(
            "  person: { tier: C }\n  email: { type: email, tier: C, from: contact(person) }\n",
        );
        assert!(not_high.contains("not tier H"), "{not_high}");

        let not_email = reason("  person: { tier: H }\n  email: { from: contact(person) }\n");
        assert!(not_email.contains("only allowed on"), "{not_email}");

        let bad_form = reason("  person: { tier: H }\n  email: { type: email, from: person }\n");
        assert!(bad_form.contains("must be `contact(<slot>)`"), "{bad_form}");

        let empty = reason("  person: { tier: H }\n  email: { type: email, from: contact() }\n");
        assert!(empty.contains("must be `contact(<slot>)`"), "{empty}");

        let non_string = reason("  person: { tier: H }\n  email: { type: email, from: 3 }\n");
        assert!(non_string.contains("from must be a string"), "{non_string}");

        let itself = reason("  email: { type: email, tier: H, from: contact(email) }\n");
        assert!(itself.contains("names itself"), "{itself}");

        let derived_source = reason(
            "  person: { tier: H }\n  email: { type: email, tier: H, from: contact(person) }\n  other: { type: email, tier: C, from: contact(email) }\n",
        );
        assert!(
            derived_source.contains("names derived input"),
            "{derived_source}"
        );
    }

    #[test]
    fn rejects_an_input_name_that_is_not_identifier_like() {
        let agent = agent(&["google.gmail.send"]);
        let reason = |name: &str| {
            parse_skill(
                &skill_text(&format!(
                    "name: send-invite\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ninputs:\n  {name}: {{ tier: H }}\n"
                )),
                "send-invite.md",
                "send-invite",
                &agent,
            )
            .unwrap_err()
        };

        // An e-mail address as a key is the case the loader must stop: it would
        // otherwise reach a provider as a JSON Schema property name.
        let email = reason("owner@example.com");
        assert_eq!(email.file, "send-invite.md");
        assert!(
            email.reason.contains("owner@example.com"),
            "{}",
            email.reason
        );
        assert!(email.reason.contains("valid name"), "{}", email.reason);

        let upper = reason("Owner");
        assert!(upper.reason.contains("valid name"), "{}", upper.reason);

        let long = reason(&"a".repeat(65));
        assert!(long.reason.contains("valid name"), "{}", long.reason);
    }

    #[test]
    fn cron_validator_accepts_the_contract_forms() {
        assert!(validate_cron("0 8 * * *").is_ok());
        assert!(validate_cron("*/15 0-23 1,15 * 0-7").is_ok());
        assert!(validate_cron("0 8 * *").is_err());
        assert!(validate_cron("60 8 * * *").is_err());
        assert!(validate_cron("0 8 * * mon").is_err());
        assert!(validate_cron("*/0 8 * * *").is_err());
    }
}
