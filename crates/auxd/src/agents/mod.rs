//! The agent registry (D33, WO E0): the chief and the four domain agents.
//!
//! Each agent is a named bundle of a role, a glyph, a brain, a skills list and
//! grants over its own directory `<home>/agents/<id>/`. The registry is seeded
//! from config: the built-in seed below, overridden whole by
//! `<home>/agents.toml` when that file exists. Both the seed file and each
//! agent's `grants.toml` are parsed with `deny_unknown_fields`, so a typo is an
//! error the owner sees rather than a silently dropped grant.
//!
//! Grants are a **ceiling**: [`crate::api::turn`] turns each refusal into a
//! per-agent broker `Deny`, so a tool outside the agent's `do` list never runs.
//! Memory is one JSON array per agent in its own directory; the endpoints read
//! and forget items, and a missing file is simply empty memory.

use std::path::{Path, PathBuf};

use aux_runtime::grants::{
    AccessLevel, ActionLevel, AgentGrants, DoGrant, SeeGrant, CHIEF_AGENT, DOMAIN_AGENTS,
    LEGACY_CHIEF,
};
use kernel_core::SandboxHome;
use serde::{Deserialize, Serialize};

/// Refuse to read a seed/grants/memory file larger than this.
const MAX_REGISTRY_FILE_BYTES: u64 = 256 * 1024;

/// `chief` or `domain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    /// The owner's only contact.
    Chief,
    /// One of the four domains.
    Domain,
}

impl AgentRole {
    /// Stable lowercase label for the API.
    pub fn as_str(self) -> &'static str {
        match self {
            AgentRole::Chief => "chief",
            AgentRole::Domain => "domain",
        }
    }
}

/// Provider + model an agent runs with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrainRef {
    /// Provider id from `[[providers]]`.
    #[serde(default)]
    pub provider: Option<String>,
    /// Model id for that provider.
    #[serde(default)]
    pub model: Option<String>,
}

impl BrainRef {
    /// `provider/model`, or just one of them.
    pub fn label(&self) -> Option<String> {
        match (&self.provider, &self.model) {
            (Some(provider), Some(model)) => Some(format!("{provider}/{model}")),
            (Some(provider), None) => Some(provider.clone()),
            (None, Some(model)) => Some(model.clone()),
            (None, None) => None,
        }
    }
}

/// One seeded agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDef {
    /// Directory-safe id (`aux`, `mail`, …).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Chief or domain.
    pub role: AgentRole,
    /// Glyph id the app draws.
    pub glyph: String,
    /// Provider + model.
    pub brain: BrainRef,
    /// Local instruction skills.
    pub skills: Vec<String>,
    /// What it may see and do.
    pub grants: AgentGrants,
}

/// A memory item saved by an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryItem {
    /// Stable item id (`mem-<millis>-<seq>`).
    pub id: String,
    /// The rule or fact text.
    pub text: String,
    /// UTC timestamp (`YYYY-MM-DD HH:MM:SS`).
    pub saved_at: String,
}

/// Why the registry could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A filesystem operation failed.
    #[error("{0}")]
    Io(String),
    /// A seed/grants/memory file exists but cannot be parsed (fail closed).
    #[error("the agent registry file is unreadable: {0}")]
    Config(String),
    /// The id is not one of the seeded agents.
    #[error("no such agent `{0}`")]
    UnknownAgent(String),
    /// The proposed permissions exceed the chief's ceiling.
    #[error("the agent would have access beyond the chief")]
    ExceedsChief,
    /// The grants changed since the proposal was made.
    #[error("the grants changed since this change was proposed")]
    GrantsChanged,
}

/// `agents.toml`: the whole seed, strict.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedFile {
    agents: Vec<SeedAgent>,
}

/// One `[[agents]]` entry, strict.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedAgent {
    id: String,
    name: String,
    role: AgentRole,
    glyph: String,
    #[serde(default)]
    brain: BrainRef,
    #[serde(default)]
    skills: Vec<String>,
    #[serde(default)]
    grants: Option<GrantsFile>,
}

/// `grants.toml` and the seed's `[agents.grants]`, strict.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsFile {
    #[serde(default)]
    see: Vec<SeeFile>,
    #[serde(rename = "do", default)]
    can_do: Vec<DoFile>,
    #[serde(default)]
    never: Vec<String>,
    #[serde(default)]
    egress_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeeFile {
    scope: String,
    via: String,
    level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DoFile {
    skill: String,
    level: String,
}

/// The memory file wrapper.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryFile {
    #[serde(default)]
    items: Vec<MemoryItem>,
}

impl From<&AgentGrants> for GrantsFile {
    fn from(grants: &AgentGrants) -> Self {
        Self {
            see: grants
                .see
                .iter()
                .map(|grant| SeeFile {
                    scope: grant.scope.clone(),
                    via: grant.via.clone(),
                    level: grant.level.as_str().to_string(),
                })
                .collect(),
            can_do: grants
                .can_do
                .iter()
                .map(|grant| DoFile {
                    skill: grant.skill.clone(),
                    level: grant.level.as_str().to_string(),
                })
                .collect(),
            never: grants.never.clone(),
            egress_note: grants.egress_note.clone(),
        }
    }
}

impl From<GrantsFile> for AgentGrants {
    fn from(file: GrantsFile) -> Self {
        Self {
            see: file
                .see
                .into_iter()
                .map(|grant| SeeGrant {
                    scope: grant.scope,
                    via: grant.via,
                    level: AccessLevel::parse(&grant.level),
                })
                .collect(),
            can_do: file
                .can_do
                .into_iter()
                .map(|grant| DoGrant {
                    skill: grant.skill,
                    level: ActionLevel::parse(&grant.level),
                })
                .collect(),
            never: file.never,
            egress_note: file.egress_note,
        }
    }
}

/// The seed file path.
pub fn seed_path(home: &Path) -> PathBuf {
    home.join("agents.toml")
}

/// The built-in seed: the chief alone. Mail, Calendar, Clients and Documents
/// are templates the owner creates agents from.
pub fn built_in_seed() -> Vec<AgentDef> {
    vec![AgentDef {
        id: CHIEF_AGENT.to_string(),
        name: "Aux".to_string(),
        role: AgentRole::Chief,
        glyph: "aux".to_string(),
        brain: BrainRef::default(),
        skills: Vec::new(),
        grants: aux_runtime::grants::default_grants(CHIEF_AGENT)
            .expect("the seeded chief has grants"),
    }]
}

/// A starter template: the domain's shipped name, glyph, grants and files.
pub fn template(id: &str) -> Option<AgentDef> {
    let (name, glyph) = match id {
        "mail" => ("Mail", "envelope"),
        "calendar" => ("Calendar", "calendar"),
        "clients" => ("Clients", "people"),
        "documents" => ("Documents", "receipt"),
        _ => return None,
    };
    Some(AgentDef {
        id: id.to_string(),
        name: name.to_string(),
        role: AgentRole::Domain,
        glyph: glyph.to_string(),
        brain: BrainRef::default(),
        skills: Vec::new(),
        grants: aux_runtime::grants::default_grants(id)?,
    })
}

/// Load the seed: `agents.toml` when present (strict), else the built-in five.
pub fn seed(home: &Path) -> Result<Vec<AgentDef>, RegistryError> {
    seed_for(home, chief_id(home))
}

/// [`seed`] for a chief already read from the config.
fn seed_for(home: &Path, chief: &'static str) -> Result<Vec<AgentDef>, RegistryError> {
    let path = seed_path(home);
    let text = match read_private(home, Path::new("agents.toml")) {
        Ok(Some(text)) => text,
        Ok(None) => {
            let mut agents = built_in_seed();
            // An older install keeps its chief, `aux`, and its four domain
            // agents exactly as before. Elsewhere a domain agent exists once
            // it was created from its template (or an older daemon made it).
            let legacy = chief == LEGACY_CHIEF;
            if legacy {
                agents[0].id = LEGACY_CHIEF.to_string();
                agents[0].grants = aux_runtime::grants::default_grants(LEGACY_CHIEF)
                    .expect("the legacy chief has grants");
            }
            let domains = DOMAIN_AGENTS.into_iter();
            let present = domains.filter(|id| legacy || crate::agent::exists(home, id));
            agents.extend(present.filter_map(template));
            return Ok(agents);
        }
        Err(err) => return Err(err),
    };
    let _ = path;
    let parsed: SeedFile =
        toml::from_str(&text).map_err(|err| redacted(&err, "agents.toml", &text))?;
    if parsed.agents.is_empty() {
        return Err(RegistryError::Config(
            "agents.toml lists no agents; the five seeded agents must stay".to_string(),
        ));
    }
    Ok(parsed
        .agents
        .into_iter()
        .map(|seed| AgentDef {
            id: seed.id,
            name: seed.name,
            role: seed.role,
            glyph: seed.glyph,
            brain: seed.brain,
            skills: seed.skills,
            grants: seed
                .grants
                .map(AgentGrants::from)
                .unwrap_or_else(|| AgentGrants {
                    see: Vec::new(),
                    can_do: Vec::new(),
                    never: Vec::new(),
                    egress_note: String::new(),
                }),
        })
        .collect())
}

/// The full registry: the seed with each agent's `grants.toml` overlaid.
/// No agent ever holds more than the chief: one that would (a template agent
/// whose directory was made by hand, with the chief lowered) is capped.
pub fn registry(home: &Path) -> Result<Vec<AgentDef>, RegistryError> {
    let chief = chief_id(home);
    let mut agents = seed_for(home, chief)?;
    for agent in &mut agents {
        if let Some(grants) = read_agent_grants(home, &agent.id)? {
            agent.grants = grants;
        }
    }
    // Each ceiling as listed, before any cap. `main` is never capped here:
    // its grants are the cap the other agents keep (on an older install, the
    // four domain agents too); the run-time ceiling still holds it under the
    // chief `aux` there.
    let caps: Vec<(&str, AgentGrants)> = [CHIEF_AGENT, chief]
        .into_iter()
        .map(|id| (id, ceiling_grants(&agents, id)))
        .collect();
    for agent in &mut agents {
        if agent.id == CHIEF_AGENT {
            continue;
        }
        let over: Vec<&AgentGrants> = ceilings_for(chief, &agent.id)
            .into_iter()
            .filter_map(|id| caps.iter().find(|(cap, _)| *cap == id))
            .map(|(_, grants)| grants)
            .collect();
        if over.iter().all(|cap| subset(&agent.grants, cap)) {
            continue;
        }
        let capped = clamp_all(&agent.grants, &over);
        log_capped(&agent.id, &cut(&agent.grants, &capped));
        agent.grants = capped;
    }
    Ok(agents)
}

/// The names of the grants `capped` lowers or drops from `grants`, and of
/// the chief `never`s it adds.
fn cut(grants: &AgentGrants, capped: &AgentGrants) -> Vec<String> {
    let see = grants.see.iter().filter(|grant| {
        !capped
            .see
            .iter()
            .any(|c| c.scope == grant.scope && c.level == grant.level)
    });
    let can_do = grants.can_do.iter().filter(|grant| {
        !capped
            .can_do
            .iter()
            .any(|c| c.skill == grant.skill && c.level == grant.level)
    });
    let never = capped.never.iter().filter(|n| !grants.never.contains(n));
    see.map(|grant| grant.scope.clone())
        .chain(can_do.map(|grant| grant.skill.clone()))
        .chain(never.cloned())
        .collect()
}

/// One warning per agent and capped set, never repeated: the agent id and
/// the grant or tool names only, never a level, a note or any content.
pub(crate) fn log_capped(agent: &str, names: &[String]) {
    static SEEN: std::sync::Mutex<std::collections::BTreeSet<String>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let names = names.join(",");
    if kernel_core::lock_recover(&SEEN).insert(format!("{agent}\n{names}")) {
        tracing::warn!(agent, grants = %names, "agent access capped at the chief");
    }
}

/// `grants` capped at each ceiling in turn. If that still exceeds one of
/// them, only their `never`s remain.
fn clamp_all(grants: &AgentGrants, caps: &[&AgentGrants]) -> AgentGrants {
    let mut out = grants.clone();
    for cap in caps {
        out = clamp(&out, cap);
    }
    if caps.iter().all(|cap| subset(&out, cap)) {
        return out;
    }
    let mut never: Vec<String> = Vec::new();
    for denied in caps.iter().flat_map(|cap| &cap.never) {
        if !never.contains(denied) {
            never.push(denied.clone());
        }
    }
    AgentGrants {
        see: Vec::new(),
        can_do: Vec::new(),
        never,
        egress_note: grants.egress_note.clone(),
    }
}

/// `grants` capped at `chief`: each level at most the chief's, each chief
/// skill below `auto` that `grants` lacks pinned `off`, every chief `never`
/// kept. If that still exceeds the chief, only the chief's `never`s remain.
fn clamp(grants: &AgentGrants, chief: &AgentGrants) -> AgentGrants {
    let see = |level| match level {
        AccessLevel::Off => 0,
        AccessLevel::Ask => 1,
        AccessLevel::Read => 2,
    };
    let act = |level| match level {
        ActionLevel::Off => 0,
        ActionLevel::Ask => 1,
        ActionLevel::Auto => 2,
    };
    let mut out = grants.clone();
    // A display-only row decides no read, so it never exceeds the chief.
    for grant in out.see.iter_mut().filter(|grant| !grant.is_display_only()) {
        let own = chief.see.iter().filter(|own| own.scope == grant.scope);
        let max = own.map(|own| own.level).min_by_key(|level| see(*level));
        let max = max.unwrap_or(AccessLevel::Off);
        if see(grant.level) > see(max) {
            grant.level = max;
        }
    }
    for grant in &mut out.can_do {
        // `granted_level`: a chief that reads the calendar also holds its
        // free times (`calendar.freebusy`).
        let max = chief.granted_level(&grant.skill);
        let max = max.unwrap_or(ActionLevel::Off);
        if act(grant.level) > act(max) {
            grant.level = max;
        }
    }
    for own in &chief.can_do {
        if own.level != ActionLevel::Auto && !out.can_do.iter().any(|g| g.skill == own.skill) {
            out.can_do.push(aux_runtime::grants::DoGrant {
                skill: own.skill.clone(),
                level: ActionLevel::Off,
            });
        }
    }
    for denied in &chief.never {
        if !out.never.contains(denied) {
            out.never.push(denied.clone());
        }
    }
    if subset(&out, chief) {
        return out;
    }
    AgentGrants {
        see: Vec::new(),
        can_do: Vec::new(),
        never: chief.never.clone(),
        egress_note: grants.egress_note.clone(),
    }
}

/// One agent's definition, or `None`.
pub fn definition(home: &Path, id: &str) -> Result<Option<AgentDef>, RegistryError> {
    Ok(registry(home)?.into_iter().find(|agent| agent.id == id))
}

/// The chief: `aux` when `config.toml` names it (older installs; also the
/// kernel default and an unreadable config), else `main`. A home with no
/// config yet is a fresh install: `main`. No side effects.
pub fn chief_id(home: &Path) -> &'static str {
    #[derive(Deserialize)]
    struct Head {
        #[serde(alias = "default_dot")]
        default_agent: Option<String>,
    }
    let named = match read_private(home, Path::new("config.toml")) {
        Ok(Some(text)) => toml::from_str::<Head>(&text)
            .ok()
            .map(|head| head.default_agent),
        Ok(None) => Some(Some(CHIEF_AGENT.to_string())),
        Err(_) => None,
    };
    let fallback = || kernel_core::Config::default().default_agent;
    match named.map(|name| name.unwrap_or_else(fallback)) {
        Some(name) if name != LEGACY_CHIEF => CHIEF_AGENT,
        _ => LEGACY_CHIEF,
    }
}

/// The agents whose grants, tools lists and owner rules cap `agent`; none
/// for the chief itself.
///
/// Every other agent stays under `main`, the shipped ceiling, as before. On
/// an older install the chief is `aux`, so an added agent stays under `aux`
/// too: it never gets a tool its actual chief lacks. The four domain agents
/// `aux` hands work to keep their shipped access there.
pub fn ceilings(home: &Path, agent: &str) -> Vec<&'static str> {
    ceilings_for(chief_id(home), agent)
}

/// [`ceilings`] for a chief already read from the config.
fn ceilings_for(chief: &'static str, agent: &str) -> Vec<&'static str> {
    let mut ids = Vec::new();
    if agent == chief {
        return ids;
    }
    if agent != CHIEF_AGENT {
        ids.push(CHIEF_AGENT);
    }
    if chief != CHIEF_AGENT && !DOMAIN_AGENTS.contains(&agent) {
        ids.push(chief);
    }
    ids
}

/// The grants of one ceiling: its entry in `agents`, or its shipped grants
/// when this home does not list it. An id with neither has no scoped access.
pub fn ceiling_grants(agents: &[AgentDef], id: &str) -> AgentGrants {
    agents
        .iter()
        .find(|agent| agent.id == id)
        .map(|agent| agent.grants.clone())
        .or_else(|| aux_runtime::grants::default_grants(id))
        .unwrap_or_else(|| AgentGrants {
            see: Vec::new(),
            can_do: Vec::new(),
            never: Vec::new(),
            egress_note: String::new(),
        })
}

/// One agent's grants: the seed, overlaid by `agents/<id>/grants.toml`.
pub fn grants(home: &Path, id: &str) -> Result<AgentGrants, RegistryError> {
    let def = definition(home, id)?.ok_or_else(|| RegistryError::UnknownAgent(id.to_string()))?;
    Ok(def.grants)
}

/// The files a built-in agent ships with, by agent and path under its
/// directory (CAL-AGENT-INSTALL, M4-3a, M4-3b, M5-5). The send-invite and
/// collect-receipts skills are the exact files the hero tests run, so the
/// shipped bytes are the tested bytes.
const SHIPPED_FILES: [(&str, &str, &str); 9] = [
    ("calendar", "agent.md", include_str!("calendar/agent.md")),
    (
        "calendar",
        "skills/move-event.md",
        include_str!("calendar/skills/move-event.md"),
    ),
    (
        "calendar",
        "skills/send-invite.md",
        include_str!("../../../aux-runtime/src/skills/fixtures/skills/send-invite.md"),
    ),
    ("mail", "agent.md", include_str!("mail/agent.md")),
    (
        "mail",
        "skills/follow-up.md",
        include_str!("mail/skills/follow-up.md"),
    ),
    (
        "mail",
        "skills/reply-availability.md",
        include_str!("mail/skills/reply-availability.md"),
    ),
    (
        "mail",
        "skills/send-draft.md",
        include_str!("mail/skills/send-draft.md"),
    ),
    ("documents", "agent.md", include_str!("documents/agent.md")),
    (
        "documents",
        "skills/collect-receipts.md",
        include_str!("../../../aux-runtime/src/skills/fixtures/skills/collect-receipts.md"),
    ),
];

/// The tools a template's shipped `agent.md` lists, read before any file is
/// written, so a create the chief ceiling refuses leaves nothing behind.
pub(crate) fn shipped_tools(id: &str) -> Vec<String> {
    let text = SHIPPED_FILES
        .iter()
        .find(|(agent, file, _)| *agent == id && *file == "agent.md")
        .map(|(_, _, text)| *text);
    let meta = text.and_then(|text| aux_runtime::skills::frontmatter::parse(text).ok());
    let items = meta
        .as_ref()
        .and_then(|(meta, _)| meta.get("tools")?.as_list());
    let names = items.into_iter().flatten().filter_map(|item| item.as_str());
    names.map(str::to_string).collect()
}

/// True when `name` is a skill shipped inside `agent`'s directory.
pub(crate) fn is_shipped_skill(agent: &str, name: &str) -> bool {
    SHIPPED_FILES.iter().any(|(shipped_agent, file, _)| {
        (*shipped_agent == agent || agent == CHIEF_AGENT)
            && file
                .strip_prefix("skills/")
                .and_then(|file| file.strip_suffix(".md"))
                == Some(name)
    })
}

/// The versions of a shipped file that were shipped before the current one:
/// `(agent, file, hash)` per older version.
///
/// A file on disk that matches one of these hashes is an old shipped version,
/// not an owner edit: it is updated to the current shipped text, so a new
/// daemon reaches an owner who never touched the file. A file that matches
/// none of them was edited by the owner and is kept byte-identical.
///
/// The hash is the first 16 hex characters of the BLAKE3 of the shipped bytes.
/// Every shipped file that changes adds its old hash here before that change
/// merges (one PR), with a test that the old bytes are updated; a file shipped
/// without its old hash would read as an owner edit and stay old for good.
const PAST_SHIPPED_HASHES: [(&str, &str, &str); 11] = [
    ("calendar", "agent.md", "eae3a046eee2a171"),
    ("calendar", "agent.md", "2a4d1d80176dc3b7"),
    ("mail", "agent.md", "2546a133a8b8cdec"),
    ("mail", "agent.md", "b255a6a7a44afd92"),
    ("mail", "agent.md", "53b8436b4290542c"),
    ("documents", "agent.md", "adf17956714da82c"),
    ("calendar", "skills/send-invite.md", "7dbc5035db053257"),
    ("mail", "skills/follow-up.md", "f48e1767c6ec0e33"),
    (
        "documents",
        "skills/collect-receipts.md",
        "312443cd825ff10c",
    ),
    (
        "documents",
        "skills/collect-receipts.md",
        "ec9cc16235cc1f1d",
    ),
    (
        "documents",
        "skills/collect-receipts.md",
        "7bc7d0414b3f4716",
    ),
];

/// True when the bytes on disk are a version of this shipped file that was
/// shipped before the current one.
fn is_past_shipped_version(agent: &str, file: &str, bytes: &[u8]) -> bool {
    let hex = blake3::hash(bytes).to_hex();
    let hash = &hex[..16];
    PAST_SHIPPED_HASHES
        .iter()
        .any(|(a, f, h)| *a == agent && *f == file && *h == hash)
}

/// Add each shipped file a built-in agent is missing, at daemon start, and
/// return the paths added (relative to the home). A file that exists is never
/// rewritten, whatever it holds: the owner's edits stay byte-identical. An
/// agent the registry does not list gets nothing, so the files can never
/// create an agent. Writes are `O_EXCL|O_NOFOLLOW` on the verified home.
///
/// The one exception is a file that still holds an older *shipped* version
/// ([`PAST_SHIPPED_HASHES`]): the owner never edited it, so it is updated to
/// the current shipped text. A file the owner edited is kept, and the log
/// says so.
pub fn install_shipped_files(home: &Path) -> Result<Vec<PathBuf>, RegistryError> {
    install_shipped_files_for(home, None)
}

/// [`install_shipped_files`] for one agent only (`Some(id)`), as at creation.
/// The `main` chief, once its directory exists, also gets every shipped skill.
pub fn install_shipped_files_for(
    home: &Path,
    only: Option<&str>,
) -> Result<Vec<PathBuf>, RegistryError> {
    let agents = registry(home)?;
    let handle = SandboxHome::open(home).map_err(|err| RegistryError::Io(err.to_string()))?;
    let mut added = Vec::new();
    let chief_skills = SHIPPED_FILES
        .into_iter()
        .filter(|(_, file, _)| file.starts_with("skills/"))
        .map(|(from, file, text)| (CHIEF_AGENT, from, file, text));
    let all = SHIPPED_FILES
        .into_iter()
        .map(|(agent, file, text)| (agent, agent, file, text));
    for (agent, from, file, text) in all.chain(chief_skills) {
        let skip_chief = agent == CHIEF_AGENT && !crate::agent::exists(home, CHIEF_AGENT);
        if only.is_some_and(|only| only != agent)
            || skip_chief
            || !agents.iter().any(|def| def.id == agent)
        {
            continue;
        }
        let rel = Path::new("agents").join(agent).join(file);
        if let Some(parent) = rel.parent() {
            handle
                .create_dir_all(parent)
                .map_err(|err| RegistryError::Io(err.to_string()))?;
            // A directory that already existed keeps its mode, so
            // a 0777 `agents/mail/skills` stayed writable by anyone. Each directory
            // the shipped files live in is owner-only, or the install stops.
            let mut dir = Path::new("agents").join(agent);
            owner_only_dir(handle.path(), &dir)?;
            for part in parent
                .strip_prefix(&dir)
                .into_iter()
                .flat_map(Path::components)
            {
                dir.push(part);
                owner_only_dir(handle.path(), &dir)?;
            }
        }
        let created = handle
            .write_new(&rel, text.as_bytes(), 0o600)
            .map_err(|err| RegistryError::Io(format!("writing {}: {err}", rel.display())))?;
        if created {
            added.push(rel);
            continue;
        }
        let Some(on_disk) = read_private(home, &rel).ok().flatten() else {
            continue;
        };
        if on_disk == text {
            continue;
        }
        if is_past_shipped_version(from, file, on_disk.as_bytes()) {
            handle
                .write_atomic(&rel, text.as_bytes(), 0o600)
                .map_err(|err| RegistryError::Io(format!("writing {}: {err}", rel.display())))?;
            tracing::info!(
                agent,
                file,
                "updated a shipped agent file to the current version"
            );
            continue;
        }
        tracing::info!(
            agent,
            file,
            "kept the owner's version of a shipped agent file"
        );
    }
    Ok(added)
}

/// Make `rel` (a real directory, never a symlink) `0700`; refuse anything else.
fn owner_only_dir(home: &Path, rel: &Path) -> Result<(), RegistryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = home.join(rel);
        let fail = |what: String| RegistryError::Io(format!("{}: {what}", rel.display()));
        let meta = std::fs::symlink_metadata(&path).map_err(|err| fail(err.to_string()))?;
        if !meta.file_type().is_dir() {
            return Err(fail("not a directory".to_string()));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|err| fail(err.to_string()))?;
        }
    }
    Ok(())
}

fn grants_rel(id: &str) -> PathBuf {
    Path::new("agents").join(id).join("grants.toml")
}

fn memory_rel(id: &str) -> PathBuf {
    Path::new("agents").join(id).join("memory.json")
}

fn read_agent_grants(home: &Path, id: &str) -> Result<Option<AgentGrants>, RegistryError> {
    let Some(text) = read_private(home, &grants_rel(id))? else {
        return Ok(None);
    };
    let file: GrantsFile = toml::from_str(&text)
        .map_err(|err| redacted(&err, &format!("agents/{id}/grants.toml"), &text))?;
    Ok(Some(AgentGrants::from(file)))
}

/// One agent's grants as its own `grants.toml` (or the seed) says, before
/// any chief cap, or why that file cannot be used (READS-6, words per
/// READS-7/8). The file is read once; `Err` exactly when [`read_agent_grants`]
/// fails. `Ok(None)`: no file and not seeded.
pub(crate) fn uncapped_grants(
    home: &Path,
    id: &str,
) -> Result<Option<AgentGrants>, aux_runtime::executor::FileFault> {
    use aux_runtime::executor::FileFault;
    match read_private(home, &grants_rel(id)) {
        Ok(Some(text)) => toml::from_str::<GrantsFile>(&text)
            .map(|file| Some(AgentGrants::from(file)))
            .map_err(|_| FileFault::Parse),
        Ok(None) => Ok(seed_for(home, chief_id(home)).ok().and_then(|seed| {
            seed.into_iter()
                .find(|agent| agent.id == id)
                .map(|agent| agent.grants)
        })),
        Err(_) => Err(unreadable_fault(&home.join(grants_rel(id)))),
    }
}

/// Why a grants file that failed to open or read cannot be used: a symlink
/// (never followed), over the size limit, a mode that refuses reading, or
/// something else (not UTF-8, I/O error).
fn unreadable_fault(path: &Path) -> aux_runtime::executor::FileFault {
    use aux_runtime::executor::FileFault;
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => FileFault::Symlink,
        Ok(meta) if meta.len() > MAX_REGISTRY_FILE_BYTES => FileFault::TooLarge,
        Ok(meta) if meta.permissions().mode() & 0o444 == 0 => FileFault::Denied,
        _ => FileFault::Read,
    }
}

/// A parse error of a home file: file, line and column, never the text.
fn redacted(err: &toml::de::Error, file: &str, text: &str) -> RegistryError {
    RegistryError::Config(
        kernel_core::redact_toml_error(err, file, text)
            .message()
            .to_string(),
    )
}

/// Write one agent's grants atomically (`0600`).
pub fn write_grants(home: &Path, id: &str, grants: &AgentGrants) -> Result<(), RegistryError> {
    let _guard = kernel_core::lock_recover(grants_lock());
    write_grants_locked(home, id, grants)
}

/// Apply an approved proposal, only if the agent's grants are still the set
/// it was made against: an older card never overwrites a newer set.
pub fn apply_proposal(home: &Path, proposal: &GrantsProposal) -> Result<(), RegistryError> {
    let _guard = kernel_core::lock_recover(grants_lock());
    if grants_hash(&grants(home, &proposal.agent)?) != proposal.base {
        return Err(RegistryError::GrantsChanged);
    }
    write_grants_locked(home, &proposal.agent, &proposal.grants)
}

fn write_grants_locked(home: &Path, id: &str, grants: &AgentGrants) -> Result<(), RegistryError> {
    definition(home, id)?.ok_or_else(|| RegistryError::UnknownAgent(id.to_string()))?;
    validate_grants(home, id, grants)?;
    let text = toml::to_string(&GrantsFile::from(grants))
        .map_err(|err| RegistryError::Config(format!("could not serialize grants: {err}")))?;
    write_private(home, &grants_rel(id), text.as_bytes())
}

/// Serializes grants writes and agent creation, so a ceiling check and the
/// write it allows cannot interleave with a concurrent change.
pub(crate) fn grants_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

/// Probe tools, one per scope and verb, that compare two grant sets the way
/// the runtime resolves them (scope fallbacks included).
const PROBE_TOOLS: &str =
    "mail_read mail_draft mail_send mail_unknown calendar_freebusy calendar_list \
    calendar_write calendar_unknown clients_read clients_note clients_unknown documents_read \
    documents_file documents_unknown mcp__server__unknown google_unknown";

/// True when `child` grants nothing beyond `chief`: every scope, skill and
/// probe tool at most at the chief's level, and every chief `never` kept.
fn subset(child: &AgentGrants, chief: &AgentGrants) -> bool {
    use aux_runtime::grants::GrantLevel;
    let see = |level| match level {
        AccessLevel::Off => 0,
        AccessLevel::Ask => 1,
        AccessLevel::Read => 2,
    };
    let act = |level| match level {
        ActionLevel::Off => 0,
        ActionLevel::Ask => 1,
        ActionLevel::Auto => 2,
    };
    let tool = |grants: &AgentGrants, name: &str| match grants.action_for_tool("agent", name) {
        Err(_) => 0,
        Ok(GrantLevel::Ask) => 1,
        Ok(GrantLevel::Allow) => 2,
    };
    // A display-only row decides no read, so it never exceeds the chief.
    child.see.iter().filter(|grant| !grant.is_display_only()).all(|grant| {
        let own = chief.see.iter().filter(|own| own.scope == grant.scope);
        see(grant.level) <= own.map(|own| see(own.level)).min().unwrap_or(0)
    }) && child.can_do.iter().all(|grant| {
        act(grant.level) <= chief.granted_level(&grant.skill).map_or(0, act)
    }) && PROBE_TOOLS
        .split_whitespace()
        .all(|name| tool(child, name) <= tool(chief, name))
        // Exact entries: a shorter prefix (`m` for `mail`) would not refuse
        // what the chief's entry refuses (its scope), so it never replaces it.
        && chief
            .never
            .iter()
            .all(|denied| child.never.iter().any(|own| own == denied))
}

/// The chief ceiling, checked when a change is proposed and again when it is
/// applied (an approval can wait while the chief changes). Narrowing the
/// chief below an existing agent is refused too: nothing is lost silently.
pub fn validate_grants(home: &Path, id: &str, proposed: &AgentGrants) -> Result<(), RegistryError> {
    let agents = registry(home)?;
    if id == CHIEF_AGENT {
        let below = |agent: &&AgentDef| agent.id != id && agent.id != LEGACY_CHIEF;
        if agents
            .iter()
            .filter(below)
            .any(|a| !subset(&a.grants, proposed))
        {
            return Err(RegistryError::ExceedsChief);
        }
    }
    let chief = chief_id(home);
    let mut caps = ceilings_for(chief, id);
    // The chief of an older install stays under `main`'s grants, as before.
    if id == chief && id != CHIEF_AGENT {
        caps.push(CHIEF_AGENT);
    }
    if caps
        .into_iter()
        .any(|cap| !subset(proposed, &ceiling_grants(&agents, cap)))
    {
        return Err(RegistryError::ExceedsChief);
    }
    Ok(())
}

/// A grants change waiting for the owner's approval.
#[derive(Debug, Clone)]
pub struct GrantsProposal {
    /// Agent whose grants would change.
    pub agent: String,
    /// Hash of the proposed grants.
    pub hash: String,
    /// Hash of the agent's grants when the change was proposed.
    pub base: String,
    /// The proposed grants.
    pub grants: AgentGrants,
}

fn proposals() -> &'static std::sync::Mutex<std::collections::HashMap<String, GrantsProposal>> {
    static PROPOSALS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, GrantsProposal>>,
    > = std::sync::OnceLock::new();
    PROPOSALS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Hash of the canonical serialization of one grants set.
pub fn grants_hash(grants: &AgentGrants) -> String {
    let text = toml::to_string(&GrantsFile::from(grants)).unwrap_or_default();
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// Remember a proposed grants change under `approval_id`.
pub fn propose_grants(approval_id: &str, agent: &str, base: String, grants: AgentGrants) -> String {
    let hash = grants_hash(&grants);
    kernel_core::lock_recover(proposals()).insert(
        approval_id.to_string(),
        GrantsProposal {
            agent: agent.to_string(),
            hash: hash.clone(),
            base,
            grants,
        },
    );
    hash
}

/// Take the proposal bound to `approval_id`; a proposal applies at most once.
pub fn take_proposal(approval_id: &str) -> Option<GrantsProposal> {
    kernel_core::lock_recover(proposals()).remove(approval_id)
}

/// Drop a proposal without applying it (deny, or a superseded id).
pub fn drop_proposal(approval_id: &str) {
    kernel_core::lock_recover(proposals()).remove(approval_id);
}

/// Read an agent's memory; missing is empty. MEM-FORGET-HANG: what
/// `remember` saved (the store) comes first, then the older file items.
pub fn memory(home: &Path, id: &str) -> Result<Vec<MemoryItem>, RegistryError> {
    definition(home, id)?.ok_or_else(|| RegistryError::UnknownAgent(id.to_string()))?;
    let mut items: Vec<MemoryItem> = match memory_store(home)? {
        Some(store) => kernel_core::lock_recover(&store)
            .memory_items_for_agent(id, 100)
            .map_err(|err| RegistryError::Io(format!("memory: {err}")))?
            .into_iter()
            .map(|item| MemoryItem {
                id: item.id.to_string(),
                text: item.body,
                saved_at: item.created_at,
            })
            .collect(),
        None => Vec::new(),
    };
    items.extend(file_memory(home, id)?);
    Ok(items)
}

const MEMORY_VIEW_LIMIT: usize = 200;

fn memory_source_label(source: &str, trust: &str) -> &'static str {
    if source.starts_with(aux_store::ACCEPTED_OUTSIDE_SUGGESTION) {
        // The owner accepted a proposal made from outside content: an owner
        // memory now, but the page still says where it came from.
        "suggestion from outside content"
    } else if matches!(trust, "untrusted" | "tainted") {
        "from an outside message"
    } else if source == "accepted_suggestion" {
        "accepted suggestion"
    } else if source.to_ascii_lowercase().contains("mail") {
        "learned from a mail"
    } else {
        "you told Aux"
    }
}

/// The proposing run's ref kept on an accepted outside suggestion, when the
/// item carries one. It stays on the memory item next to its source label.
fn accepted_suggestion_ref(source: &str) -> Option<&str> {
    source
        .strip_prefix(aux_store::ACCEPTED_OUTSIDE_SUGGESTION)?
        .strip_prefix(':')
}

fn memory_item_json(
    id: String,
    text: String,
    source: &'static str,
    provenance: Option<&str>,
    saved_at: String,
) -> serde_json::Value {
    let mut item = serde_json::json!({
        "id": id,
        "text": text,
        "source": source,
        "saved_at": saved_at,
        "editable": true,
    });
    if let Some(provenance) = provenance {
        item["provenance"] = serde_json::Value::String(provenance.to_string());
    }
    item
}

fn memory_group_index(fact_key: Option<&str>) -> usize {
    match fact_key {
        Some(key) if key.starts_with("owner.") => 0,
        Some(key) if key.starts_with("person.") || key.starts_with("party.") => 1,
        Some(key) if key.starts_with("rule.") => 2,
        _ => 3,
    }
}

fn memory_view(home: &Path, id: &str) -> Result<serde_json::Value, RegistryError> {
    definition(home, id)?.ok_or_else(|| RegistryError::UnknownAgent(id.to_string()))?;
    let store = memory_store(home)?;
    let store_items = match store.as_ref() {
        Some(store) => kernel_core::lock_recover(store)
            .active_memory_items_for_agent(id, MEMORY_VIEW_LIMIT)
            .map_err(|err| RegistryError::Io(format!("memory: {err}")))?,
        None => Vec::new(),
    };
    let mut groups: [Vec<serde_json::Value>; 4] = std::array::from_fn(|_| Vec::new());
    for item in store_items.iter() {
        groups[memory_group_index(item.fact_key.as_deref())].push(memory_item_json(
            item.id.to_string(),
            item.body.clone(),
            memory_source_label(&item.source, &item.trust),
            accepted_suggestion_ref(&item.source),
            item.created_at.clone(),
        ));
    }
    let file_limit = MEMORY_VIEW_LIMIT.saturating_sub(store_items.len());
    if file_limit > 0 {
        for item in file_memory(home, id)?.into_iter().take(file_limit) {
            groups[3].push(memory_item_json(
                item.id,
                item.text,
                "older note",
                None,
                item.saved_at,
            ));
        }
    }
    let suggestions = match store.as_ref() {
        Some(store) => kernel_core::lock_recover(store)
            .pending_memory_suggestions(id, aux_store::MEMORY_SUGGESTIONS_PER_AGENT_MAX)
            .map_err(|err| RegistryError::Io(format!("memory suggestions: {err}")))?
            .into_iter()
            .map(|suggestion| {
                serde_json::json!({
                    "id": format!("s-{}", suggestion.id),
                    "text": suggestion.body,
                    "source": if suggestion.trust == "owner" { "learned from a mail" } else { "from an outside message" },
                    "created_at": suggestion.created_at,
                })
            })
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    Ok(serde_json::json!({
        "agent": id,
        "groups": [
            {"key": "about_you", "items": groups[0]},
            {"key": "people", "items": groups[1]},
            {"key": "rules", "items": groups[2]},
            {"key": "other", "items": groups[3]},
        ],
        "suggestions": suggestions,
    }))
}

fn edit_memory(
    home: &Path,
    id: &str,
    item_id: &str,
    text: &str,
) -> Result<Option<serde_json::Value>, RegistryError> {
    definition(home, id)?.ok_or_else(|| RegistryError::UnknownAgent(id.to_string()))?;
    if let Ok(number) = item_id.parse::<i64>() {
        let Some(store) = memory_store(home)? else {
            return Ok(None);
        };
        let edited = kernel_core::lock_recover(&store)
            .edit_memory_item(id, number, text)
            .map_err(|err| RegistryError::Io(format!("memory: {err}")))?;
        if let Some(item) = edited {
            aux_runtime::tools::sync_note_mirror(&store, home, id)
                .map_err(|err| RegistryError::Io(format!("memory mirror: {err}")))?;
            return Ok(Some(memory_item_json(
                item.id.to_string(),
                item.body,
                memory_source_label(&item.source, &item.trust),
                accepted_suggestion_ref(&item.source),
                item.created_at,
            )));
        }
        return Ok(None);
    }
    let mut items = file_memory(home, id)?;
    let Some(item) = items.iter_mut().find(|entry| entry.id == item_id) else {
        return Ok(None);
    };
    item.text = kernel_broker::sanitize_text(text).trim().to_owned();
    let result = item.clone();
    write_memory(home, id, &items)?;
    Ok(Some(memory_item_json(
        result.id,
        result.text,
        "older note",
        None,
        result.saved_at,
    )))
}

/// The store `remember` writes to, or `None` before the first one exists.
fn memory_store(
    home: &Path,
) -> Result<Option<std::sync::Arc<std::sync::Mutex<aux_store::Store>>>, RegistryError> {
    let path = kernel_core::store_path(home);
    if !path.exists() {
        return Ok(None);
    }
    let store =
        aux_store::Store::open(&path).map_err(|err| RegistryError::Io(format!("memory: {err}")))?;
    Ok(Some(std::sync::Arc::new(std::sync::Mutex::new(store))))
}

fn file_memory(home: &Path, id: &str) -> Result<Vec<MemoryItem>, RegistryError> {
    let Some(text) = read_private(home, &memory_rel(id))? else {
        return Ok(Vec::new());
    };
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let file: MemoryFile = serde_json::from_str(&text)
        .map_err(|err| RegistryError::Config(format!("agents/{id}/memory.json: {err}")))?;
    Ok(file.items)
}

/// Forget one memory item; `true` when it was present. A store item (a
/// numeric id) also leaves the generated note mirror.
pub fn forget_memory(home: &Path, id: &str, item: &str) -> Result<bool, RegistryError> {
    definition(home, id)?.ok_or_else(|| RegistryError::UnknownAgent(id.to_string()))?;
    if let (Ok(number), Some(store)) = (item.parse::<i64>(), memory_store(home)?) {
        let deleted = kernel_core::lock_recover(&store)
            .delete_memory_item(id, number)
            .map_err(|err| RegistryError::Io(format!("memory: {err}")))?;
        if deleted {
            aux_runtime::tools::sync_note_mirror(&store, home, id)
                .map_err(|err| RegistryError::Io(format!("memory mirror: {err}")))?;
        }
        return Ok(deleted);
    }
    let mut items = file_memory(home, id)?;
    let before = items.len();
    items.retain(|entry| entry.id != item);
    if items.len() == before {
        return Ok(false);
    }
    write_memory(home, id, &items)?;
    Ok(true)
}

/// Append one memory item and return it.
pub fn append_memory(home: &Path, id: &str, text: &str) -> Result<MemoryItem, RegistryError> {
    definition(home, id)?.ok_or_else(|| RegistryError::UnknownAgent(id.to_string()))?;
    let mut items = file_memory(home, id)?;
    let item = MemoryItem {
        id: format!("mem-{}-{}", millis(), items.len() + 1),
        text: text.to_string(),
        saved_at: now_stamp(),
    };
    items.push(item.clone());
    write_memory(home, id, &items)?;
    Ok(item)
}

fn write_memory(home: &Path, id: &str, items: &[MemoryItem]) -> Result<(), RegistryError> {
    let file = MemoryFile {
        items: items.to_vec(),
    };
    let text = serde_json::to_string_pretty(&file)
        .map_err(|err| RegistryError::Config(format!("could not serialize memory: {err}")))?;
    write_private(home, &memory_rel(id), text.as_bytes())
}

/// Read one private registry file, bounded; `None` when it does not exist.
fn read_private(home: &Path, rel: &Path) -> Result<Option<String>, RegistryError> {
    let handle = match SandboxHome::open_existing(home) {
        Ok(handle) => handle,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(RegistryError::Io(err.to_string())),
    };
    let mut file = match handle.open_read_existing(rel, MAX_REGISTRY_FILE_BYTES) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(RegistryError::Io(format!(
                "could not read {}: {err}",
                rel.display()
            )))
        }
    };
    let mut bytes = Vec::new();
    use std::io::Read;
    std::io::Read::take(&mut file, MAX_REGISTRY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| RegistryError::Io(format!("could not read {}: {err}", rel.display())))?;
    if bytes.len() as u64 > MAX_REGISTRY_FILE_BYTES {
        return Err(RegistryError::Config(format!(
            "{} is unexpectedly large",
            rel.display()
        )));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| RegistryError::Config(format!("{} is not valid UTF-8", rel.display())))
}

/// Write one private registry file atomically (`0600`), creating its directory.
fn write_private(home: &Path, rel: &Path, bytes: &[u8]) -> Result<(), RegistryError> {
    let handle = SandboxHome::open(home).map_err(|err| RegistryError::Io(err.to_string()))?;
    if let Some(parent) = rel.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        handle
            .create_dir_all(parent)
            .map_err(|err| RegistryError::Io(err.to_string()))?;
    }
    handle
        .write_atomic(rel, bytes, 0o600)
        .map_err(|err| RegistryError::Io(format!("writing {}: {err}", rel.display())))
}

fn now_stamp() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// HTTP handlers (grants + memory)
// ---------------------------------------------------------------------------

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;

use crate::api::{error, ApiState};

/// `GET /v1/agents/{id}/grants`.
pub async fn grants_show(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let home = state.home.clone();
    let result = tokio::task::spawn_blocking(move || grants(&home, &id)).await;
    match result {
        Ok(Ok(grants)) => Json(grants_json(&grants)).into_response(),
        Ok(Err(RegistryError::UnknownAgent(_))) => agent_not_found(),
        Ok(Err(err)) => registry_error(&err),
        Err(err) => internal(&err.to_string()),
    }
}

/// `PUT /v1/agents/{id}/grants`.
///
/// A grants change is a permission change: the PUT never writes. It
/// registers a pending approval bound to the agent id and a hash of the
/// proposed grants; the change applies only when the owner approves that
/// exact approval id, and at most once.
pub async fn grants_update(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return bad_json("the request body could not be read"),
    };
    let file: GrantsFile = match serde_json::from_slice(&body) {
        Ok(file) => file,
        Err(_) => return bad_json("the body must be `{see, do, never, egress_note}`"),
    };
    let grants = AgentGrants::from(file);
    let (home, id_for_check, proposed) = (state.home.clone(), id.clone(), grants.clone());
    let checked = tokio::task::spawn_blocking(move || {
        definition(&home, &id_for_check)?
            .ok_or_else(|| RegistryError::UnknownAgent(id_for_check.clone()))?;
        validate_grants(&home, &id_for_check, &proposed)?;
        self::grants(&home, &id_for_check).map(|current| grants_hash(&current))
    })
    .await;
    let base = match checked {
        Ok(Ok(base)) => base,
        Ok(Err(RegistryError::UnknownAgent(_))) => return agent_not_found(),
        Ok(Err(RegistryError::ExceedsChief)) => return exceeds_chief(),
        Ok(Err(err)) => return registry_error(&err),
        Err(err) => return internal(&err.to_string()),
    };
    let approval_id = state.approvals.next_id();
    let hash = propose_grants(&approval_id, &id, base, grants);
    // The card is built by the shared builder, like every other ask: the
    // proposal it carries is one of its fields.
    let arguments = serde_json::json!({
        "agent": id,
        "proposal": &hash[..hash.len().min(12)],
    });
    let card = crate::api::approval_preview::build("agent.grants", &arguments, &[]).unwrap_or_else(
        |reason| crate::api::approval_preview::CardPreview {
            title: format!("Change the grants of `{id}`"),
            body: reason,
            detail: Vec::new(),
        },
    );
    let pending = crate::api::PendingApproval {
        id: approval_id.clone(),
        audit_id: 0,
        agent: id.clone(),
        thread_id: 0,
        root_thread: None,
        tool: "agent.grants".to_string(),
        risk: kernel_broker::Risk::Medium,
        card_title: card.title,
        card_body: card.body,
        card_detail: card.detail,
        edit_args: arguments.to_string(),
        taint: None,
        unsandboxed: false,
        networked: false,
        created_ms: chrono::Utc::now().timestamp_millis(),
    };
    let _waiter = state.approvals.register(pending.clone());
    let _ = crate::api::wire::send_bounded(
        &state.events,
        &crate::api::wire::approval_new(&pending.frame()),
    );
    Json(serde_json::json!({
        "state": "pending",
        "approval_id": approval_id,
        "agent": id,
        "hash": hash,
    }))
    .into_response()
}

/// `GET /v1/agents/{id}/memory`.
pub async fn memory_list(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let home = state.home.clone();
    let result = tokio::task::spawn_blocking(move || memory(&home, &id)).await;
    match result {
        Ok(Ok(items)) => Json(serde_json::json!({ "items": items })).into_response(),
        Ok(Err(RegistryError::UnknownAgent(_))) => agent_not_found(),
        Ok(Err(err)) => registry_error(&err),
        Err(err) => internal(&err.to_string()),
    }
}

/// `GET /v1/agents/{id}/memory/view`.
pub async fn memory_view_list(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || memory_view(&home, &id)).await {
        Ok(Ok(view)) => Json(view).into_response(),
        Ok(Err(RegistryError::UnknownAgent(_))) => agent_not_found(),
        Ok(Err(err)) => registry_error(&err),
        Err(err) => internal(&err.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryEditBody {
    text: String,
}

/// `PATCH /v1/agents/{id}/memory/{item}`.
pub async fn memory_edit(
    State(state): State<Arc<ApiState>>,
    AxumPath((id, item)): AxumPath<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return memory_body_too_large(),
    };
    let edit: MemoryEditBody = match serde_json::from_slice(&body) {
        Ok(edit) => edit,
        Err(_) => return invalid_memory_text(),
    };
    let trimmed = edit.text.trim();
    if !(1..=2000).contains(&trimmed.chars().count()) {
        return invalid_memory_text();
    }
    let cleaned = kernel_broker::sanitize_text(trimmed).trim().to_owned();
    if cleaned.is_empty() {
        return invalid_memory_text();
    }
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || edit_memory(&home, &id, &item, &cleaned)).await {
        Ok(Ok(Some(item))) => Json(item).into_response(),
        Ok(Ok(None)) => memory_not_found(),
        Ok(Err(RegistryError::UnknownAgent(_))) => agent_not_found(),
        Ok(Err(err)) => registry_error(&err),
        Err(err) => internal(&err.to_string()),
    }
}

fn memory_body_too_large() -> Response {
    error::error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
        "memory request body exceeds 8 KiB",
        None,
    )
}

fn invalid_memory_text() -> Response {
    error::error_response(
        StatusCode::BAD_REQUEST,
        "invalid_text",
        "text must contain 1 to 2000 characters after trimming",
        None,
    )
}

fn memory_not_found() -> Response {
    error::error_response(
        StatusCode::NOT_FOUND,
        "memory_not_found",
        "no such memory item",
        None,
    )
}

fn suggestion_id(id: &str) -> Option<i64> {
    id.strip_prefix("s-")?.parse().ok()
}

enum MemorySuggestionDecision {
    Accepted(serde_json::Value),
    Rejected,
}

/// The owner's decision on one pending suggestion. This and the store method
/// it calls are the only way a suggestion becomes memory: no model tool
/// accepts one, and the route below is the app's owner-authenticated path.
fn decide_memory_suggestion(
    home: &Path,
    agent: &str,
    suggestion: i64,
    decision: &str,
) -> Result<Option<MemorySuggestionDecision>, RegistryError> {
    definition(home, agent)?.ok_or_else(|| RegistryError::UnknownAgent(agent.to_string()))?;
    let Some(store) = memory_store(home)? else {
        return Ok(None);
    };
    match decision {
        "accept" => {
            let item = kernel_core::lock_recover(&store)
                .accept_memory_suggestion(agent, suggestion)
                .map_err(|err| RegistryError::Io(format!("memory suggestion: {err}")))?;
            let Some(item) = item else { return Ok(None) };
            aux_runtime::tools::sync_note_mirror(&store, home, agent)
                .map_err(|err| RegistryError::Io(format!("memory mirror: {err}")))?;
            Ok(Some(MemorySuggestionDecision::Accepted(memory_item_json(
                item.id.to_string(),
                item.body,
                memory_source_label(&item.source, &item.trust),
                accepted_suggestion_ref(&item.source),
                item.created_at,
            ))))
        }
        "reject" => Ok(kernel_core::lock_recover(&store)
            .reject_memory_suggestion(agent, suggestion)
            .map_err(|err| RegistryError::Io(format!("memory suggestion: {err}")))?
            .then_some(MemorySuggestionDecision::Rejected)),
        _ => Ok(None),
    }
}

/// `POST /v1/agents/{id}/memory/suggestions/{sid}/{decision}`.
pub async fn memory_suggestion_decide(
    State(state): State<Arc<ApiState>>,
    AxumPath((id, sid, decision)): AxumPath<(String, String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if body.is_err() {
        return memory_body_too_large();
    }
    let Some(suggestion) = suggestion_id(&sid) else {
        return memory_not_found();
    };
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || {
        decide_memory_suggestion(&home, &id, suggestion, &decision)
    })
    .await
    {
        Ok(Ok(Some(MemorySuggestionDecision::Accepted(item)))) => Json(item).into_response(),
        Ok(Ok(Some(MemorySuggestionDecision::Rejected))) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(None)) => memory_not_found(),
        Ok(Err(RegistryError::UnknownAgent(_))) => agent_not_found(),
        Ok(Err(err)) => registry_error(&err),
        Err(err) => internal(&err.to_string()),
    }
}

/// `DELETE /v1/agents/{id}/memory/{item}`.
pub async fn memory_forget(
    State(state): State<Arc<ApiState>>,
    AxumPath((id, item)): AxumPath<(String, String)>,
) -> Response {
    let home = state.home.clone();
    let result = tokio::task::spawn_blocking(move || forget_memory(&home, &id, &item)).await;
    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "forgotten": true })).into_response(),
        Ok(Ok(false)) => error::error_response(
            StatusCode::NOT_FOUND,
            "memory_not_found",
            "no such memory item",
            None,
        ),
        Ok(Err(RegistryError::UnknownAgent(_))) => agent_not_found(),
        Ok(Err(err)) => registry_error(&err),
        Err(err) => internal(&err.to_string()),
    }
}

/// JSON shape of one agent's grants, shared by GET and PUT.
pub fn grants_json(grants: &AgentGrants) -> serde_json::Value {
    serde_json::json!({
        "see": grants.see.iter().map(|grant| serde_json::json!({
            "scope": grant.scope,
            "via": grant.via,
            "level": grant.level.as_str(),
        })).collect::<Vec<_>>(),
        "do": grants.can_do.iter().map(|grant| serde_json::json!({
            "skill": grant.skill,
            "level": grant.level.as_str(),
        })).collect::<Vec<_>>(),
        "never": grants.never,
        "egress_note": grants.egress_note,
    })
}

fn agent_not_found() -> Response {
    error::error_response(
        StatusCode::NOT_FOUND,
        "agent_not_found",
        "no such agent",
        None,
    )
}

/// `409 grant_exceeds_chief`: the shared refusal for any change that would
/// give an agent more than the chief has.
pub(crate) fn exceeds_chief() -> Response {
    error::error_response(
        StatusCode::CONFLICT,
        "grant_exceeds_chief",
        "the agent would have access beyond the chief",
        None,
    )
}

fn registry_error(err: &RegistryError) -> Response {
    error::error_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "agent_registry_unreadable",
        err.to_string(),
        None,
    )
}

fn bad_json(message: &str) -> Response {
    error::error_response(StatusCode::BAD_REQUEST, "invalid_json", message, None)
}

fn internal(detail: &str) -> Response {
    tracing::warn!(detail = %detail, "agent registry API failed");
    error::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "agent_registry_error",
        "the agent registry could not be read or updated",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn a_scope_fallback_must_not_bypass_the_chiefs_specific_off_grant() {
        let mut chief = aux_runtime::grants::default_grants(CHIEF_AGENT).unwrap();
        let send = chief.can_do.iter_mut().find(|g| g.skill == "mail.send");
        send.unwrap().level = ActionLevel::Off;
        let mut child = aux_runtime::grants::default_grants("mail").unwrap();
        child.can_do.retain(|g| g.skill != "mail.send");
        assert!(!subset(&child, &chief));
        let full = aux_runtime::grants::default_grants(CHIEF_AGENT).unwrap();
        let fits = |id| subset(&aux_runtime::grants::default_grants(id).unwrap(), &full);
        assert!(DOMAIN_AGENTS.iter().all(|id| fits(id)));
    }

    /// Break-It B: a child never replaces a chief `never` with a shorter
    /// prefix (`m` for `mail`); only the exact entry (or more) keeps it.
    #[test]
    fn a_child_never_keeps_each_chief_never_exactly() {
        let mut chief = aux_runtime::grants::default_grants(CHIEF_AGENT).unwrap();
        chief.never.push("mail".to_string());
        let mut child = aux_runtime::grants::default_grants("documents").unwrap();
        child.never = vec!["m".to_string()];
        assert!(!subset(&child, &chief));
        child.never = vec!["mail".to_string(), "m".to_string()];
        assert!(subset(&child, &chief));
    }

    /// Break-It A: a template agent whose directory was made by hand (or by
    /// an older daemon) is capped at a lowered chief on every reload.
    #[test]
    fn a_hand_made_template_directory_is_capped_at_the_chief() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join("config.toml"), "default_agent = \"main\"\n").unwrap();
        let mut chief = aux_runtime::grants::default_grants(CHIEF_AGENT).unwrap();
        let send = chief.can_do.iter_mut().find(|g| g.skill == "mail.send");
        send.unwrap().level = ActionLevel::Off;
        chief.see.retain(|g| g.scope != "documents");
        write_grants(home, CHIEF_AGENT, &chief).unwrap();
        for id in DOMAIN_AGENTS {
            std::fs::create_dir_all(home.join("agents").join(id)).unwrap();
        }
        let agents = registry(home).unwrap();
        let chief = ceiling_grants(&agents, CHIEF_AGENT);
        for id in DOMAIN_AGENTS {
            let agent = agents.iter().find(|a| a.id == id).expect("listed");
            assert!(subset(&agent.grants, &chief), "{id}");
        }
        let mail = grants(home, "mail").unwrap();
        assert!(mail.check_tool("mail", "mail_send").is_err());
        assert!(mail.check_tool("mail", "mail_read").is_ok());
    }

    #[test]
    fn an_older_install_keeps_aux_and_a_main_home_caps_every_agent() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join("config.toml"), "default_agent = \"aux\"\n").unwrap();
        assert_eq!(registry(home).unwrap()[0].id, LEGACY_CHIEF);
        std::fs::write(home.join("config.toml"), "default_agent = \"main\"\n").unwrap();
        std::fs::create_dir_all(home.join("agents/mail")).unwrap();
        assert_eq!(registry(home).unwrap()[0].id, CHIEF_AGENT);
        let mut wider = aux_runtime::grants::default_grants("mail").unwrap();
        wider.can_do[0].skill = "payments.send".to_string();
        let refused = write_grants(home, "mail", &wider);
        assert!(matches!(refused, Err(RegistryError::ExceedsChief)));
        let mut narrow = aux_runtime::grants::default_grants(CHIEF_AGENT).unwrap();
        narrow.can_do.retain(|g| g.skill != "mail.read");
        let refused = write_grants(home, CHIEF_AGENT, &narrow);
        assert!(matches!(refused, Err(RegistryError::ExceedsChief)));
    }

    /// READS-4: Mail's free-times row refuses no chief without a calendar See
    /// row and caps nothing; a real calendar row still exceeds that chief.
    #[test]
    fn the_free_times_see_row_refuses_no_chief_narrowing() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join("config.toml"), "default_agent = \"main\"\n").unwrap();
        std::fs::create_dir_all(home.join("agents/mail")).unwrap();
        let mut chief = aux_runtime::grants::default_grants(CHIEF_AGENT).unwrap();
        chief.see.retain(|see| see.scope != "calendar");
        write_grants(home, CHIEF_AGENT, &chief).unwrap();
        let shipped = aux_runtime::grants::default_grants("mail").unwrap();
        assert_eq!(grants(home, "mail").unwrap(), shipped);
        write_grants(home, "mail", &shipped).unwrap();
        let mut wider = shipped.clone();
        let row = wider.see.iter_mut().find(|see| see.is_display_only());
        row.unwrap().via = "local".to_string();
        let refused = write_grants(home, "mail", &wider);
        assert!(matches!(refused, Err(RegistryError::ExceedsChief)));
        let mail = grants(home, "mail").unwrap();
        assert!(!mail.allows_scope("calendar"));
        assert!(mail
            .check_tool("mail", "apple_calendar_list_events")
            .is_err());
    }

    /// The chief is never held to itself: a set wider than its shipped one is
    /// written and read back as is, and no ceiling caps it.
    #[test]
    fn the_chief_is_never_refused_against_itself() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join("config.toml"), "default_agent = \"main\"\n").unwrap();
        let mut wider = aux_runtime::grants::default_grants(CHIEF_AGENT).unwrap();
        wider.can_do.push(DoGrant {
            skill: "mcp__bank__pay".to_string(),
            level: ActionLevel::Auto,
        });
        write_grants(home, CHIEF_AGENT, &wider).unwrap();
        assert_eq!(grants(home, CHIEF_AGENT).unwrap(), wider);
        assert!(ceilings(home, CHIEF_AGENT).is_empty());
    }

    /// An older install's chief is `aux`: an added agent (and `main`, which
    /// is not the chief there) stays under it as well as under `main`; the
    /// four domain agents `aux` hands work to keep `main`'s cap only. A
    /// `main` home is as before.
    #[test]
    fn every_agent_stays_under_the_chief_this_home_runs() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join("config.toml"), "default_agent = \"aux\"\n").unwrap();
        assert!(ceilings(home, LEGACY_CHIEF).is_empty());
        assert_eq!(ceilings(home, "scout"), [CHIEF_AGENT, LEGACY_CHIEF]);
        assert_eq!(ceilings(home, CHIEF_AGENT), [LEGACY_CHIEF]);
        for id in DOMAIN_AGENTS {
            assert_eq!(ceilings(home, id), [CHIEF_AGENT], "{id}");
        }
        std::fs::write(home.join("config.toml"), "default_agent = \"main\"\n").unwrap();
        assert!(ceilings(home, CHIEF_AGENT).is_empty());
        assert_eq!(ceilings(home, "scout"), [CHIEF_AGENT]);
        assert_eq!(ceilings(home, LEGACY_CHIEF), [CHIEF_AGENT]);
        for id in DOMAIN_AGENTS {
            assert_eq!(ceilings(home, id), [CHIEF_AGENT], "{id}");
        }
    }

    /// On an older install a child listed in `agents.toml` never holds a
    /// tool the chief `aux` lacks: its grants are capped and a wider set is
    /// refused. Mail keeps reading mail, and a `main` home is as before.
    #[test]
    fn a_child_of_the_legacy_chief_never_holds_mail() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let seed = r#"
[[agents]]
id = "aux"
name = "Aux"
role = "chief"
glyph = "aux"

[[agents]]
id = "mail"
name = "Mail"
role = "domain"
glyph = "envelope"

[[agents.grants.do]]
skill = "mail.read"
level = "auto"

[[agents]]
id = "scout"
name = "Scout"
role = "domain"
glyph = "scout"

[[agents.grants.do]]
skill = "mail.read"
level = "auto"
"#;
        std::fs::write(seed_path(home), seed).unwrap();
        let reader = grants(home, "mail").unwrap();
        std::fs::write(home.join("config.toml"), "default_agent = \"aux\"\n").unwrap();
        assert!(grants(home, LEGACY_CHIEF)
            .unwrap()
            .check_tool(LEGACY_CHIEF, "mail_read")
            .is_err());
        let scout = grants(home, "scout").unwrap();
        assert!(scout.check_tool("scout", "mail_read").is_err());
        let refused = validate_grants(home, "scout", &reader);
        assert!(matches!(refused, Err(RegistryError::ExceedsChief)));
        let mail = grants(home, "mail").unwrap();
        assert!(mail.check_tool("mail", "mail_read").is_ok());
        assert!(validate_grants(home, "mail", &reader).is_ok());

        std::fs::write(home.join("config.toml"), "default_agent = \"main\"\n").unwrap();
        let scout = grants(home, "scout").unwrap();
        assert!(scout.check_tool("scout", "mail_read").is_ok());
        assert!(validate_grants(home, "scout", &reader).is_ok());
    }

    /// Run one daemon path that can create `config.toml` on `home`.
    fn create_config_through(path: &str, home: &Path) {
        let config = kernel_core::config_path(home);
        match path {
            "daemon and API load" => {
                crate::api::load_config_verified(home).unwrap();
            }
            "job load by path" => {
                aux_engine::config::load_or_create(&config).unwrap();
            }
            "job load by handle" => {
                let verified = kernel_core::verified_home_or_verify(home).unwrap();
                aux_engine::config::load_or_create_verified(&verified).unwrap();
            }
            "always-allow rule" => {
                let rule =
                    kernel_broker::Rule::new("main", "read_file", kernel_broker::Action::Allow);
                aux_engine::config::append_rule(&config, &rule).unwrap();
            }
            other => panic!("no daemon path named {other}"),
        }
    }

    /// Each daemon path that can create `config.toml` names `main` the chief,
    /// so a new home starts with the chief alone; a home whose config names
    /// `aux` stays an older install.
    #[test]
    fn a_daemon_path_that_creates_the_config_names_main_the_chief() {
        let paths = [
            "daemon and API load",
            "job load by path",
            "job load by handle",
            "always-allow rule",
        ];
        for name in paths {
            let dir = tempdir().unwrap();
            create_config_through(name, dir.path());
            assert_eq!(chief_id(dir.path()), CHIEF_AGENT, "{name}");
            let ids: Vec<String> = registry(dir.path())
                .unwrap()
                .into_iter()
                .map(|agent| agent.id)
                .collect();
            assert_eq!(ids, [CHIEF_AGENT], "{name}");

            let dir = tempdir().unwrap();
            let older = "version = 1\ndefault_agent = \"aux\"\n";
            std::fs::write(dir.path().join("config.toml"), older).unwrap();
            create_config_through(name, dir.path());
            assert_eq!(chief_id(dir.path()), LEGACY_CHIEF, "{name}");
        }
    }

    /// The daemon paths racing on a fresh home, as a start that overlaps a job
    /// or an always-allow click: every reader sees `main` as the chief, and
    /// the roster is the chief alone.
    #[test]
    fn racing_daemon_paths_on_a_fresh_home_all_see_main_the_chief() {
        let paths = [
            "daemon and API load",
            "job load by path",
            "job load by handle",
            "always-allow rule",
        ];
        for round in 0..20 {
            let dir = tempdir().unwrap();
            let home = dir.path();
            let start = std::sync::Barrier::new(paths.len() * 2);
            std::thread::scope(|scope| {
                for name in paths.iter().chain(&paths) {
                    let start = &start;
                    scope.spawn(move || {
                        start.wait();
                        create_config_through(name, home);
                        assert_eq!(chief_id(home), CHIEF_AGENT, "round {round}: {name}");
                    });
                }
            });
            let ids: Vec<String> = registry(home)
                .unwrap()
                .into_iter()
                .map(|agent| agent.id)
                .collect();
            assert_eq!(ids, [CHIEF_AGENT], "round {round}");
        }
    }

    fn calendar_file(home: &Path, file: &str) -> Option<Vec<u8>> {
        std::fs::read(home.join("agents").join("calendar").join(file)).ok()
    }

    /// The added paths under one agent's directory.
    fn in_agent(added: &[PathBuf], agent: &str) -> Vec<PathBuf> {
        let dir = Path::new("agents").join(agent);
        added
            .iter()
            .filter(|path| path.starts_with(&dir))
            .cloned()
            .collect()
    }

    /// An agent directory that already exists wide open is made
    /// owner-only; a symlink where the directory should be stops the install.
    #[cfg(unix)]
    #[test]
    fn a_loose_or_linked_agent_directory_is_tightened_or_refused() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join("config.toml"), "default_agent = \"aux\"\n").unwrap();
        install_shipped_files(home).unwrap();
        for agent in ["mail", "calendar"] {
            for sub in ["", "skills"] {
                let path = home.join("agents").join(agent).join(sub);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
            }
        }
        install_shipped_files(home).unwrap();
        for agent in ["mail", "calendar"] {
            assert_eq!(mode(&home.join("agents").join(agent)), 0o700, "{agent}");
            assert_eq!(
                mode(&home.join("agents").join(agent).join("skills")),
                0o700,
                "{agent}"
            );
        }

        let other = tempdir().unwrap();
        let skills = home.join("agents/mail/skills");
        std::fs::remove_dir_all(&skills).unwrap();
        std::os::unix::fs::symlink(other.path(), &skills).unwrap();
        assert!(install_shipped_files(home).is_err());
        assert!(std::fs::read_dir(other.path()).unwrap().next().is_none());
    }

    #[test]
    fn a_fresh_home_gets_the_calendar_files_once() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir_all(home.join("agents/calendar")).unwrap();
        let added = install_shipped_files(home).unwrap();
        assert_eq!(
            in_agent(&added, "calendar"),
            vec![
                PathBuf::from("agents/calendar/agent.md"),
                PathBuf::from("agents/calendar/skills/move-event.md"),
                PathBuf::from("agents/calendar/skills/send-invite.md"),
            ]
        );
        for (agent, file, text) in SHIPPED_FILES {
            if agent == "calendar" {
                assert_eq!(calendar_file(home, file).unwrap(), text.as_bytes());
            }
        }
        let agent_dir = home.join("agents").join("calendar");
        let agent = aux_runtime::skills::load_agent(&agent_dir).unwrap();
        assert_eq!(
            agent.tools,
            [
                "calendar.list_events",
                "calendar.create_event",
                "calendar.update_event",
                "reminders.list",
                "mail.send",
                "recall",
                "remember",
                "suggest_memory"
            ]
        );
        let load = aux_runtime::skills::load_skills(&agent_dir, &agent, None);
        assert!(load.errors.is_empty(), "{:?}", load.errors);
        assert_eq!(
            load.skills[0].approval,
            aux_runtime::skills::Approval::EachRun
        );
        assert!(
            install_shipped_files(home).unwrap().is_empty(),
            "second start"
        );
    }

    #[test]
    fn existing_files_stay_byte_identical_and_only_missing_ones_are_added() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let agent_dir = home.join("agents").join("calendar");
        std::fs::create_dir_all(agent_dir.join("skills")).unwrap();
        std::fs::write(agent_dir.join("agent.md"), "edited by the owner").unwrap();
        std::fs::write(
            agent_dir.join("skills").join("send-invite.md"),
            b"\xff garbled",
        )
        .unwrap();
        std::fs::write(agent_dir.join("skills").join("move-event.md"), "mine").unwrap();
        assert!(in_agent(&install_shipped_files(home).unwrap(), "calendar").is_empty());
        assert_eq!(
            calendar_file(home, "agent.md").unwrap(),
            b"edited by the owner"
        );
        assert_eq!(
            calendar_file(home, "skills/send-invite.md").unwrap(),
            b"\xff garbled"
        );

        std::fs::remove_file(agent_dir.join("skills").join("send-invite.md")).unwrap();
        let added = install_shipped_files(home).unwrap();
        assert_eq!(
            added,
            vec![PathBuf::from("agents/calendar/skills/send-invite.md")]
        );
        assert_eq!(
            calendar_file(home, "agent.md").unwrap(),
            b"edited by the owner"
        );
    }

    /// M4-3a: the Mail agent gets its tool list and the follow-up skill once,
    /// private files in private directories; the owner's soul and edits stay.
    #[test]
    fn a_fresh_home_gets_the_mail_files_once_and_keeps_the_owner_s() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let home = dir.path();
        let agent_dir = home.join("agents").join("mail");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(agent_dir.join("soul.md"), "Mail soul.\n").unwrap();
        let added = install_shipped_files(home).unwrap();
        assert_eq!(
            in_agent(&added, "mail"),
            vec![
                PathBuf::from("agents/mail/agent.md"),
                PathBuf::from("agents/mail/skills/follow-up.md"),
                PathBuf::from("agents/mail/skills/reply-availability.md"),
                PathBuf::from("agents/mail/skills/send-draft.md"),
            ]
        );
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&agent_dir.join("agent.md")), 0o600);
        assert_eq!(mode(&agent_dir.join("skills/follow-up.md")), 0o600);
        assert_eq!(mode(&agent_dir.join("skills")), 0o700);
        assert_eq!(
            std::fs::read(agent_dir.join("soul.md")).unwrap(),
            b"Mail soul.\n"
        );

        let agent = aux_runtime::skills::load_agent(&agent_dir).unwrap();
        assert_eq!(
            agent.tools,
            [
                "mail.list",
                "mail.search",
                "mail.thread",
                "mail.read",
                "mail.draft",
                "mail.send",
                "calendar_freebusy",
                "recall",
                "remember",
                "suggest_memory"
            ]
        );
        for tool in &agent.tools[..6] {
            assert!(
                aux_runtime::skills::tool_map::lookup(tool).is_some(),
                "{tool} is a registered tool"
            );
        }
        let load = aux_runtime::skills::load_skills(&agent_dir, &agent, None);
        assert!(load.errors.is_empty(), "{:?}", load.errors);
        let follow = &load.skills[0];
        assert_eq!(follow.command.as_deref(), Some("followup"));
        assert_eq!(follow.approval, aux_runtime::skills::Approval::EachAction);
        assert_eq!(
            follow.recipients_policy,
            aux_runtime::skills::RecipientPolicy::KnownContacts
        );
        assert_eq!(follow.effective_tools, ["mail.send"]);
        assert!(aux_runtime::skills::fill::recipients_are_runtime_owned(
            follow
        ));
        // M4-3b: `/availability` sends one mail whose times the runtime writes.
        let reply = &load.skills[1];
        assert_eq!(reply.command.as_deref(), Some("availability"));
        assert_eq!(reply.approval, aux_runtime::skills::Approval::EachAction);
        assert_eq!(reply.effective_tools, ["mail.send"]);
        assert!(reply.body.contains(aux_runtime::skills::free_times::MARKER));
        assert!(aux_runtime::skills::fill::recipients_are_runtime_owned(
            reply
        ));

        std::fs::write(agent_dir.join("skills/follow-up.md"), "edited").unwrap();
        assert!(install_shipped_files(home).unwrap().is_empty());
        assert_eq!(
            std::fs::read(agent_dir.join("skills/follow-up.md")).unwrap(),
            b"edited"
        );
    }

    /// M5-5: the Documents agent gets `collect-receipts` on a fresh home and
    /// on an upgraded one that has only its soul; it runs with no model and no
    /// card, and the owner's edited copy stays.
    #[test]
    fn the_documents_agent_gets_collect_receipts_once_and_keeps_the_owner_s() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let agent_dir = home.join("agents").join("documents");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(agent_dir.join("soul.md"), "Documents soul.\n").unwrap();
        let added = install_shipped_files(home).unwrap();
        assert_eq!(
            in_agent(&added, "documents"),
            vec![
                PathBuf::from("agents/documents/agent.md"),
                PathBuf::from("agents/documents/skills/collect-receipts.md"),
            ]
        );
        let agent = aux_runtime::skills::load_agent(&agent_dir).unwrap();
        let load = aux_runtime::skills::load_skills(&agent_dir, &agent, None);
        assert!(load.errors.is_empty(), "{:?}", load.errors);
        let collect = &load.skills[0];
        assert_eq!(collect.command.as_deref(), Some("collect-receipts"));
        assert_eq!(collect.brain, aux_runtime::skills::SkillBrain::None);
        assert_eq!(collect.approval, aux_runtime::skills::Approval::None);
        assert_eq!(collect.effective_tools, ["docs.ingest"]);

        std::fs::write(agent_dir.join("skills/collect-receipts.md"), "edited").unwrap();
        assert!(install_shipped_files(home).unwrap().is_empty());
        assert_eq!(
            std::fs::read(agent_dir.join("skills/collect-receipts.md")).unwrap(),
            b"edited"
        );
        assert_eq!(
            std::fs::read(agent_dir.join("soul.md")).unwrap(),
            b"Documents soul.\n"
        );
    }

    /// DOC-REEXTRACT-1: a shipped file that still holds an older *shipped*
    /// version is updated to the current one, so a new daemon reaches an owner
    /// who never touched it. A file the owner edited is kept byte-identical.
    #[test]
    fn an_old_shipped_file_is_updated_and_an_owner_edit_is_kept() {
        const OLD_COLLECT_RECEIPTS: &str =
            include_str!("../../tests/data/collect-receipts-pre-275.md");
        const CURRENT_COLLECT_RECEIPTS: &str =
            include_str!("../../../aux-runtime/src/skills/fixtures/skills/collect-receipts.md");
        let dir = tempdir().unwrap();
        let home = dir.path();
        let file = home.join("agents/documents/skills/collect-receipts.md");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, OLD_COLLECT_RECEIPTS).unwrap();

        // An old shipped version is not an owner edit: it becomes the current
        // shipped file.
        install_shipped_files(home).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            CURRENT_COLLECT_RECEIPTS
        );

        // The owner's own text is kept, byte for byte.
        std::fs::write(&file, "the owner's own words").unwrap();
        install_shipped_files(home).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "the owner's own words"
        );
    }

    /// EXECUTOR-READS: the Mail agent.md shipped before `calendar_freebusy`
    /// joined its tools list is updated on an existing home, so free times keep
    /// working after an upgrade.
    #[test]
    fn the_mail_agent_shipped_before_freebusy_is_updated() {
        const OLD: &str = include_str!("../../tests/data/mail-agent-pre-160.md");
        const CURRENT: &str = include_str!("mail/agent.md");
        assert!(CURRENT.contains("calendar_freebusy"));
        let dir = tempdir().unwrap();
        let file = dir.path().join("agents/mail/agent.md");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, OLD).unwrap();
        install_shipped_files(dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), CURRENT);

        // READS-3: an owner's own edit of that old file is kept byte for byte;
        // `calendar_freebusy` is never added behind the owner's back.
        let edited = OLD.replace("  - mail.send\n", "");
        std::fs::write(&file, &edited).unwrap();
        install_shipped_files(dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), edited);
    }

    #[test]
    fn an_agent_the_registry_does_not_list_gets_no_files() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        std::fs::write(
            seed_path(home),
            "[[agents]]\nid = \"aux\"\nname = \"Aux\"\nrole = \"chief\"\nglyph = \"aux\"\n",
        )
        .unwrap();
        assert!(install_shipped_files(home).unwrap().is_empty());
        assert!(!home.join("agents").join("calendar").exists());
    }

    #[test]
    fn a_symlinked_agent_directory_is_refused_not_followed() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(home.join("agents")).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join("agents").join("calendar")).unwrap();
        assert!(install_shipped_files(&home).is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn the_built_in_seed_is_the_chief_and_the_domains_are_templates() {
        let seed = built_in_seed();
        assert_eq!(seed.len(), 1);
        assert_eq!(
            (seed[0].id.as_str(), seed[0].name.as_str()),
            (CHIEF_AGENT, "Aux")
        );
        assert_eq!(seed[0].role, AgentRole::Chief);
        for id in DOMAIN_AGENTS {
            let template = template(id).unwrap();
            assert!(!template.glyph.is_empty(), "{id} has a glyph");
            assert!(
                subset(&template.grants, &seed[0].grants),
                "{id} fits the chief"
            );
        }
        // A `main` home lists only the chief until a template agent exists.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), "default_agent = \"main\"\n").unwrap();
        assert_eq!(registry(dir.path()).unwrap().len(), 1);
        std::fs::create_dir_all(dir.path().join("agents/mail")).unwrap();
        let ids: Vec<String> = registry(dir.path())
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, [CHIEF_AGENT, "mail"]);
    }

    #[test]
    fn a_home_with_no_config_is_fresh_and_lists_the_chief_alone() {
        let dir = tempdir().unwrap();
        let registry = registry(dir.path()).unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn a_seed_file_replaces_the_built_in_seed_and_rejects_unknown_fields() {
        let dir = tempdir().unwrap();
        let good = r#"
[[agents]]
id = "mail"
name = "Mail"
role = "domain"
glyph = "envelope"
skills = ["draft"]
[agents.brain]
provider = "deepseek"
model = "deepseek-chat"
"#;
        std::fs::write(dir.path().join("agents.toml"), good).unwrap();
        let agents = registry(dir.path()).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(
            agents[0].brain.label().as_deref(),
            Some("deepseek/deepseek-chat")
        );
        assert_eq!(agents[0].skills, vec!["draft".to_string()]);

        let bad = "[[agents]]\nid = \"mail\"\nname = \"Mail\"\nrole = \"domain\"\nglyph = \"x\"\nnope = 1\n";
        std::fs::write(dir.path().join("agents.toml"), bad).unwrap();
        assert!(matches!(
            registry(dir.path()),
            Err(RegistryError::Config(_))
        ));
    }

    #[test]
    fn grants_overlay_round_trips_and_unknown_ids_are_unknown() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents/mail")).unwrap();
        let mut custom = aux_runtime::grants::default_grants("mail").unwrap();
        custom.egress_note = "stays local".to_string();
        write_grants(dir.path(), "mail", &custom).unwrap();
        let read = grants(dir.path(), "mail").unwrap();
        assert_eq!(read, custom);
        assert!(matches!(
            grants(dir.path(), "scout"),
            Err(RegistryError::UnknownAgent(_))
        ));
    }

    #[test]
    fn memory_appends_lists_and_forgets_in_its_own_directory() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents/mail")).unwrap();
        assert!(memory(dir.path(), "mail").unwrap().is_empty());
        let first = append_memory(dir.path(), "mail", "Always sign as Camille").unwrap();
        append_memory(dir.path(), "mail", "Jonas is a client").unwrap();
        let items = memory(dir.path(), "mail").unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().any(|item| item.id == first.id));
        assert!(dir.path().join("agents/mail/memory.json").is_file());
        assert!(forget_memory(dir.path(), "mail", &first.id).unwrap());
        assert_eq!(memory(dir.path(), "mail").unwrap().len(), 1);
        assert!(!forget_memory(dir.path(), "mail", "nope").unwrap());
    }
}
