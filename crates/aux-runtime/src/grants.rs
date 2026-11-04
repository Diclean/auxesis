//! Per-agent grants: what one agent may see and do.
//!
//! A grant is a **ceiling, never a right**: a tool an agent's grants do not
//! cover is refused before it runs, whatever the global rules say. The check
//! here is the runtime's typed decision; the daemon turns it into a per-agent
//! broker rule (deny, or an explicit ask) so the decision lands before the
//! tool body, and the broker writes the content-free `tool.decision` Ledger
//! row.
//!
//! The model is deliberately small. `see` describes data scopes (mail,
//! calendar, contacts, documents) and `do` describes skills in the form
//! `<scope>.<verb>` (`mail.send`). A tool is classified by its **underlying**
//! scope — including connector names like `google_calendar_create_event`,
//! Apple's `apple_calendar_list_events`, and MCP wire names
//! `mcp__<server>__<remote>` — so renaming or re-homing a tool cannot smuggle
//! it past a grant. A scoped tool the agent's grants do not cover is denied; a
//! scoped tool covered only at `ask` always asks. Core local tools (`read_file`,
//! `shell`, memory, fetch) are unscoped and keep their global rules.

use thiserror::Error;

/// The preset chief: every access, shown as "Aux". An agent the owner adds
/// can only get a subset of it.
pub const CHIEF_AGENT: &str = "main";

/// The chief of older installs (`default_agent = "aux"`): delegates only.
pub const LEGACY_CHIEF: &str = "aux";

/// The four domain agents, in the sidebar's order.
pub const DOMAIN_AGENTS: [&str; 4] = ["mail", "calendar", "clients", "documents"];

/// Scopes a tool can belong to. `mcp` and `connector` are the fail-closed
/// buckets for a tool of that family whose exact scope is unknown.
const SCOPES: [&str; 6] = [
    "mail",
    "calendar",
    "clients",
    "documents",
    "mcp",
    "connector",
];

/// Name prefixes that are never core local tools. This is a **secondary
/// hint only**: the authoritative origin is the registration site the turn
/// carries into [`AgentGrants::action_for_origin`].
const CONNECTOR_PREFIXES: [&str; 4] = ["google_", "apple_", "eventkit_", "mcp__"];

/// The daemon's own connector tools whose names carry a connector prefix.
/// Only these resolve their domain scope from the name; any other prefixed
/// or MCP tool needs an explicit grant (see [`AgentGrants::action_for_origin`]).
const NATIVE_CONNECTOR_TOOLS: [&str; 6] = [
    "google_calendar_create_event",
    "google_gmail_create_draft",
    "google_gmail_send",
    "apple_calendar_list_events",
    "apple_calendar_create_event",
    "apple_reminders_list",
];

/// True for a tool that is not the daemon's own: an MCP or extension tool, or
/// a connector-prefixed name the daemon does not ship. Its name never grants
/// a domain scope: a domain word in `mcp__evil__mail_send` opens nothing.
fn is_external(tool: &str, origin: Option<ToolOrigin>) -> bool {
    let lower = tool.to_ascii_lowercase();
    origin == Some(ToolOrigin::Mcp)
        || lower.starts_with("mcp__")
        || (CONNECTOR_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
            && !NATIVE_CONNECTOR_TOOLS.contains(&lower.as_str()))
}

/// Where a registered tool came from. The turn registry records this at the
/// registration site, so a connector tool cannot hide behind a name the
/// scope table does not recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOrigin {
    /// Shipped with the daemon (shell, files, memory, fetch, delegate, …).
    Builtin,
    /// A connector (mail, calendar, Google, Apple, a named service).
    Connector,
    /// An MCP server or a mounted extension/workshop tool.
    Mcp,
    /// A tool the daemon did not register itself (test seams, unknown).
    Unknown,
}

impl ToolOrigin {
    /// True only for the daemon's own tools.
    pub fn is_builtin(self) -> bool {
        matches!(self, ToolOrigin::Builtin)
    }
}

/// How much of a data scope an agent may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    /// Read it directly.
    Read,
    /// Ask the owner first.
    Ask,
    /// Not at all.
    Off,
}

impl AccessLevel {
    /// The stored lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            AccessLevel::Read => "read",
            AccessLevel::Ask => "ask",
            AccessLevel::Off => "off",
        }
    }

    /// Parse a stored label; anything unknown is `Off` (fail closed).
    pub fn parse(raw: &str) -> Self {
        match raw {
            "read" => AccessLevel::Read,
            "ask" => AccessLevel::Ask,
            _ => AccessLevel::Off,
        }
    }
}

/// How an agent may run one skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionLevel {
    /// On its own.
    Auto,
    /// Asks every time.
    Ask,
    /// Not at all.
    Off,
}

impl ActionLevel {
    /// The stored lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionLevel::Auto => "auto",
            ActionLevel::Ask => "ask",
            ActionLevel::Off => "off",
        }
    }

    /// Parse a stored label; anything unknown is `Off` (fail closed).
    pub fn parse(raw: &str) -> Self {
        match raw {
            "auto" => ActionLevel::Auto,
            "ask" => ActionLevel::Ask,
            _ => ActionLevel::Off,
        }
    }

    /// `Off` is more restrictive than `Ask`, which is more restrictive than
    /// `Auto`.
    fn rank(self) -> u8 {
        match self {
            ActionLevel::Auto => 0,
            ActionLevel::Ask => 1,
            ActionLevel::Off => 2,
        }
    }
}

/// The decision a grant produces for one tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantLevel {
    /// Run under the global rules.
    Allow,
    /// Ask the owner, whatever a broader rule says.
    Ask,
}

/// One "Can see" row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeeGrant {
    /// Data scope (`mail`, `calendar`, `contacts`, `documents`).
    pub scope: String,
    /// How it reaches the agent (`IMAP (local)`, `Address Book`, …).
    pub via: String,
    /// Read / ask / off.
    pub level: AccessLevel,
}

/// One "Can do" row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoGrant {
    /// Skill name (`mail.send`).
    pub skill: String,
    /// On its own / asks every time / off.
    pub level: ActionLevel,
}

/// Everything an agent may see and do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrants {
    /// Data scopes it can see.
    pub see: Vec<SeeGrant>,
    /// Skills it can run.
    pub can_do: Vec<DoGrant>,
    /// Scopes it must never touch.
    pub never: Vec<String>,
    /// The one green line on the profile: what stays here and what leaves.
    pub egress_note: String,
}

/// Why a tool call was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRefusalKind {
    /// The tool's scope is on the agent's `never` list.
    Never,
    /// The tool's scope is not covered by any `do` grant.
    NotGranted,
}

impl GrantRefusalKind {
    /// Stable token for the Ledger row and the model's error.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantRefusalKind::Never => "grant_never",
            GrantRefusalKind::NotGranted => "grant_not_granted",
        }
    }
}

/// A typed, content-free refusal. It names the agent and the tool, never the
/// call's arguments.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("agent `{agent}` is not granted `{tool}` ({kind:?})")]
pub struct GrantRefusal {
    /// The calling agent.
    pub agent: String,
    /// The tool it tried to call.
    pub tool: String,
    /// Why.
    pub kind: GrantRefusalKind,
}

/// The remote name under an MCP wire name `mcp__<server>__<remote>`, if any.
fn mcp_remote(tool: &str) -> Option<&str> {
    let rest = tool.strip_prefix("mcp__")?;
    match rest.rsplit_once("__") {
        Some((_, remote)) => Some(remote),
        None => Some(rest),
    }
}

/// Classify one tool by its **underlying** name: `(scope, skill)`.
///
/// Connector and MCP names are unwrapped (`mcp__server__mail_read` →
/// `mail_read`, `google_calendar_create_event` → the calendar scope) so a
/// wrapper cannot hide the scope. `None` means a core, unscoped tool.
pub fn tool_skill(tool: &str) -> Option<(&'static str, &'static str)> {
    let lower = tool.to_ascii_lowercase();
    if lower == "docs_ingest" {
        return Some(("documents", "documents.read"));
    }
    let base = mcp_remote(&lower).unwrap_or(&lower);
    let tokens: Vec<&str> = base
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    let has = |needle: &str| tokens.contains(&needle);
    let writes = has("send")
        || has("create")
        || has("update")
        || has("delete")
        || has("write")
        || has("insert")
        || has("file")
        || has("link")
        || has("export")
        || has("reply")
        || has("forward")
        || has("note");
    if has("mail") || has("gmail") || has("imap") || has("smtp") {
        let skill = if has("send") || has("reply") || has("forward") {
            "mail.send"
        } else if has("draft") {
            "mail.draft"
        } else {
            "mail.read"
        };
        return Some(("mail", skill));
    }
    if has("calendar") || has("eventkit") || has("event") || has("reminders") {
        let skill = if writes {
            "calendar.write"
        } else {
            "calendar.read"
        };
        return Some(("calendar", skill));
    }
    if has("contacts")
        || has("contact")
        || has("clients")
        || has("client")
        || has("crm")
        || has("people")
    {
        let skill = if writes {
            "clients.note"
        } else {
            "clients.read"
        };
        return Some(("clients", skill));
    }
    if has("documents")
        || has("document")
        || has("receipt")
        || has("receipts")
        || has("invoice")
        || has("invoices")
    {
        let skill = if writes {
            "documents.file"
        } else {
            "documents.read"
        };
        return Some(("documents", skill));
    }
    None
}

/// The scope a tool **name** hints at, or `None`.
///
/// This is only a hint: the granted decision is made by
/// [`AgentGrants::action_for_origin`], which denies any non-builtin tool whose
/// scope cannot be resolved even when this returns `None`.
///
/// A connector or MCP tool whose exact scope cannot be named still lands in
/// the `mcp`/`connector` bucket here, so the common wrappers are denied unless
/// the agent is explicitly granted that bucket.
pub fn tool_scope(tool: &str) -> Option<&'static str> {
    if let Some((scope, _)) = tool_skill(tool) {
        return Some(scope);
    }
    if tool.starts_with("mcp__") {
        return Some("mcp");
    }
    let lower = tool.to_ascii_lowercase();
    if CONNECTOR_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return Some("connector");
    }
    None
}

/// The scope of a skill name (`mail.send` → `mail`).
fn skill_scope(skill: &str) -> Option<&str> {
    skill.split('.').next()
}

impl AgentGrants {
    /// True when the agent's `do` list covers `scope` at all (any level but
    /// `Off`).
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.can_do.iter().any(|grant| {
            grant.level != ActionLevel::Off && skill_scope(&grant.skill) == Some(scope)
        })
    }

    /// The most restrictive level granted for one exact skill, if any.
    fn level_for_skill(&self, skill: &str) -> Option<ActionLevel> {
        self.can_do
            .iter()
            .filter(|grant| grant.skill == skill)
            .map(|grant| grant.level)
            .max_by_key(|level| level.rank())
    }

    /// The decision this agent's grants produce for one tool call, using the
    /// tool name as the scope hint.
    ///
    /// `Ask` is reported as [`GrantLevel::Ask`] so the caller can force an
    /// approval even when a broader global rule says allow.
    pub fn action_for_tool(&self, agent: &str, tool: &str) -> Result<GrantLevel, GrantRefusal> {
        if is_external(tool, None) {
            return self.action_for_external(agent, tool, None);
        }
        self.action_for_scope(agent, tool, tool_scope(tool))
    }

    /// An external tool (MCP, extension, unknown connector): only an explicit
    /// grant opens it — the exact tool name, `mcp.<server>`, or the
    /// `mcp.access` / `connector.access` bucket. Every `never` the name could
    /// match (its name, its domain word, its bucket) still refuses it.
    fn action_for_external(
        &self,
        agent: &str,
        tool: &str,
        origin: Option<ToolOrigin>,
    ) -> Result<GrantLevel, GrantRefusal> {
        let refused = |kind| {
            Err(GrantRefusal {
                agent: agent.to_string(),
                tool: tool.to_string(),
                kind,
            })
        };
        let lower = tool.to_ascii_lowercase();
        let bucket = if origin == Some(ToolOrigin::Mcp) || lower.starts_with("mcp__") {
            "mcp"
        } else {
            "connector"
        };
        let named = tool_skill(tool).map(|(scope, _)| scope);
        if self.never.iter().any(|never| {
            never == tool
                || tool.starts_with(never.as_str())
                || named == Some(never.as_str())
                || never == bucket
        }) {
            return refused(GrantRefusalKind::Never);
        }
        let server = lower
            .strip_prefix("mcp__")
            .and_then(|rest| rest.split_once("__"))
            .map(|(server, _)| format!("mcp.{server}"));
        // A per-tool grant names a wire name (`mcp__…`, `google_…`), never a
        // plain one: `delegate` as a skill must not open an MCP `delegate`.
        let wire = lower.starts_with("mcp__")
            || CONNECTOR_PREFIXES
                .iter()
                .any(|prefix| lower.starts_with(prefix));
        let level = wire
            .then(|| self.level_for_skill(tool))
            .flatten()
            .or_else(|| server.and_then(|skill| self.level_for_skill(&skill)))
            .or_else(|| {
                // The bucket: `mcp` / `connector`, or its `.access` form.
                [bucket.to_string(), format!("{bucket}.access")]
                    .iter()
                    .filter_map(|skill| self.level_for_skill(skill))
                    .max_by_key(|level| level.rank())
            });
        match level {
            Some(ActionLevel::Auto) => Ok(GrantLevel::Allow),
            Some(ActionLevel::Ask) => Ok(GrantLevel::Ask),
            _ => refused(GrantRefusalKind::NotGranted),
        }
    }

    /// The decision for one tool call, given its **registered origin** and the
    /// scope resolved for it.
    ///
    /// This is the authoritative check: any non-builtin tool whose scope cannot
    /// be resolved is refused, whatever its name looks like. A builtin keeps the
    /// name hint (core tools are unscoped and allowed).
    pub fn action_for_origin(
        &self,
        agent: &str,
        tool: &str,
        origin: ToolOrigin,
        resolved_scope: Option<&'static str>,
    ) -> Result<GrantLevel, GrantRefusal> {
        // A tool the daemon did not register itself is never trusted to
        // widen a scoped name, even when the name resolves to a granted
        // scope: it is refused outright for every agent, the chief included.
        // A builtin (the `delegate` tool) has a registered origin and is
        // unaffected.
        if origin == ToolOrigin::Unknown {
            return Err(GrantRefusal {
                agent: agent.to_string(),
                tool: tool.to_string(),
                kind: GrantRefusalKind::NotGranted,
            });
        }
        if !origin.is_builtin() && resolved_scope.is_none() {
            return Err(GrantRefusal {
                agent: agent.to_string(),
                tool: tool.to_string(),
                kind: GrantRefusalKind::NotGranted,
            });
        }
        if !origin.is_builtin() && is_external(tool, Some(origin)) {
            return self.action_for_external(agent, tool, Some(origin));
        }
        self.action_for_scope(agent, tool, resolved_scope)
    }

    fn action_for_scope(
        &self,
        agent: &str,
        tool: &str,
        scope: Option<&'static str>,
    ) -> Result<GrantLevel, GrantRefusal> {
        let refused = |kind| {
            Err(GrantRefusal {
                agent: agent.to_string(),
                tool: tool.to_string(),
                kind,
            })
        };
        if self.never.iter().any(|never| {
            never == tool || tool.starts_with(never.as_str()) || scope == Some(never.as_str())
        }) {
            return refused(GrantRefusalKind::Never);
        }
        let Some(scope) = scope else {
            return Ok(GrantLevel::Allow);
        };
        // The precise skill wins when the tool names one (`mail_send` →
        // `mail.send`), so a read grant never widens a send.
        if let Some((_, skill)) = tool_skill(tool) {
            if let Some(level) = self.level_for_skill(skill) {
                return match level {
                    ActionLevel::Off => refused(GrantRefusalKind::NotGranted),
                    ActionLevel::Ask => Ok(GrantLevel::Ask),
                    ActionLevel::Auto => Ok(GrantLevel::Allow),
                };
            }
        }
        // Scope fallback: the most restrictive grant that names this scope.
        let levels: Vec<ActionLevel> = self
            .can_do
            .iter()
            .filter(|grant| skill_scope(&grant.skill) == Some(scope))
            .map(|grant| grant.level)
            .collect();
        if levels.is_empty() || levels.contains(&ActionLevel::Off) {
            return refused(GrantRefusalKind::NotGranted);
        }
        if levels.contains(&ActionLevel::Ask) {
            return Ok(GrantLevel::Ask);
        }
        Ok(GrantLevel::Allow)
    }

    /// Check one tool call against this agent's grants.
    pub fn check_tool(&self, agent: &str, tool: &str) -> Result<(), GrantRefusal> {
        self.action_for_tool(agent, tool).map(|_| ())
    }
}

/// The built-in grants for one seed agent, or `None` for an unknown id.
pub fn default_grants(agent: &str) -> Option<AgentGrants> {
    let see = |scope: &str, via: &str, level: AccessLevel| SeeGrant {
        scope: scope.to_string(),
        via: via.to_string(),
        level,
    };
    let do_grant = |skill: &str, level: ActionLevel| DoGrant {
        skill: skill.to_string(),
        level,
    };
    let note = |text: &str| text.to_string();
    let grants = match agent {
        CHIEF_AGENT => AgentGrants {
            // No blanket `mcp`/`connector` access: an MCP or connector tool
            // whose scope cannot be named is refused, as for every agent,
            // unless the owner grants it explicitly.
            see: "mail calendar contacts clients documents"
                .split_whitespace()
                .map(|scope| see(scope, "local", AccessLevel::Read))
                .collect(),
            can_do: "delegate read_file mail.read mail.draft mail.send calendar.read \
                calendar.write clients.read clients.note documents.read documents.file"
                .split_whitespace()
                .map(|skill| do_grant(skill, ActionLevel::Auto))
                .collect(),
            never: Vec::new(),
            egress_note: note("Aux can work with your connected services; privacy and approval rules still apply."),
        },
        LEGACY_CHIEF => AgentGrants {
            see: DOMAIN_AGENTS
                .iter()
                .map(|scope| see(scope, "short results only", AccessLevel::Read))
                .collect(),
            can_do: vec![
                do_grant("delegate", ActionLevel::Auto),
                // The daemon lets the chief's local reads run with no card
                // (an unscoped, read-only builtin); the list says the same.
                // Reads of the daemon's own secrets stay refused elsewhere.
                do_grant("read_file", ActionLevel::Auto),
            ],
            never: vec![
                "mail.raw".to_string(),
                "calendar.raw".to_string(),
                "documents.raw".to_string(),
            ],
            egress_note: note("Aux never receives raw mail, files or bank lines: only the short results agents send back."),
        },
        "mail" => AgentGrants {
            see: vec![
                see("mail", "IMAP (local)", AccessLevel::Read),
                see("contacts", "Address Book", AccessLevel::Ask),
            ],
            can_do: vec![
                do_grant("mail.read", ActionLevel::Auto),
                do_grant("mail.draft", ActionLevel::Auto),
                do_grant("mail.send", ActionLevel::Ask),
            ],
            never: vec!["documents".to_string(), "calendar.raw".to_string()],
            egress_note: note(
                "Mail reads the mailbox on this Mac; only what you send leaves, through your provider.",
            ),
        },
        "calendar" => AgentGrants {
            see: vec![see("calendar", "EventKit (local)", AccessLevel::Read)],
            // `send-invite` mails the `.ics` through `mail_send`, a
            // skill-only tool, so Calendar may send behind the run's one
            // approval. Reads and drafts are off by name: the send grant must
            // not open the rest of the mail scope through the scope fallback.
            can_do: vec![
                do_grant("calendar.read", ActionLevel::Auto),
                do_grant("calendar.write", ActionLevel::Ask),
                do_grant("mail.send", ActionLevel::Ask),
                do_grant("mail.read", ActionLevel::Off),
                do_grant("mail.draft", ActionLevel::Off),
            ],
            never: vec!["documents".to_string()],
            egress_note: note("Calendar reads events on this Mac; new events and their invites ask before they are written or sent."),
        },
        "clients" => AgentGrants {
            see: vec![see("contacts", "Address Book (local)", AccessLevel::Read)],
            can_do: vec![
                do_grant("clients.read", ActionLevel::Auto),
                do_grant("clients.note", ActionLevel::Auto),
            ],
            never: vec!["documents".to_string()],
            egress_note: note("Clients reads contacts on this Mac; notes stay in the local store."),
        },
        "documents" => AgentGrants {
            see: vec![
                see("documents", "Local files", AccessLevel::Read),
                see("mail", "Mail attachments", AccessLevel::Ask),
            ],
            can_do: vec![
                do_grant("documents.read", ActionLevel::Auto),
                do_grant("documents.file", ActionLevel::Ask),
            ],
            never: Vec::new(),
            egress_note: note("Documents reads files and mail attachments on this Mac; filing asks first."),
        },
        _ => return None,
    };
    Some(grants)
}

/// The scopes a tool name can belong to, for the fail-closed fallback.
pub fn all_scopes() -> &'static [&'static str] {
    &SCOPES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_calling_a_documents_tool_is_refused() {
        let grants = default_grants("mail").unwrap();
        let refusal = grants.check_tool("mail", "documents.read").unwrap_err();
        assert_eq!(refusal.kind, GrantRefusalKind::Never);
        assert_eq!(refusal.agent, "mail");
        assert_eq!(refusal.tool, "documents.read");
        assert!(!refusal.to_string().contains("attachment"));
    }

    #[test]
    fn a_scope_without_a_do_grant_is_not_granted_not_never() {
        let mut grants = default_grants("mail").unwrap();
        grants.never.clear();
        let refusal = grants.check_tool("mail", "documents.read").unwrap_err();
        assert_eq!(refusal.kind, GrantRefusalKind::NotGranted);
    }

    #[test]
    fn mail_may_call_its_own_tools() {
        let grants = default_grants("mail").unwrap();
        assert!(grants.check_tool("mail", "mail_read").is_ok());
        assert!(grants.check_tool("mail", "mail.send").is_ok());
    }

    #[test]
    fn unscoped_tools_keep_their_global_rules() {
        let grants = default_grants("mail").unwrap();
        for tool in ["read_file", "shell", "memory", "web_fetch", "delegate"] {
            assert!(grants.check_tool("mail", tool).is_ok(), "{tool}");
        }
    }

    #[test]
    fn documents_may_read_documents_and_a_delegate_grant_is_unscoped() {
        let grants = default_grants("documents").unwrap();
        assert!(grants.check_tool("documents", "documents.file").is_ok());
        let chief = default_grants(CHIEF_AGENT).unwrap();
        assert!(chief.check_tool(CHIEF_AGENT, "delegate").is_ok());
        assert!(chief.check_tool(CHIEF_AGENT, "mail.raw").is_ok());
        // The legacy chief still hands work out and never reads raw data.
        let legacy = default_grants(LEGACY_CHIEF).unwrap();
        assert!(legacy.check_tool(LEGACY_CHIEF, "delegate").is_ok());
        assert!(legacy.check_tool(LEGACY_CHIEF, "mail.raw").is_err());
        assert!(legacy.check_tool(LEGACY_CHIEF, "mail_read").is_err());
    }

    #[test]
    fn unknown_agents_have_no_grants() {
        assert!(default_grants("scout").is_none());
        assert_eq!(tool_scope("mail_thread"), Some("mail"));
        assert_eq!(tool_scope("receipt_scan"), Some("documents"));
        assert_eq!(tool_scope("shell"), None);
    }

    #[test]
    fn google_and_mcp_tools_are_classified_by_their_underlying_scope() {
        assert_eq!(
            tool_skill("google_calendar_create_event"),
            Some(("calendar", "calendar.write"))
        );
        assert_eq!(tool_skill("google_gmail_send"), Some(("mail", "mail.send")));
        assert_eq!(
            tool_skill("apple_calendar_list_events"),
            Some(("calendar", "calendar.read"))
        );
        assert_eq!(
            tool_skill("mcp__server__mail_read"),
            Some(("mail", "mail.read"))
        );
        // A wrapped name cannot hide the scope.
        let mail = default_grants("mail").unwrap();
        assert!(mail
            .check_tool("mail", "google_calendar_create_event")
            .is_err());
        assert!(mail
            .check_tool("mail", "mcp__server__documents_read")
            .is_err());
    }

    #[test]
    fn the_chief_can_call_domain_tools_directly() {
        let chief = default_grants(CHIEF_AGENT).unwrap();
        assert!(chief.check_tool(CHIEF_AGENT, "mail_read").is_ok());
        assert!(chief
            .check_tool(CHIEF_AGENT, "google_calendar_create_event")
            .is_ok());
        assert!(chief
            .check_tool(CHIEF_AGENT, "apple_calendar_list_events")
            .is_ok());
    }

    #[test]
    fn an_unknown_connector_or_mcp_tool_is_scoped_and_refused_by_default() {
        assert_eq!(tool_scope("google_mystery_thing"), Some("connector"));
        assert_eq!(tool_scope("mcp__server__weird_tool"), Some("mcp"));
        for chief in [CHIEF_AGENT, LEGACY_CHIEF] {
            let grants = default_grants(chief).unwrap();
            assert!(grants.check_tool(chief, "google_mystery_thing").is_err());
            assert!(grants.check_tool(chief, "mcp__server__weird_tool").is_err());
        }
    }

    #[test]
    fn an_explicitly_granted_mcp_or_connector_tool_works_for_the_chief() {
        let mut chief = default_grants(CHIEF_AGENT).unwrap();
        // A domain word in an MCP name opens nothing on its own.
        assert!(chief
            .check_tool(CHIEF_AGENT, "mcp__server__mail_read")
            .is_err());
        // The owner's explicit grant opens the unknown bucket, nothing else.
        chief.can_do.push(DoGrant {
            skill: "mcp.access".to_string(),
            level: ActionLevel::Ask,
        });
        assert_eq!(
            chief.action_for_tool(CHIEF_AGENT, "mcp__server__weird_tool"),
            Ok(GrantLevel::Ask)
        );
        assert!(chief
            .check_tool(CHIEF_AGENT, "google_mystery_thing")
            .is_err());
    }

    #[test]
    fn a_connector_tool_with_an_unknown_name_is_refused_by_its_origin() {
        let mail = default_grants("mail").unwrap();
        // A name the scope table does not know: the registered origin decides.
        assert_eq!(tool_scope("notion_export_records"), None);
        let refusal = mail
            .action_for_origin("mail", "notion_export_records", ToolOrigin::Connector, None)
            .unwrap_err();
        assert_eq!(refusal.kind, GrantRefusalKind::NotGranted);
        assert_eq!(tool_scope("google-export"), None);
        assert!(mail
            .action_for_origin("mail", "google-export", ToolOrigin::Connector, None)
            .is_err());
    }

    #[test]
    fn an_unknown_origin_is_denied_for_every_agent() {
        let mail = default_grants("mail").unwrap();
        // The name resolves to the granted `mail` scope, but the origin
        // is not one the daemon registered: refused for Mail.
        assert_eq!(tool_scope("mail_read"), Some("mail"));
        assert!(mail
            .action_for_origin(
                "mail",
                "mail_read",
                ToolOrigin::Unknown,
                tool_scope("mail_read")
            )
            .is_err());
        // The chief is not exempt: an Unknown-origin call is denied even when
        // the chief holds the matching Auto grant.
        let mut chief = default_grants(CHIEF_AGENT).unwrap();
        chief.can_do.push(DoGrant {
            skill: "mail.read".to_string(),
            level: ActionLevel::Auto,
        });
        assert!(chief
            .action_for_origin(
                CHIEF_AGENT,
                "mail_read",
                ToolOrigin::Unknown,
                tool_scope("mail_read")
            )
            .is_err());
        // A registered builtin still works for the chief: the hero's
        // `delegate` tool.
        assert_eq!(
            chief
                .action_for_origin(CHIEF_AGENT, "delegate", ToolOrigin::Builtin, None)
                .unwrap(),
            GrantLevel::Allow
        );
    }

    #[test]
    fn a_builtin_tool_still_works_through_the_origin_check() {
        let mail = default_grants("mail").unwrap();
        assert_eq!(
            mail.action_for_origin("mail", "read_file", ToolOrigin::Builtin, None)
                .unwrap(),
            GrantLevel::Allow
        );
        // A wrapped MCP tool never inherits the domain grant of its name.
        assert!(mail
            .action_for_origin(
                "mail",
                "mcp__server__mail_read",
                ToolOrigin::Mcp,
                tool_scope("mcp__server__mail_read")
            )
            .is_err());
    }

    /// An MCP tool or an unknown connector whose name carries a
    /// domain word does not inherit the chief's domain grants; only an
    /// explicit per-tool, per-server or bucket grant opens it.
    #[test]
    fn an_external_tool_needs_an_explicit_grant_whatever_its_name() {
        let mut chief = default_grants(CHIEF_AGENT).unwrap();
        let cases = [
            ("mcp__evil__mail_send", ToolOrigin::Mcp),
            ("mcp__x__calendar_create", ToolOrigin::Mcp),
            ("google_mail_send_x", ToolOrigin::Connector),
        ];
        for (tool, origin) in cases {
            assert!(chief.check_tool(CHIEF_AGENT, tool).is_err(), "{tool}");
            assert!(chief
                .action_for_origin(CHIEF_AGENT, tool, origin, tool_scope(tool))
                .is_err());
        }
        // An extension registered under a plain name is still external.
        assert!(chief
            .action_for_origin(
                CHIEF_AGENT,
                "mail_send_now",
                ToolOrigin::Mcp,
                tool_scope("mail_send_now")
            )
            .is_err());
        // The daemon's own prefixed connectors keep their domain scope.
        assert!(chief
            .action_for_origin(
                CHIEF_AGENT,
                "google_gmail_send",
                ToolOrigin::Connector,
                tool_scope("google_gmail_send")
            )
            .is_ok());
        // An explicit per-tool grant opens exactly that tool.
        for (tool, _) in cases {
            chief.can_do.push(DoGrant {
                skill: tool.to_string(),
                level: ActionLevel::Ask,
            });
        }
        for (tool, origin) in cases {
            assert_eq!(
                chief.action_for_origin(CHIEF_AGENT, tool, origin, tool_scope(tool)),
                Ok(GrantLevel::Ask),
                "{tool}"
            );
        }
        assert!(chief
            .check_tool(CHIEF_AGENT, "mcp__evil__mail_read")
            .is_err());
        // A per-server grant opens that server only.
        chief.can_do.push(DoGrant {
            skill: "mcp.good".to_string(),
            level: ActionLevel::Auto,
        });
        assert_eq!(
            chief.action_for_tool(CHIEF_AGENT, "mcp__good__mail_send"),
            Ok(GrantLevel::Allow)
        );
        assert!(chief
            .check_tool(CHIEF_AGENT, "mcp__evil__mail_read")
            .is_err());
        // The bare bucket skill (`mcp`, as main read it) opens every MCP tool.
        let mut bucket = default_grants(CHIEF_AGENT).unwrap();
        bucket.can_do.push(DoGrant {
            skill: "mcp".to_string(),
            level: ActionLevel::Auto,
        });
        assert_eq!(
            bucket.action_for_tool(CHIEF_AGENT, "mcp__any__read_note"),
            Ok(GrantLevel::Allow)
        );
        assert!(bucket
            .check_tool(CHIEF_AGENT, "google_mail_send_x")
            .is_err());
        // A `never` on the domain word still refuses the explicit grant.
        chief.never.push("mail".to_string());
        assert!(chief
            .check_tool(CHIEF_AGENT, "mcp__evil__mail_send")
            .is_err());
    }

    /// ACT-FREE-GRANTS-1: the grants list the owner sees matches what is
    /// enforced. The chief's `read_file` runs with no card, so it is listed as
    /// allowed (`auto`), never `ask`.
    #[test]
    fn the_chief_grants_list_shows_read_file_as_allowed_like_the_check() {
        let chief = default_grants(CHIEF_AGENT).unwrap();
        let listed = chief
            .can_do
            .iter()
            .find(|grant| grant.skill == "read_file")
            .expect("the chief lists read_file");
        assert_eq!(listed.level, ActionLevel::Auto);
        assert_eq!(
            chief
                .action_for_origin(CHIEF_AGENT, "read_file", ToolOrigin::Builtin, None)
                .unwrap(),
            GrantLevel::Allow
        );
        // Every seeded agent: an unscoped tool it lists never shows a level
        // the check ignores.
        for agent in std::iter::once(CHIEF_AGENT).chain(DOMAIN_AGENTS.iter().copied()) {
            let grants = default_grants(agent).unwrap();
            let unscoped = grants
                .can_do
                .iter()
                .filter(|grant| !grant.skill.contains('.') && tool_scope(&grant.skill).is_none());
            for grant in unscoped {
                assert_eq!(grant.level, ActionLevel::Auto, "{agent}: {}", grant.skill);
            }
        }
    }

    #[test]
    fn an_ask_grant_is_ask_even_when_the_scope_also_has_an_auto_grant() {
        let grants = default_grants("mail").unwrap();
        // `mail.read` is auto; a send tool must still ask.
        assert_eq!(
            grants.action_for_tool("mail", "google_gmail_send").unwrap(),
            GrantLevel::Ask
        );
        assert_eq!(
            grants.action_for_tool("mail", "mail_read").unwrap(),
            GrantLevel::Allow
        );
    }
}
