//! WO-11 round 2: the runtime skills of one chat turn.
//!
//! The engine loads an agent's runtime skills, advertises one `skill__<name>`
//! tool per skill, and routes a model call named `skill__<name>` to
//! `aux_runtime::executor`. A leading `/<command>` in the owner's message
//! selects that skill for the turn.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use aux_providers::{SafeToolSpec, ToolSpec};
use aux_runtime::executor::TokenResolver;
use aux_runtime::skills::{
    load_agent, load_skills, skill_tool_name, tool_schema, Approval, LoadedSkill, SkillLoad,
};
use kernel_broker::AuditSink;
use kernel_privacy::safetext::{Gate, GateError};

/// The session's minted `(token, value)` pairs, for local rehydration.
///
/// The gate's key is a process-lifetime root (`aux_engine::outbound`), and a
/// resolver answers only for its own session: a token minted elsewhere
/// resolves to `None`, and the executor refuses the run. A private session's
/// pairs that reach a stored row are also kept in the store's `session_tokens`
/// table (SQLCipher) and loaded back when the session resumes after a restart
/// (PRIVATE-TRANSCRIPT); this map itself is memory only.
#[derive(Default, Clone)]
pub struct SessionTokenStore {
    by_token: BTreeMap<String, String>,
    /// TOK-CONSISTENT-1: a token this session minted → the carried token that
    /// already stood for its value, put back every time (`handoff::carry`).
    pub(crate) aliases: BTreeMap<String, String>,
}

impl SessionTokenStore {
    /// Keep the first value seen for a token, as the gate does.
    pub fn record(&mut self, pairs: &[(String, String)]) {
        for (token, value) in pairs {
            self.by_token
                .entry(token.clone())
                .or_insert_with(|| value.clone());
        }
    }

    /// Every token recorded, without its value.
    pub fn tokens(&self) -> std::collections::BTreeSet<String> {
        self.by_token.keys().cloned().collect()
    }

    /// The pairs a carried token may come from: never one aliased away.
    pub(crate) fn carried(&self) -> Vec<(String, String)> {
        let mut pairs = self.pairs();
        pairs.retain(|(t, _)| !self.aliases.contains_key(t));
        pairs
    }

    /// Whether no pair has been recorded.
    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }
}

impl TokenResolver for SessionTokenStore {
    fn resolve(&self, token: &str) -> Option<String> {
        self.by_token.get(token).cloned()
    }

    fn pairs(&self) -> Vec<(String, String)> {
        self.by_token
            .iter()
            .map(|(token, value)| (token.clone(), value.clone()))
            .collect()
    }
}

/// Every session's token store in this process, keyed by session id. A session's
/// tokens outlive its turns: a later turn can rehydrate what an earlier one
/// minted. Memory only; the engine stores the pairs a private row needs
/// (`session_tokens` table, PRIVATE-TRANSCRIPT), not this map.
static SESSION_TOKENS: OnceLock<Mutex<BTreeMap<i64, Arc<Mutex<SessionTokenStore>>>>> =
    OnceLock::new();

/// The token store of `session_id`, created empty on first use.
pub fn session_tokens(session_id: i64) -> Arc<Mutex<SessionTokenStore>> {
    let registry = SESSION_TOKENS.get_or_init(Default::default);
    let mut registry = kernel_core::sync::lock_recover(registry);
    Arc::clone(registry.entry(session_id).or_default())
}

/// The agent's loaded skills and its recipient allowlist.
#[derive(Default)]
pub struct RuntimeSkills {
    /// Skills that passed every loader rule.
    pub skills: Vec<LoadedSkill>,
    /// The agent's `recipients.allowlist`.
    pub allowlist: Vec<String>,
}

/// Load `<home>/agents/<agent>`'s skills, logging every load error through
/// `sink`. A missing or invalid `agent.md` loads no skill (never a partial
/// set): the loader's fail-to-load rule.
pub fn load_runtime_skills(
    home: &Path,
    agent: &str,
    sink: Option<&dyn AuditSink>,
) -> RuntimeSkills {
    let dir = crate::agent_dir(home, agent);
    let Ok(definition) = load_agent(&dir) else {
        return RuntimeSkills::default();
    };
    let load: SkillLoad = load_skills(&dir, &definition, sink);
    RuntimeSkills {
        skills: load.skills,
        allowlist: definition.recipients_allowlist,
    }
}

/// One `skill__<name>` spec per loaded skill, in loader order.
///
/// Every part is built from a skill file: the name, the description and the
/// generated schema (whose property keys are the declared input names). None of
/// it is compile-time application text, so all of it goes through the session
/// gate under the live mode and is tokenised in Private. A skill's own static
/// wording may be over-masked by the person rules; that is accepted here.
pub fn skill_specs(
    gate: &mut Gate,
    skills: &[LoadedSkill],
) -> Result<Vec<SafeToolSpec>, GateError> {
    let mut specs = Vec::with_capacity(skills.len());
    for skill in skills {
        let spec = ToolSpec::new(
            skill_tool_name(&skill.name),
            skill_description(skill),
            tool_schema(skill),
        );
        specs.push(SafeToolSpec::issue(gate, &spec)?);
    }
    Ok(specs)
}

/// The cap on a skill tool's description, in characters.
///
/// The description carries the skill's whole body, so it is bounded: a body
/// longer than this is cut on a character boundary and marked with `…`.
const SKILL_DESCRIPTION_MAX_CHARS: usize = 1200;

/// The description the model reads for a skill tool: the fixed sentence, then
/// the skill's whole body.
///
/// The model only ever reads the tool description, so a body read as a first
/// line left the rest of the instructions unseen (`send-invite`'s "Do not add
/// anyone else. Do not change the time." never reached it). The body is
/// flattened to one line and the whole description is capped.
///
/// A skill that needs no approval says so here: the model has only this
/// description, and a local skill it thinks needs permission is asked for
/// instead of run (DOC-COLLECT-2).
fn skill_description(skill: &LoadedSkill) -> String {
    let mut text = format!(
        "Run the `{}` skill (v{}). Fill its slots and list the calls.",
        skill.name, skill.version
    );
    if skill.approval == Approval::None {
        text.push_str(
            " It runs locally on this Mac and needs no approval: call it yourself, \
             never ask the owner to approve it, and report what it found.",
        );
    }
    let body = flattened_body(&skill.body);
    if !body.is_empty() {
        text.push(' ');
        text.push_str(&body);
    }
    capped_description(text)
}

/// The skill body as one line: the lines joined by single spaces, the blank
/// ones dropped, every whitespace run inside a line collapsed to one space.
///
/// `lines()` ends a line at `\n` or `\r\n`, so a CRLF file reads the same as
/// an LF one.
fn flattened_body(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if words.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&words);
    }
    out
}

/// The description, cut to [`SKILL_DESCRIPTION_MAX_CHARS`] characters on a
/// character boundary and marked with `…` when it was cut.
fn capped_description(text: String) -> String {
    if text.chars().count() <= SKILL_DESCRIPTION_MAX_CHARS {
        return text;
    }
    let mut capped: String = text.chars().take(SKILL_DESCRIPTION_MAX_CHARS - 1).collect();
    capped.push('…');
    capped
}

/// The skill an owner `/command` selects, when one does.
pub fn command_skill<'s>(input: &str, skills: &'s [LoadedSkill]) -> Option<&'s LoadedSkill> {
    let rest = input.strip_prefix('/')?;
    let command = rest.split_whitespace().next()?;
    if command.is_empty() {
        return None;
    }
    skills
        .iter()
        .find(|skill| skill.command.as_deref() == Some(command))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `send-invite` skill file, from the runtime's fixtures.
    const SEND_INVITE: &str =
        include_str!("../../aux-runtime/src/skills/fixtures/skills/send-invite.md");

    /// The agent the `send-invite` fixture needs: the two tools it declares.
    fn send_invite_agent() -> aux_runtime::skills::agent::LoadedAgent {
        aux_runtime::skills::agent::LoadedAgent {
            name: "assistant".to_string(),
            brain: aux_runtime::skills::agent::Brain::Cloud,
            default_mode: aux_runtime::skills::agent::AgentMode::Private,
            budget: None,
            channels: vec!["mac".to_string()],
            tools: vec!["calendar.create_event".to_string(), "mail.send".to_string()],
            recipients_policy: aux_runtime::skills::RecipientPolicy::KnownContacts,
            recipients_allowlist: Vec::new(),
            body: String::new(),
            source: aux_runtime::skills::agent::AgentSource::AgentMd,
            dir: std::path::PathBuf::new(),
        }
    }

    /// The `send-invite` skill as the loader reads it.
    fn send_invite_skill() -> LoadedSkill {
        aux_runtime::skills::skill::parse_skill(
            SEND_INVITE.as_bytes(),
            "send-invite.md",
            "send-invite",
            &send_invite_agent(),
        )
        .expect("the send-invite fixture parses")
    }

    /// A minimal loaded skill whose body carries `body`.
    fn loaded_skill_with_body(name: &str, body: &str) -> LoadedSkill {
        LoadedSkill {
            name: name.to_string(),
            version: 1,
            command: None,
            brain: aux_runtime::skills::SkillBrain::Agent,
            trigger: aux_runtime::skills::Trigger {
                manual: true,
                schedule: None,
                on: None,
            },
            tools: Vec::new(),
            effective_tools: Vec::new(),
            inputs: Vec::new(),
            recipients_policy: aux_runtime::skills::RecipientPolicy::KnownContacts,
            approval: aux_runtime::skills::Approval::EachRun,
            on_failure: aux_runtime::skills::OnFailure::Stop,
            body: body.to_string(),
            hash: "0".repeat(64),
            file: format!("{name}.md"),
        }
    }

    #[test]
    fn command_skill_matches_the_declared_command() {
        let skill = |name: &str, command: Option<&str>| LoadedSkill {
            name: name.to_string(),
            version: 1,
            command: command.map(str::to_string),
            brain: aux_runtime::skills::SkillBrain::Agent,
            trigger: aux_runtime::skills::Trigger {
                manual: true,
                schedule: None,
                on: None,
            },
            tools: Vec::new(),
            effective_tools: Vec::new(),
            inputs: Vec::new(),
            recipients_policy: aux_runtime::skills::RecipientPolicy::KnownContacts,
            approval: aux_runtime::skills::Approval::EachRun,
            on_failure: aux_runtime::skills::OnFailure::Stop,
            body: "Body.".to_string(),
            hash: "0".repeat(64),
            file: format!("{name}.md"),
        };
        let skills = vec![skill("send-invite", Some("invite")), skill("brief", None)];
        assert_eq!(
            command_skill("/invite Camille", &skills).map(|skill| skill.name.as_str()),
            Some("send-invite")
        );
        assert!(command_skill("/unknown x", &skills).is_none());
        assert!(command_skill("hello", &skills).is_none());
    }

    #[test]
    fn a_session_keeps_its_tokens_across_turns() {
        let first = session_tokens(9_001);
        kernel_core::sync::lock_recover(&first)
            .record(&[("EMAIL_9".to_string(), "x@b.fr".to_string())]);
        let later = session_tokens(9_001);
        assert_eq!(
            kernel_core::sync::lock_recover(&later)
                .resolve("EMAIL_9")
                .as_deref(),
            Some("x@b.fr")
        );
        assert!(session_tokens(9_002).lock().unwrap().is_empty());
    }

    #[test]
    fn session_tokens_resolve_only_what_they_recorded() {
        let mut store = SessionTokenStore::default();
        assert!(store.is_empty());
        store.record(&[("EMAIL_1".to_string(), "a@b.fr".to_string())]);
        store.record(&[("EMAIL_1".to_string(), "other@b.fr".to_string())]);
        assert_eq!(store.resolve("EMAIL_1").as_deref(), Some("a@b.fr"));
        assert_eq!(store.resolve("EMAIL_2"), None);
        assert_eq!(store.pairs().len(), 1);
    }

    #[test]
    fn a_skill_description_is_tokenised_on_the_private_gate() {
        // A skill's description comes from its body, a user-editable file: it
        // is never application text, so the session gate tokenises it under
        // Private. An e-mail or a phone in it must not reach the provider raw.
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        let mut gate =
            Gate::for_tests(&grant, [4u8; 32], aux_providers::test_gate::names_checked());
        let skills = vec![loaded_skill_with_body(
            "contact",
            "Write to owner@example.com or call +33 6 12 34 56 78.\n",
        )];

        let specs = skill_specs(&mut gate, &skills).unwrap();

        let description = specs[0].description().as_str();
        assert!(!description.contains("owner@example.com"), "{description}");
        assert!(!description.contains("+33 6 12 34 56 78"), "{description}");
        assert!(description.contains('⟦'), "{description}");
    }

    /// The acceptance test of SKILL-FIRST-LINE: the model reads the skill's
    /// whole body, not its first line. The `send-invite` fixture's second
    /// line carries the rules that decide the mail ("Do not add anyone else.
    /// Do not change the time."); before, only the first line reached the
    /// model.
    #[test]
    fn a_skill_description_carries_the_whole_body() {
        let description = skill_description(&send_invite_skill());
        assert!(
            description.contains("Do not add anyone else. Do not change the time."),
            "{description}"
        );
        assert!(
            description.contains("Create a {duration} event"),
            "{description}"
        );
        // One line: the body is flattened, so the model reads it whole.
        assert!(!description.contains('\n'), "{description}");
        assert!(!description.contains('\r'), "{description}");
    }

    #[test]
    fn an_empty_body_leaves_the_fixed_sentence_alone() {
        let skill = loaded_skill_with_body("demo", "");
        assert_eq!(
            skill_description(&skill),
            "Run the `demo` skill (v1). Fill its slots and list the calls."
        );
    }

    #[test]
    fn a_body_of_blank_lines_leaves_the_fixed_sentence_alone() {
        let skill = loaded_skill_with_body("demo", "\n\n   \n\t\n\r\n");
        assert_eq!(
            skill_description(&skill),
            "Run the `demo` skill (v1). Fill its slots and list the calls."
        );
    }

    #[test]
    fn a_long_body_is_capped_and_marked() {
        let body = "word ".repeat(1000);
        let description = skill_description(&loaded_skill_with_body("demo", &body));
        assert!(
            description.chars().count() <= SKILL_DESCRIPTION_MAX_CHARS,
            "{}",
            description.chars().count()
        );
        assert!(description.ends_with('…'), "{description}");
    }

    #[test]
    fn the_cap_cuts_on_a_character_boundary() {
        let fixed = skill_description(&loaded_skill_with_body("demo", ""));
        // The last character kept is a two-byte `é`, the one after it a
        // four-byte emoji: a cut on a byte boundary would split them.
        let kept = SKILL_DESCRIPTION_MAX_CHARS - 1 - fixed.chars().count() - 1;
        let body = format!("{}é🎉{}", "a".repeat(kept - 1), "z".repeat(20));
        let description = skill_description(&loaded_skill_with_body("demo", &body));
        assert_eq!(description.chars().count(), SKILL_DESCRIPTION_MAX_CHARS);
        assert!(description.ends_with("é…"), "{description}");
    }

    #[test]
    fn a_crlf_body_is_flattened() {
        let skill = loaded_skill_with_body("demo", "First line.\r\nSecond line.\r\n");
        let description = skill_description(&skill);
        assert!(
            description.contains("First line. Second line."),
            "{description}"
        );
        assert!(!description.contains('\r'), "{description}");
    }

    #[test]
    fn the_whole_body_goes_through_the_gate() {
        // The body is one string through the same gate call as the sentence:
        // a value on the second line is masked like one on the first.
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        let mut gate =
            Gate::for_tests(&grant, [4u8; 32], aux_providers::test_gate::names_checked());
        let skills = vec![loaded_skill_with_body(
            "contact",
            "First line, no value here.\nWrite to owner@example.com for the rest.\n",
        )];

        let specs = skill_specs(&mut gate, &skills).unwrap();

        let description = specs[0].description().as_str();
        assert!(!description.contains("owner@example.com"), "{description}");
        assert!(description.contains('⟦'), "{description}");
        assert!(
            description.contains("First line, no value here."),
            "{description}"
        );
    }
}
