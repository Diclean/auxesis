//! The skill loader.
//!
//! A skill is a Markdown file with YAML front matter under
//! `<agent dir>/skills/`. This module reads `agent.md` (with the `soul.md` /
//! `dot.toml` aliases), parses and validates each skill file, maps logical
//! tool names to wire names, and validates the typed `skill__<name>` fill
//! before the broker ever sees a call. It **fails to load, never degrades**:
//! every rejected file becomes a `skill.load_error` Ledger row.

pub mod agent;
pub mod event_time;
pub mod fill;
pub mod free_times;
pub mod frontmatter;
pub mod skill;
pub mod tool_map;

pub use agent::{
    agent_mode_layer, effective_mode, load_agent, AgentLoadError, AgentMode, AgentSource, Brain,
    LoadedAgent,
};
pub use fill::{
    skill_tool_name, tool_schema, validate_fill, FillError, RunContext, ValidatedCall,
    ValidatedFill, SKILL_TOOL_PREFIX,
};
pub use skill::{
    load_skills, Approval, LoadedSkill, OnFailure, SkillBrain, SkillInput, SkillLoad,
    SkillLoadError, Tier, Trigger, ValueType, MAX_SKILL_BYTES,
};

/// How strictly a recipient is checked before a write runs. The order is
/// fixed: `allowlist` is the strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientPolicy {
    /// Only values on the agent's allowlist.
    Allowlist,
    /// Only values present in the contact index.
    KnownContacts,
    /// Any value, because the run was approved.
    AnyWithApproval,
}

impl RecipientPolicy {
    /// Parse one of the three contract spellings.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "allowlist" => Some(RecipientPolicy::Allowlist),
            "known-contacts" => Some(RecipientPolicy::KnownContacts),
            "any-with-approval" => Some(RecipientPolicy::AnyWithApproval),
            _ => None,
        }
    }

    /// The contract spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            RecipientPolicy::Allowlist => "allowlist",
            RecipientPolicy::KnownContacts => "known-contacts",
            RecipientPolicy::AnyWithApproval => "any-with-approval",
        }
    }

    /// The strictness rank: lower is stricter.
    fn rank(self) -> u8 {
        match self {
            RecipientPolicy::Allowlist => 0,
            RecipientPolicy::KnownContacts => 1,
            RecipientPolicy::AnyWithApproval => 2,
        }
    }

    /// The stricter of two policies.
    pub fn strictest(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const AGENT_MD: &str = include_str!("fixtures/agent.md");
    const BRIEF: &str = include_str!("fixtures/skills/brief.md");
    const SEND_INVITE: &str = include_str!("fixtures/skills/send-invite.md");
    const FOLLOW_UP: &str = include_str!("fixtures/skills/follow-up.md");
    const REPLY_AVAILABILITY: &str = include_str!("fixtures/skills/reply-availability.md");
    const COLLECT_RECEIPTS: &str = include_str!("fixtures/skills/collect-receipts.md");
    const CLIENT_BRIEF: &str = include_str!("fixtures/skills/client-brief.md");
    const LOG_INTERACTION: &str = include_str!("fixtures/skills/log-interaction.md");

    fn setup(skills: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf, LoadedAgent) {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("agents").join("assistant");
        fs::create_dir_all(agent_dir.join("skills")).unwrap();
        fs::write(agent_dir.join("agent.md"), AGENT_MD).unwrap();
        for (name, text) in skills {
            fs::write(agent_dir.join("skills").join(name), text).unwrap();
        }
        let agent = agent::load_agent(&agent_dir).unwrap();
        (dir, agent_dir, agent)
    }

    /// The Phase 0 view of a Phase 1 fixture: drop `on:` and downgrade the
    /// `once_per_recipient` approval.
    fn strip_phase1(text: &str) -> String {
        let mut out = String::new();
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("on:") {
                continue;
            }
            if trimmed.starts_with("approval: once_per_recipient") {
                out.push_str("approval: each_run\n");
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn one(name: &str, text: &str) -> (tempfile::TempDir, PathBuf, LoadedAgent) {
        setup(&[(name, text)])
    }

    #[test]
    fn loader_loads_the_four_fixtures() {
        let reply = strip_phase1(REPLY_AVAILABILITY);
        let (_dir, agent_dir, agent) = setup(&[
            ("brief.md", BRIEF),
            ("send-invite.md", SEND_INVITE),
            ("follow-up.md", FOLLOW_UP),
            ("reply-availability.md", &reply),
        ]);
        let load = load_skills(&agent_dir, &agent, None);
        assert!(load.errors.is_empty(), "{:?}", load.errors);
        let names: Vec<&str> = load
            .skills
            .iter()
            .map(|skill| skill.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["brief", "follow-up", "reply-availability", "send-invite"]
        );

        let invite = load
            .skills
            .iter()
            .find(|skill| skill.name == "send-invite")
            .unwrap();
        assert_eq!(invite.version, 1);
        assert_eq!(invite.approval, Approval::EachRun);
        assert_eq!(
            invite.effective_tools,
            vec!["calendar.create_event", "mail.send"]
        );
        assert_eq!(invite.inputs.len(), 4);
        assert_eq!(invite.inputs[3].default.as_deref(), Some("30m"));
        assert_eq!(invite.skill_ref().version, "1");
        assert!(invite.trigger.manual);

        let brief = load
            .skills
            .iter()
            .find(|skill| skill.name == "brief")
            .unwrap();
        assert_eq!(brief.trigger.schedule.as_deref(), Some("0 8 * * *"));
        assert!(brief.all_tools_read_only());

        let follow = load
            .skills
            .iter()
            .find(|skill| skill.name == "follow-up")
            .unwrap();
        assert_eq!(follow.recipients_policy, RecipientPolicy::Allowlist);
    }

    #[test]
    fn b4_crm_skills_load_with_their_tools_and_approvals() {
        let (_dir, agent_dir, agent) = setup(&[
            ("client-brief.md", CLIENT_BRIEF),
            ("log-interaction.md", LOG_INTERACTION),
        ]);
        let load = load_skills(&agent_dir, &agent, None);
        assert!(load.errors.is_empty(), "{:?}", load.errors);

        let client = load
            .skills
            .iter()
            .find(|skill| skill.name == "client-brief")
            .unwrap();
        assert_eq!(client.command.as_deref(), Some("client"));
        assert_eq!(client.approval, Approval::None);
        assert!(client.all_tools_read_only());
        assert_eq!(client.effective_tools, vec!["crm.get"]);

        let log = load
            .skills
            .iter()
            .find(|skill| skill.name == "log-interaction")
            .unwrap();
        assert_eq!(log.command.as_deref(), Some("log"));
        assert_eq!(log.approval, Approval::EachRun);
        assert!(!log.all_tools_read_only());
        assert_eq!(log.effective_tools, vec!["crm.log_interaction"]);
    }

    #[test]
    fn approval_none_is_refused_when_a_tool_can_write() {
        let text =
            "---\nname: bad-none\nversion: 1\ntools: [google.gmail.send]\napproval: none\n---\n";
        assert!(
            rejection("bad-none.md", text).contains("only allowed when every tool is read-only")
        );
    }

    #[test]
    fn collect_receipts_loads_with_only_local_tools() {
        // M5-3: the shipped file loads as is; a `trigger.on` would refuse it.
        let (_dir, agent_dir, agent) = one("collect-receipts.md", COLLECT_RECEIPTS);
        let load = load_skills(&agent_dir, &agent, None);
        assert!(load.errors.is_empty(), "{:?}", load.errors);
        let skill = &load.skills[0];
        assert_eq!(skill.name, "collect-receipts");
        assert_eq!(skill.command.as_deref(), Some("collect-receipts"));
        assert_eq!(skill.brain, SkillBrain::None, "the collector is no-model");
        assert_eq!(skill.effective_tools, vec!["docs.ingest"]);
        assert!(skill.trigger.manual);
        // M5-5: a local read and ingest asks no card (owner rule 2026-10-16).
        assert_eq!(skill.approval, Approval::None);
    }

    #[test]
    fn approval_none_still_refuses_every_other_local_write() {
        // M5-5: only `docs.ingest` joins the reads; a CRM write still asks.
        for tool in [
            "crm.log_interaction",
            "crm.create_followup",
            "mail.fetch_attachments",
        ] {
            let text = format!("---\nname: n\nversion: 1\ntools: [{tool}]\napproval: none\n---\n");
            assert!(
                rejection("n.md", &text).contains("only allowed when every tool is read-only"),
                "{tool}"
            );
        }
    }

    #[test]
    fn raw_reply_availability_is_refused_in_phase_0() {
        let (_dir, agent_dir, agent) = one("reply-availability.md", REPLY_AVAILABILITY);
        let sink = kernel_broker::MemoryAuditSink::new();
        let load = load_skills(&agent_dir, &agent, Some(&sink));
        assert!(load.skills.is_empty());
        assert_eq!(load.errors.len(), 1);
        assert!(load.errors[0].reason.contains("Phase 1"));
        assert_eq!(sink.count("skill.load_error"), 1);
        let payload = &sink.payloads("skill.load_error")[0];
        assert_eq!(payload["agent"], "assistant");
        assert_eq!(payload["file"], "reply-availability.md");
        assert_eq!(payload["skill_name"], "reply-availability");
        assert_eq!(payload["skill_version"], 1);
        assert_eq!(payload["run_id"], serde_json::Value::Null);
        assert!(payload["skill_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64));
    }

    fn rejection(name: &str, text: &str) -> String {
        let (_dir, agent_dir, agent) = one(name, text);
        let load = load_skills(&agent_dir, &agent, None);
        assert!(load.skills.is_empty(), "{:?}", load.skills);
        assert_eq!(load.errors.len(), 1, "{:?}", load.errors);
        load.errors[0].reason.clone()
    }

    #[test]
    fn loader_rejects_the_contract_errors() {
        let unknown_tool = "---\nname: bad-tool\nversion: 1\ntools: [google.gmail.archive]\napproval: each_run\n---\n";
        assert!(rejection("bad-tool.md", unknown_tool).contains("unknown tool"));

        let missing_field = "---\nname: missing\nversion: 1\ntools: [google.gmail.search]\n---\n";
        assert!(
            rejection("missing.md", missing_field).contains("missing required field `approval`")
        );

        let missing_tools = "---\nname: no-tools\nversion: 1\napproval: each_run\n---\n";
        assert!(rejection("no-tools.md", missing_tools).contains("missing required field `tools`"));

        let bad_cron = "---\nname: bad-cron\nversion: 1\ntools: [google.gmail.search]\napproval: each_run\ntrigger:\n  schedule: \"61 * * * *\"\n---\n";
        assert!(rejection("bad-cron.md", bad_cron).contains("invalid cron"));

        let write_schedule = "---\nname: write-schedule\nversion: 1\ntools: [google.gmail.send]\napproval: each_run\ntrigger:\n  schedule: \"0 8 * * *\"\n---\n";
        assert!(rejection("write-schedule.md", write_schedule).contains("read-only"));

        let once = "---\nname: once\nversion: 1\ntools: [google.gmail.send]\napproval: once_per_recipient\n---\n";
        assert!(rejection("once.md", once).contains("Phase 1"));
    }

    #[test]
    fn loader_rejects_a_duplicate_command() {
        let first = "---\nname: first\nversion: 1\ncommand: shared\ntools: [google.gmail.search]\napproval: each_run\n---\n";
        let second = "---\nname: second\nversion: 1\ncommand: shared\ntools: [google.gmail.search]\napproval: each_run\n---\n";
        let (_dir, agent_dir, agent) = setup(&[("first.md", first), ("second.md", second)]);
        let load = load_skills(&agent_dir, &agent, None);
        assert!(load.skills.is_empty());
        assert_eq!(load.errors.len(), 2);
        assert!(load
            .errors
            .iter()
            .all(|err| err.reason.contains("duplicate command")));
    }

    #[test]
    fn duplicate_names_are_rejected_when_they_occur() {
        let (_dir, _agent_dir, agent) = one("send-invite.md", SEND_INVITE);
        let text =
            b"---\nname: dup\nversion: 1\ntools: [google.gmail.search]\napproval: each_run\n---\n";
        let first = skill::parse_skill(text, "a.md", "dup", &agent).unwrap();
        let second = skill::parse_skill(text, "b.md", "dup", &agent).unwrap();
        let mut load = SkillLoad::default();
        let sink = kernel_broker::MemoryAuditSink::new();
        skill::reject_duplicates(&mut load, Some(&sink), "assistant", vec![first, second]);
        assert!(load.skills.is_empty());
        assert_eq!(load.errors.len(), 2);
        assert!(load
            .errors
            .iter()
            .all(|err| err.reason.contains("duplicate skill name")));
        assert_eq!(sink.count("skill.load_error"), 2);
    }

    #[test]
    fn tool_outside_the_skill_is_rejected_before_the_broker() {
        let reply = strip_phase1(REPLY_AVAILABILITY);
        let (_dir, agent_dir, agent) = setup(&[
            ("brief.md", BRIEF),
            ("send-invite.md", SEND_INVITE),
            ("follow-up.md", FOLLOW_UP),
            ("reply-availability.md", &reply),
        ]);
        let load = load_skills(&agent_dir, &agent, None);
        let invite = load
            .skills
            .iter()
            .find(|skill| skill.name == "send-invite")
            .unwrap();
        let sink = kernel_broker::MemoryAuditSink::new();
        let value = serde_json::json!({
            "slots": { "person": "⟦PERSON_1⟧", "when": "2026-10-06T10:00:00+02:00" },
            "calls": [{ "tool": "google_gmail_search", "arguments": {} }]
        });
        let context = RunContext {
            agent: "assistant",
            run_id: "run-1",
            schemas: None,
            owner_input: None,
        };
        let err = validate_fill(invite, &value, &context, Some(&sink)).unwrap_err();
        assert!(matches!(err, FillError::RejectedTool(_)));
        assert_eq!(sink.count("skill.rejected_tool"), 1);
        let payload = &sink.payloads("skill.rejected_tool")[0];
        assert_eq!(payload["skill_name"], "send-invite");
        assert_eq!(payload["tool"], "google_gmail_search");
        assert_eq!(payload["skill_hash"], invite.hash);
    }

    #[test]
    fn every_loaded_skill_carries_the_blake3_hash_of_its_bytes() {
        let (_dir, agent_dir, agent) = one("send-invite.md", SEND_INVITE);
        let load = load_skills(&agent_dir, &agent, None);
        let skill = &load.skills[0];
        assert_eq!(
            skill.hash,
            blake3::hash(SEND_INVITE.as_bytes()).to_hex().to_string()
        );
        assert_eq!(skill.hash.len(), 64);

        let edited = SEND_INVITE.replace("Do not change the time.", "Do not change the time!");
        let (_dir2, agent_dir2, agent2) = one("send-invite.md", &edited);
        let load2 = load_skills(&agent_dir2, &agent2, None);
        assert_ne!(load2.skills[0].hash, skill.hash);
    }

    #[test]
    fn agent_tools_bound_the_effective_tools() {
        let (_dir, agent_dir, _agent) = one("send-invite.md", SEND_INVITE);
        let mut narrowed = agent::load_agent(&agent_dir).unwrap();
        narrowed.tools = vec!["google.gmail.send".to_string()];
        let load = load_skills(&agent_dir, &narrowed, None);
        assert!(load.skills.is_empty());
        assert!(load.errors[0].reason.contains("not in the agent's tools"));
    }

    #[test]
    fn recipient_policy_is_the_stricter_of_agent_and_skill() {
        let text = "---\nname: strict\nversion: 1\ntools: [google.gmail.search]\nrecipients:\n  policy: any-with-approval\napproval: each_run\n---\n";
        let (_dir, agent_dir, agent) = one("strict.md", text);
        assert_eq!(agent.recipients_policy, RecipientPolicy::KnownContacts);
        let load = load_skills(&agent_dir, &agent, None);
        assert_eq!(
            load.skills[0].recipients_policy,
            RecipientPolicy::KnownContacts
        );
    }

    #[test]
    fn effective_tools_are_the_intersection_not_the_union() {
        let (_dir, agent_dir, agent) = one("send-invite.md", SEND_INVITE);
        // The agent fixture allows nine tools; the skill declares two.
        assert!(agent.tools.len() > 2);
        assert!(agent.allows("google.gmail.search"));
        let load = load_skills(&agent_dir, &agent, None);
        let invite = &load.skills[0];
        assert_eq!(
            invite.effective_tools,
            vec!["calendar.create_event", "mail.send"]
        );
        assert!(!invite
            .effective_tools
            .contains(&"google.gmail.search".to_string()));

        // At fill time an agent-only tool is not callable: the validator uses
        // the intersection, not the union of agent and skill tools.
        let value = serde_json::json!({
            "slots": {
                "person": "⟦PERSON_1⟧",
                "when": "2026-10-06T10:00:00+02:00"
            },
            "calls": [{ "tool": "google_gmail_search", "arguments": { "query": "x" } }]
        });
        let context = RunContext {
            agent: "assistant",
            run_id: "run-1",
            schemas: None,
            owner_input: None,
        };
        let err = validate_fill(invite, &value, &context, None).unwrap_err();
        assert!(
            matches!(err, FillError::RejectedTool(_)),
            "agent-only tool must be rejected, got {err:?}"
        );
    }

    #[test]
    fn load_error_carries_the_identity_it_knows() {
        let missing_tools = "---\nname: no-tools\nversion: 7\napproval: each_run\n---\n";
        let (_dir, agent_dir, agent) = one("no-tools.md", missing_tools);
        let sink = kernel_broker::MemoryAuditSink::new();
        let load = load_skills(&agent_dir, &agent, Some(&sink));
        assert_eq!(load.errors.len(), 1);
        let payload = &sink.payloads("skill.load_error")[0];
        assert_eq!(payload["skill_name"], "no-tools");
        assert_eq!(payload["skill_version"], 7);
        assert_eq!(payload["run_id"], serde_json::Value::Null);
        assert!(payload["skill_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64));

        // A file whose front matter never parses still names its file stem.
        let broken = "not front matter at all";
        let (_dir2, agent_dir2, agent2) = one("broken.md", broken);
        let sink2 = kernel_broker::MemoryAuditSink::new();
        let load2 = load_skills(&agent_dir2, &agent2, Some(&sink2));
        assert_eq!(load2.errors.len(), 1);
        let payload2 = &sink2.payloads("skill.load_error")[0];
        assert_eq!(payload2["skill_name"], "broken");
        assert_eq!(payload2["skill_version"], serde_json::Value::Null);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_and_oversized_skill_files_are_rejected() {
        use std::os::unix::fs::symlink;
        let (_dir, agent_dir, agent) = one("send-invite.md", SEND_INVITE);
        let skills = agent_dir.join("skills");
        symlink(skills.join("send-invite.md"), skills.join("link.md")).unwrap();
        let load = load_skills(&agent_dir, &agent, None);
        let link = load
            .errors
            .iter()
            .find(|err| err.file == "link.md")
            .expect("symlink error");
        assert!(link.reason.contains("symbolic link"), "{link:?}");

        let big = format!(
            "---\nname: big\nversion: 1\ntools: [google.gmail.search]\napproval: each_run\n---\n{}",
            "x".repeat(MAX_SKILL_BYTES as usize)
        );
        fs::write(skills.join("big.md"), big).unwrap();
        let load = load_skills(&agent_dir, &agent, None);
        let big = load
            .errors
            .iter()
            .find(|err| err.file == "big.md")
            .expect("size error");
        assert!(big.reason.contains("larger than 64 KiB"), "{big:?}");
        assert!(big.skill_hash.is_none(), "too-large files carry no hash");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_skill_file_names_are_reported() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let (_dir, agent_dir, agent) = one("send-invite.md", SEND_INVITE);
        let skills = agent_dir.join("skills");
        let name = OsStr::from_bytes(b"bad\xFF.md");
        if let Err(err) = fs::write(skills.join(name), SEND_INVITE) {
            // APFS refuses a non-UTF-8 name (EILSEQ), so this host cannot hold
            // the case under test. Skip here; Linux still runs it.
            if err.raw_os_error() == Some(libc::EILSEQ) {
                eprintln!(
                    "SKIPPED non_utf8_skill_file_names_are_reported: this filesystem refuses non-UTF-8 file names (EILSEQ)"
                );
                return;
            }
            panic!("write the non-UTF-8 skill: {err}");
        }
        let load = load_skills(&agent_dir, &agent, None);
        let bad = load
            .errors
            .iter()
            .find(|err| err.reason.contains("not valid UTF-8"))
            .expect("non-UTF-8 name error");
        assert!(bad.file.contains("bad"), "{bad:?}");
    }
}
