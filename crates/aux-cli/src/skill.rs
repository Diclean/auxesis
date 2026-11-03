//! `aux skill` — list, dry-run and run an agent's skills.
//!
//! `list` and `test` are read-only and execute nothing. `run` executes one
//! skill through `aux_runtime::executor`: it validates a model fill, rehydrates
//! real values from the vault, asks the owner once on the terminal, then calls
//! the Google connector. The fill is supplied as the JSON the model would have
//! produced (`{ "slots": { … }, "calls": [ … ] }`); forcing the
//! `skill__<name>` tool inside a provider turn lands with the engine wiring.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aux_runtime::executor::SkillContext;
use aux_runtime::executor::{
    default_approval_timeout, session_token_map, ApprovalCard, Clock, ConnectorError, Executor,
    RealClock, RecipientDirectory, RunDecision, RunOutcome, RunStop, SkillApprover, SkillConnector,
};
#[cfg(feature = "google")]
use aux_runtime::skills::tool_map;
use aux_runtime::skills::{
    validate_fill, LoadedAgent, LoadedSkill, RunContext, SkillLoad, ValidatedFill,
};
use aux_store::{Store, StoreHandle};
use clap::{Args, Subcommand};
use kernel_broker::{
    ApprovalRequest, Approver, ApproverError, AuditSink, Broker, SkillOnlyLookup, Taint,
};
#[cfg(feature = "google")]
use kernel_broker::{NativeTool, ToolCtx};
use kernel_core::{clean_field, ensure_home, Config, SandboxHome};
use kernel_privacy::{TokenMap, Vault};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

/// `aux skill <list|test|run>`.
#[derive(Debug, Args)]
pub struct SkillArgs {
    /// Agent whose skills are read (default: `main`).
    #[arg(long, value_name = "AGENT", default_value = "main")]
    pub agent: String,
    #[command(subcommand)]
    pub action: SkillAction,
}

#[derive(Debug, Subcommand)]
pub enum SkillAction {
    /// List the agent's loaded skills.
    List,
    /// Render one skill's definition and fill schema; execute nothing.
    Test {
        /// Skill name (the file stem).
        name: String,
        /// Free text for the dry run; shown back, never executed.
        text: String,
    },
    /// Run one skill with a model fill (the `skill__<name>` JSON).
    Run {
        /// Skill name (the file stem).
        name: String,
        /// The model fill as JSON: `{ "slots": { … }, "calls": [ … ] }`, or
        /// `@<path>` to read it from a file and keep client data out of argv.
        text: String,
    },
}

/// Run `aux skill`.
pub fn run(args: SkillArgs) -> ExitCode {
    let home = kernel_core::auxesis_home();
    let agent_dir = aux_engine::agent_dir(&home, &args.agent);
    let agent = match aux_runtime::skills::load_agent(&agent_dir) {
        Ok(agent) => agent,
        Err(err) => {
            eprintln!("aux skill: {err}");
            return ExitCode::FAILURE;
        }
    };
    let load = aux_runtime::skills::load_skills(&agent_dir, &agent, None);
    for err in &load.errors {
        eprintln!("aux skill: {err}");
    }
    let agent_name = args.agent.clone();
    match args.action {
        SkillAction::List => {
            list(&load);
            ExitCode::SUCCESS
        }
        SkillAction::Test { name, text } => test(&load, &name, &text),
        SkillAction::Run { name, text } => {
            run_skill(&home, &agent_dir, &load, &agent, &agent_name, &name, &text)
        }
    }
}

fn list(load: &aux_runtime::skills::SkillLoad) {
    if load.skills.is_empty() {
        println!("no skills loaded");
        return;
    }
    println!("NAME\tVERSION\tCOMMAND\tAPPROVAL\tTOOLS");
    for skill in &load.skills {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            skill.name,
            skill.version,
            skill.command.as_deref().unwrap_or("-"),
            skill.approval.as_str(),
            skill.effective_tools.join(",")
        );
    }
}

fn test(load: &aux_runtime::skills::SkillLoad, name: &str, text: &str) -> ExitCode {
    let Some(skill) = load.skills.iter().find(|skill| skill.name == name) else {
        eprintln!("aux skill test: unknown skill `{name}`");
        return ExitCode::FAILURE;
    };
    println!(
        "skill {} v{} (blake3 {})",
        skill.name, skill.version, skill.hash
    );
    println!("command: {}", skill.command.as_deref().unwrap_or("-"));
    println!("approval: {}", skill.approval.as_str());
    println!("recipients: {}", skill.recipients_policy.as_str());
    println!(
        "trigger: manual={} schedule={} on={}",
        skill.trigger.manual,
        skill.trigger.schedule.as_deref().unwrap_or("-"),
        skill.trigger.on.as_deref().unwrap_or("-")
    );
    println!("tools: {}", skill.effective_tools.join(", "));
    for input in &skill.inputs {
        println!(
            "input {}: type={} tier={:?} default={}",
            input.name,
            input.value_type.as_str(),
            input.tier,
            input.default.as_deref().unwrap_or("-")
        );
    }
    println!("text: {}", clean_field(text));
    println!(
        "tool: {}",
        aux_runtime::skills::skill_tool_name(&skill.name)
    );
    println!("schema: {}", aux_runtime::skills::tool_schema(skill));
    ExitCode::SUCCESS
}

/// Everything the executor needs for one CLI run besides the fill.
struct RunDeps<'a> {
    broker: &'a Broker,
    sink: &'a dyn AuditSink,
    approver: &'a dyn SkillApprover,
    connector: &'a dyn SkillConnector,
    stop: &'a dyn RunStop,
    allowlist: &'a [String],
    directory: &'a dyn RecipientDirectory,
    clock: &'a dyn Clock,
}

/// Validate a model fill and run it through the executor. The CLI and its
/// tests both come through here, so the operator rules, STOP and the
/// approval channel are the same in both.
async fn execute_fill(
    deps: &RunDeps<'_>,
    skill: &LoadedSkill,
    value: &serde_json::Value,
    run: &RunContext<'_>,
    tokens: &TokenMap,
) -> Result<RunOutcome, String> {
    let fill: ValidatedFill =
        validate_fill(skill, value, run, Some(deps.sink)).map_err(|err| err.to_string())?;
    let executor = Executor {
        broker: deps.broker,
        sink: deps.sink,
        approver: deps.approver,
        connector: deps.connector,
        directory: deps.directory,
        allowlist: deps.allowlist,
        clock: deps.clock,
        stop: deps.stop,
        approval_timeout: default_approval_timeout(),
    };
    Ok(executor
        .execute(skill, &fill, run, tokens, &Taint::Clean)
        .await)
}

/// The STOP switch of this home (see `README.md`): the same marker the daemon,
/// the chat and the brief honour.
struct KillSwitch {
    home: std::path::PathBuf,
}

impl RunStop for KillSwitch {
    fn is_stopped(&self) -> bool {
        kernel_core::killswitch::is_stopped(&self.home)
    }
}

/// The operator's `[[rules]]`, loaded from the verified home's `config.toml`
/// exactly as `aux chat` and the daemon load them.
fn operator_rules(verified: &SandboxHome) -> Result<Vec<kernel_broker::Rule>, String> {
    let path = verified.real_path().map_err(|err| err.to_string())?;
    aux_engine::load_rules(&path.join("config.toml")).map_err(|err| err.to_string())
}

/// Execute one skill for real: validate → rehydrate → approve → broker →
/// connector → Ledger, with no retry.
fn run_skill(
    home: &Path,
    agent_dir: &Path,
    load: &SkillLoad,
    agent: &LoadedAgent,
    agent_name: &str,
    name: &str,
    text: &str,
) -> ExitCode {
    let Some(skill) = load.skills.iter().find(|skill| skill.name == name) else {
        eprintln!("aux skill run: unknown skill `{name}`");
        return ExitCode::FAILURE;
    };
    // `@<path>`: a fill holds client data, and argv is visible in process
    // listings, so callers can hand it over in a file instead.
    let text = match text.strip_prefix('@') {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("aux skill run: cannot read the fill file `{path}`: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => text.to_owned(),
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(err) => {
            eprintln!(
                "aux skill run: `<text>` must be the model fill JSON `{{ \"slots\": {{ … }}, \"calls\": [ … ] }}`: {err}"
            );
            return ExitCode::FAILURE;
        }
    };

    let verified = match ensure_home(home) {
        Ok(verified) => verified,
        Err(err) => {
            eprintln!("aux skill run: {err}");
            return ExitCode::FAILURE;
        }
    };
    let config = match Config::load_or_create_verified(&verified) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("aux skill run: {err}");
            return ExitCode::FAILURE;
        }
    };
    let rules = match operator_rules(&verified) {
        Ok(rules) => rules,
        Err(err) => {
            eprintln!("aux skill run: {err}");
            return ExitCode::FAILURE;
        }
    };
    let store = match Store::open_verified(&verified) {
        Ok(store) => Arc::new(Mutex::new(store)),
        Err(err) => {
            eprintln!("aux skill run: {err}");
            return ExitCode::FAILURE;
        }
    };
    // The Ledger sink is the store's own kernel sink, so `skill.*` rows land in
    // the same journal the daemon writes.
    let Some(sink): Option<Arc<dyn AuditSink>> =
        StoreHandle::Shared(Arc::clone(&store)).audit_sink()
    else {
        eprintln!("aux skill run: the store has no audit sink");
        return ExitCode::FAILURE;
    };

    // The run-level card is the owner's approval; the broker's per-call ask is
    // pre-approved so the owner is asked exactly once. The operator's rules
    // apply here as they do in the daemon: a `deny` stops the run.
    let broker = Broker::new(
        Arc::clone(&sink),
        rules,
        Arc::new(PreApproved),
        Arc::new(SkillOnlyTools),
    );

    // B4: Google is optional here: a CRM or docs skill runs without a
    // connection, and a Google skill still refuses cleanly when the connector
    // is absent. The CRM connector is always mounted; every CRM read and the
    // `log-interaction` write are local.
    #[cfg(feature = "google")]
    let connector = {
        let connection = aux_google::MacConnection::at(home);
        let google = if connection.connected() {
            let client = match connection.client() {
                Ok(client) => client,
                Err(err) => {
                    eprintln!("aux skill run: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let tools = match aux_google::tools::GoogleTools::new(
                Arc::new(client),
                Arc::clone(&store),
                config.budgets,
            ) {
                Ok(google) => google,
                Err(err) => {
                    eprintln!("aux skill run: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let context = SkillContext::from_loaded(skill);
            Some(GoogleConnector {
                tools: tools.skill_tools_for(&aux_google::tools::SkillContext {
                    name: context.name.clone(),
                    version: context.version,
                    hash: context.hash.clone(),
                }),
                ctx: ToolCtx::new(agent_name, agent_dir.join("workspace")),
            })
        } else {
            None
        };
        CliConnector {
            google,
            crm: auxd::crm::CrmSkillConnector::new(home, agent_name, Arc::clone(&store)),
            docs: docs_connector(home, &store),
        }
    };
    #[cfg(not(feature = "google"))]
    let connector = {
        // Only the Google connector needs these in the default build.
        let _ = agent_dir;
        let _ = &config.budgets;
        CliConnector {
            crm: auxd::crm::CrmSkillConnector::new(home, agent_name, Arc::clone(&store)),
            docs: docs_connector(home, &store),
        }
    };

    let vault = match Vault::open(home.join("vault")) {
        Ok(vault) => vault,
        Err(err) => {
            eprintln!("aux skill run: {err}");
            return ExitCode::FAILURE;
        }
    };
    let run_id = format!(
        "skill-{}-{}",
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    );
    let approver = TerminalApprover::stdin();
    let killswitch = KillSwitch {
        home: home.to_path_buf(),
    };
    let deps = RunDeps {
        broker: &broker,
        sink: sink.as_ref(),
        approver: &approver,
        connector: &connector,
        stop: &killswitch,
        allowlist: &agent.recipients_allowlist,
        directory: &EmptyDirectory,
        clock: &RealClock,
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("aux skill run: {err}");
            return ExitCode::FAILURE;
        }
    };
    let outcome = runtime.block_on(async {
        let run = RunContext {
            agent: agent_name,
            run_id: &run_id,
            schemas: None,
            owner_input: None,
        };
        let tokens = session_token_map(&vault, &run_id).map_err(|err| err.to_string())?;
        execute_fill(&deps, skill, &value, &run, &tokens).await
    });
    // A timed-out read may still be parked on stdin: do not wait for it.
    runtime.shutdown_background();
    match outcome {
        Ok(RunOutcome::Done { actions }) => {
            println!(
                "skill `{name}` ran {} action(s); nothing was retried",
                actions.len()
            );
            ExitCode::SUCCESS
        }
        Ok(RunOutcome::Refused { reason, .. }) => {
            eprintln!("skill `{name}` refused: {reason}");
            ExitCode::FAILURE
        }
        Ok(RunOutcome::Timeout) => {
            eprintln!("skill `{name}` timed out; nothing was sent");
            ExitCode::FAILURE
        }
        Ok(RunOutcome::Failed { error }) => {
            eprintln!("skill `{name}` failed: {error}");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("aux skill run: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The broker's per-call approver for a skill run: the run-level card was the
/// owner's approval, so each call is already approved.
struct PreApproved;

#[async_trait]
impl Approver for PreApproved {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }
}

/// The two skill-only tools, by wire name, for the broker's hardline floor.
struct SkillOnlyTools;

impl SkillOnlyLookup for SkillOnlyTools {
    fn is_skill_only(&self, tool: &str) -> bool {
        matches!(
            tool,
            "google_gmail_send"
                | "google_calendar_create_event"
                | "mail_send"
                | "apple_calendar_create_event"
                | "crm_create_followup"
                | "crm_log_interaction"
        )
    }
}

/// The CLI's `known-contacts` directory is empty: the daemon's contact index is
/// not available here, so a `known-contacts` skill refuses a recipient on the
/// CLI. `allowlist` and `any-with-approval` work as documented.
struct EmptyDirectory;

impl RecipientDirectory for EmptyDirectory {
    fn is_known(&self, _value: &str) -> bool {
        false
    }
}

/// Show the card on stderr and read the answer from the terminal. Anything but
/// `y`, `yes`, `o` or `oui` is a refusal.
///
/// The read is async, so the executor's clock races it on the same runtime
/// (P2-2): no answer within the timeout is `timeout` and nothing runs. A late
/// answer is read by nobody, because the future that reads it was dropped.
struct TerminalApprover<R> {
    input: tokio::sync::Mutex<R>,
}

impl TerminalApprover<BufReader<tokio::io::Stdin>> {
    /// The approver on the process's stdin.
    fn stdin() -> Self {
        TerminalApprover {
            input: tokio::sync::Mutex::new(BufReader::new(tokio::io::stdin())),
        }
    }
}

#[async_trait]
impl<R> SkillApprover for TerminalApprover<R>
where
    R: AsyncBufRead + Unpin + Send,
{
    async fn decide(&self, card: &ApprovalCard) -> RunDecision {
        show_card(&mut std::io::stderr().lock(), card);
        let mut line = String::new();
        let mut input = self.input.lock().await;
        match input.read_line(&mut line).await {
            Ok(0) | Err(_) => RunDecision::Refused,
            Ok(_)
                if matches!(
                    line.trim().to_ascii_lowercase().as_str(),
                    "y" | "yes" | "o" | "oui"
                ) =>
            {
                RunDecision::approved()
            }
            Ok(_) => RunDecision::Refused,
        }
    }
}

/// The approval card as the owner reads it on the terminal (real values, local
/// only, and the tokenised form the model saw).
fn show_card(out: &mut impl Write, card: &ApprovalCard) {
    let _ = writeln!(
        out,
        "[skill] {} v{} — {}",
        card.skill_name, card.skill_version, card.reason
    );
    for call in &card.calls {
        let _ = writeln!(out, "  {} real (local): {}", call.tool, call.real_arguments);
        let _ = writeln!(
            out,
            "  {} what the model saw: {}",
            call.tool, call.token_arguments
        );
    }
    let _ = writeln!(out, "  countdown: {}s", card.countdown_secs);
    let _ = write!(out, "  approve? [y/N] ");
    let _ = out.flush();
}

/// The CLI's connector over the bound Google skill-only writes.
#[cfg(feature = "google")]
struct GoogleConnector {
    tools: Vec<Box<dyn NativeTool>>,
    ctx: ToolCtx,
}

#[cfg(feature = "google")]
#[async_trait]
impl SkillConnector for GoogleConnector {
    async fn call(
        &self,
        _skill: &SkillContext,
        logical: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, ConnectorError> {
        let wire = tool_map::wire_name(logical)
            .ok_or_else(|| ConnectorError::new(format!("unknown tool `{logical}`")))?;
        let tool = self
            .tools
            .iter()
            .find(|tool| tool.name() == wire)
            .ok_or_else(|| ConnectorError::new(format!("no connector for `{wire}`")))?;
        let output = tool
            .as_ref()
            .run(arguments, &self.ctx)
            .await
            .map_err(|err| ConnectorError::new(err.to_string()))?;
        if output.is_error {
            return Err(ConnectorError::new(output.content));
        }
        Ok(serde_json::json!({ "content": output.content }))
    }
}

/// The CLI's one skill connector: the CRM connector always, plus Google when
/// this Mac holds an authorization. A logical tool neither serves is refused.
struct CliConnector {
    #[cfg(feature = "google")]
    google: Option<GoogleConnector>,
    crm: auxd::crm::CrmSkillConnector,
    /// The local receipts collector, when the home configures a mailbox.
    docs: Option<auxd::skill_executor::DocsSkillConnector>,
}

/// The `docs.ingest` collector over the home's configured mailbox, the same
/// connector the daemon mounts on a turn; `None` without a mailbox, so a
/// collect run refuses cleanly instead of reading nothing.
fn docs_connector(
    home: &Path,
    store: &Arc<Mutex<Store>>,
) -> Option<auxd::skill_executor::DocsSkillConnector> {
    let mail = crate::mail::configured_service(home)?;
    Some(auxd::skill_executor::DocsSkillConnector::new(
        home,
        Arc::clone(store),
        Arc::new(mail),
    ))
}

#[async_trait]
impl SkillConnector for CliConnector {
    async fn call(
        &self,
        skill: &SkillContext,
        logical: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, ConnectorError> {
        if logical.starts_with("crm.") {
            return self.crm.call(skill, logical, arguments).await;
        }
        if logical == "docs.ingest" {
            let Some(docs) = &self.docs else {
                return Err(ConnectorError::new(
                    "no mailbox is configured to collect receipts from",
                ));
            };
            return docs.call(skill, logical, arguments).await;
        }
        if logical == "docs.queue" {
            // The documents queue is the empty C4 hook; `brief` reads it beside
            // the CRM section. Nothing is written here.
            return Ok(serde_json::json!({ "items": [] }));
        }
        #[cfg(feature = "google")]
        if let Some(google) = &self.google {
            return google.call(skill, logical, arguments).await;
        }
        Err(ConnectorError::new(format!("no connector for `{logical}`")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use aux_runtime::executor::{Clock, NeverStopped, SkillContext};
    use aux_runtime::skills::agent::{AgentMode, AgentSource, Brain, LoadedAgent};
    use aux_runtime::skills::skill::parse_skill;
    use aux_runtime::skills::RecipientPolicy;
    use kernel_privacy::TokenMap;
    use serde_json::json;
    use tokio::io::AsyncWriteExt;

    const SEND_INVITE: &str =
        include_str!("../../aux-runtime/src/skills/fixtures/skills/send-invite.md");

    /// The clock is already up: silence reaches the timeout at once, with no
    /// real sleep.
    struct ImmediateClock;

    #[async_trait]
    impl Clock for ImmediateClock {
        async fn sleep(&self, _duration: Duration) {}
    }

    /// Counts the connector calls the executor actually makes.
    #[derive(Default)]
    struct CountingConnector(AtomicUsize);

    #[async_trait]
    impl SkillConnector for CountingConnector {
        async fn call(
            &self,
            _skill: &SkillContext,
            _logical: &str,
            _arguments: &serde_json::Value,
        ) -> Result<serde_json::Value, ConnectorError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "ok": true }))
        }

        /// One configured mailbox, so a send's account resolves before the card.
        fn account_ids(&self) -> Vec<String> {
            vec!["personal".to_string()]
        }
    }

    /// The test address is a known contact.
    struct KnownContact;

    impl RecipientDirectory for KnownContact {
        fn is_known(&self, value: &str) -> bool {
            value == "camille@exemple.fr"
        }

        fn addresses_for_name(&self, name: &str) -> Vec<String> {
            if name == "Camille Exemple" {
                vec!["camille@exemple.fr".to_string()]
            } else {
                Vec::new()
            }
        }

        /// The one spelling this contact is known by, as the production
        /// `ContactIndex` enumerates it. The sealed fix derives a recipient
        /// only from these groups, so a directory that omits them is refused.
        fn name_groups(&self) -> Vec<Vec<String>> {
            vec![vec!["Camille Exemple".to_string()]]
        }
    }

    fn agent() -> LoadedAgent {
        LoadedAgent {
            name: "assistant".to_string(),
            brain: Brain::Cloud,
            default_mode: AgentMode::Private,
            budget: None,
            channels: Vec::new(),
            tools: vec![
                "google.calendar.create_event".to_string(),
                "google.gmail.send".to_string(),
                // MA4: the fixture now declares the EventKit create and SMTP send.
                "calendar.create_event".to_string(),
                "mail.send".to_string(),
            ],
            recipients_policy: RecipientPolicy::KnownContacts,
            recipients_allowlist: Vec::new(),
            body: String::new(),
            source: AgentSource::AgentMd,
            dir: std::path::PathBuf::from("/tmp/assistant"),
        }
    }

    /// The send-invite fill both tests run. `email` is derived from `person`, so
    /// every recipient field carries that value and the runtime resolves it.
    /// The times carry no offset, so the owner's zone reads them on any machine.
    fn invite_fill() -> serde_json::Value {
        json!({
            "slots": {
                "person": "Camille Exemple",
                "when": "2026-10-11T10:00:00+02:00"
            },
            "calls": [
                {
                    "tool": "apple_calendar_create_event",
                    "arguments": {
                        "title": "Meeting with Camille Exemple",
                        "start": "2026-10-11T10:00:00",
                        "end": "2026-10-11T10:30:00"
                    }
                },
                {
                    "tool": "mail_send",
                    "arguments": {
                        "to": ["Camille Exemple"],
                        "subject": "Invitation",
                        "body": "See you.",
                        "ics": "event"
                    }
                }
            ]
        })
    }

    /// Answers yes at once, like the owner typing `y`.
    struct AlwaysYes;

    #[async_trait]
    impl SkillApprover for AlwaysYes {
        async fn decide(&self, _card: &ApprovalCard) -> RunDecision {
            RunDecision::approved()
        }
    }

    /// Run the CLI's own execution path (`execute_fill`) for the invite fill.
    async fn run_with(
        approver: &dyn SkillApprover,
        connector: &CountingConnector,
        sink: &Arc<kernel_broker::MemoryAuditSink>,
        rules: Vec<kernel_broker::Rule>,
        stop: &dyn RunStop,
        clock: &dyn Clock,
    ) -> Result<RunOutcome, String> {
        let skill = parse_skill(
            SEND_INVITE.as_bytes(),
            "send-invite.md",
            "send-invite",
            &agent(),
        )
        .unwrap();
        let run = RunContext {
            agent: "assistant",
            run_id: "cli-test",
            schemas: None,
            owner_input: Some("Send the invitation to Camille Exemple."),
        };
        let broker = Broker::new(
            Arc::clone(sink) as Arc<dyn AuditSink>,
            rules,
            Arc::new(PreApproved),
            Arc::new(SkillOnlyTools),
        );
        let deps = RunDeps {
            broker: &broker,
            sink: sink.as_ref(),
            approver,
            connector,
            stop,
            allowlist: &[],
            directory: &KnownContact,
            clock,
        };
        execute_fill(&deps, &skill, &invite_fill(), &run, &TokenMap::default()).await
    }

    /// The `[[rules]]` of a config file, loaded by the same parser the CLI uses.
    fn rules_from(text: &str) -> Vec<kernel_broker::Rule> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        aux_engine::load_rules(&path).unwrap()
    }

    /// The operator's deny on Gmail is honoured by `aux skill run`: the
    /// calendar insert that comes first is not sent either.
    #[tokio::test]
    async fn operator_deny_rule_refuses_the_cli_run_before_any_call() {
        let rules =
            rules_from("[[rules]]\ndot = \"assistant\"\ntool = \"mail_send\"\naction = \"deny\"\n");
        let connector = CountingConnector::default();
        let sink = Arc::new(kernel_broker::MemoryAuditSink::new());

        let outcome = run_with(
            &AlwaysYes,
            &connector,
            &sink,
            rules,
            &NeverStopped,
            &ImmediateClock,
        )
        .await;
        assert!(
            matches!(outcome, Ok(RunOutcome::Refused { .. })),
            "{outcome:?}"
        );
        assert_eq!(connector.0.load(Ordering::SeqCst), 0, "nothing was sent");
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "refused");
    }

    /// STOP raised before the run: the CLI refuses and sends nothing.
    #[tokio::test]
    async fn stop_refuses_the_cli_run_before_any_call() {
        let dir = tempfile::tempdir().unwrap();
        kernel_core::killswitch::engage(dir.path()).unwrap();
        let killswitch = KillSwitch {
            home: dir.path().to_path_buf(),
        };
        let connector = CountingConnector::default();
        let sink = Arc::new(kernel_broker::MemoryAuditSink::new());

        let outcome = run_with(
            &AlwaysYes,
            &connector,
            &sink,
            Vec::new(),
            &killswitch,
            &ImmediateClock,
        )
        .await;
        assert!(
            matches!(outcome, Ok(RunOutcome::Refused { .. })),
            "{outcome:?}"
        );
        assert_eq!(connector.0.load(Ordering::SeqCst), 0, "nothing was sent");
    }

    /// P2-2: the owner never answers. The timeout wins the race, nothing is
    /// sent, and a late `y` is read by nobody.
    #[tokio::test]
    async fn silence_past_the_timeout_sends_nothing_and_a_late_answer_does_nothing() {
        let (client, mut owner) = tokio::io::duplex(64);
        let approver = TerminalApprover {
            input: tokio::sync::Mutex::new(BufReader::new(client)),
        };
        let connector = CountingConnector::default();
        let sink = Arc::new(kernel_broker::MemoryAuditSink::new());

        let outcome = run_with(
            &approver,
            &connector,
            &sink,
            Vec::new(),
            &NeverStopped,
            &ImmediateClock,
        )
        .await
        .unwrap();
        assert_eq!(outcome, RunOutcome::Timeout);
        assert_eq!(connector.0.load(Ordering::SeqCst), 0, "nothing was sent");

        owner.write_all(b"y\n").await.unwrap();
        assert_eq!(
            connector.0.load(Ordering::SeqCst),
            0,
            "a late y does nothing"
        );
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "timeout");
    }

    /// B4: the CLI connector serves the CRM reads and the `log-interaction`
    /// write over a real store, with no Google connection.
    #[tokio::test]
    async fn the_cli_connector_serves_crm_reads_and_the_log_interaction_write() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("store.db")).unwrap(),
        ));
        let party = store
            .lock()
            .unwrap()
            .insert_party(&aux_store::NewParty {
                display_name: "Camille Exemple".to_string(),
                emails: vec!["camille@exemple.test".to_string()],
                origin: "owner".to_string(),
                ..aux_store::NewParty::default()
            })
            .unwrap();
        let connector = CliConnector {
            #[cfg(feature = "google")]
            google: None,
            crm: auxd::crm::CrmSkillConnector::new(dir.path(), "assistant", Arc::clone(&store)),
            docs: docs_connector(dir.path(), &store),
        };
        let skill = SkillContext {
            name: "log-interaction".to_string(),
            version: 1,
            hash: "abc".to_string(),
            tainted: false,
        };

        let found = connector
            .call(&skill, "crm.search", &json!({ "query": "Camille" }))
            .await
            .unwrap();
        assert_eq!(found["matches"][0]["display_name"], "Camille Exemple");

        let logged = connector
            .call(
                &skill,
                "crm.log_interaction",
                &json!({
                    "party_id": party,
                    "kind": "note",
                    "at": "2026-10-06T10:00:00Z",
                    "source_ref": "{\"owner\":true}",
                    "summary": "Appel",
                    "memory": [{ "kind": "fact", "title": "Suivi", "body": "Rappeler" }],
                }),
            )
            .await
            .unwrap();
        assert!(logged["interaction_id"].is_i64());
        // M5-3: no mailbox in this home, so a collect refuses cleanly.
        let refused = connector
            .call(&skill, "docs.ingest", &json!({ "account": "personal" }))
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("no mailbox"), "{refused}");
        let guard = store.lock().unwrap();
        assert_eq!(guard.interactions_for_party(party).unwrap().len(), 1);
        assert_eq!(
            guard
                .memory_items_for_party("assistant", party, 5)
                .unwrap()
                .len(),
            1
        );
    }

    /// The owner answers in time: both calls run, in order, once each.
    #[tokio::test]
    async fn an_answer_in_time_runs_the_calls_once() {
        let (client, mut owner) = tokio::io::duplex(64);
        owner.write_all(b"yes\n").await.unwrap();
        let approver = TerminalApprover {
            input: tokio::sync::Mutex::new(BufReader::new(client)),
        };
        let connector = CountingConnector::default();
        let sink = Arc::new(kernel_broker::MemoryAuditSink::new());

        let outcome = run_with(
            &approver,
            &connector,
            &sink,
            Vec::new(),
            &NeverStopped,
            &ImmediateClock,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, RunOutcome::Done { ref actions } if actions.len() == 2));
        assert_eq!(connector.0.load(Ordering::SeqCst), 2);
    }
}
