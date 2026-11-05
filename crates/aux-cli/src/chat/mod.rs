//! `aux chat` — interactive REPL and single-shot chat with an agent.
//!
//! Single-shot: `aux chat --agent main "hello"` sends one message and exits.
//! Interactive: `aux chat --agent main` reads lines from stdin until EOF.
//!
//! Wiring:
//!
//! - provider: `--provider <id>` picks a `[[providers]]` entry; without the
//!   flag a single configured provider is used and several are an error.
//! - soul: `<home>/agents/<agent>/soul.md`, created with a default when missing;
//!   unreadable or corrupt souls fall back to the default in memory.
//! - tools: the v1 registry (`shell`, `read_file`, `write_file`), rooted at
//!   `<home>/agents/<agent>/workspace`.
//! - permissions: ordered `[[rules]]` in `config.toml` (`agent`, `tool`,
//!   `action = "allow" | "ask" | "deny"`), last match wins (defaults first), no match asks.
//!   Interactive mode prompts on stdin for asks; single-shot mode denies
//!   them unless `--auto-approve` is given, which only approves clean,
//!   sandboxed requests.

use aux_engine::{
    load_rules, select_provider, AutoApproveApprover, ChatError, ChatSession, ChatSetup,
    DenyApprover, MarkerStop, ModeChangeStop, ProviderSelectError, RulesError, SoulStatus,
    StdinApprover, StopCheck, TurnOutcome,
};
use aux_providers::{load_providers, ConfigError as ProviderConfigError, ProviderError};
use aux_store::{Store, StoreError, StoreHandle};
use clap::Args;
use kernel_broker::Approver;
use kernel_core::{auxesis_home, ensure_home, Config, ConfigError};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;

mod daemon;

/// Used only for `aux chat --help`, before clap renders the context-sensitive options.
pub fn daemon_is_available() -> bool {
    daemon::is_available()
}

/// Arguments of `aux chat`.
#[derive(Debug, Args)]
pub struct ChatArgs {
    /// Agent to chat with (default: `default_agent` from config.toml).
    #[arg(long, value_name = "AGENT")]
    pub agent: Option<String>,
    /// Provider id from config.toml (default: the only configured provider).
    #[arg(long, value_name = "ID")]
    pub provider: Option<String>,
    /// Approve clean, sandboxed tool requests without prompting. Tainted or
    /// unsandboxed requests are denied. Single-shot mode denies asks otherwise.
    #[arg(long)]
    pub auto_approve: bool,
    /// Start a new conversation with the agent (through auxd); the old one is kept.
    #[arg(long)]
    pub new: bool,
    /// Message to send once and exit; omit for an interactive REPL.
    #[arg(value_name = "MESSAGE")]
    pub message: Option<String>,
}

/// Errors that abort the command before or during the chat run.
#[derive(Debug, Error)]
enum ChatCliError {
    #[error(transparent)]
    CoreConfig(#[from] ConfigError),
    #[error(transparent)]
    ProvidersConfig(#[from] ProviderConfigError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Engine(#[from] ChatError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ProviderSelect(#[from] ProviderSelectError),
    #[error(transparent)]
    Rules(#[from] RulesError),
}

/// Run `aux chat`, printing errors to stderr and mapping them to the exit code.
/// With `auxd` running the turn goes through its chat API, with the app's tools.
pub fn run(args: ChatArgs) -> ExitCode {
    let lang = kernel_core::Lang::from_env();
    if let Some(code) = daemon::try_run(&args) {
        return code;
    }
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        daemon::choose(
            lang,
            "auxd ne tourne pas : ce chat n'a ni mail, ni agenda, ni outils clients.",
            "auxd is not running: this chat has no mail, calendar or client tools."
        )
    );
    match run_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux chat: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner(args: ChatArgs) -> Result<(), ChatCliError> {
    // J-02 round 5: one verified handle; the config path is built from its
    // canonical real path, never from the raw env spelling.
    let home = auxesis_home();
    let verified = ensure_home(&home)?;
    let config_file = verified.real_path()?.join("config.toml");
    // `aux chat` is the CLI's first run: a fresh home starts with the chief.
    let config = aux_engine::config::load_or_create_verified(&verified)?;
    let agent = args
        .agent
        .clone()
        .unwrap_or_else(|| config.default_agent.clone());
    aux_engine::validate_agent(&agent)?;

    let providers = load_providers(&config_file)?;
    let provider_config = select_provider(&providers, args.provider.as_deref(), &config_file)?;
    let provider = provider_config.build_provider()?;

    // Key material is now in memory: scrub the env fallback so a child
    // process (`ps eww`) can never read it back out of our environment.
    crate::vault::scrub_process_key_env();

    let store = Arc::new(Mutex::new(Store::open_verified(&verified)?));
    // The registry carries the `[shell]` section: sandbox/network/opt-in.
    let rules = load_rules(&config_file)?;

    let interactive = args.message.is_none();
    let approver = build_approver(args.auto_approve, interactive);
    // APPROVAL-MODES: `--auto-approve` stays as is; otherwise the config mode
    // decides. Under `auto` the eligible calls run with an `auto` audit row and
    // every other ask still prompts (REPL) or is denied (single shot).
    let approver = if args.auto_approve {
        approver
    } else {
        aux_engine::approver::for_mode(
            config.approvals,
            approver,
            &rules,
            &aux_engine::registry_from_config(&config),
            StoreHandle::Shared(Arc::clone(&store)).audit_sink(),
            None,
            // SHELL-JUDGE is wired in the daemon only; the CLI keeps its prompt.
            None,
        )
    };
    if args.auto_approve {
        warn("--auto-approve is on: clean, sandboxed tool requests will be approved; tainted or unsandboxed requests will be denied");
    }

    let title = if interactive {
        Some("interactive chat".to_string())
    } else {
        args.message.as_deref().map(session_title)
    };
    let message = args.message.clone();
    let provider_name = provider.name().to_string();
    // The mode is read live, at each message. A switch made while this session
    // runs (from the Mac app or another terminal) starts a new session on the same
    // conversation before the next message (`Conversation::send`), so the gate
    // follows the mode in force. A config that cannot be read reads as private.
    // The agent's own default is a layer too (`README.md`, "The two modes"):
    // the most private of the global mode and agent.md's `default_mode` applies.
    let live_config = config_file.clone();
    let live_agent_dir = aux_engine::agent_dir(&home, &agent);
    let live_mode: kernel_core::privacy::ModeFn = std::sync::Arc::new(move || {
        aux_runtime::skills::effective_mode(
            kernel_core::privacy::PrivacyMode::from_config_or_private(
                aux_engine::config::load_or_create(&live_config).map(|config| config.privacy),
            ),
            aux_runtime::skills::agent_mode_layer(&live_agent_dir),
        )
    });

    // The broker authenticates through the store handle; a current-thread
    // runtime hosts the single interactive loop.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // The sessions of this conversation are made from these parts: the first one
    // now, and again whenever the mode changes (`Conversation::send`).
    let parts = ChatParts {
        store: Arc::clone(&store),
        provider: provider.as_ref(),
        config: &config,
        rules,
        approver,
        agent: agent.clone(),
        home: home.clone(),
        title,
        contacts: aux_runtime::known_names::owner_contacts(),
        live: live_mode,
    };
    runtime.block_on(async {
        let mut conversation = Conversation::start(&parts)?;
        match &message {
            Some(message) => {
                let outcome = conversation.send(message).await?;
                print_outcome(&outcome, conversation.session().session().id);
            }
            None => repl(&mut conversation, &agent, &provider_name).await?,
        }
        Ok::<(), ChatCliError>(())
    })
}

/// What a chat conversation is made from. Every session, the first one and each
/// restart, is built here, so the stop and the tool wiring are one thing.
struct ChatParts<'a> {
    store: Arc<Mutex<Store>>,
    provider: &'a dyn aux_providers::ChatProvider,
    config: &'a Config,
    rules: Vec<kernel_broker::Rule>,
    approver: Arc<dyn Approver>,
    agent: String,
    home: PathBuf,
    title: Option<String>,
    contacts: aux_runtime::known_names::Contacts,
    /// The owner's privacy mode, read live.
    live: kernel_core::privacy::ModeFn,
}

impl ChatParts<'_> {
    /// The rules a session runs under: the owner's, MAIL-NO-SHELL, then the
    /// agent's own grants held to the chief, as the daemon holds a turn
    /// ([`auxd::api::constrain_non_api_turn`]).
    fn session_rules(
        &self,
        registry: &mut kernel_broker::ToolRegistry,
    ) -> Vec<kernel_broker::Rule> {
        // A config that cannot be read opts into nothing: no shell.
        let toml_tools = auxd::agent::config(&self.home, &self.agent)
            .ok()
            .and_then(|config| config.tools);
        let mut rules = self.rules.clone();
        aux_engine::config::keep_shell_from_domain_agent(
            &self.home,
            &self.agent,
            toml_tools.as_deref(),
            registry,
            &mut rules,
        );
        auxd::api::constrain_non_api_turn(&self.home, &self.agent, registry, &mut rules);
        rules
    }

    /// A session under `mode`, resuming `resume` when given. Its gate and its
    /// stop follow `mode`: a change of the live mode stops its turns. Its tools
    /// are dispatched through the live mode, so each call asks it again.
    fn session(
        &self,
        mode: kernel_core::privacy::PrivacyMode,
        resume: Option<i64>,
    ) -> Result<ChatSession<'_>, ChatError> {
        // Mounting is decided by the session's mode, as the daemon decides it per
        // turn (`retain_mountable`), and again on each restart. Each dispatch
        // asks the live mode (`gate_dispatch`).
        let mut registry = aux_engine::registry_from_config(self.config);
        let dropped = kernel_broker::retain_mountable(&mut registry, mode);
        if !dropped.is_empty() {
            warn(format!(
                "not mounted in private mode: {}",
                dropped.join(", ")
            ));
        }
        kernel_broker::gate_dispatch(&mut registry, Arc::clone(&self.live));
        let rules = self.session_rules(&mut registry);
        ChatSession::start(ChatSetup {
            mode: Arc::new(move || mode),
            contacts: Arc::clone(&self.contacts),
            store: StoreHandle::Shared(Arc::clone(&self.store)),
            provider: self.provider,
            registry: Arc::new(RwLock::new(registry)),
            rules,
            approver: Arc::clone(&self.approver),
            agent: self.agent.clone(),
            home: self.home.clone(),
            skills: Vec::new(),
            budgets: &self.config.budgets,
            prices: &self.config.prices,
            context: self.config.context.clone(),
            title: self.title.clone(),
            stop: Some(Arc::new(ChatStop {
                marker: MarkerStop::new(self.home.clone()),
                mode: ModeChangeStop::new(mode, Arc::clone(&self.live)),
            })),
            cancel: None,
            session_id: resume,
            events: None,
            run_id: None,
        })
    }
}

/// The checks between two steps of a chat turn: the STOP marker, and a privacy
/// mode that differs from the one the turn started under, in either direction.
struct ChatStop {
    marker: MarkerStop,
    mode: ModeChangeStop,
}

impl StopCheck for ChatStop {
    fn is_stopped(&self) -> bool {
        self.marker.is_stopped() || self.mode.is_stopped()
    }
}

/// One conversation of `aux chat`. A session's gate and stop are fixed to the
/// mode in force when it starts; `send` starts it again on this conversation
/// when the live mode has changed since.
struct Conversation<'a> {
    parts: &'a ChatParts<'a>,
    session: ChatSession<'a>,
}

impl<'a> Conversation<'a> {
    fn start(parts: &'a ChatParts<'a>) -> Result<Self, ChatError> {
        let session = parts.session((parts.live)(), None)?;
        Ok(Self { parts, session })
    }

    fn session(&self) -> &ChatSession<'a> {
        &self.session
    }

    /// Send one message. The STOP marker is read first, so a stopped turn sends
    /// nothing. The live mode is read next: when it differs from the mode the
    /// session was started under, the session is started again on this
    /// conversation, and its history is gated under the live mode.
    async fn send(&mut self, input: &str) -> Result<TurnOutcome, ChatError> {
        if MarkerStop::new(self.parts.home.clone()).is_stopped() {
            return Err(ChatError::Stopped);
        }
        let mode = (self.parts.live)();
        if mode != self.session.gate_mode() {
            let id = self.session.session().id;
            self.session = self.parts.session(mode, Some(id))?;
        }
        self.session.send(input).await
    }
}

async fn repl(
    conversation: &mut Conversation<'_>,
    agent: &str,
    provider_name: &str,
) -> Result<(), ChatCliError> {
    if let SoulStatus::FellBack { reason } = conversation.session().soul_status() {
        warn(format!("using the default soul: {reason}"));
    }
    warn(format!(
        "chatting with agent `{agent}` via provider `{provider_name}` — `exit` or Ctrl-D to leave"
    ));

    let stdin = std::io::stdin();
    loop {
        {
            let mut stderr = std::io::stderr().lock();
            let _ = write!(stderr, "> ");
            let _ = stderr.flush();
        }
        let mut line = String::new();
        let read = stdin.lock().read_line(&mut line)?;
        if read == 0 {
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if matches!(input, "exit" | "quit" | ":q" | "/exit" | "/quit") {
            break;
        }
        match conversation.send(input).await {
            Ok(outcome) => print_outcome(&outcome, conversation.session().session().id),
            // A stopped turn ends here and the loop goes on: the next message is
            // read under the mode in force then.
            Err(ChatError::Stopped) => {
                warn("this turn was stopped (STOP set, or the privacy mode changed); send the message again")
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

/// The answer as the owner's terminal shows it. In Private mode the model answers
/// with this session's tokens: they are restored here, locally, and a token no
/// turn of this session minted shows `[name hidden]`, never the raw marker.
fn shown_text(text: &str, session_id: i64) -> String {
    let shown = auxd::privacy_wiring::rehydrate_local(session_id, text);
    kernel_broker::sanitize_external_text(&shown, 1024 * 1024)
}

fn print_outcome(outcome: &TurnOutcome, session_id: i64) {
    if !outcome.text.is_empty() {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            shown_text(&outcome.text, session_id)
        );
    }
    if outcome.capped {
        warn(format!(
            "tool loop stopped after {} rounds without a final answer",
            outcome.rounds
        ));
    }
}

fn warn(message: impl std::fmt::Display) {
    let _ = writeln!(std::io::stderr(), "warning: {message}");
}

/// Pick the approver for the run: `--auto-approve` wins everywhere, the REPL
/// prompts, and single-shot mode is fail-closed.
fn build_approver(auto_approve: bool, interactive: bool) -> Arc<dyn Approver> {
    if auto_approve {
        Arc::new(AutoApproveApprover)
    } else if interactive {
        Arc::new(StdinApprover)
    } else {
        Arc::new(DenyApprover)
    }
}

/// Session titles are one short line derived from the first message.
/// Detection runs first; the 60-character display cap comes after it.
fn session_title(message: &str) -> String {
    let scrubbed = kernel_broker::scrub_title(message);
    let mut title: String = scrubbed.chars().take(60).collect();
    if scrubbed.chars().count() > 60 {
        title.push('…');
    }
    if title.is_empty() {
        "chat".to_string()
    } else {
        title
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Chat parts over the file store under `home`, with Camille Exemple as the
    /// owner's contact, the owner's mode `live`, and `provider`.
    fn test_parts<'a>(
        home: &Path,
        config: &'a Config,
        provider: &'a dyn aux_providers::ChatProvider,
        live: kernel_core::privacy::ModeFn,
    ) -> ChatParts<'a> {
        let mut contacts = kernel_privacy::ContactIndex::new();
        contacts.add_from_header("Camille Exemple", "camille@exemple.fr");
        ChatParts {
            store: Arc::new(Mutex::new(Store::open(&home.join("store.db")).unwrap())),
            provider,
            config,
            rules: Vec::new(),
            approver: Arc::new(AutoApproveApprover),
            agent: "main".to_string(),
            home: home.to_path_buf(),
            title: None,
            contacts: Arc::new(contacts),
            live,
        }
    }

    /// The owner's mode, read live from `config_file`.
    fn live_from(config_file: &Path) -> kernel_core::privacy::ModeFn {
        let config_file = config_file.to_path_buf();
        Arc::new(move || {
            kernel_core::privacy::PrivacyMode::from_config_or_private(
                aux_engine::config::load_or_create(&config_file).map(|config| config.privacy),
            )
        })
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn a_switch_to_private_applies_to_the_next_message() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config_file = kernel_core::config_path(&home);
        std::fs::write(&config_file, "version = 1\nprivacy.mode = \"open\"\n").unwrap();
        let config = Config::default();
        let provider = aux_providers::FakeProvider::echo("main");
        let parts = test_parts(&home, &config, &provider, live_from(&config_file));

        runtime().block_on(async {
            let mut conversation = Conversation::start(&parts).unwrap();
            conversation
                .send("Dis bonjour à Camille Exemple, camille@exemple.fr.")
                .await
                .unwrap();
            std::fs::write(&config_file, "version = 1\nprivacy.mode = \"private\"\n").unwrap();
            conversation
                .send("Et Camille Exemple, camille@exemple.fr ?")
                .await
                .unwrap();
        });

        let requests = provider.requests();
        let last = serde_json::to_string(&requests.last().unwrap().messages).unwrap();
        // A name is no hidden value.
        assert!(
            !last.contains("camille@exemple.fr"),
            "the private turn sent raw text: {last}"
        );
    }

    #[test]
    fn a_private_session_offers_the_local_tools_and_masks_what_they_read() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config_file = kernel_core::config_path(&home);
        std::fs::write(&config_file, "version = 1\nprivacy.mode = \"private\"\n").unwrap();
        let note = "Camille Exemple <camille@exemple.fr> +33 6 12 34 56 78";
        let workspace = aux_engine::workspace_dir(&home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("notes.txt"), note).unwrap();
        // TOK-3: a private session offers read_file; the note it reads reaches
        // the provider only through the session gate.
        let provider = aux_providers::FakeProvider::scripted(
            "main",
            vec![
                aux_providers::ChatResponse::new(
                    aux_providers::ChatMessage::assistant_with_tool_calls(
                        "",
                        vec![aux_providers::ToolCall {
                            id: "call_1".to_string(),
                            name: "read_file".to_string(),
                            arguments: serde_json::json!({"path": "notes.txt"}),
                        }],
                    ),
                ),
                aux_providers::ChatResponse::assistant("fini"),
            ],
        );
        let config = Config::default();
        let parts = test_parts(&home, &config, &provider, live_from(&config_file));

        runtime().block_on(async {
            let mut conversation = Conversation::start(&parts).unwrap();
            conversation.send("Lis notes.txt.").await.unwrap();
        });

        let requests = provider.requests();
        let offered: Vec<String> = requests[0]
            .tools
            .iter()
            .map(|tool| tool.name().as_str().to_string())
            .collect();
        for local in ["read_file", "write_file", "shell"] {
            assert!(
                offered.iter().any(|name| name == local),
                "{local} is not offered in private mode: {offered:?}"
            );
        }
        assert_eq!(requests.len(), 2, "the call ran and its result went back");
        for request in &requests {
            let body = serde_json::to_string(&request.messages).unwrap();
            assert!(
                !body.contains("camille@exemple.fr") && !body.contains("+33 6 12 34 56 78"),
                "the note reached the provider unmasked: {body}"
            );
        }
    }

    /// MAIL-NO-SHELL, seal r1: the `aux chat` fallback (no auxd) under a
    /// global `allow shell`: a domain agent is not offered the shell and a
    /// forced call is denied; an agent.md opt-in and the chief keep it.
    #[test]
    fn the_fallback_keeps_the_shell_from_a_domain_agent_without_an_opt_in() {
        for (agent, opt_in, keeps) in [
            ("mail", false, false),
            ("mail", true, true),
            ("aux", false, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            let agent_dir = aux_engine::agent_dir(&home, agent);
            std::fs::create_dir_all(&agent_dir).unwrap();
            let config_file = kernel_core::config_path(&home);
            std::fs::write(&config_file, "version = 1\nprivacy.mode = \"open\"\n").unwrap();
            if opt_in {
                let md = format!("---\nname: {agent}\ntools: [shell]\n---\nAgent.\n");
                std::fs::write(agent_dir.join("agent.md"), md).unwrap();
            }
            let call = aux_providers::ToolCall::new(
                "call_1",
                "shell",
                serde_json::json!({"command": "echo ran"}),
            );
            let provider = aux_providers::FakeProvider::scripted(
                agent,
                vec![
                    aux_providers::ChatResponse::new(
                        aux_providers::ChatMessage::assistant_with_tool_calls("", vec![call]),
                    ),
                    aux_providers::ChatResponse::assistant("done"),
                ],
            );
            let config = Config::default();
            let mut parts = test_parts(&home, &config, &provider, live_from(&config_file));
            parts.agent = agent.to_string();
            parts.rules = vec![kernel_broker::Rule::new(
                "*",
                "shell",
                kernel_broker::Action::Allow,
            )];
            runtime().block_on(async {
                Conversation::start(&parts)
                    .unwrap()
                    .send("run it")
                    .await
                    .unwrap();
            });
            let offered = provider.requests()[0]
                .tools
                .iter()
                .any(|tool| tool.name().as_str() == "shell");
            assert_eq!(offered, keeps, "{agent} opt-in {opt_in}");
            let outcomes: Vec<String> = parts
                .store
                .lock()
                .unwrap()
                .event_payloads("tool.decision")
                .unwrap()
                .iter()
                .map(|raw| serde_json::from_str::<serde_json::Value>(raw).unwrap())
                .filter(|row| row["tool"] == "shell")
                .map(|row| row["outcome"].as_str().unwrap().to_string())
                .collect();
            let expected = if keeps { "allowed" } else { "denied" };
            assert_eq!(
                outcomes,
                vec![expected.to_string()],
                "{agent} opt-in {opt_in}"
            );
        }
    }

    /// `aux chat` holds the agent to its own grants, not only to the chief:
    /// with Calendar's `mail.send` set `off`, its send is denied though the
    /// chief may send. With the shipped grants it asks.
    #[test]
    fn a_session_holds_the_agent_to_its_own_grants_even_when_the_chief_allows() {
        use aux_runtime::grants::{default_grants, ActionLevel};
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(aux_engine::agent_dir(&home, "calendar")).unwrap();
        let config_file = kernel_core::config_path(&home);
        let text = "version = 1\ndefault_agent = \"main\"\nprivacy.mode = \"open\"\n";
        std::fs::write(&config_file, text).unwrap();
        let config = Config::default();
        let provider = aux_providers::FakeProvider::echo("calendar");
        let mut parts = test_parts(&home, &config, &provider, live_from(&config_file));
        let send = |parts: &ChatParts<'_>| {
            let mut registry = aux_engine::registry_from_config(parts.config);
            let rules = parts.session_rules(&mut registry);
            kernel_broker::matching_rule(&rules, &parts.agent, "mail_send", false)
                .map(|(_, rule)| rule.action)
        };
        parts.agent = "calendar".to_string();
        assert_eq!(send(&parts), Some(kernel_broker::Action::Ask));
        let mut own = default_grants("calendar").unwrap();
        for grant in own.can_do.iter_mut().filter(|g| g.skill == "mail.send") {
            grant.level = ActionLevel::Off;
        }
        auxd::agents::write_grants(&home, "calendar", &own).unwrap();
        assert_eq!(send(&parts), Some(kernel_broker::Action::Deny));
        parts.agent = "main".to_string();
        assert_eq!(send(&parts), None, "the chief may send");
    }

    /// A scripted brain that asks for `calls` at once, then answers "done".
    fn calling(name: &str, calls: &[(&str, serde_json::Value)]) -> aux_providers::FakeProvider {
        let calls = calls
            .iter()
            .enumerate()
            .map(|(i, (tool, args))| {
                aux_providers::ToolCall::new(format!("call_{i}"), *tool, args.clone())
            })
            .collect();
        aux_providers::FakeProvider::scripted(
            name,
            vec![
                aux_providers::ChatResponse::new(
                    aux_providers::ChatMessage::assistant_with_tool_calls("", calls),
                ),
                aux_providers::ChatResponse::assistant("done"),
            ],
        )
    }

    /// The `tool.decision` outcome of each call to `tool` in the store at `home`.
    fn decisions(home: &Path, tool: &str) -> Vec<String> {
        Store::open(&home.join("store.db"))
            .unwrap()
            .event_payloads("tool.decision")
            .unwrap()
            .iter()
            .map(|raw| serde_json::from_str::<serde_json::Value>(raw).unwrap())
            .filter(|row| row["tool"] == tool)
            .map(|row| row["outcome"].as_str().unwrap().to_string())
            .collect()
    }

    /// The text the brain got back for the first call (the tool result).
    fn first_result(provider: &aux_providers::FakeProvider) -> String {
        let requests = provider.requests();
        let messages = &requests[1].messages;
        let at = messages
            .iter()
            .position(|message| !message.tool_calls().is_empty())
            .unwrap();
        messages[at + 1].content().as_str().to_string()
    }

    /// An agent.md for `agent` listing `tools`, in the open mode.
    fn list_tools(home: &Path, agent: &str, tools: &str) {
        let agent_dir = aux_engine::agent_dir(home, agent);
        std::fs::create_dir_all(&agent_dir).unwrap();
        let md = format!("---\nname: {agent}\ndefault_mode: open\ntools: [{tools}]\n---\nAgent.\n");
        std::fs::write(agent_dir.join("agent.md"), md).unwrap();
    }

    /// AGENT-CEILING-CHAT (seal #123 P3): `aux chat --agent mail` holds Mail
    /// to its own tools list as the daemon does. Listing only `mail.read`
    /// and `recall`, its `write_file` is denied before it runs, even with
    /// every ask approved; listing `write_file` too, it runs. (`recall` is a
    /// daemon tool: `aux chat` does not mount it.)
    #[test]
    fn a_session_holds_the_agent_to_its_tools_list() {
        for (list, runs) in [
            ("mail.read, recall", false),
            ("mail.read, recall, write_file", true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            let config_file = kernel_core::config_path(&home);
            std::fs::write(&config_file, "version = 1\nprivacy.mode = \"open\"\n").unwrap();
            list_tools(&home, "mail", list);
            let args = serde_json::json!({"path": "x.txt", "content": "x"});
            let provider = calling("mail", &[("write_file", args)]);
            let config = Config::default();
            let mut parts = test_parts(&home, &config, &provider, live_from(&config_file));
            parts.agent = "mail".to_string();
            runtime().block_on(async {
                let mut conversation = Conversation::start(&parts).unwrap();
                conversation.send("write it").await.unwrap();
            });
            let written = aux_engine::workspace_dir(&home, "mail").join("x.txt");
            assert_eq!(written.exists(), runs, "[{list}]");
            let expected = if runs { "allowed" } else { "denied" };
            assert_eq!(
                decisions(&home, "write_file"),
                vec![expected.to_string()],
                "[{list}]"
            );
        }
    }

    /// The daemon's turn and `aux chat` give the same verdict, and the same
    /// refusal text, for each (tools list, tool) pair.
    #[test]
    fn the_daemon_and_the_chat_hold_the_same_tools_ceiling() {
        let table = [
            ("mail.read, recall", "write_file", true),
            ("mail.read, recall", "read_file", true),
            ("read_file", "read_file", false),
            ("read_file, write_file", "write_file", false),
            ("read_file", "write_file", true),
        ];
        let args = serde_json::json!({"path": "x.txt", "content": "x"});
        let owner = "[[rules]]\nagent = \"*\"\ntool = \"read_file\"\naction = \"allow\"\n\
                     [[rules]]\nagent = \"*\"\ntool = \"write_file\"\naction = \"allow\"\n";
        let home_for = |dir: &Path, list: &str| {
            let home = dir.join("home");
            std::fs::create_dir_all(&home).unwrap();
            let text = format!(
                "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n\
                 [[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
                 model = \"m\"\nkind = \"fake\"\n{owner}"
            );
            std::fs::write(kernel_core::config_path(&home), text).unwrap();
            list_tools(&home, "main", list);
            home
        };
        for (list, tool, denied) in table {
            let api_dir = tempfile::tempdir().unwrap();
            let api_home = home_for(api_dir.path(), list);
            use auxd::api::TurnRunner as _;
            let api = Arc::new(calling("fakey", &[(tool, args.clone())]));
            auxd::api::EngineTurnRunner::new(&api_home)
                .with_provider(Arc::clone(&api) as Arc<dyn aux_providers::ChatProvider>)
                .run_turn("main", None, "go", None)
                .unwrap();

            let cli_dir = tempfile::tempdir().unwrap();
            let cli_home = home_for(cli_dir.path(), list);
            let config_file = kernel_core::config_path(&cli_home);
            let cli = calling("fakey", &[(tool, args.clone())]);
            let config = Config::default();
            let mut parts = test_parts(&cli_home, &config, &cli, live_from(&config_file));
            parts.rules = aux_engine::load_rules(&config_file).unwrap();
            runtime().block_on(async {
                Conversation::start(&parts)
                    .unwrap()
                    .send("go")
                    .await
                    .unwrap();
            });

            let (api_verdict, cli_verdict) =
                (decisions(&api_home, tool), decisions(&cli_home, tool));
            let case = format!("[{list}] {tool}");
            assert_eq!(api_verdict, cli_verdict, "{case}");
            assert_eq!(
                api_verdict == vec!["denied".to_string()],
                denied,
                "{case}: {api_verdict:?}"
            );
            if denied {
                // The rule's index differs (the daemon holds more rules).
                let text = |provider| {
                    let result: String = first_result(provider);
                    result.replace(|c: char| c.is_ascii_digit(), "")
                };
                assert_eq!(text(&api), text(&cli), "{case}");
            }
        }
    }

    #[test]
    fn stop_is_honoured_before_a_turn_sends_anything() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config_file = kernel_core::config_path(&home);
        std::fs::write(&config_file, "version = 1\nprivacy.mode = \"open\"\n").unwrap();
        let config = Config::default();
        let provider = aux_providers::FakeProvider::echo("main");
        let parts = test_parts(&home, &config, &provider, live_from(&config_file));

        // The owner's STOP marker is set before the next message.
        std::fs::write(kernel_core::killswitch::stop_path(&home), "").unwrap();
        runtime().block_on(async {
            let mut conversation = Conversation::start(&parts).unwrap();
            let err = conversation.send("ping").await.err();
            assert!(
                matches!(err, Some(ChatError::Stopped)),
                "a stopped turn must stop before anything is sent"
            );
        });
        assert!(
            provider.requests().is_empty(),
            "a stopped turn sent a request"
        );
    }

    /// A provider that answers from `inner` and, after its first completion,
    /// switches the owner's config to private, as the Mac app does mid-turn.
    struct SwitchAfterFirst {
        inner: aux_providers::FakeProvider,
        config_file: PathBuf,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl aux_providers::ChatProvider for SwitchAfterFirst {
        async fn complete(
            &self,
            req: &aux_providers::ChatRequest,
        ) -> Result<aux_providers::ChatResponse, aux_providers::ProviderError> {
            let response = self.inner.complete(req).await?;
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                std::fs::write(
                    &self.config_file,
                    "version = 1\nprivacy.mode = \"private\"\n",
                )
                .unwrap();
            }
            Ok(response)
        }

        fn name(&self) -> &str {
            self.inner.name()
        }
    }

    #[test]
    fn a_switch_to_private_mid_turn_stops_before_the_next_round_and_the_tool() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config_file = kernel_core::config_path(&home);
        std::fs::write(&config_file, "version = 1\nprivacy.mode = \"open\"\n").unwrap();
        let note = "Camille Exemple <camille@exemple.fr> +33 6 12 34 56 78";
        let workspace = aux_engine::workspace_dir(&home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("notes.txt"), note).unwrap();
        let provider = SwitchAfterFirst {
            inner: aux_providers::FakeProvider::scripted(
                "main",
                vec![
                    aux_providers::ChatResponse::new(
                        aux_providers::ChatMessage::assistant_with_tool_calls(
                            "",
                            vec![aux_providers::ToolCall {
                                id: "call_1".to_string(),
                                name: "read_file".to_string(),
                                arguments: serde_json::json!({"path": "notes.txt"}),
                            }],
                        ),
                    ),
                    aux_providers::ChatResponse::assistant("fini"),
                ],
            ),
            config_file: config_file.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let config = Config::default();
        let parts = test_parts(&home, &config, &provider, live_from(&config_file));

        runtime().block_on(async {
            let mut conversation = Conversation::start(&parts).unwrap();
            let err = conversation.send("Lis notes.txt.").await.err();
            assert!(
                matches!(err, Some(ChatError::Stopped)),
                "the switch must stop the turn: {err:?}"
            );
        });

        let requests = provider.inner.requests();
        assert_eq!(requests.len(), 1, "no provider round after the switch");
        for request in &requests {
            let body = serde_json::to_string(&request.messages).unwrap();
            assert!(
                !body.contains("Camille") && !body.contains("camille@exemple.fr"),
                "raw contact text reached the provider: {body}"
            );
        }
    }

    #[test]
    fn the_owner_sees_restored_values_and_never_a_raw_token() {
        // A fictional session id, far from any real one.
        let tokens = aux_engine::skill_runtime::session_tokens(9_200_001);
        kernel_core::sync::lock_recover(&tokens).record(&[(
            "PERSON_0123456789AB".to_string(),
            "Camille Exemple".to_string(),
        )]);
        let shown = shown_text(
            "Hi ⟦PERSON_0123456789AB⟧, and ⟦PERSON_FFFFFFFFFFFF⟧ (not minted).",
            9_200_001,
        );
        assert_eq!(shown, "Hi Camille Exemple, and [name hidden] (not minted).");
        // Another session never resolves this session's token.
        assert_eq!(
            shown_text("⟦PERSON_0123456789AB⟧", 9_200_002),
            "[name hidden]"
        );
    }

    #[test]
    fn a_megabyte_of_openers_is_shown_in_linear_time() {
        let text = "⟦x".repeat(1024 * 1024 / 4);
        let started = std::time::Instant::now();
        let shown = shown_text(&text, 9_200_003);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(!shown.is_empty());
    }

    #[test]
    fn session_title_is_short_and_single_line() {
        assert_eq!(session_title("hello\nthere"), "hello");
        assert_eq!(session_title("   "), "chat");
        assert_eq!(session_title("x"), "x");
        let long = "a".repeat(100);
        let title = session_title(&long);
        assert_eq!(title.chars().count(), 61);
        assert!(title.ends_with('…'));
    }

    fn approval_request() -> kernel_broker::ApprovalRequest {
        kernel_broker::ApprovalRequest {
            agent: "main".to_string(),
            tool: "shell".to_string(),
            risk: kernel_broker::Risk::High,
            arguments: serde_json::Value::Null,
            tainted: false,
            taint_source: None,
            web_approval: None,
            unsandboxed: false,
            networked: false,
        }
    }

    #[tokio::test]
    async fn single_shot_without_auto_approve_is_fail_closed() {
        let approver = build_approver(false, false);
        assert!(!approver.approve(&approval_request()).await.unwrap());
    }

    #[tokio::test]
    async fn single_shot_auto_mode_runs_a_write_even_tainted_and_denies_shell_and_send() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(Store::open(&dir.path().join("s.db")).unwrap()));
        let approver = aux_engine::approver::for_mode(
            kernel_core::config::ApprovalMode::Auto,
            build_approver(false, false),
            &[],
            &aux_engine::registry_from_config(&Config::default()),
            StoreHandle::Shared(Arc::clone(&store)).audit_sink(),
            None,
            None,
        );
        let mut write = approval_request();
        write.tool = "write_file".to_string();
        write.arguments = serde_json::json!({ "path": "note.txt", "content": "x" });
        assert!(approver.approve(&write).await.unwrap());
        // The shell never auto-runs, not even a plain `ls`.
        let mut ls = approval_request();
        ls.arguments = serde_json::json!({ "command": "ls" });
        assert!(!approver.approve(&ls).await.unwrap());
        let mut send = approval_request();
        send.tool = "mail_send".to_string();
        assert!(!approver.approve(&send).await.unwrap());
        // ACT-FREE: a workspace write stays free after taint; a send does not.
        let mut tainted = approval_request();
        tainted.tool = "write_file".to_string();
        tainted.arguments = serde_json::json!({ "path": "note.txt", "content": "x" });
        tainted.tainted = true;
        assert!(approver.approve(&tainted).await.unwrap());
        send.tainted = true;
        assert!(!approver.approve(&send).await.unwrap());
    }

    #[tokio::test]
    async fn auto_approve_approves_in_both_modes() {
        for interactive in [false, true] {
            let approver = build_approver(true, interactive);
            assert!(approver.approve(&approval_request()).await.unwrap());
        }
    }
}
