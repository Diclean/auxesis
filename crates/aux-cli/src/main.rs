//! `aux` — the Auxesis control CLI.

mod activity;
mod brief;
mod budget;
mod chat;
#[cfg(feature = "google")]
mod connect;
mod contacts;
mod crm;
mod docs;
mod docs_export;
mod doctor;
mod ext;
mod install;
mod mail;
mod mcp;
mod memory;
mod notify;
mod skill;
mod vault;
mod workspace;

use budget::UsageArgs;
use chat::ChatArgs;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::io::Write;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "aux", version, about = "Auxesis control CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check that this machine can run Auxesis.
    Doctor,
    /// Show the read-only activity timeline from the store.
    Activity(activity::ActivityArgs),
    /// Chat with an agent.
    Chat(ChatArgs),
    /// Connect this Mac to an app (Google mail and calendar).
    #[cfg(feature = "google")]
    Connect(connect::ConnectArgs),
    /// Send a macOS notification (manual check).
    Notify(notify::NotifyArgs),
    /// Manage AI service keys in the macOS Keychain.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Install the launchd agent that keeps auxd running (macOS).
    Install,
    /// Boot out the launchd agent and remove its plist.
    Uninstall,
    /// Show the launchd agent state and the daemon log heartbeat.
    Status,
    /// Pause everything: always-on work stops at the next step.
    Stop,
    /// Resume after a pause.
    Resume,
    /// Show recorded usage per agent and day.
    Usage(UsageArgs),
    /// Generate or manage the morning brief.
    Brief(brief::BriefArgs),
    /// Trust a workspace that was marked as untrusted.
    Workspace(workspace::WorkspaceArgs),
    /// Inspect the configured MCP servers (`~/.auxesis/mcp.toml`).
    Mcp(mcp::McpArgs),
    /// Browse, install and mount extensions from the signed catalog.
    Ext(ext::ExtArgs),
    /// Inspect quarantined memory (read-only owner view).
    Memory(memory::MemoryArgs),
    /// Set up and read a mailbox (IMAP).
    Mail(mail::MailArgs),
    /// Import and manage the local contacts that Private mode checks names against.
    Contacts(contacts::ContactsArgs),
    /// Manage the owner's clients: promote a mail sender you confirm to a party.
    Crm(crm::CrmArgs),
    /// List the receipts collected from mail, link each one to its client, export them.
    Docs(docs::DocsArgs),
    /// Manage an agent's skills (list, dry run, run).
    Skill(skill::SkillArgs),
}

#[derive(Debug, Subcommand)]
enum SecretAction {
    /// Store a secret in `~/.auxesis/.env` (0600); the value is read from
    /// stdin and never appears in argv.
    Set {
        /// Account name (e.g. `deepseek`) — used as the env var id.
        account: String,
    },
    /// Check whether a secret exists; never prints its value.
    Check {
        /// Account name (e.g. `deepseek`).
        account: String,
        /// Check the macOS Keychain instead of `~/.auxesis/.env`.
        #[arg(long)]
        keychain: bool,
    },
}

fn main() -> ExitCode {
    // A panic in a command must not echo its input payload to the terminal or
    // a log: the shared hook writes only the source location, as auxd does.
    kernel_broker::install_payload_free_panic_hook();
    let lang = kernel_core::Lang::from_env();
    // The one shared sandbox guard (J-02): refuse the real ~/.auxesis before
    // any command reads or writes. The connect-time port check lives in
    // `doctor` (`ensure_sandbox_port`).
    let home = match kernel_core::ensure_sandbox_guard(None) {
        Ok(home) => home,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux: {err}");
            return ExitCode::FAILURE;
        }
    };
    // WO-07: the one-time `dots/` -> `agents/` move, before any command reads them.
    match aux_engine::layout::migrate_legacy_agents_dir(&home) {
        Ok(Some(moved)) => {
            let _ = writeln!(
                std::io::stderr(),
                "aux: moved {} to {}",
                moved.from.display(),
                moved.to.display()
            );
        }
        Ok(None) => {}
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux: {err}");
            return ExitCode::FAILURE;
        }
    }
    let mut command = Cli::command();
    let args: Vec<_> = std::env::args_os().collect();
    let chat_help = args.get(1).is_some_and(|arg| arg == "chat")
        && args
            .iter()
            .skip(2)
            .any(|arg| arg == "--help" || arg == "-h");
    if chat_help && chat::daemon_is_available() {
        command = command.mut_subcommand("chat", |chat| {
            chat.mut_arg("auto_approve", |arg| arg.hide(true))
        });
    }
    let matches = command.get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    match cli.command {
        Some(Command::Doctor) => {
            let report = doctor::run();
            report.print();
            if report.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some(Command::Activity(args)) => activity::run(args),
        Some(Command::Chat(args)) => chat::run(args),
        #[cfg(feature = "google")]
        Some(Command::Connect(args)) => connect::run(args),
        Some(Command::Notify(args)) => notify::run(args),
        Some(Command::Install) => match install::install() {
            Ok(report) => {
                report.print();
                ExitCode::SUCCESS
            }
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "aux install: {err}");
                ExitCode::FAILURE
            }
        },
        Some(Command::Uninstall) => match install::uninstall() {
            Ok(report) => {
                report.print();
                ExitCode::SUCCESS
            }
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "aux uninstall: {err}");
                ExitCode::FAILURE
            }
        },
        Some(Command::Status) => match install::status() {
            Ok(report) => {
                report.print();
                if report.success() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "aux status: {err}");
                ExitCode::FAILURE
            }
        },
        Some(Command::Stop) => budget::run_stop(),
        Some(Command::Resume) => budget::run_resume(),
        Some(Command::Usage(args)) => budget::run_usage(args),
        Some(Command::Brief(args)) => brief::run(args),
        Some(Command::Workspace(args)) => workspace::run(args),
        Some(Command::Mcp(args)) => mcp::run(args, lang),
        Some(Command::Ext(args)) => ext::run(args, lang),
        Some(Command::Memory(args)) => memory::run(args),
        Some(Command::Mail(args)) => mail::run(args),
        Some(Command::Contacts(args)) => contacts::run(args),
        Some(Command::Crm(args)) => crm::run(args),
        Some(Command::Docs(args)) => docs::run(args),
        Some(Command::Skill(args)) => skill::run(args),
        Some(Command::Secret { action }) => match action {
            SecretAction::Set { account } => {
                let result = vault::read_from_stdin().and_then(|value| {
                    vault::set_in_env_file(&kernel_core::auxesis_home(), &account, &value)
                });
                match result {
                    Ok(()) => {
                        let target = kernel_core::auxesis_home().join(".env");
                        let _ = writeln!(
                            std::io::stdout(),
                            "secret stored for `{account}` in {}",
                            target.display()
                        );
                        ExitCode::SUCCESS
                    }
                    Err(err) => {
                        let _ = writeln!(std::io::stderr(), "aux secret: {err}");
                        ExitCode::FAILURE
                    }
                }
            }
            SecretAction::Check { account, keychain } => {
                let use_keychain = keychain && cfg!(target_os = "macos");
                let result = if use_keychain {
                    vault::exists(&account)
                } else {
                    Ok(vault::env_file_has(&kernel_core::auxesis_home(), &account))
                };
                match result {
                    Ok(true) => {
                        let target = if use_keychain {
                            format!("Keychain service `{}`", vault::SERVICE)
                        } else {
                            format!("{}", kernel_core::auxesis_home().join(".env").display())
                        };
                        let _ = writeln!(std::io::stdout(), "found for `{account}` in {target}");
                        ExitCode::SUCCESS
                    }
                    Ok(false) => {
                        let _ = writeln!(
                            std::io::stderr(),
                            "not found for `{account}` ({}); try the other source",
                            if use_keychain { "Keychain" } else { ".env" }
                        );
                        ExitCode::FAILURE
                    }
                    Err(err) => {
                        let _ = writeln!(std::io::stderr(), "aux secret: {err}");
                        ExitCode::FAILURE
                    }
                }
            }
        },
        None => {
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                match lang {
                    kernel_core::Lang::Fr => format!(
                        "aux {} — lance `aux doctor` pour vérifier l'installation",
                        kernel_core::VERSION
                    ),
                    kernel_core::Lang::En => format!(
                        "aux {} — run `aux doctor` to check the installation",
                        kernel_core::VERSION
                    ),
                }
            );
            ExitCode::SUCCESS
        }
    }
}
