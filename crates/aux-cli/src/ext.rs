//! `aux ext` — the extensions surface.
//!
//! Read-only commands (`search`, `show`) work offline from the verified cache.
//! `install`, `mount`, `unmount`, `remove` and `verify` write, and every one
//! refuses a catalog that does not verify against `CATALOG_PUBKEY`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use aux_runtime::extensions::install::KeptApproval;
use aux_runtime::extensions::{self, Catalog, Entry, InstallOptions, SessionOptions};
use clap::{Args, Subcommand};
use kernel_core::Lang;

/// `aux ext <search|show|install|verify|mount|unmount|remove>`.
#[derive(Debug, Args)]
pub struct ExtArgs {
    #[command(subcommand)]
    action: ExtAction,
}

#[derive(Debug, Subcommand)]
enum ExtAction {
    /// Search the catalog by text.
    Search {
        /// Text to match against name and summaries.
        text: String,
    },
    /// Show every field of one entry.
    Show {
        /// Entry name.
        name: String,
    },
    /// Install one pinned extension.
    Install {
        /// Entry name.
        name: String,
    },
    /// Re-hash an install and re-check its pinned tool identities.
    Verify {
        /// Entry name; omit to verify every install.
        name: Option<String>,
        /// Accept the current tools after a freeze (owner re-approval).
        #[arg(long)]
        accept: bool,
        /// With `--accept`: re-pin this build although it is not the approved
        /// one (another version or other bytes, e.g. a newer entry is corrupt
        /// or gone, or a row from before the artefact pin).
        #[arg(long, value_name = "VERSION", requires = "accept", requires = "name")]
        downgrade_to: Option<String>,
        /// With `--accept`: re-trust these changed fields, comma separated
        /// (e.g. `run.args,network`). A plain `--accept` refuses any change to
        /// `source.type`, `kind`, `sensitivity` or `[run]`, a new host
        /// (`network`), a new secret name (`secrets`), another `[oauth]`
        /// table (`oauth`) or a tool added, removed or changed (`tools`), and
        /// this list must name exactly what changed.
        #[arg(
            long,
            alias = "accept-launch-change",
            value_name = "FIELDS",
            value_delimiter = ',',
            requires = "accept",
            requires = "name"
        )]
        accept_change: Vec<String>,
        /// With `--accept`: trust a row approved before launch pins existed;
        /// its command, args and source are printed before it starts.
        #[arg(long, requires = "accept", requires = "name")]
        accept_legacy: bool,
    },
    /// Mount an installed extension for one agent.
    Mount {
        /// Entry name.
        name: String,
        /// Agent to mount for.
        #[arg(long)]
        agent: String,
    },
    /// Unmount an installed extension from one agent.
    Unmount {
        /// Entry name.
        name: String,
        /// Agent to unmount from.
        #[arg(long)]
        agent: String,
    },
    /// Remove an install, its mounts and its secrets. The last approval is
    /// kept: a later install diffs over it like an upgrade.
    Remove {
        /// Entry name.
        name: String,
        /// Also drop the last approval: the next install is a fresh one.
        #[arg(long)]
        forget: bool,
    },
}

/// Run `aux ext`.
pub fn run(args: ExtArgs, _lang: Lang) -> ExitCode {
    let home = kernel_core::auxesis_home();
    match args.action {
        ExtAction::Search { text } => search(&home, &text),
        ExtAction::Show { name } => show(&home, &name),
        ExtAction::Install { name } => install(&home, &name),
        ExtAction::Verify {
            name,
            accept,
            downgrade_to,
            accept_change,
            accept_legacy,
        } => {
            let options = extensions::session::AcceptOptions {
                allow_loopback: false,
                downgrade_to: downgrade_to.as_deref(),
                launch_change: &accept_change,
                legacy: accept_legacy,
            };
            verify(&home, name.as_deref(), accept, &options)
        }
        ExtAction::Mount { name, agent } => mount(&home, &name, &agent),
        ExtAction::Unmount { name, agent } => unmount(&home, &name, &agent),
        ExtAction::Remove { name, forget } => remove(&home, &name, forget),
    }
}

/// Load the verified catalog from the cache, or `None` when absent/unverifiable.
fn load_catalog(home: &Path) -> Option<Catalog> {
    extensions::load_verified_catalog(home)
}

/// Refuse a name that is not `[a-z0-9-]{1,40}` before any work.
fn reject_invalid_name(name: &str) -> Option<ExitCode> {
    if extensions::valid_name(name) {
        None
    } else {
        let _ = writeln!(std::io::stderr(), "invalid extension name `{name}`");
        Some(ExitCode::FAILURE)
    }
}

fn search(home: &Path, text: &str) -> ExitCode {
    let Some(catalog) = load_catalog(home) else {
        let _ = writeln!(
            std::io::stdout(),
            "no verified catalog available yet (the signing key is an open item)"
        );
        return ExitCode::SUCCESS;
    };
    for entry in catalog.search(text) {
        let _ = writeln!(
            std::io::stdout(),
            "{} {} — {}",
            entry.name,
            entry.version,
            entry.summary_en
        );
    }
    ExitCode::SUCCESS
}

fn show(home: &Path, name: &str) -> ExitCode {
    if let Some(code) = reject_invalid_name(name) {
        return code;
    }
    let Some(catalog) = load_catalog(home) else {
        let _ = writeln!(std::io::stderr(), "no verified catalog available yet");
        return ExitCode::FAILURE;
    };
    let Some(entry) = catalog.entry(name) else {
        let _ = writeln!(std::io::stderr(), "unknown extension `{name}`");
        return ExitCode::FAILURE;
    };
    let reviewed = if entry.reviewed {
        "Reviewed"
    } else {
        "Unreviewed"
    };
    let _ = writeln!(std::io::stdout(), "name: {}", entry.name);
    let _ = writeln!(std::io::stdout(), "kind: {:?}", entry.kind);
    let _ = writeln!(std::io::stdout(), "version: {}", entry.version);
    let _ = writeln!(std::io::stdout(), "licence: {}", entry.licence);
    let _ = writeln!(std::io::stdout(), "status: {reviewed}");
    let _ = writeln!(std::io::stdout(), "sensitivity: {:?}", entry.sensitivity);
    let _ = writeln!(std::io::stdout(), "sha256: {}", entry.source.sha256);
    for tool in &entry.tools {
        let _ = writeln!(
            std::io::stdout(),
            "tool: {} network={} secrets={}",
            json(&tool.name),
            json(&tool.network),
            json(&tool.secrets)
        );
    }
    ExitCode::SUCCESS
}

fn install(home: &Path, name: &str) -> ExitCode {
    if let Some(code) = reject_invalid_name(name) {
        return code;
    }
    let Some(catalog) = load_catalog(home) else {
        let _ = writeln!(std::io::stderr(), "no verified catalog available yet");
        return ExitCode::FAILURE;
    };
    let entry = match catalog.installable(name) {
        Ok(entry) => entry.clone(),
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux ext install: {err}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux ext install: {err}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(extensions::install(
        home,
        &entry,
        &InstallOptions::default(),
    ));
    match result {
        Ok(installed) => {
            extensions::ledger::log(
                home,
                extensions::ledger::INSTALL,
                &serde_json::json!({
                    "name": installed.name,
                    "version": installed.version,
                    "sha256": installed.entry.source.sha256,
                }),
            );
            let approval = extensions::mount::require_approval(home, &installed);
            let report = install_report(
                &installed.name,
                &installed.version,
                &installed.entry,
                approval.err().map(|err| err.to_string()),
            );
            let _ = write!(std::io::stdout(), "{report}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            extensions::ledger::log(
                home,
                extensions::ledger::CATALOG_REFUSED,
                &serde_json::json!({"name": name, "reason": err.to_string()}),
            );
            let _ = writeln!(std::io::stderr(), "aux ext install: {err}");
            ExitCode::FAILURE
        }
    }
}

/// What `aux ext install` prints: the build, every host and secret name it
/// declares (EXT-ANCHOR-10), and, for an upgrade or a reinstall over a kept
/// approval (EXT-ANCHOR-9 r2), that it was not started and why. EXT-ANCHOR-11:
/// the hosts as declared too, each one dropped (a wildcard or an invalid
/// `host:port`, never reachable) flagged, and the `[oauth]` client secret.
fn install_report(name: &str, version: &str, entry: &Entry, refused: Option<String>) -> String {
    let list = |values: &[String]| match values.is_empty() {
        true => "none".to_owned(),
        false => json(values),
    };
    let mut declared: Vec<String> = Vec::new();
    for host in entry.tools.iter().flat_map(|tool| &tool.network) {
        if !declared.contains(host) {
            declared.push(host.clone());
        }
    }
    let dropped: Vec<String> = (declared.iter())
        .filter(|host| extensions::catalog::parse_host_port(host).is_none())
        .cloned()
        .collect();
    let mut secrets = entry.secret_names();
    let oauth = entry.oauth.as_ref();
    if let Some(secret) = oauth.and_then(|oauth| oauth.client_secret_env.as_ref()) {
        if !secret.is_empty() && !secrets.contains(secret) {
            secrets.push(secret.clone());
        }
    }
    let mut out = format!(
        "installed {}@{}\n  hosts: {}\n  declared hosts: {}\n  secrets: {}\n",
        extensions::escape_text(name),
        extensions::escape_text(version),
        list(&extensions::mount::network_pins(entry)),
        list(&declared),
        list(&secrets)
    );
    if !dropped.is_empty() {
        out.push_str(&format!(
            "warning: dropped hosts (wildcard or invalid, never reachable): {}\n",
            json(&dropped)
        ));
    }
    if let Some(err) = refused {
        out.push_str(&format!(
            "not started: it needs verify --accept before it runs ({})\n",
            extensions::escape_text(&err)
        ));
    }
    out
}

/// Tell the owner about corrupt entries above the build that runs: they never
/// run, and the running build is the one verified or re-pinned.
fn warn_corrupt_newer(name: &str, running: &str, corrupt_newer: &[String]) {
    for version in corrupt_newer {
        let _ = writeln!(
            std::io::stderr(),
            "aux ext verify: warning: {name}@{version} has a corrupt entry.toml and never runs; \
             {name}@{running} is the build checked"
        );
    }
}

/// The serde name of a catalog value (`binary`, `mcp`, `stdio`), the
/// spelling entry.toml uses.
fn serde_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// A value JSON-quoted: an ANSI escape, a newline or a bidi control inside
/// it is shown escaped, never rendered, so it cannot spoof another line.
fn json<T: serde::Serialize + ?Sized>(value: &T) -> String {
    extensions::quoted(value)
}

/// What an `--accept` now trusts: the artefact sha256, the hosts, secret
/// names and OAuth endpoints granted, and how it runs, so the owner sees the
/// pin before the build starts.
fn trusted_summary(state: &extensions::ExtensionState) -> String {
    let none = || "none".to_owned();
    let hosts = match state.network.is_empty() {
        true => none(),
        false => json(&state.network),
    };
    // EXT-ANCHOR-10: the approved tool names, before the build starts; a
    // tool change is refused once it lists them unless `tools` is named.
    let tools: Vec<&String> = state.tools.keys().collect();
    let mut out = format!(
        "  sha256: {}\n  hosts: {hosts}\n  secrets: {}\n  oauth: {}\n  tools: {}\n",
        state.artefact.clone().unwrap_or_else(none),
        json(&state.secrets),
        state.oauth.as_ref().map_or_else(none, json),
        json(&tools),
    );
    if let Some(launch) = &state.launch {
        // Args as a JSON list: a space inside one arg stays visible.
        let args = json(&launch.run.args);
        out.push_str(&format!(
            "  command: {}\n  args: {args}\n  kind: {}\n  transport: {}\n  \
             source: {}\n  sensitivity: {}\n",
            json(&launch.run.command),
            serde_name(&launch.kind),
            serde_name(&launch.run.transport),
            serde_name(&launch.source),
            serde_name(&launch.sensitivity),
        ));
    }
    out
}

fn verify(
    home: &Path,
    name: Option<&str>,
    accept: bool,
    options: &extensions::session::AcceptOptions<'_>,
) -> ExitCode {
    let names: Vec<String> = match name {
        Some(name) => vec![name.to_owned()],
        // Listed through the verified home: a linked or unreadable root fails.
        None => match extensions::install::installed_names(home) {
            Ok(found) => found,
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "aux ext verify: {err}");
                return ExitCode::FAILURE;
            }
        },
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux ext verify: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut failed = false;
    for name in names {
        if let Some(_code) = reject_invalid_name(&name) {
            failed = true;
            continue;
        }
        if accept {
            // Re-pin the current identity before clearing the freeze, so the
            // next start does not refreeze on the same drift. The pin is saved
            // and printed before the build starts.
            let print = |state: &extensions::ExtensionState| {
                let version = &state.version;
                let _ = writeln!(std::io::stdout(), "trusting {name}@{version}");
                let _ = write!(std::io::stdout(), "{}", trusted_summary(state));
            };
            let accepted = extensions::session::accept_with(home, &name, options, print);
            match runtime.block_on(accepted) {
                Ok(accepted) => {
                    let version = &accepted.state.version;
                    warn_corrupt_newer(&name, version, &accepted.corrupt_newer);
                    let _ = writeln!(std::io::stdout(), "accepted {name}@{version}");
                    continue;
                }
                Err(err) => {
                    // The refusal still names the corrupt newer entries.
                    if let extensions::session::SessionError::DowngradeRefused {
                        installed,
                        corrupt_newer,
                        ..
                    } = &err
                    {
                        warn_corrupt_newer(&name, installed, corrupt_newer);
                    }
                    let _ = writeln!(std::io::stderr(), "aux ext verify: {err}");
                    failed = true;
                    continue;
                }
            }
        }
        match extensions::verify_installed_report(home, &name) {
            Ok(report) => {
                let installed = report.installed;
                warn_corrupt_newer(&name, &installed.version, &report.corrupt_newer);
                // An upgraded build the owner did not approve is never started
                // to be checked: only `--accept` may run it.
                if let Err(err) = extensions::mount::require_approval(home, &installed) {
                    let _ = writeln!(std::io::stderr(), "aux ext verify: {err}");
                    failed = true;
                    continue;
                }
                let drift = runtime.block_on(async {
                    match extensions::session::session_for(
                        home,
                        &installed,
                        &SessionOptions::default(),
                    )
                    .await
                    {
                        Ok(session) => {
                            let result =
                                extensions::session::verify_identity(home, &name, &session.tools);
                            session.stop().await;
                            result.map_err(|err| err.to_string())
                        }
                        Err(err) => Err(err.to_string()),
                    }
                });
                match drift {
                    Ok(()) => {
                        extensions::ledger::log(
                            home,
                            extensions::ledger::VERIFY,
                            &serde_json::json!({"name": name, "ok": true}),
                        );
                        let _ = writeln!(std::io::stdout(), "verified {name}");
                    }
                    Err(err) => {
                        let _ = writeln!(std::io::stderr(), "aux ext verify: {err}");
                        failed = true;
                    }
                }
            }
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "aux ext verify: {err}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn mount(home: &Path, name: &str, agent: &str) -> ExitCode {
    if let Some(code) = reject_invalid_name(name) {
        return code;
    }
    match extensions::mount(home, name, agent) {
        Ok(()) => {
            let _ = writeln!(std::io::stdout(), "mounted {name} for {agent}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux ext mount: {err}");
            ExitCode::FAILURE
        }
    }
}

fn unmount(home: &Path, name: &str, agent: &str) -> ExitCode {
    if let Some(code) = reject_invalid_name(name) {
        return code;
    }
    match extensions::unmount(home, name, agent) {
        Ok(()) => {
            let _ = writeln!(std::io::stdout(), "unmounted {name} from {agent}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux ext unmount: {err}");
            ExitCode::FAILURE
        }
    }
}

fn remove(home: &Path, name: &str, forget: bool) -> ExitCode {
    if let Some(code) = reject_invalid_name(name) {
        return code;
    }
    // Read before the row goes: a corrupt row is never kept as `.last`.
    let corrupt_row = extensions::install::approval_row_is_corrupt(home, name);
    let removed = match forget {
        true => extensions::install::remove_and_forget(home, name),
        false => extensions::remove(home, name),
    };
    match removed {
        Ok(removed) => {
            extensions::ledger::log(
                home,
                extensions::ledger::REMOVE,
                &serde_json::json!({"name": name, "removed": removed, "forget": forget}),
            );
            let _ = writeln!(std::io::stdout(), "removed {name} ({removed} install(s))");
            if !forget {
                let kept = extensions::install::kept_approval(home, name);
                let _ = write!(
                    std::io::stdout(),
                    "{}",
                    remove_notes(name, corrupt_row, kept)
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux ext remove: {err}");
            ExitCode::FAILURE
        }
    }
}

/// What a plain `remove` says about the approval it keeps (EXT-ANCHOR-11):
/// kept, a corrupt row it could not keep, or an unreadable `.last`.
fn remove_notes(name: &str, corrupt_row: bool, kept: KeptApproval) -> String {
    let forget = format!("`aux ext remove {name} --forget` drops it");
    let mut out = String::new();
    if corrupt_row {
        out.push_str(&format!(
            "warning: the approval row of {name} is corrupt and was not kept as {name}.last\n"
        ));
    }
    match kept {
        KeptApproval::None => {}
        KeptApproval::Kept => out.push_str(&format!("approval kept; {forget}\n")),
        KeptApproval::Unreadable => out.push_str(&format!(
            "warning: the kept approval {name}.last is unreadable and refuses any \
             reinstall; {forget}\n"
        )),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_names_are_rejected_before_any_work() {
        assert!(reject_invalid_name("Bad_Name").is_some());
        assert!(reject_invalid_name("../escape").is_some());
        assert!(reject_invalid_name("").is_some());
        assert!(reject_invalid_name("datagouv-mcp").is_none());
    }

    // EXT-ANCHOR-6: an older build is re-pinned only by name, with `--accept`.
    #[test]
    fn downgrade_to_needs_accept_and_one_name() {
        #[derive(Debug, clap::Parser)]
        struct Cli {
            #[command(flatten)]
            ext: ExtArgs,
        }
        let parse = |args: &[&str]| {
            let argv = ["aux"].iter().chain(args).copied();
            <Cli as clap::Parser>::try_parse_from(argv).map(|cli| cli.ext.action)
        };
        assert!(parse(&["verify", "demo", "--downgrade-to", "1.0.0"]).is_err());
        assert!(parse(&["verify", "--accept", "--downgrade-to", "1.0.0"]).is_err());
        let ok = parse(&["verify", "demo", "--accept", "--downgrade-to", "1.0.0"]);
        assert!(
            matches!(ok, Ok(ExtAction::Verify { downgrade_to: Some(ref v), .. }) if v == "1.0.0"),
            "{ok:?}"
        );
        let fields = ["verify", "demo", "--accept-launch-change", "run.args"];
        assert!(parse(&fields).is_err());
        let ok = parse(&[
            "verify",
            "demo",
            "--accept",
            "--accept-launch-change",
            "run.args,run.command",
        ]);
        // EXT-ANCHOR-9: `--accept-change` is the name, the old one an alias.
        let Ok(ExtAction::Verify { accept_change, .. }) = &ok else {
            panic!("{ok:?}");
        };
        assert_eq!(*accept_change, ["run.args", "run.command"]);
        let ok = parse(&["verify", "demo", "--accept", "--accept-change", "secrets"]);
        let Ok(ExtAction::Verify { accept_change, .. }) = &ok else {
            panic!("{ok:?}");
        };
        assert_eq!(*accept_change, ["secrets"]);
        assert!(parse(&["verify", "demo", "--accept-legacy"]).is_err());
        let ok = parse(&["verify", "demo", "--accept", "--accept-legacy"]);
        assert!(
            matches!(
                ok,
                Ok(ExtAction::Verify {
                    accept_legacy: true,
                    ..
                })
            ),
            "{ok:?}"
        );
    }

    // EXT-ANCHOR-8: the summary names every trusted value, with the
    // entry.toml spelling of kind, transport, source and sensitivity.
    #[test]
    fn trusted_summary_names_every_trusted_value() {
        use extensions::catalog::{EntryKind, Run, Sensitivity, SourceType, Transport};
        let mut state = extensions::ExtensionState {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            kind: "mcp".to_owned(),
            frozen: false,
            tools: Default::default(),
            network: vec![
                "a.example:443".to_owned(),
                "b\u{202e}.example:443".to_owned(),
            ],
            secrets: vec!["EXT_DEMO__TOKEN".to_owned()],
            oauth: None,
            artefact: Some("ab".repeat(32)),
            launch: Some(extensions::mount::LaunchPin {
                source: SourceType::Uv,
                kind: EntryKind::SkillPack,
                sensitivity: Sensitivity::Sensitive,
                run: Run {
                    transport: Transport::Http,
                    command: "server\u{1b}[2K\n  sha256: forged".to_owned(),
                    args: vec!["-c".to_owned(), "a b".to_owned()],
                },
            }),
        };
        let text = trusted_summary(&state);
        for line in [
            format!("  sha256: {}\n", "ab".repeat(32)),
            // EXT-ANCHOR-9 r2: hosts escaped like the rest, bidi as `\u{..}`.
            "  hosts: [\"a.example:443\",\"b\\u{202e}.example:443\"]\n".to_owned(),
            "  secrets: [\"EXT_DEMO__TOKEN\"]\n".to_owned(),
            "  oauth: none\n".to_owned(),
            // EXT-ANCHOR-9: escaped like args, never a raw ANSI or new line.
            "  command: \"server\\u001b[2K\\n  sha256: forged\"\n".to_owned(),
            "  args: [\"-c\",\"a b\"]\n".to_owned(),
            "  kind: skill-pack\n".to_owned(),
            "  transport: http\n".to_owned(),
            "  source: uv\n".to_owned(),
            "  sensitivity: sensitive\n".to_owned(),
        ] {
            assert!(text.contains(&line), "{line:?} in {text}");
        }
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{202e}'),
            "{text}"
        );
        let sha_lines = text.lines().filter(|l| l.starts_with("  sha256:"));
        assert_eq!(sha_lines.count(), 1, "no forged line: {text}");
        (state.network, state.artefact, state.launch) = (Vec::new(), None, None);
        state.secrets.clear();
        assert_eq!(
            trusted_summary(&state),
            "  sha256: none\n  hosts: none\n  secrets: []\n  oauth: none\n  tools: []\n"
        );
        state.tools.insert("ping".to_owned(), "ab".to_owned());
        state
            .tools
            .insert("new\u{2028}".to_owned(), "cd".to_owned());
        let text = trusted_summary(&state);
        assert!(
            text.contains("  tools: [\"new\\u{2028}\",\"ping\"]\n"),
            "{text}"
        );
    }

    fn report_entry(network: &str, oauth: &str) -> Entry {
        let text = format!(
            "name = \"demo\"\nkind = \"mcp\"\nversion = \"1.0.0\"\nlicence = \"MIT\"\n\
             reviewed = true\nsensitivity = \"public\"\nsummary_en = \"d\"\nsummary_fr = \"d\"\n\
             [source]\ntype = \"binary\"\npackage = \"server\"\nsha256 = \"{}\"\n\
             [run]\ntransport = \"stdio\"\ncommand = \"server\"\n\
             [[tools]]\nname = \"ping\"\ndescription = \"Ping\"\nnetwork = [{network}]\n\
             secrets = [\"EXT_DEMO__TOKEN\"]\nauth = \"none\"\nfs = []\n{oauth}",
            "a".repeat(64)
        );
        toml::from_str(&text).unwrap()
    }

    // EXT-ANCHOR-10: every install names its hosts and secret names; one that
    // waits for the owner says it was not started and names the command.
    // EXT-ANCHOR-11: the declared hosts too, a dropped wildcard flagged, and
    // the `[oauth]` client secret among the secret names.
    #[test]
    fn install_report_names_hosts_secrets_and_the_verify_command() {
        let fresh = install_report(
            "demo",
            "1.0.0",
            &report_entry(r#""a.example:443""#, ""),
            None,
        );
        assert_eq!(
            fresh,
            "installed demo@1.0.0\n  hosts: [\"a.example:443\"]\n  \
             declared hosts: [\"a.example:443\"]\n  secrets: [\"EXT_DEMO__TOKEN\"]\n"
        );
        let oauth = "[oauth]\nauthorization_url = \"https://a.example/auth\"\n\
                     token_url = \"https://a.example/token\"\nclient_id = \"c\"\n\
                     client_secret_env = \"EXT_DEMO__CLIENT_SECRET\"\nscopes = []\n";
        let entry = report_entry(r#""*.example:443", "b.example:443""#, oauth);
        let refused = "approval_required: extension `demo` changed since approval \
                       (new network hosts: \"b.example:443\"); run \
                       `aux ext verify demo --accept --accept-change network`";
        let text = install_report("demo", "2.0.0", &entry, Some(refused.to_owned()));
        assert!(text.contains("  hosts: [\"b.example:443\"]\n"), "{text}");
        let declared = "  declared hosts: [\"*.example:443\",\"b.example:443\"]\n";
        assert!(text.contains(declared), "{text}");
        let dropped = "warning: dropped hosts (wildcard or invalid, never reachable): \
                       [\"*.example:443\"]\n";
        assert!(text.contains(dropped), "{text}");
        let secrets = "  secrets: [\"EXT_DEMO__TOKEN\",\"EXT_DEMO__CLIENT_SECRET\"]\n";
        assert!(text.contains(secrets), "{text}");
        assert!(
            text.contains("not started: it needs verify --accept"),
            "{text}"
        );
        assert!(
            text.contains("`aux ext verify demo --accept --accept-change network`)\n"),
            "{text}"
        );
    }

    // EXT-ANCHOR-11: a plain remove says what it kept, a corrupt row it could
    // not keep, and an unreadable `.last`, each with `--forget`.
    #[test]
    fn remove_notes_name_the_kept_approval() {
        let forget = "`aux ext remove demo --forget` drops it\n";
        let kept = remove_notes("demo", false, KeptApproval::Kept);
        assert_eq!(kept, format!("approval kept; {forget}"));
        assert_eq!(remove_notes("demo", false, KeptApproval::None), "");
        let corrupt = remove_notes("demo", true, KeptApproval::Unreadable);
        assert!(
            corrupt.contains("row of demo is corrupt and was not kept"),
            "{corrupt}"
        );
        assert!(corrupt.contains("demo.last is unreadable"), "{corrupt}");
        assert!(corrupt.ends_with(forget), "{corrupt}");
    }

    #[test]
    fn remove_takes_forget() {
        #[derive(Debug, clap::Parser)]
        struct Cli {
            #[command(flatten)]
            ext: ExtArgs,
        }
        let parse = |args: &[&str]| {
            let argv = ["aux"].iter().chain(args).copied();
            <Cli as clap::Parser>::try_parse_from(argv).map(|cli| cli.ext.action)
        };
        let ok = parse(&["remove", "demo", "--forget"]);
        assert!(
            matches!(ok, Ok(ExtAction::Remove { forget: true, .. })),
            "{ok:?}"
        );
        let ok = parse(&["remove", "demo"]);
        assert!(
            matches!(ok, Ok(ExtAction::Remove { forget: false, .. })),
            "{ok:?}"
        );
    }
}
