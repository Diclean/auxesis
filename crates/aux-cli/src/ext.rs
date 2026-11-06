//! `aux ext` — the extensions surface.
//!
//! Read-only commands (`search`, `show`) work offline from the verified cache.
//! `install`, `mount`, `unmount`, `remove` and `verify` write, and every one
//! refuses a catalog that does not verify against `CATALOG_PUBKEY`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use aux_runtime::extensions::{self, Catalog, InstallOptions, SessionOptions};
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
        /// With `--accept`: re-pin this build even though it is older than the
        /// approved one (a newer entry is corrupt or gone).
        #[arg(long, value_name = "VERSION", requires = "accept", requires = "name")]
        downgrade_to: Option<String>,
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
    /// Remove an install, its mounts and its secrets.
    Remove {
        /// Entry name.
        name: String,
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
        } => verify(&home, name.as_deref(), accept, downgrade_to.as_deref()),
        ExtAction::Mount { name, agent } => mount(&home, &name, &agent),
        ExtAction::Unmount { name, agent } => unmount(&home, &name, &agent),
        ExtAction::Remove { name } => remove(&home, &name),
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
            "tool: {} network=[{}] secrets=[{}]",
            tool.name,
            tool.network.join(","),
            tool.secrets.join(",")
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
            let _ = writeln!(
                std::io::stdout(),
                "installed {}@{}",
                installed.name,
                installed.version
            );
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

fn verify(home: &Path, name: Option<&str>, accept: bool, downgrade_to: Option<&str>) -> ExitCode {
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
            // next start does not refreeze on the same drift.
            let accepted = extensions::session::accept_installed(home, &name, false, downgrade_to);
            match runtime.block_on(accepted) {
                Ok(accepted) => {
                    let version = &accepted.state.version;
                    warn_corrupt_newer(&name, version, &accepted.corrupt_newer);
                    let _ = writeln!(std::io::stdout(), "accepted {name}@{version}");
                    continue;
                }
                Err(err) => {
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

fn remove(home: &Path, name: &str) -> ExitCode {
    if let Some(code) = reject_invalid_name(name) {
        return code;
    }
    match extensions::remove(home, name) {
        Ok(removed) => {
            extensions::ledger::log(
                home,
                extensions::ledger::REMOVE,
                &serde_json::json!({"name": name, "removed": removed}),
            );
            let _ = writeln!(std::io::stdout(), "removed {name} ({removed} install(s))");
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux ext remove: {err}");
            ExitCode::FAILURE
        }
    }
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
    }
}
