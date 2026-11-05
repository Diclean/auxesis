//! Config plumbing shared by `aux chat` and the daemon's scheduled jobs:
//! pick one `[[providers]]` entry and load the ordered `[[rules]]`.
//!
//! The error messages are part of the CLI's user-facing contract, so they
//! are kept verbatim when `aux-cli` wraps these errors.

use aux_providers::{shown_id_plain, ProviderConfig};
use kernel_broker::{Rule, ShellSandbox, ToolRegistry};
use kernel_core::Config;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

/// The text of a new `config.toml`: the kernel's defaults with `main` as the
/// chief. Every path that creates the file starts from it. A new file with no
/// `default_agent` would read as an older install, whose chief is `aux`.
pub fn new_config_text() -> Result<String, toml::ser::Error> {
    let config = kernel_core::Config {
        default_agent: aux_runtime::grants::CHIEF_AGENT.to_string(),
        ..kernel_core::Config::default()
    };
    toml::to_string_pretty(&config)
}

/// Create an app default only when this home has no config; never rewrite an
/// existing installation. An explicit `default_agent`, or an older install's
/// file without one, stays exactly as it is. The file is the one under the
/// verified home's real path, and it must be a regular file this user owns.
pub fn bootstrap_config(home: &kernel_core::SandboxHome) -> Result<(), kernel_core::ConfigError> {
    ensure_config_file(&home.real_path()?.join("config.toml"))
}

/// Load the config of `home`, creating it first with [`bootstrap_config`].
///
/// The app loads through this or [`load_or_create`], never through the
/// kernel's own load-or-create: that one writes the kernel's defaults, whose
/// chief is `aux`, into a new home (the workspace `clippy.toml` refuses it).
#[allow(clippy::disallowed_methods)]
pub fn load_or_create_verified(
    home: &kernel_core::SandboxHome,
) -> Result<Config, kernel_core::ConfigError> {
    bootstrap_config(home)?;
    Config::load_or_create_verified(home)
}

/// [`load_or_create_verified`] for a config file given by path, as the
/// kernel's path-based load takes it: a missing file is published from
/// [`new_config_text`], and only a regular file this user owns is loaded.
#[allow(clippy::disallowed_methods)]
pub fn load_or_create(path: &Path) -> Result<Config, kernel_core::ConfigError> {
    ensure_config_file(path)?;
    Config::load_or_create(path)
}

/// Publish `path` from [`new_config_text`] when nothing is there, then accept
/// what is there only as a regular file this user owns.
fn ensure_config_file(path: &Path) -> Result<(), kernel_core::ConfigError> {
    match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            publish_new(path, new_config_text()?.as_bytes())?;
        }
        Err(err) => return Err(err.into()),
        Ok(_) => {}
    }
    Ok(check_config_file(path)?)
}

/// Write `data` to a unique temp file beside `path` (0600, synced), then
/// hard-link it to `path` and drop the temp name. The link fails when `path`
/// exists, so the file appears complete or not at all, and an existing file
/// or symlink is never replaced: a process that loses the race keeps the
/// winner's file.
fn publish_new(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let next = NEXT.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_file_name(format!(".{name}.new.{}.{stamp}.{next}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    let linked = file
        .write_all(data)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&temp, path));
    drop(file);
    // The temp name goes either way: once linked, `path` holds the bytes.
    let _ = std::fs::remove_file(&temp);
    match linked {
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

/// Refuse a `config.toml` that must not be loaded, without following it: a
/// symlink (it can name an older install's file elsewhere), anything but a
/// regular file, or a file another user owns.
fn check_config_file(path: &Path) -> std::io::Result<()> {
    if !check_config_owner(path)?.is_file() {
        return Err(refusal(path, "it is not a regular file"));
    }
    Ok(())
}

/// Refuse a symlink at `path` (it can name another install's file) or a file
/// another user owns, without following it; return what is there.
fn check_config_owner(path: &Path) -> std::io::Result<std::fs::Metadata> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(refusal(path, "it is a symlink, not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(refusal(path, "another user owns it"));
        }
    }
    Ok(meta)
}

fn refusal(path: &Path, why: &str) -> std::io::Error {
    let message = format!("refusing {}: {why}", path.display());
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

/// Why no provider could be selected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderSelectError {
    /// The config has no `[[providers]]` entry.
    #[error("no providers are configured in {path}; add a [[providers]] entry")]
    NoProviders {
        /// Config file that was read.
        path: String,
    },
    /// `--provider <id>` names an unknown entry.
    #[error("provider `{id}` is not configured (available: {available})")]
    UnknownProvider {
        /// Requested id.
        id: String,
        /// Ids that do exist, comma-separated (or `none`).
        available: String,
    },
    /// No `--provider` was given and several entries exist.
    #[error("several providers are configured ({available}); pass --provider <id>")]
    AmbiguousProvider {
        /// Ids that exist, comma-separated.
        available: String,
    },
}

/// Pick the provider entry to use. With several entries, guessing is worse
/// than asking for `--provider`.
pub fn select_provider<'p>(
    providers: &'p [ProviderConfig],
    requested: Option<&str>,
    config_file: &Path,
) -> Result<&'p ProviderConfig, ProviderSelectError> {
    match requested {
        Some(id) => providers
            .iter()
            .find(|provider| provider.id == id)
            .ok_or_else(|| ProviderSelectError::UnknownProvider {
                id: shown_id_plain(id),
                available: provider_ids(providers),
            }),
        None => match providers {
            [] => Err(ProviderSelectError::NoProviders {
                path: config_file.display().to_string(),
            }),
            [only] => Ok(only),
            _ => Err(ProviderSelectError::AmbiguousProvider {
                available: provider_ids(providers),
            }),
        },
    }
}

fn provider_ids(providers: &[ProviderConfig]) -> String {
    if providers.is_empty() {
        "none".to_string()
    } else {
        providers
            .iter()
            .map(|provider| shown_id_plain(&provider.id))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Translate the `[shell]` config section into the shell sandbox profile.
///
/// Only the three documented switches cross over; the sandbox helper path
/// stays the compiled-in default, so config can never point the tool at a
/// different binary.
pub fn shell_sandbox(config: &kernel_core::ShellConfig) -> ShellSandbox {
    ShellSandbox::new(config.sandbox, config.network, config.allow_unsandboxed)
}

/// Build the default tool registry with `shell` configured from `[shell]`.
///
/// This is the production entry point for both `aux chat` and the daemon:
/// `shell.sandbox`, `shell.network` and `shell.allow_unsandboxed` take effect,
/// while [`ToolRegistry::with_defaults`] keeps the safe profile (sandboxed,
/// no network, fail closed) for callers without a config. The double opt-in
/// for unsandboxed runs stays enforced inside the shell tool, and `shell`
/// stays classified as untrusted, so its dispatch write-ahead taints the
/// conversation and the workspace. The `[web]` section is passed through too,
/// so `http_fetch`'s own gate and the engine's egress policy are the same
/// configured gate.
pub fn registry_from_config(config: &Config) -> ToolRegistry {
    let sandbox = shell_sandbox(&config.shell);
    let mut registry = ToolRegistry::with_shell_web(sandbox.clone(), config.web.clone());
    aux_runtime::tools::register_builtins(&mut registry, sandbox.clone(), config.web.clone());
    // `[shell] timeout_secs`: the same tool, under the configured wall clock.
    let shell = aux_runtime::tools::ShellTool::with_options(config.shell.timeout(), sandbox);
    registry.register_native(Box::new(shell));
    registry
}

/// MAIL-NO-SHELL: a domain agent (Mail, Calendar, Clients, Documents) works
/// through its own tools; Mail once hunted the disk with `ls` instead of
/// calling `mail_list`. Unless its agent.md or agent.toml (`toml_tools`) tools
/// list names `shell`, the shell is not offered to it, and a last deny rule
/// refuses a forced call before it runs. Every session setup calls this: the
/// daemon's turn (delegated runs included), scheduled jobs and `aux chat`.
pub fn keep_shell_from_domain_agent(
    home: &Path,
    agent: &str,
    toml_tools: Option<&[String]>,
    registry: &mut ToolRegistry,
    rules: &mut Vec<Rule>,
) {
    // Seal #92 r2: `Mail` is the same agent as `mail`.
    let domain = aux_runtime::grants::DOMAIN_AGENTS
        .iter()
        .any(|id| id.eq_ignore_ascii_case(agent.trim()));
    if !domain {
        return;
    }
    let names_shell = |tools: &[String]| tools.iter().any(|tool| tool == "shell");
    // An agent.md that cannot be read names no tool.
    let md_asks =
        aux_runtime::skills::load_agent(&crate::soul::agent_dir(home, agent)).is_ok_and(|loaded| {
            loaded.source == aux_runtime::skills::agent::AgentSource::AgentMd
                && names_shell(&loaded.tools)
        });
    if md_asks || toml_tools.is_some_and(names_shell) {
        return;
    }
    rules.push(Rule::new(agent, "shell", kernel_broker::Action::Deny));
    registry.mark_unoffered("shell");
}

/// Why `[[rules]]` could not be loaded.
#[derive(Debug, Error)]
pub enum RulesError {
    /// The config file could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The `[[rules]]` section did not parse.
    #[error("parsing [[rules]] in {path}: {}", source.message())]
    Parse {
        /// Config file that was read.
        path: String,
        /// TOML error from [`kernel_core::redact_toml_error`]: position only.
        #[source]
        source: toml::de::Error,
    },
    /// A new rule fragment could not be serialized.
    #[error("serializing [[rules]]: {source}")]
    Serialize {
        /// TOML error.
        #[source]
        source: toml::ser::Error,
    },
}

#[derive(Debug, serde::Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<Rule>,
}

/// Load the optional `[[rules]]` section from the main config file.
pub fn load_rules(path: &Path) -> Result<Vec<Rule>, RulesError> {
    let text = std::fs::read_to_string(path)?;
    let file: RulesFile = toml::from_str(&text).map_err(|err| RulesError::Parse {
        path: path.display().to_string(),
        source: kernel_core::redact_toml_error(&err, "config.toml", &text),
    })?;
    Ok(file.rules)
}

/// Serializes every in-process `append_rule` for the whole process.
///
/// The daemon can answer several approvals concurrently; without this lock
/// two read-modify-write cycles interleave and silently lose rules (and, with
/// a truncating `fs::write`, can tear the file). The daemon call site also
/// holds `kernel_core::with_config_lock`, the shared `<home>/.config.lock` file
/// lock, so writers in other processes are serialized too.
static APPEND_RULE_LOCK: Mutex<()> = Mutex::new(());

/// Append one `[[rules]]` entry to `path`, creating the file when missing
/// (from [`new_config_text`], as every new config starts).
///
/// Existing content is preserved byte for byte; the new rule is appended
/// last, so it wins under the broker's last-match-wins evaluation.
///
/// The read-modify-write is serialized in-process and committed with an
/// atomic replace: the new text is written to a sibling temp file, fsynced
/// and renamed over `path` (never a truncating in-place write), so a
/// concurrent reader can only ever observe the old or the new file, never a
/// torn one. The previous file is kept as `<name>.bak` (best effort) and the
/// parent directory is fsynced so the rename survives a crash.
///
/// A file that is already unparseable is refused with [`RulesError::Parse`]
/// rather than appended to: the next step is a human repair, not more
/// corruption.
pub fn append_rule(path: &Path, rule: &Rule) -> Result<(), RulesError> {
    #[derive(serde::Serialize)]
    struct Fragment<'a> {
        rules: Vec<&'a Rule>,
    }

    let fragment = toml::to_string(&Fragment { rules: vec![rule] })
        .map_err(|source| RulesError::Serialize { source })?;
    let _guard = kernel_core::lock_recover(&APPEND_RULE_LOCK);

    // Never follow a symlink or edit another user's file. A special file
    // keeps the read below, as before: a stalled read only holds this lock.
    match check_config_owner(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(RulesError::Io(err)),
        _ => {}
    }
    let mut text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            new_config_text().map_err(|source| RulesError::Serialize { source })?
        }
        Err(err) => return Err(RulesError::Io(err)),
    };
    if !text.is_empty() {
        // Refuse to stack a good rule onto a broken file: the error names the
        // parse problem and the file stays exactly as it was.
        toml::from_str::<RulesFile>(&text).map_err(|err| RulesError::Parse {
            path: path.display().to_string(),
            source: kernel_core::redact_toml_error(&err, "config.toml", &text),
        })?;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push('\n');
    }
    text.push_str(&fragment);
    replace_file_atomically(path, text.as_bytes())
}

/// Atomically replace `path` with `bytes`.
///
/// Writes a sibling temp file, fsyncs it, keeps the previous contents as
/// `<name>.bak` (best effort), renames over the target and fsyncs the parent
/// directory. On any failure the temp file is removed and `path` is left
/// untouched.
fn replace_file_atomically(path: &Path, bytes: &[u8]) -> Result<(), RulesError> {
    let parent: PathBuf = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    let temp = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let backup = parent.join(format!("{file_name}.bak"));

    let result = (|| -> std::io::Result<()> {
        // SANDBOX-GATEWAY-EXEMPT: legacy agent-config writer, path-based by design; tracked for the gateway follow-up.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // The fresh temp file must not widen the config's permissions: keep
        // the existing mode (config.toml is 0600), or 0600 for a new file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .map(|meta| meta.permissions().mode() & 0o7777)
                .unwrap_or(0o600);
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))?;
        }
        if path.exists() {
            let _ = std::fs::copy(path, &backup);
        }
        std::fs::rename(&temp, path)?;
        // Make the rename durable: without this a crash can lose the new file
        // while the temp names are already gone.
        if let Ok(dir) = std::fs::File::open(&parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if let Err(err) = result {
        let _ = std::fs::remove_file(&temp);
        return Err(RulesError::Io(err));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_broker::Action;
    use tempfile::tempdir;

    #[test]
    fn a_domain_agent_in_any_case_gets_no_shell_but_the_chief_keeps_it() {
        let home = tempdir().unwrap();
        for agent in ["mail", "Mail", "CALENDAR", "Clients"] {
            let mut registry = ToolRegistry::with_defaults();
            let mut rules = Vec::new();
            keep_shell_from_domain_agent(home.path(), agent, None, &mut registry, &mut rules);
            assert!(registry.is_unoffered("shell"), "{agent}");
            assert!(
                rules.iter().any(|rule| rule.agent == agent
                    && rule.tool == "shell"
                    && rule.action == Action::Deny),
                "{agent}: {rules:?}"
            );
        }
        let mut registry = ToolRegistry::with_defaults();
        let mut rules = Vec::new();
        keep_shell_from_domain_agent(home.path(), "aux", None, &mut registry, &mut rules);
        assert!(!registry.is_unoffered("shell"));
        assert!(rules.is_empty());
        // An explicit opt-in still gets it, whatever the case.
        let tools = vec!["shell".to_string()];
        keep_shell_from_domain_agent(home.path(), "Mail", Some(&tools), &mut registry, &mut rules);
        assert!(rules.is_empty());
    }

    #[test]
    fn registry_from_config_applies_the_shell_section() {
        use kernel_core::ShellConfig;

        let config = Config {
            shell: ShellConfig {
                sandbox: false,
                network: true,
                allow_unsandboxed: true,
                ..ShellConfig::default()
            },
            ..Config::default()
        };
        let registry = registry_from_config(&config);
        let sandbox = registry.shell_sandbox().expect("shell is registered");
        assert!(!sandbox.enabled);
        assert!(sandbox.network);
        assert!(sandbox.allow_unsandboxed);
        // The class survives the config path: an unsandboxed shell is still
        // untrusted, so its dispatch taints the conversation and workspace.
        assert!(registry.is_untrusted_output("shell"));
    }

    #[test]
    fn registry_from_default_config_carries_the_safe_profile() {
        let registry = registry_from_config(&Config::default());
        let sandbox = registry.shell_sandbox().expect("shell is registered");
        assert!(sandbox.enabled, "sandbox on by default");
        assert!(!sandbox.network, "network off by default");
        assert!(!sandbox.allow_unsandboxed, "fail closed by default");
    }

    fn provider(id: &str) -> ProviderConfig {
        ProviderConfig {
            disable_thinking: false,
            id: id.to_string(),
            base_url: "http://127.0.0.1:9/v1".to_string(),
            model: "fake-model".to_string(),
            key_user: None,
            kind: aux_providers::ProviderKind::Fake,
        }
    }

    #[test]
    fn select_provider_requires_exactly_one_candidate_without_a_flag() {
        let none: Vec<ProviderConfig> = Vec::new();
        let path = Path::new("/tmp/config.toml");
        assert!(matches!(
            select_provider(&none, None, path),
            Err(ProviderSelectError::NoProviders { .. })
        ));

        let one = vec![provider("alpha")];
        assert_eq!(select_provider(&one, None, path).unwrap().id, "alpha");

        let two = vec![provider("alpha"), provider("beta")];
        assert!(matches!(
            select_provider(&two, None, path),
            Err(ProviderSelectError::AmbiguousProvider { .. })
        ));
        assert_eq!(
            select_provider(&two, Some("beta"), path).unwrap().id,
            "beta"
        );
        assert!(matches!(
            select_provider(&two, Some("gamma"), path),
            Err(ProviderSelectError::UnknownProvider { .. })
        ));
    }

    #[test]
    fn select_provider_errors_name_the_available_ids() {
        let two = vec![provider("alpha"), provider("beta")];
        let path = Path::new("/tmp/config.toml");
        let err = select_provider(&two, Some("gamma"), path).unwrap_err();
        assert_eq!(
            err.to_string(),
            "provider `gamma` is not configured (available: alpha, beta)"
        );
        let err = select_provider(&two, None, path).unwrap_err();
        assert_eq!(
            err.to_string(),
            "several providers are configured (alpha, beta); pass --provider <id>"
        );
        let err = select_provider(&Vec::new(), None, path).unwrap_err();
        assert!(err
            .to_string()
            .starts_with("no providers are configured in"));
    }

    #[test]
    fn select_provider_errors_never_echo_a_key_shaped_id() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let path = Path::new("/tmp/config.toml");

        // A key-shaped id in the available list is hidden in the ambiguity error.
        let two = vec![provider("alpha"), provider(&key)];
        let err = select_provider(&two, None, path).unwrap_err();
        let text = err.to_string();
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<id>"), "{text}");

        // A key-shaped requested id is hidden too.
        let one = vec![provider("alpha")];
        let err = select_provider(&one, Some(&key), path).unwrap_err();
        let text = err.to_string();
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn legacy_dot_keys_still_load_as_agent() {
        // The kernel owns these structs; the app relies on their aliases.
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
            [[rules]]
            dot = "main"
            tool = "read_file"
            action = "allow"
            "#,
        )
        .unwrap();
        let rules = load_rules(&path).unwrap();
        assert_eq!(rules.len(), 1);
        let config: kernel_core::Config = toml::from_str("default_dot = \"axis\"\n").unwrap();
        assert_eq!(config.default_agent, "axis");
        let budgets: kernel_core::Budgets = toml::from_str("[dots.main]\ntokens_in = 5\n").unwrap();
        assert!(budgets.agents.contains_key("main"));
    }

    #[test]
    fn rules_parse_with_all_actions_and_keep_order() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
            [[rules]]
            agent = "main"
            tool = "read_file"
            action = "allow"

            [[rules]]
            agent = "*"
            tool = "shell"
            action = "ask"

            [[rules]]
            agent = "main"
            tool = "*"
            action = "deny"
            "#,
        )
        .unwrap();

        let rules = load_rules(&path).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0], Rule::new("main", "read_file", Action::Allow));
        assert_eq!(rules[1], Rule::new("*", "shell", Action::Ask));
        assert_eq!(rules[2], Rule::new("main", "*", Action::Deny));
    }

    #[test]
    fn rules_absent_or_invalid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n").unwrap();
        assert!(load_rules(&path).unwrap().is_empty());

        std::fs::write(
            &path,
            r#"
            [[rules]]
            agent = "main"
            tool = "shell"
            action = "maybe"
            "#,
        )
        .unwrap();
        let err = load_rules(&path).unwrap_err();
        assert!(matches!(err, RulesError::Parse { .. }), "got {err:?}");
        assert!(err.to_string().contains("parsing [[rules]]"));
    }

    #[test]
    fn rules_unreadable_file_is_an_io_error() {
        let dir = tempdir().unwrap();
        let err = load_rules(&dir.path().join("missing.toml")).unwrap_err();
        assert!(matches!(err, RulesError::Io(_)), "got {err:?}");
    }

    #[test]
    fn append_rule_keeps_existing_content_and_wins_last() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n\n[[rules]]\ndot = \"main\"\ntool = \"shell\"\naction = \"deny\"",
        )
        .unwrap();

        append_rule(&path, &Rule::new("main", "shell", Action::Allow)).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("version = 1\n"), "existing content kept");
        let rules = load_rules(&path).unwrap();
        assert_eq!(
            rules,
            vec![
                Rule::new("main", "shell", Action::Deny),
                Rule::new("main", "shell", Action::Allow),
            ],
            "the appended rule comes last"
        );
    }

    #[test]
    fn append_rule_creates_a_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        append_rule(&path, &Rule::new("axis", "read_file", Action::Allow)).unwrap();
        assert_eq!(
            load_rules(&path).unwrap(),
            vec![Rule::new("axis", "read_file", Action::Allow)]
        );
        // It starts as every new config does: `main` is the chief.
        let text = std::fs::read_to_string(&path).unwrap();
        let config: Config = toml::from_str(&text).unwrap();
        assert_eq!(config.default_agent, "main", "{text}");
    }

    /// A new config names `main` as its chief, whichever load creates it; an
    /// existing file is never rewritten, so an explicit `aux` and an older
    /// install's file without the key both stay exactly as they were.
    #[test]
    fn a_new_config_names_main_and_an_existing_one_is_kept_byte_for_byte() {
        let existing = [
            "version = 1\ndefault_agent = \"aux\"\n",
            "version = 1\n\n[privacy]\nmode = \"open\"\n",
        ];
        for verified in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("config.toml");
            let load = |path: &Path| {
                if verified {
                    let home = kernel_core::verified_home_or_verify(path.parent().unwrap());
                    load_or_create_verified(&home.unwrap())
                } else {
                    load_or_create(path)
                }
            };
            let config = load(&path).unwrap();
            assert_eq!(config.default_agent, "main", "verified: {verified}");
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains("default_agent = \"main\""), "{text}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "verified: {verified}");
            }

            for before in existing {
                std::fs::write(&path, before).unwrap();
                load(&path).unwrap();
                append_rule(&path, &Rule::new("main", "shell", Action::Allow)).unwrap();
                // Kept as it was; the rule is only added after it.
                let after = std::fs::read_to_string(&path).unwrap();
                assert!(after.starts_with(before), "{after}");
                let raw: toml::Table = toml::from_str(&after).unwrap();
                let named = raw.get("default_agent").and_then(|value| value.as_str());
                let expected = before.contains("default_agent").then_some("aux");
                assert_eq!(named, expected, "{after}");
            }
        }
    }

    /// Racing first creates on an empty home, by path and through the verified
    /// handle: the file appears complete or not at all, so every loser loads
    /// the winner's file and every load names `main`. No temp file is left.
    #[test]
    fn racing_first_creates_all_load_a_complete_config_naming_main() {
        const LOADERS: usize = 8;
        for round in 0..50 {
            let dir = tempdir().unwrap();
            let verified = kernel_core::verified_home_or_verify(dir.path()).unwrap();
            let path = dir.path().join("config.toml");
            let start = std::sync::Barrier::new(LOADERS);
            std::thread::scope(|scope| {
                for loader in 0..LOADERS {
                    let (start, verified, path) = (&start, &verified, &path);
                    scope.spawn(move || {
                        start.wait();
                        let config = if loader % 2 == 0 {
                            load_or_create(path)
                        } else {
                            load_or_create_verified(verified)
                        };
                        let config = config.unwrap_or_else(|err| panic!("round {round}: {err}"));
                        assert_eq!(config.default_agent, "main", "round {round}, {loader}");
                    });
                }
            });
            let names: Vec<String> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            let temp = names
                .iter()
                .any(|name| name.starts_with(".config.toml.new"));
            assert!(!temp, "round {round}: {names:?}");
        }
    }

    /// A `config.toml` that is a symlink is refused by every entry point and
    /// never followed: not to create a dangling link's target, and not to load
    /// an older install's file (no `default_agent`), which would read as `aux`.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_config_is_refused_never_followed() {
        let legacy = "version = 1\n\n[privacy]\nmode = \"open\"\n";
        for dangling in [true, false] {
            let dir = tempdir().unwrap();
            let home = dir.path().join("home");
            std::fs::create_dir(&home).unwrap();
            let verified = kernel_core::verified_home_or_verify(&home).unwrap();
            let target = dir.path().join("legacy.toml");
            if !dangling {
                std::fs::write(&target, legacy).unwrap();
            }
            let path = home.join("config.toml");
            std::os::unix::fs::symlink(&target, &path).unwrap();

            let err = load_or_create(&path).unwrap_err();
            assert!(err.to_string().contains("symlink"), "{err}");
            assert!(load_or_create_verified(&verified).is_err());
            assert!(bootstrap_config(&verified).is_err());
            let rule = Rule::new("main", "shell", Action::Allow);
            assert!(append_rule(&path, &rule).is_err());

            let link = std::fs::symlink_metadata(&path).unwrap();
            assert!(link.file_type().is_symlink(), "the link was replaced");
            if dangling {
                assert!(!target.exists(), "the symlink target was created");
            } else {
                assert_eq!(std::fs::read_to_string(&target).unwrap(), legacy);
            }
        }
    }

    #[test]
    fn append_rule_refuses_a_corrupt_file_without_touching_it() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let broken = "version = 1\n[[rules]]\ndot = \"main\"\ntool = \"ow\"\n";
        std::fs::write(&path, broken).unwrap();

        let err = append_rule(&path, &Rule::new("main", "shell", Action::Allow)).unwrap_err();
        assert!(matches!(err, RulesError::Parse { .. }), "got {err:?}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            broken,
            "a broken file must never be appended to"
        );
    }

    #[test]
    fn append_rule_replaces_atomically_and_keeps_a_backup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n").unwrap();

        append_rule(&path, &Rule::new("main", "shell", Action::Allow)).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        append_rule(&path, &Rule::new("main", "read_file", Action::Allow)).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.toml.bak")).unwrap(),
            first,
            "the backup holds the previous version"
        );
        assert_eq!(load_rules(&path).unwrap().len(), 2, "live file has both");
        // No temp file survives a successful replace.
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn append_rule_preserves_the_config_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        append_rule(&path, &Rule::new("main", "shell", Action::Allow)).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the atomic replace must not widen 0600"
        );
    }
}
