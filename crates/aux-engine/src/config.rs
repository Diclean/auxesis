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
/// lock, so writers in other processes are serialized too (security review P2).
static APPEND_RULE_LOCK: Mutex<()> = Mutex::new(());

/// Append one `[[rules]]` entry to `path`, creating the file when missing.
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

    let mut text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
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
