//! Runtime resolution of the `[acp]` configuration.
//!
//! `config.toml` parsing lives in `aux-core` (`AcpConfig`); this module turns
//! one entry into the runtime spec the supervisor consumes, expands `~`, and
//! computes the per-agent scratch workspace:
//!
//! `<home>/agents/<agent>/acp-workspace` — never the repo, never `~/.auxesis`
//! itself (owner decision for A0). The agent gets a private `HOME`/`TMPDIR`
//! inside that scratch dir and no other writable surface.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kernel_core::config::AcpConfig;

use crate::error::AcpError;
use crate::jsonrpc::RpcLimits;

/// One resolved `[acp.agents.<id>]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpAgentSpec {
    /// Config key (`opencode`, `claude`, ...).
    pub id: String,
    /// Executable name or path.
    pub command: String,
    /// Arguments passed verbatim after the executable.
    pub args: Vec<String>,
    /// Model label recorded for the run (the agent picks its own default in
    /// A0; session model selection is a fast follow).
    pub model: String,
    /// Authentication mode.
    pub auth: kernel_core::config::AcpAuthMode,
    /// Read-only vendor data dir exposed to the child, expanded and
    /// canonicalised when it exists.
    pub vendor_data_dir: Option<PathBuf>,
    /// Extra environment variable names passed through to the child.
    pub env_passthrough: Vec<String>,
}

impl AcpAgentSpec {
    /// A spec for tests and the smoke example.
    pub fn new(id: impl Into<String>, command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            id: id.into(),
            command: command.into(),
            args,
            model: String::new(),
            auth: kernel_core::config::AcpAuthMode::CliLogin,
            vendor_data_dir: None,
            env_passthrough: Vec::new(),
        }
    }
}

/// Effective hard caps for one ACP backend.
#[derive(Debug, Clone)]
pub struct AcpLimits {
    /// Wall-clock cap for one turn.
    pub turn_timeout: Duration,
    /// Turns allowed per task.
    pub max_turns_per_task: u32,
    /// Turn attempts allowed per rolling minute per task (`0` disables).
    pub max_turns_per_minute: u32,
    /// Output budget for one turn, in bytes.
    pub max_output_bytes: usize,
    /// Bounded wait for one permission answer.
    pub permission_timeout: Duration,
    /// Fixed cost reserve per turn, in whole cents.
    pub turn_cost_estimate_cents: u64,
    /// `RLIMIT_CPU` seconds for the agent (`0` = turn timeout + grace).
    pub max_cpu_seconds: u64,
    /// `RLIMIT_FSIZE` per file for the agent.
    pub max_file_bytes: u64,
    /// `RLIMIT_NOFILE` for the agent.
    pub max_open_files: u64,
    /// `RLIMIT_NPROC` headroom above the current user count (`0` disables).
    pub max_processes: u64,
    /// Best-effort `RLIMIT_AS`/`RLIMIT_DATA` (`0` disables).
    pub max_memory_bytes: u64,
    /// JSON-RPC framing caps.
    pub rpc: RpcLimits,
}

impl Default for AcpLimits {
    fn default() -> Self {
        let config = AcpConfig::default();
        Self::from_config(&config)
    }
}

impl AcpLimits {
    /// Build from the `[acp]` section, keeping the JSON-RPC defaults.
    pub fn from_config(config: &AcpConfig) -> Self {
        Self {
            turn_timeout: config.turn_timeout(),
            max_turns_per_task: config.max_turns_per_task,
            max_turns_per_minute: config.max_turns_per_minute,
            max_output_bytes: config.max_output_bytes,
            permission_timeout: config.permission_timeout(),
            turn_cost_estimate_cents: config.turn_cost_estimate_cents,
            max_cpu_seconds: config.max_cpu_seconds,
            max_file_bytes: config.max_file_bytes,
            max_open_files: config.max_open_files,
            max_processes: config.max_processes,
            max_memory_bytes: config.max_memory_bytes,
            rpc: RpcLimits::default(),
        }
    }

    /// Build from the `[acp]` section with explicit RPC caps (tests).
    pub fn from_config_with_rpc(config: &AcpConfig, rpc: RpcLimits) -> Self {
        Self {
            rpc,
            ..Self::from_config(config)
        }
    }
}

/// Expand a leading `~/` against the real home.
///
/// The home comes from `$HOME` when it names an existing directory;
/// otherwise the path is left unchanged and resolution fails loudly later.
/// Only a literal `~/` prefix is expanded — `~user` is not a thing here and
/// must not silently become a path under the wrong home.
pub fn expand_tilde(path: &str, home: Option<&Path>) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => match home {
            Some(home) => home.join(rest),
            None => PathBuf::from(path),
        },
        None => PathBuf::from(path),
    }
}

/// The per-agent scratch workspace: `<home>/agents/<agent>/acp-workspace`.
pub fn scratch_workspace(home: &Path, agent: &str) -> PathBuf {
    aux_engine::agent_dir(home, agent).join("acp-workspace")
}

/// Names that may never be forwarded to the child.
const FORBIDDEN_ENV_NAMES: &[&str] = &["HOME", "TMPDIR", "PATH", "SHELL", "PWD", "OLDPWD"];

/// True when an env **name** is the agent's own credential (`*_API_KEY`,
/// `*_TOKEN`, `*_KEY`): the one passthrough a private turn still forwards.
pub fn env_name_is_credential(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ["_API_KEY", "_AUTH_TOKEN", "_ACCESS_TOKEN", "_TOKEN", "_KEY"]
        .iter()
        .any(|suffix| upper.ends_with(suffix))
}

/// True when an env **name** must never cross into the child: our own key
/// shapes, the private path variables, and the dynamic-linker injection
/// variables (`DYLD_*`/`LD_*` and friends) that would let a name smuggle code
/// or library resolution into the agent/terminal process.
pub fn env_name_forbidden(name: &str) -> bool {
    name.starts_with("AUX_KEY_")
        || name.starts_with("AUXESIS_")
        || name.starts_with("DYLD_")
        || name.starts_with("LD_")
        || FORBIDDEN_ENV_NAMES.contains(&name)
}

/// Resolve one agent for a provider id.
///
/// Resolution order: an explicit `agent_id`; else an agent whose
/// `provider_id` matches; else an agent whose config key equals the provider
/// id; else the only configured agent. Never guesses between several
/// candidates. `home` expands a `~/` vendor data dir.
pub fn resolve_agent(
    config: &AcpConfig,
    provider_id: Option<&str>,
    agent_id: Option<&str>,
    home: Option<&Path>,
) -> Result<AcpAgentSpec, AcpError> {
    let chosen = match agent_id {
        Some(id) => config
            .agents
            .get(id)
            .map(|entry| (id, entry))
            .ok_or_else(|| AcpError::Config(format!("no [acp.agents.{id}] entry")))?,
        None => {
            if let Some(provider_id) = provider_id {
                config
                    .agents
                    .iter()
                    .find(|(_, entry)| entry.provider_id.as_deref() == Some(provider_id))
                    .map(|(id, entry)| (id.as_str(), entry))
                    .or_else(|| {
                        config
                            .agents
                            .get_key_value(provider_id)
                            .map(|(id, entry)| (id.as_str(), entry))
                    })
                    .ok_or_else(|| {
                        AcpError::Config(format!(
                            "no [acp.agents.*] entry serves provider `{provider_id}`"
                        ))
                    })?
            } else if config.agents.len() == 1 {
                config
                    .agents
                    .iter()
                    .next()
                    .map(|(id, entry)| (id.as_str(), entry))
                    .expect("length checked")
            } else {
                return Err(AcpError::Config(
                    "several agents are configured; name one explicitly".to_string(),
                ));
            }
        }
    };
    let (id, entry) = chosen;
    if entry.command.trim().is_empty() {
        return Err(AcpError::Config(format!(
            "agent `{id}` has an empty command"
        )));
    }
    if !entry.model.trim().is_empty() {
        tracing::debug!(
            agent = %id,
            model = %entry.model,
            "acp: model label recorded; A0 agents pick their own default model"
        );
    }
    for name in &entry.env_passthrough {
        if env_name_forbidden(name) {
            return Err(AcpError::Config(format!(
                "agent `{id}`: env passthrough `{name}` is refused (never forward \
                 AUX_KEY_*/AUXESIS_*/DYLD_*/LD_* or the private HOME/TMPDIR/PATH)"
            )));
        }
    }
    Ok(AcpAgentSpec {
        id: id.to_string(),
        command: entry.command.clone(),
        args: entry.args.clone(),
        model: entry.model.clone(),
        auth: entry.auth,
        vendor_data_dir: entry
            .vendor_data_dir
            .as_deref()
            .map(|raw| expand_tilde(raw, home)),
        env_passthrough: entry.env_passthrough.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::config::{AcpAgentConfig, AcpAuthMode};

    fn config_with(agents: Vec<(&str, AcpAgentConfig)>) -> AcpConfig {
        AcpConfig {
            enabled: true,
            agents: agents
                .into_iter()
                .map(|(id, entry)| (id.to_string(), entry))
                .collect(),
            ..AcpConfig::default()
        }
    }

    #[test]
    fn tilde_expands_only_for_a_literal_home_prefix() {
        let home = Path::new("/Users/tester");
        assert_eq!(
            expand_tilde("~/.local/share/opencode", Some(home)),
            PathBuf::from("/Users/tester/.local/share/opencode")
        );
        assert_eq!(
            expand_tilde("/abs/path", Some(home)),
            PathBuf::from("/abs/path")
        );
        assert_eq!(
            expand_tilde("~user/x", Some(home)),
            PathBuf::from("~user/x")
        );
        assert_eq!(expand_tilde("~/x", None), PathBuf::from("~/x"));
    }

    #[test]
    fn scratch_workspace_is_a_sibling_of_the_agent_workspace() {
        assert_eq!(
            scratch_workspace(Path::new("/home/u/.auxesis"), "main"),
            PathBuf::from("/home/u/.auxesis/agents/main/acp-workspace")
        );
    }

    #[test]
    fn resolves_by_provider_then_key_then_only_agent() {
        let mut opencode = AcpAgentConfig {
            command: "opencode".to_string(),
            args: vec!["acp".to_string()],
            provider_id: Some("opencode-go".to_string()),
            ..AcpAgentConfig::default()
        };
        let config = config_with(vec![("opencode", opencode.clone())]);
        let spec = resolve_agent(&config, Some("opencode-go"), None, None).unwrap();
        assert_eq!(spec.id, "opencode");
        assert_eq!(spec.args, vec!["acp".to_string()]);

        // Provider id equal to the agent key.
        let spec = resolve_agent(&config, Some("opencode"), None, None).unwrap();
        assert_eq!(spec.id, "opencode");

        // A lone agent resolves without any provider hint.
        assert!(resolve_agent(&config, None, None, None).is_ok());

        // Several agents without a hint refuse to guess.
        opencode.provider_id = Some("other".to_string());
        let two = config_with(vec![
            ("opencode", opencode),
            (
                "gemini",
                AcpAgentConfig {
                    command: "gemini".to_string(),
                    args: vec!["--acp".to_string()],
                    ..AcpAgentConfig::default()
                },
            ),
        ]);
        assert!(resolve_agent(&two, None, None, None).is_err());
        assert!(resolve_agent(&two, Some("nope"), None, None).is_err());
        assert_eq!(
            resolve_agent(&two, Some("nope"), Some("gemini"), None)
                .unwrap()
                .id,
            "gemini"
        );
    }

    #[test]
    fn vendor_data_dir_expands_tilde() {
        let config = config_with(vec![(
            "opencode",
            AcpAgentConfig {
                command: "opencode".to_string(),
                vendor_data_dir: Some("~/.local/share/opencode".to_string()),
                ..AcpAgentConfig::default()
            },
        )]);
        let spec =
            resolve_agent(&config, Some("opencode"), None, Some(Path::new("/Users/t"))).unwrap();
        assert_eq!(
            spec.vendor_data_dir,
            Some(PathBuf::from("/Users/t/.local/share/opencode"))
        );
    }

    #[test]
    fn empty_command_and_forbidden_env_are_refused() {
        let config = config_with(vec![(
            "bad",
            AcpAgentConfig {
                command: "  ".to_string(),
                ..AcpAgentConfig::default()
            },
        )]);
        let err = resolve_agent(&config, Some("bad"), None, None).unwrap_err();
        assert!(err.to_string().contains("empty command"));

        for name in ["AUX_KEY_DEEPSEEK", "AUXESIS_HOME", "HOME", "TMPDIR", "PATH"] {
            let config = config_with(vec![(
                "bad-env",
                AcpAgentConfig {
                    command: "x".to_string(),
                    env_passthrough: vec![name.to_string()],
                    ..AcpAgentConfig::default()
                },
            )]);
            assert!(
                resolve_agent(&config, Some("bad-env"), None, None).is_err(),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn env_name_forbidden_covers_dynamic_linker_variables() {
        for name in [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
        ] {
            assert!(env_name_forbidden(name), "{name} must be refused");
        }
        assert!(env_name_forbidden("AUX_KEY_DEEPSEEK"));
        assert!(env_name_forbidden("HOME"));
        assert!(!env_name_forbidden("LANG"));
    }

    #[test]
    fn auth_defaults_to_cli_login_and_api_key_is_explicit() {
        assert_eq!(AcpAuthMode::default(), AcpAuthMode::CliLogin);
    }
}
