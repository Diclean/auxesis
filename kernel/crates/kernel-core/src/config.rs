//! Configuration model for an Auxesis installation.

use crate::budget::{Budgets, PriceTable};
use crate::i18n::Lang;
use crate::privacy::PrivacyConfig;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

/// Refuse to read config files larger than this (protects against device
/// files and runaway writes).
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Log levels accepted in `Config::log_level`.
pub const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

/// Default hard cap on one API turn (`POST /v1/threads/{id}/messages`).
///
/// Calibration H-05: 1,800 s. The previous 300 s cut real work (long tool
/// loops, slow providers) mid-turn; the cap still exists, it is just no
/// longer the first thing that fires.
pub const DEFAULT_TURN_TIMEOUT_SECS: u64 = 1800;

/// Default wait before an unanswered approval is denied (`[approval]
/// timeout_secs`). Calibration H-04: long enough for a human to notice the
/// card during daily use; the turn timeout still bounds it (see
/// [`Config::approval_timeout`]).
pub const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 600;

/// Default newest-messages window the engine builds a model context from.
pub const DEFAULT_CONTEXT_MAX_MESSAGES: usize = 100;

/// Default soft token budget for that window (newest messages kept first).
pub const DEFAULT_CONTEXT_MAX_TOKENS: u64 = 32_000;

/// Errors while loading or creating the configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O failure while reading or writing the config file.
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    /// The config path exists but is not a regular file (FIFO, device, ...).
    #[error("config path {path} is not a regular file")]
    NotRegularFile {
        /// Offending path.
        path: String,
    },
    /// The config file is too large to be a real config.
    #[error("config file {path} is unexpectedly large ({size} bytes)")]
    TooLarge {
        /// Offending path.
        path: String,
        /// Observed size.
        size: u64,
    },
    /// The config file exists but does not parse.
    #[error("parsing config at {path}: {}", source.message())]
    Parse {
        /// Path that failed to parse.
        path: String,
        /// Underlying TOML error, built by [`redact_toml_error`].
        source: toml::de::Error,
    },
    /// `log_level` is not one of the accepted values.
    /// The value is never kept: it came from the file (CONFIG-ERR-ECHO-1).
    #[error("invalid log_level (expected one of: error, warn, info, debug, trace)")]
    UnknownLogLevel {},
    /// A local-time setting is not valid `HH:MM`. The value is never kept.
    #[error("invalid local time for {field} (expected HH:MM)")]
    InvalidLocalTime { field: &'static str },
    /// `[shell] timeout_secs` is above [`MAX_SHELL_TIMEOUT_SECS`].
    #[error("[shell] timeout_secs = {value} is above the {MAX_SHELL_TIMEOUT_SECS} s maximum")]
    ShellTimeoutTooLong { value: u64 },
    /// Failure while serializing a default config.
    #[error("serializing config: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// Top-level configuration (`~/.auxesis/config.toml`).
///
/// Missing fields are filled with defaults, so older configs keep working
/// when new fields are added.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Config format version.
    pub version: u32,
    /// Default log level (`error`, `warn`, `info`, `debug`, `trace`).
    pub log_level: String,
    /// Name of the default agent the CLI talks to. Read from the legacy
    /// `default_dot` key too.
    #[serde(alias = "default_dot")]
    pub default_agent: String,
    /// Per-agent daily caps over recorded provider usage (`[budgets]`).
    ///
    /// Absent fields keep the conservative defaults: a fresh install is
    /// capped, never silently unlimited. An empty `[budgets.default]` table
    /// (what every pre-E-17 config carries) also keeps them.
    pub budgets: Budgets,
    /// Per-model prices (`[prices.models.<model>]`), in whole cents per
    /// million tokens. Used to record `usd_cents` spend from token counts
    /// when the provider does not report a cost, so the daily money cap can
    /// bind. Absent: the built-in prices for the documented models.
    pub prices: PriceTable,
    /// Shell tool sandbox settings (`[shell]`).
    pub shell: ShellConfig,
    /// Model-context window (`[context]`).
    pub context: ContextConfig,
    /// Interactive approval settings (`[approval]`).
    pub approval: ApprovalConfig,
    /// Approval mode (`approvals = "auto" | "ask"`), `auto` when absent.
    /// `auto` approves reads, clean sandboxed calls and the chief's
    /// `delegate` without a card; sends, deletes, payments, unsandboxed or
    /// tainted calls and explicit `[[rules]]` still decide. `ask` is the
    /// card for every ask.
    pub approvals: ApprovalMode,
    /// ACP agent backends (`[acp]`), off by default (ACP-A0 ships behind a
    /// flag until the security review passes).
    pub acp: AcpConfig,
    /// Web egress policy (`[web]`). A GET is egress, not a local read.
    pub web: WebConfig,
    /// Morning brief settings (`[brief]`), disabled by default.
    pub brief: BriefConfig,
    /// Owner-selected city (`[location]`).
    pub location: LocationConfig,
    /// Memory behavior (`[memory]`).
    pub memory: MemoryConfig,
    /// User interface language (`[ui].language`), used by background sends.
    pub ui: UiConfig,
    /// Local quiet window (`[quiet]`).
    pub quiet: QuietConfig,
    /// Hard cap on one API turn, in seconds (default
    /// [`DEFAULT_TURN_TIMEOUT_SECS`]). `0` falls back to the default.
    pub turn_timeout_secs: u64,
    /// Telegram bot channel settings (`[telegram]`), disabled by default.
    pub telegram: TelegramConfig,
    /// Global privacy mode (`[privacy]`), private by default. See `crate::privacy`.
    pub privacy: PrivacyConfig,
}

/// Telegram owner-only bot settings. The token is resolved from the
/// protected `~/.auxesis/.env` store and is never part of this config.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub owner_id: Option<i64>,
}

/// The top-level `approvals` setting. There is no "full access" level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    /// Clean, sandboxed, local calls and `delegate` run without a card.
    #[default]
    Auto,
    /// Every ask shows a card (the behaviour before APPROVAL-MODES).
    Ask,
}

/// Interactive approval settings (`[approval]` in `config.toml`).
///
/// The approval timeout is a **fail-closed** bound: an unanswered card is a
/// deny (H-04 keeps that). What changed is the value and where it comes
/// from — 600 s by default, owner-tunable, and always strictly below the
/// turn timeout so the turn can still report the denial instead of being
/// killed first ([`Config::approval_timeout`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalConfig {
    /// Seconds an unanswered approval may wait before the fail-closed deny.
    /// `0` falls back to [`DEFAULT_APPROVAL_TIMEOUT_SECS`]. Clamped strictly
    /// below the turn timeout (see [`Config::approval_timeout`]).
    pub timeout_secs: u64,
    /// SHELL-JUDGE: under `approvals = "auto"`, a clean, sandboxed `shell`
    /// ask with the network off goes to a judge model before the card (default
    /// true). A value that is not a boolean turns it off.
    #[serde(deserialize_with = "bool_or_off")]
    pub shell_judge: bool,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_APPROVAL_TIMEOUT_SECS,
            shell_judge: true,
        }
    }
}

/// A boolean, or `false` for any other value: a mistyped switch fails closed.
fn bool_or_off<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Lenient {
        Bool(bool),
        Other(serde::de::IgnoredAny),
    }
    Ok(matches!(
        Lenient::deserialize(deserializer)?,
        Lenient::Bool(true)
    ))
}

/// Model-context window (`[context]` in `config.toml`).
///
/// A resumed conversation sends only its newest messages to the provider: the
/// engine reads a bounded page from the store, keeps the system prompt, drops
/// leading orphaned tool results, and trims the oldest messages until both
/// bounds fit. Persisted history is **never** deleted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContextConfig {
    /// Newest messages (system prompt excluded) kept in the model context.
    pub max_messages: usize,
    /// Soft token budget for that window, newest first.
    pub max_tokens: u64,
}

/// Morning brief schedule (`[brief]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BriefConfig {
    /// Master switch; false on fresh installs.
    pub enabled: bool,
    /// Local wall-clock time in `HH:MM` form.
    pub time: String,
}

impl Default for BriefConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            time: "08:00".to_string(),
        }
    }
}

/// Owner-selected city (`[location]`). Unset until the owner picks one: the
/// app never assumes where the owner lives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, from = "RawLocationConfig")]
pub struct LocationConfig {
    /// City used by the weather source; `None` until the owner sets one.
    /// `default_city` is accepted too: the WhatsApp call tools read that key.
    pub city: Option<String>,
    /// ISO 3166-1 alpha-2 country code, when set.
    pub country: Option<String>,
}

/// On-disk `[location]`: `city` and the WhatsApp `default_city` key may both be
/// present (a serde alias would reject that as a duplicate field and stop the
/// daemon from starting), so read both and prefer `city`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawLocationConfig {
    city: Option<String>,
    default_city: Option<String>,
    country: Option<String>,
}

impl From<RawLocationConfig> for LocationConfig {
    fn from(raw: RawLocationConfig) -> Self {
        Self {
            city: raw.city.or(raw.default_city),
            country: raw.country,
        }
    }
}

/// Optional memory behavior (`[memory]` in `config.toml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryConfig {
    /// Offer the model a tool for proposing stable facts for owner review.
    pub suggestions: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self { suggestions: true }
    }
}

/// User-interface settings (`[ui]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Language used for notifications and scheduled messages.
    pub language: Lang,
}

impl Default for UiConfig {
    /// The system language, so a fresh install speaks the owner's language.
    fn default() -> Self {
        Self {
            language: Lang::from_env(),
        }
    }
}

/// Quiet hours (`[quiet]`), in local `HH:MM` time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct QuietConfig {
    /// Start of the quiet period.
    pub start: String,
    /// End of the quiet period.
    pub end: String,
}

impl Default for QuietConfig {
    fn default() -> Self {
        Self {
            start: "22:00".to_string(),
            end: "07:00".to_string(),
        }
    }
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_messages: DEFAULT_CONTEXT_MAX_MESSAGES,
            max_tokens: DEFAULT_CONTEXT_MAX_TOKENS,
        }
    }
}

/// Shell tool sandbox settings (`[shell]` in `config.toml`).
///
/// Defaults are the safe ones: sandboxed, no network, and fail closed when
/// the platform cannot sandbox.
///
/// - `sandbox = false` only takes effect together with
///   `allow_unsandboxed = true`; on its own it makes every `shell` call
///   refuse to run. Both the disable and the unsandboxed run are logged
///   loudly.
/// - `network = true` means **all sockets** inside the sandbox for v1: any
///   host and any port, loopback included. There is no narrower
///   host/port allowlist.
/// - `allow_unsandboxed = true` is the explicit escape hatch for systems
///   without `sandbox-exec`; it is logged loudly when used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShellConfig {
    /// Run shell commands under `sandbox-exec` (macOS Seatbelt). `false` only
    /// takes effect together with [`ShellConfig::allow_unsandboxed`].
    pub sandbox: bool,
    /// Allow network access inside the sandbox (default false: all sockets
    /// denied, loopback included). `true` is **all sockets** for v1.
    pub network: bool,
    /// Run unsandboxed when the sandbox is unavailable, and when `sandbox` is
    /// explicitly disabled.
    pub allow_unsandboxed: bool,
    /// Wall-clock cap on one command, in seconds (default
    /// [`DEFAULT_SHELL_TIMEOUT_SECS`]). `0` falls back to the default.
    pub timeout_secs: u64,
}

/// Default wall-clock cap on one shell command (SHELL-JUDGE, maintainer OK).
pub const DEFAULT_SHELL_TIMEOUT_SECS: u64 = 30;

/// The longest `[shell] timeout_secs` a config may set: one hour.
pub const MAX_SHELL_TIMEOUT_SECS: u64 = 3600;

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            sandbox: true,
            network: false,
            allow_unsandboxed: false,
            timeout_secs: DEFAULT_SHELL_TIMEOUT_SECS,
        }
    }
}

impl ShellConfig {
    /// The wall-clock cap in force: `timeout_secs`, or the default for `0`,
    /// never above [`MAX_SHELL_TIMEOUT_SECS`].
    pub fn timeout(&self) -> std::time::Duration {
        let secs = match self.timeout_secs {
            0 => DEFAULT_SHELL_TIMEOUT_SECS,
            secs => secs.min(MAX_SHELL_TIMEOUT_SECS),
        };
        std::time::Duration::from_secs(secs)
    }
}

/// Default per-turn wall-clock cap for an ACP agent (maintainer decision: 10 min).
pub const DEFAULT_ACP_TURN_TIMEOUT_SECS: u64 = 600;

/// Default cap on ACP turns per task (maintainer decision: 20).
pub const DEFAULT_ACP_MAX_TURNS_PER_TASK: u32 = 20;

/// Default cap on ACP turn *attempts* started per rolling minute for one task:
/// a crash-looping agent must not burn the fixed per-turn reserve faster than
/// this. Failed attempts count exactly like successes.
pub const DEFAULT_ACP_MAX_TURNS_PER_MINUTE: u32 = 6;

/// Default output budget for one ACP turn (same 256 KiB as the shell tool).
pub const DEFAULT_ACP_MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// Default bounded wait for one `session/request_permission` answer.
pub const DEFAULT_ACP_PERMISSION_TIMEOUT_SECS: u64 = 120;

/// Default conservative per-turn cost reserve, in whole cents. ACP backends
/// are flat-rate subscriptions (OpenCode Go) or not metered per token, so the
/// money cap can only bind through a fixed reserve per turn; usage_update is
/// recorded best-effort and never used to authorise spend.
pub const DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS: u64 = 10;

/// Default `RLIMIT_CPU` for an ACP agent in seconds (`0` derives it from the
/// turn timeout plus a grace).
pub const DEFAULT_ACP_MAX_CPU_SECONDS: u64 = 0;

/// Default `RLIMIT_FSIZE` for an ACP agent: 1 GiB, same as the shell tool.
pub const DEFAULT_ACP_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// Default `RLIMIT_NOFILE` for an ACP agent.
pub const DEFAULT_ACP_MAX_OPEN_FILES: u64 = 4096;

/// Default `RLIMIT_NPROC` headroom above the current user process count
/// (`0` disables the limit).
pub const DEFAULT_ACP_MAX_PROCESSES: u64 = 64;

/// Default best-effort `RLIMIT_AS`/`RLIMIT_DATA` for an ACP agent: 8 GiB.
pub const DEFAULT_ACP_MAX_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// ACP backends (`[acp]` in `config.toml`), **off by default**.
///
/// A0 wires the OpenCode Go path only: Claude Code stays API-key-only (never
/// enabled here), Codex/Gemini are opt-in in later phases. Every agent runs
/// in a per-agent scratch dir, never the repo or `~/.auxesis`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcpConfig {
    /// Master flag: ACP turns are refused while this is `false`.
    pub enabled: bool,
    /// Per-turn wall-clock cap in seconds (`0` falls back to the default).
    pub turn_timeout_secs: u64,
    /// Turns allowed per task before the backend refuses more.
    pub max_turns_per_task: u32,
    /// Turn attempts allowed per rolling minute per task (`0` disables the
    /// rate cap); failed/crashed attempts count exactly like successes.
    pub max_turns_per_minute: u32,
    /// Output budget for one turn, in bytes.
    pub max_output_bytes: usize,
    /// Bounded wait for one permission answer, in seconds.
    pub permission_timeout_secs: u64,
    /// Fixed cost reserve per turn, in whole cents.
    pub turn_cost_estimate_cents: u64,
    /// `RLIMIT_CPU` for the agent in seconds (`0` = turn timeout + grace).
    pub max_cpu_seconds: u64,
    /// `RLIMIT_FSIZE` for the agent, per file.
    pub max_file_bytes: u64,
    /// `RLIMIT_NOFILE` for the agent.
    pub max_open_files: u64,
    /// `RLIMIT_NPROC` headroom above the current user process count
    /// (`0` disables the limit).
    pub max_processes: u64,
    /// Best-effort `RLIMIT_AS`/`RLIMIT_DATA` for the agent (`0` disables).
    pub max_memory_bytes: u64,
    /// Agent definitions keyed by id (`[acp.agents.<id>]`).
    pub agents: BTreeMap<String, AcpAgentConfig>,
}

impl Default for AcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            turn_timeout_secs: DEFAULT_ACP_TURN_TIMEOUT_SECS,
            max_turns_per_task: DEFAULT_ACP_MAX_TURNS_PER_TASK,
            max_turns_per_minute: DEFAULT_ACP_MAX_TURNS_PER_MINUTE,
            max_output_bytes: DEFAULT_ACP_MAX_OUTPUT_BYTES,
            permission_timeout_secs: DEFAULT_ACP_PERMISSION_TIMEOUT_SECS,
            turn_cost_estimate_cents: DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS,
            max_cpu_seconds: DEFAULT_ACP_MAX_CPU_SECONDS,
            max_file_bytes: DEFAULT_ACP_MAX_FILE_BYTES,
            max_open_files: DEFAULT_ACP_MAX_OPEN_FILES,
            max_processes: DEFAULT_ACP_MAX_PROCESSES,
            max_memory_bytes: DEFAULT_ACP_MAX_MEMORY_BYTES,
            agents: BTreeMap::new(),
        }
    }
}

impl AcpConfig {
    /// The effective wall-clock cap (zero falls back to the default).
    pub fn turn_timeout(&self) -> std::time::Duration {
        let secs = if self.turn_timeout_secs == 0 {
            DEFAULT_ACP_TURN_TIMEOUT_SECS
        } else {
            self.turn_timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }

    /// The effective permission-answer wait (zero falls back to the default).
    pub fn permission_timeout(&self) -> std::time::Duration {
        let secs = if self.permission_timeout_secs == 0 {
            DEFAULT_ACP_PERMISSION_TIMEOUT_SECS
        } else {
            self.permission_timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }
}

/// How one ACP agent authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AcpAuthMode {
    /// The CLI's own login, already present on this machine. We never read
    /// the credential store: the child gets read-only access when
    /// [`AcpAgentConfig::vendor_data_dir`] is set, and the owner's home is
    /// otherwise unreadable.
    #[default]
    #[serde(rename = "cli-login")]
    CliLogin,
    /// A metered API key. A0 does not resolve or pass API keys; the flag
    /// exists so the shape is stable and Claude Code can never default to a
    /// subscription login.
    #[serde(rename = "api-key")]
    ApiKey,
}

/// One `[acp.agents.<id>]` entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcpAgentConfig {
    /// Executable to run (found on the sandbox PATH).
    pub command: String,
    /// Arguments (for OpenCode: `["acp"]`).
    pub args: Vec<String>,
    /// Model label recorded for the run; the agent picks its own default in
    /// A0 (session model selection is a fast follow).
    pub model: String,
    /// Authentication mode (default `cli-login`).
    pub auth: AcpAuthMode,
    /// Optional `[[providers]]` id this agent serves. A turn whose selected
    /// provider has `kind = "acp"` uses the agent with this `provider_id`
    /// (or, when omitted, the provider's own id).
    pub provider_id: Option<String>,
    /// Read-only vendor data dir to expose to the child (`cli-login`), e.g.
    /// `~/.local/share/opencode`. The child may read its own login from
    /// there; we never copy or read the token ourselves, and nothing else of
    /// the real home becomes readable.
    pub vendor_data_dir: Option<String>,
    /// Extra environment variable **names** to pass through from the daemon
    /// (values are copied). `AUX_KEY_*`, `HOME` and `TMPDIR` are refused: the
    /// child must never see the daemon's secrets or paths.
    pub env_passthrough: Vec<String>,
}

impl Default for AcpAgentConfig {
    fn default() -> Self {
        Self {
            command: String::new(),
            args: Vec::new(),
            model: String::new(),
            auth: AcpAuthMode::CliLogin,
            provider_id: None,
            vendor_data_dir: None,
            env_passthrough: Vec::new(),
        }
    }
}

/// Default `[web] mode`: reads of an unseen public host are not prompted
/// until the conversation carries private data or untrusted content (W1).
pub const DEFAULT_WEB_MODE: WebMode = WebMode::OpenRead;

/// Default ports a fetch may reach. Every other port is refused.
pub const DEFAULT_WEB_PORTS: [u16; 2] = [80, 443];

/// Default redirect hops followed per fetch (the first request is not counted).
pub const DEFAULT_WEB_MAX_REDIRECTS: usize = 5;

/// Default whole-fetch byte cap (`max_bytes`), 256 KiB.
pub const DEFAULT_WEB_MAX_BYTES: usize = 256 * 1024;

/// Default whole-fetch wall-clock cap, redirects included.
pub const DEFAULT_WEB_TIMEOUT_SECS: u64 = 15;

/// Default content types the fetcher is willing to render.
pub const DEFAULT_WEB_CONTENT_TYPES: [&str; 5] = [
    "text/html",
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
];

/// Default fetches allowed in one turn.
pub const DEFAULT_WEB_FETCHES_PER_TURN: u32 = 8;

/// Default fetches allowed in one local day.
pub const DEFAULT_WEB_FETCHES_PER_DAY: u32 = 200;

/// Default fetches allowed to one host in a rolling minute.
pub const DEFAULT_WEB_PER_HOST_PER_MINUTE: u32 = 10;

/// Default lifetime of an `ask_once_per_site` approval, in days.
pub const DEFAULT_WEB_ALLOW_EXPIRY_DAYS: u64 = 30;

/// Default cap on a whole URL, in bytes. Over the cap is refused, never
/// truncated: the URL is an outbound channel, so its length is itself data.
pub const DEFAULT_WEB_MAX_URL_BYTES: usize = 512;

/// Default cap on the query string of a URL, in bytes.
pub const DEFAULT_WEB_MAX_QUERY_BYTES: usize = 256;

/// Who is asked before a web read (`[web] mode`).
///
/// The mode changes **who is asked**, never the deterministic egress gate or
/// the private-data rule. W1 ships the config and the deterministic gate; the
/// `smart`/`ask_once_per_site` memory is a later slice, so both currently ask
/// on an unseen host (fail closed) rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebMode {
    /// Nobody for a seen host; an unseen host is judged later (W2). W1: an
    /// unseen host runs silently unless the turn carries private data or
    /// untrusted content.
    #[default]
    OpenRead,
    /// Unseen host when the judge is ambiguous or unavailable. W1 has no
    /// judge, so an unseen host asks.
    Smart,
    /// First read of a registry-controlled domain, then remembered. W1 has no
    /// registry yet, so an unseen host asks.
    AskOncePerSite,
    /// Every read asks.
    AlwaysAsk,
}

impl WebMode {
    /// Lowercase config label used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            WebMode::OpenRead => "open_read",
            WebMode::Smart => "smart",
            WebMode::AskOncePerSite => "ask_once_per_site",
            WebMode::AlwaysAsk => "always_ask",
        }
    }
}

impl std::fmt::Display for WebMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Web egress settings (`[web]` in `config.toml`).
///
/// The defaults are the documented ones: `open_read`, no domain lists,
/// `http` and `https`, ports 80/443, a 256 KiB / 15 s whole-fetch budget, and
/// conservative fetch counters. An unknown `mode` is a config error (serde
/// rejects the value), never a silent fall back to `open_read`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Who is asked before a read.
    pub mode: WebMode,
    /// Domains that may be read without the seen-before ask rule. A leading
    /// `*.` (or `.`) is optional; a bare domain matches it and its subdomains.
    pub allow_domains: Vec<String>,
    /// Domains that may never be read. **Deny wins in every mode**, over any
    /// allow entry or remembered approval.
    pub deny_domains: Vec<String>,
    /// Refuse plain `http` URLs.
    pub https_only: bool,
    /// Ports a fetch may reach. Every other port is refused.
    pub port_allowlist: Vec<u16>,
    /// Redirect hops followed per fetch (the first request is not counted).
    pub max_redirects: usize,
    /// Whole-fetch byte cap, body included.
    pub max_bytes: usize,
    /// Whole-fetch wall-clock cap in seconds, redirects included.
    pub timeout_secs: u64,
    /// Content types the extractor is willing to render.
    pub content_types: Vec<String>,
    /// Fetches allowed in one turn.
    pub fetches_per_turn: u32,
    /// Fetches allowed in one local day.
    pub fetches_per_day: u32,
    /// Fetches allowed to one host in a rolling minute.
    pub per_host_per_minute: u32,
    /// Lifetime of an `ask_once_per_site` approval, in days.
    pub allow_expiry_days: u64,
    /// Cap on a whole URL, in bytes (over the cap is refused, never truncated).
    pub max_url_bytes: usize,
    /// Cap on a URL's query string, in bytes.
    pub max_query_bytes: usize,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            mode: DEFAULT_WEB_MODE,
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            https_only: false,
            port_allowlist: DEFAULT_WEB_PORTS.to_vec(),
            max_redirects: DEFAULT_WEB_MAX_REDIRECTS,
            max_bytes: DEFAULT_WEB_MAX_BYTES,
            timeout_secs: DEFAULT_WEB_TIMEOUT_SECS,
            content_types: DEFAULT_WEB_CONTENT_TYPES
                .iter()
                .map(|kind| (*kind).to_string())
                .collect(),
            fetches_per_turn: DEFAULT_WEB_FETCHES_PER_TURN,
            fetches_per_day: DEFAULT_WEB_FETCHES_PER_DAY,
            per_host_per_minute: DEFAULT_WEB_PER_HOST_PER_MINUTE,
            allow_expiry_days: DEFAULT_WEB_ALLOW_EXPIRY_DAYS,
            max_url_bytes: DEFAULT_WEB_MAX_URL_BYTES,
            max_query_bytes: DEFAULT_WEB_MAX_QUERY_BYTES,
        }
    }
}

impl WebConfig {
    /// The whole-fetch wall-clock cap; a zero falls back to the default
    /// instead of disabling the cap.
    pub fn timeout(&self) -> std::time::Duration {
        let secs = if self.timeout_secs == 0 {
            DEFAULT_WEB_TIMEOUT_SECS
        } else {
            self.timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }

    /// True when `port` is in the allowlist.
    pub fn port_allowed(&self, port: u16) -> bool {
        self.port_allowlist.contains(&port)
    }

    /// True when the response's `Content-Type` essence is in the allowlist.
    ///
    /// A missing or empty header is **refused** like any other type outside
    /// the list: the body sniffer must never widen the owner's allowlist on
    /// its own. An empty header is rendered only when the owner explicitly
    /// lists an empty entry (e.g. `content_types = ["text/html", ""]`),
    /// which is the owner opting in to the sniffer for headerless servers.
    pub fn content_type_allowed(&self, content_type: &str) -> bool {
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        self.content_types.iter().any(|allowed| {
            let allowed = allowed.trim().to_ascii_lowercase();
            if allowed.is_empty() {
                essence.is_empty()
            } else {
                allowed == essence
            }
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            log_level: "info".to_string(),
            // The chief (AGENT-DEFAULT): the owner talks to Aux, which
            // delegates to the domain agents.
            default_agent: "aux".to_string(),
            // E-17: the default posture is capped, not unlimited. The values
            // are documented in `budget::BudgetCaps::conservative_default`.
            budgets: Budgets::default(),
            prices: PriceTable::default(),
            shell: ShellConfig::default(),
            context: ContextConfig::default(),
            approval: ApprovalConfig::default(),
            approvals: ApprovalMode::default(),
            acp: AcpConfig::default(),
            web: WebConfig::default(),
            brief: BriefConfig::default(),
            location: LocationConfig::default(),
            memory: MemoryConfig::default(),
            ui: UiConfig::default(),
            quiet: QuietConfig::default(),
            turn_timeout_secs: DEFAULT_TURN_TIMEOUT_SECS,
            telegram: TelegramConfig::default(),
            privacy: PrivacyConfig::default(),
        }
    }
}

impl Config {
    /// The API turn timeout, never zero (a zero in a hand-edited file falls
    /// back to the default instead of disabling the cap).
    pub fn turn_timeout(&self) -> std::time::Duration {
        let secs = if self.turn_timeout_secs == 0 {
            DEFAULT_TURN_TIMEOUT_SECS
        } else {
            self.turn_timeout_secs
        };
        std::time::Duration::from_secs(secs)
    }

    /// The approval wait, never zero and always **strictly below** the turn
    /// timeout (H-04).
    ///
    /// An unanswered approval is a deny either way; the clamp only decides
    /// which bound reports it. If the approval timeout reached or crossed
    /// the turn timeout, the turn would be cancelled first and the denial
    /// would surface as a generic `504 turn_timeout` instead of the
    /// approval's own expiry (and the card would be retired as abandoned).
    /// A `0` in the file falls back to the default; a value at or above the
    /// turn timeout is clamped to one second below it. The result is never
    /// below one second, so a hand-edited config cannot disable the wait.
    pub fn approval_timeout(&self) -> std::time::Duration {
        let configured = if self.approval.timeout_secs == 0 {
            DEFAULT_APPROVAL_TIMEOUT_SECS
        } else {
            self.approval.timeout_secs
        };
        let turn_secs = self.turn_timeout().as_secs();
        // Strictly below the turn timeout, and never below one second.
        let secs = configured.min(turn_secs.saturating_sub(1)).max(1);
        std::time::Duration::from_secs(secs)
    }

    /// Load the config through the process's verified home (J-02 round 4):
    /// the read uses the fd's real path and the create goes through the
    /// fd-relative gateway, so a swapped home cannot plant or redirect
    /// `config.toml`.
    pub fn load_or_create_verified(home: &crate::paths::SandboxHome) -> Result<Self, ConfigError> {
        let real_home = home.real_path()?;
        let path = real_home.join("config.toml");
        match std::fs::metadata(&path) {
            Ok(_) => Self::load_or_create(&path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let config = Self::default();
                let text = toml::to_string_pretty(&config)?;
                home.write_atomic(Path::new("config.toml"), text.as_bytes(), 0o600)?;
                Ok(config)
            }
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    /// Load the config at `path`, creating it with defaults when missing.
    ///
    /// Refuses non-regular files (FIFOs, devices) and oversized files so a
    /// broken path can never hang the daemon or exhaust memory.
    pub fn load_or_create(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::metadata(path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(ConfigError::NotRegularFile {
                        path: path.display().to_string(),
                    });
                }
                if meta.len() > MAX_CONFIG_BYTES {
                    return Err(ConfigError::TooLarge {
                        path: path.display().to_string(),
                        size: meta.len(),
                    });
                }
                let text = std::fs::read_to_string(path)?;
                let config: Self = toml::from_str(&text).map_err(|err| ConfigError::Parse {
                    path: path.display().to_string(),
                    source: redact_toml_error(&err, "config.toml", &text),
                })?;
                config.validate()?;
                Ok(config)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let config = Self::default();
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // `create_new` never follows a (dangling) symlink.
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                file.write_all(toml::to_string_pretty(&config)?.as_bytes())?;
                drop(file);
                set_private_permissions(path)?;
                Ok(config)
            }
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !LOG_LEVELS.contains(&self.log_level.as_str()) {
            return Err(ConfigError::UnknownLogLevel {});
        }
        for (field, value) in [
            ("brief.time", self.brief.time.as_str()),
            ("quiet.start", self.quiet.start.as_str()),
            ("quiet.end", self.quiet.end.as_str()),
        ] {
            if chrono::NaiveTime::parse_from_str(value, "%H:%M").is_err() {
                return Err(ConfigError::InvalidLocalTime { field });
            }
        }
        if self.shell.timeout_secs > MAX_SHELL_TIMEOUT_SECS {
            return Err(ConfigError::ShellTimeoutTooLong {
                value: self.shell.timeout_secs,
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Rebuild a TOML parse error so it names the file, line and column and
/// never quotes the document.
///
/// toml 0.9 prints the offending source line in `Display` and keeps the whole
/// document in `Debug`, and serde's messages quote field names, variants and
/// values taken from the file, so a key pasted on a broken line or typed as a
/// key would reach logs, API errors and the CLI. The returned error carries
/// only `file`, the 1-based line and column of the error's span over
/// `source`, and a fixed generic kind ([`toml_error_kind`]). Its `Display` and
/// `Debug` hold nothing else.
pub fn redact_toml_error(err: &toml::de::Error, file: &str, source: &str) -> toml::de::Error {
    let message = describe_toml_error(file, source, err.span(), err.message());
    <toml::de::Error as serde::de::Error>::custom(message)
}

/// [`redact_toml_error`] for any parser that gives a span and a message
/// (`toml_edit` renders the source line the same way). An empty `file`
/// leaves just the position and kind. No text of `message` is copied.
pub fn describe_toml_error(
    file: &str,
    source: &str,
    span: Option<std::ops::Range<usize>>,
    message: &str,
) -> String {
    let mut out = file.to_string();
    if let Some(span) = span {
        let before = &source.as_bytes()[..span.start.min(source.len())];
        let line_start = before
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        let line = before.iter().filter(|b| **b == b'\n').count() + 1;
        let column = std::str::from_utf8(&before[line_start..])
            .map_or(before.len() - line_start, |text| text.chars().count())
            + 1;
        let sep = if out.is_empty() { "" } else { ", " };
        out.push_str(&format!("{sep}line {line}, column {column}"));
    }
    out.push_str(if out.is_empty() { "" } else { ": " });
    out.push_str(toml_error_kind(message));
    out
}

/// A fixed kind for a TOML/serde error message. Only the message's leading
/// words are matched, and only a constant is returned: the field names,
/// variants and values serde quotes never come through.
pub fn toml_error_kind(message: &str) -> &'static str {
    const KINDS: [(&str, &str); 8] = [
        ("unknown field", "unknown field"),
        ("unknown variant", "unknown value"),
        ("invalid type", "wrong type"),
        ("invalid value", "invalid value"),
        ("invalid length", "wrong length"),
        ("missing field", "missing field"),
        ("duplicate", "duplicate key"),
        ("missing", "missing value"),
    ];
    let message = message.trim_start();
    KINDS
        .iter()
        .find(|(prefix, _)| message.starts_with(prefix))
        .map_or("syntax error", |(_, kind)| kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn a_broken_line_with_a_key_never_reaches_the_parse_error() {
        // CONFIG-ERR-ECHO-1: a key pasted on a broken line or as a bad value
        // names the file and line, never the text.
        for text in [
            "log_level = \"info\"\napi_key = \"sk-CANARY-1234567890abcdef\n",
            "log_level = \"info\"\nturn_timeout_secs = \"CANARY-1234567890abcdef\"\n",
        ] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("config.toml");
            std::fs::write(&path, text).unwrap();
            let err = Config::load_or_create(&path).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            assert!(
                !shown.contains("CANARY") && !debug.contains("CANARY"),
                "{debug}"
            );
            assert!(shown.contains("config.toml, line 2"), "{shown}");
        }
    }

    #[test]
    fn a_redacted_error_keeps_only_a_fixed_kind() {
        let text = "a = 1\nb = [1, 2\n";
        let err = toml::from_str::<toml::Value>(text).unwrap_err();
        let shown = redact_toml_error(&err, "x.toml", text)
            .message()
            .to_string();
        assert!(shown.starts_with("x.toml, line 2, column "), "{shown}");
        assert!(shown.ends_with(": syntax error"), "{shown}");
    }

    #[test]
    fn an_unknown_variant_or_bad_value_names_only_a_kind() {
        // serde quotes the variant, the value and the field name it read.
        for (text, kind) in [
            ("approvals = \"sk-abc\"\n", "unknown value"),
            ("[web]\nmode = \"sk-abc\"\n", "unknown value"),
            ("turn_timeout_secs = \"sk-abc\"\n", "wrong type"),
            ("log_level = \"sk-abc\"\n", "invalid log_level"),
            ("[brief]\ntime = \"sk-abc\"\n", "invalid local time"),
        ] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("config.toml");
            std::fs::write(&path, text).unwrap();
            let err = Config::load_or_create(&path).unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}"));
            assert!(!shown.contains("abc") && !debug.contains("abc"), "{debug}");
            assert!(shown.contains(kind), "{shown}");
        }
    }

    #[test]
    fn creates_default_config_when_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(config, Config::default());
        assert!(path.exists(), "config file should be created");

        let again = Config::load_or_create(&path).unwrap();
        assert_eq!(again.version, 1);
        assert!(!again.brief.enabled);
        assert_eq!(again.brief.time, "08:00");
        assert_eq!(again.location, LocationConfig::default());
        assert_eq!(again.location.city, None);
        assert_eq!(again.location.country, None);
        assert_eq!(again.quiet.start, "22:00");
        assert_eq!(again.quiet.end, "07:00");
    }

    #[test]
    fn explicit_location_in_an_existing_config_is_kept() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n[location]\ncity = \"Lyon\"\ncountry = \"FR\"\n",
        )
        .unwrap();
        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(config.location.city.as_deref(), Some("Lyon"));
        assert_eq!(config.location.country.as_deref(), Some("FR"));
    }

    #[test]
    fn ui_language_follows_the_system_and_reads_config_value() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n[ui]\nlanguage = \"fr\"\n").unwrap();
        assert_eq!(Config::load_or_create(&path).unwrap().ui.language, Lang::Fr);
        assert_eq!(Config::default().ui.language, Lang::from_env());

        std::fs::write(&path, "version = 1\n[ui]\nlanguage = \"de\"\n").unwrap();
        assert_eq!(Config::load_or_create(&path).unwrap().ui.language, Lang::En);
    }

    #[test]
    fn rejects_invalid_brief_and_quiet_times() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[brief]\nenabled = true\ntime = '25:00'\n").unwrap();
        assert!(matches!(
            Config::load_or_create(&path),
            Err(ConfigError::InvalidLocalTime {
                field: "brief.time",
                ..
            })
        ));
        std::fs::write(&path, "[quiet]\nstart = '22:00'\nend = 'noon'\n").unwrap();
        assert!(matches!(
            Config::load_or_create(&path),
            Err(ConfigError::InvalidLocalTime {
                field: "quiet.end",
                ..
            })
        ));
    }

    #[test]
    fn parses_valid_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 2\nlog_level = \"debug\"\ndefault_agent = \"axis\"\n",
        )
        .unwrap();

        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(config.version, 2);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.default_agent, "axis");
    }

    #[test]
    fn legacy_default_dot_key_still_loads_as_default_agent() {
        let config: Config = toml::from_str("default_dot = \"axis\"\n").unwrap();
        assert_eq!(config.default_agent, "axis");
    }

    #[test]
    fn fills_missing_fields_with_defaults() {
        use crate::budget::UsageKind;

        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "log_level = \"trace\"\n").unwrap();

        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(config.log_level, "trace");
        assert_eq!(config.version, 1);
        assert_eq!(config.default_agent, "aux");
        // E-17: a config without `[budgets]` is capped by the conservative
        // defaults, not unlimited.
        assert!(!config.budgets.is_unset());
        assert_eq!(
            config.budgets.caps_for("main").limit(UsageKind::TokensIn),
            Some(crate::budget::DEFAULT_DAILY_TOKENS_IN)
        );
        assert_eq!(config.context, ContextConfig::default());
        assert_eq!(config.turn_timeout_secs, DEFAULT_TURN_TIMEOUT_SECS);
    }

    #[test]
    fn parses_the_context_window_and_turn_timeout() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "turn_timeout_secs = 42\n[context]\nmax_messages = 7\nmax_tokens = 900\n",
        )
        .unwrap();

        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(config.turn_timeout_secs, 42);
        assert_eq!(config.turn_timeout().as_secs(), 42);
        assert_eq!(config.context.max_messages, 7);
        assert_eq!(config.context.max_tokens, 900);

        // A zero timeout falls back to the default instead of disabling it.
        let zero: Config = toml::from_str("turn_timeout_secs = 0\n").unwrap();
        assert_eq!(zero.turn_timeout().as_secs(), DEFAULT_TURN_TIMEOUT_SECS);
    }

    #[test]
    fn approvals_default_to_auto_and_parse_ask() {
        let parsed: Config = toml::from_str("version = 1\n").unwrap();
        assert_eq!(parsed.approvals, ApprovalMode::Auto);
        let ask: Config = toml::from_str("approvals = \"ask\"\n").unwrap();
        assert_eq!(ask.approvals, ApprovalMode::Ask);
        // No "full access" level: an unknown value does not parse.
        assert!(toml::from_str::<Config>("approvals = \"full\"\n").is_err());
        let written = toml::to_string(&Config::default()).unwrap();
        assert!(written.contains("approvals = \"auto\""), "{written}");
    }

    #[test]
    fn calibration_turn_timeout_default_is_pinned() {
        // H-05: the default turn cap is 1800 s, and a config that says
        // nothing still gets it (the field keeps `serde(default)`).
        assert_eq!(DEFAULT_TURN_TIMEOUT_SECS, 1800);
        assert_eq!(Config::default().turn_timeout().as_secs(), 1800);
        let parsed: Config = toml::from_str("version = 1\n").unwrap();
        assert_eq!(parsed.turn_timeout().as_secs(), 1800);
    }

    #[test]
    fn calibration_approval_timeout_defaults_and_parses() {
        // H-04: 600 s by default, owner-tunable through `[approval]`.
        assert_eq!(DEFAULT_APPROVAL_TIMEOUT_SECS, 600);
        let config = Config::default();
        assert_eq!(config.approval.timeout_secs, 600);
        assert_eq!(config.approval_timeout().as_secs(), 600);

        assert!(config.approval.shell_judge, "the judge is on by default");
        for (raw, on) in [
            ("false", false),
            ("true", true),
            ("\"yes\"", false),
            ("1", false),
        ] {
            let parsed: Config =
                toml::from_str(&format!("[approval]\nshell_judge = {raw}\n")).unwrap();
            assert_eq!(parsed.approval.shell_judge, on, "{raw}");
        }
        let parsed: Config = toml::from_str("[approval]\ntimeout_secs = 120\n").unwrap();
        assert_eq!(parsed.approval.timeout_secs, 120);
        assert_eq!(parsed.approval_timeout().as_secs(), 120);

        // A zero falls back to the default instead of disabling the wait.
        let zero: Config = toml::from_str("[approval]\ntimeout_secs = 0\n").unwrap();
        assert_eq!(zero.approval_timeout().as_secs(), 600);

        // Unknown keys are rejected (a typo must not silently change the
        // fail-closed bound).
        let err = toml::from_str::<Config>("[approval]\ntimeout = 60\n").unwrap_err();
        assert!(err.to_string().contains("timeout"), "{err}");
    }

    #[test]
    fn the_approval_timeout_is_clamped_strictly_below_the_turn_timeout() {
        // H-04: the turn must be able to report the approval denial, so the
        // approval wait never reaches the turn timeout; expiry stays DENY.
        let config: Config =
            toml::from_str("turn_timeout_secs = 100\n[approval]\ntimeout_secs = 600\n").unwrap();
        assert_eq!(config.approval_timeout().as_secs(), 99);
        assert_eq!(config.turn_timeout().as_secs(), 100);

        // Exactly equal is clamped too ("strictly below").
        let config: Config =
            toml::from_str("turn_timeout_secs = 100\n[approval]\ntimeout_secs = 100\n").unwrap();
        assert_eq!(config.approval_timeout().as_secs(), 99);

        // A one-second turn timeout cannot drive the wait to zero (a zero
        // wait would be an instant deny, which is a different behaviour).
        let config: Config = toml::from_str("turn_timeout_secs = 1\n").unwrap();
        assert_eq!(config.approval_timeout().as_secs(), 1);

        // The default pair: 600 < 1800, no clamp involved.
        let config = Config::default();
        assert!(config.approval_timeout() < config.turn_timeout());
    }

    #[test]
    fn parses_the_budgets_section() {
        use crate::budget::{BudgetCaps, UsageKind};

        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
            version = 1
            log_level = "info"
            default_agent = "main"

            [budgets.default]
            tokens_in = 1000
            usd_cents = 25

            [budgets.agents.axis]
            tokens_in = 5
            tokens_out = 2
            "#,
        )
        .unwrap();

        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(
            config.budgets.default,
            BudgetCaps {
                tokens_in: Some(1000),
                tokens_out: None,
                usd_cents: Some(25),
                connector_calls: None,
                unlimited: false,
            }
        );
        let axis = config.budgets.caps_for("axis");
        assert_eq!(axis.limit(UsageKind::TokensIn), Some(5));
        assert_eq!(axis.limit(UsageKind::TokensOut), Some(2));
        assert_eq!(axis.limit(UsageKind::UsdCents), Some(25));
        let main = config.budgets.caps_for("main");
        assert_eq!(main.limit(UsageKind::TokensIn), Some(1000));
        assert_eq!(
            main.limit(UsageKind::TokensOut),
            Some(crate::budget::DEFAULT_DAILY_TOKENS_OUT),
            "an absent field falls back to the conservative default"
        );
    }

    #[test]
    fn an_old_config_with_an_empty_budgets_table_is_migrated_to_caps() {
        // Migration shape: the exact table header an old install wrote, plus
        // a per-agent override. Loading it must yield effective caps, not
        // `is_unlimited`.
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
            version = 1
            default_agent = "main"

            [budgets.default]

            [budgets.agents.axis]
            tokens_in = 7
            "#,
        )
        .unwrap();

        let config = Config::load_or_create(&path).unwrap();
        let main = config.budgets.caps_for("main");
        assert!(!main.is_unlimited());
        assert_eq!(
            main.limit(crate::budget::UsageKind::TokensIn),
            Some(crate::budget::DEFAULT_DAILY_TOKENS_IN)
        );
        assert_eq!(
            main.limit(crate::budget::UsageKind::UsdCents),
            Some(crate::budget::DEFAULT_DAILY_USD_CENTS)
        );
        let axis = config.budgets.caps_for("axis");
        assert_eq!(axis.limit(crate::budget::UsageKind::TokensIn), Some(7));
        assert_eq!(
            axis.limit(crate::budget::UsageKind::TokensOut),
            Some(crate::budget::DEFAULT_DAILY_TOKENS_OUT)
        );

        // The only opt-out is explicit, and it is per agent.
        std::fs::write(&path, "version = 1\n[budgets.default]\nunlimited = true\n").unwrap();
        let opted_out = Config::load_or_create(&path).unwrap();
        assert!(opted_out.budgets.caps_for("main").is_unlimited());
        for kind in crate::budget::UsageKind::ALL {
            assert_eq!(opted_out.budgets.caps_for("main").limit(kind), None);
        }
    }

    #[test]
    fn shell_sandbox_defaults_are_safe() {
        let config = Config::default();
        assert!(config.shell.sandbox, "sandbox on by default");
        assert!(!config.shell.network, "network off by default");
        assert!(!config.shell.allow_unsandboxed, "fail closed by default");
        assert_eq!(config.shell.timeout().as_secs(), 30, "30 s wall clock");
    }

    #[test]
    fn acp_is_off_by_default_and_parses_the_section() {
        let config = Config::default();
        assert!(!config.acp.enabled, "ACP must be off by default");
        assert!(config.acp.agents.is_empty());
        assert_eq!(
            config.acp.turn_timeout().as_secs(),
            DEFAULT_ACP_TURN_TIMEOUT_SECS
        );
        assert_eq!(
            config.acp.max_turns_per_task,
            DEFAULT_ACP_MAX_TURNS_PER_TASK
        );
        assert_eq!(
            config.acp.max_turns_per_minute,
            DEFAULT_ACP_MAX_TURNS_PER_MINUTE
        );
        assert_eq!(
            config.acp.turn_cost_estimate_cents,
            DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS
        );
        assert_eq!(config.acp.max_cpu_seconds, DEFAULT_ACP_MAX_CPU_SECONDS);
        assert_eq!(config.acp.max_file_bytes, DEFAULT_ACP_MAX_FILE_BYTES);
        assert_eq!(config.acp.max_open_files, DEFAULT_ACP_MAX_OPEN_FILES);
        assert_eq!(config.acp.max_processes, DEFAULT_ACP_MAX_PROCESSES);
        assert_eq!(config.acp.max_memory_bytes, DEFAULT_ACP_MAX_MEMORY_BYTES);

        let parsed: Config = toml::from_str(
            r#"
            version = 1
            [acp]
            enabled = true
            turn_timeout_secs = 30
            max_turns_per_task = 2
            max_turns_per_minute = 3
            max_cpu_seconds = 45
            max_file_bytes = 2048
            max_open_files = 64
            max_processes = 8
            max_memory_bytes = 4096

            [acp.agents.opencode]
            command = "opencode"
            args = ["acp"]
            provider_id = "opencode-go"
            vendor_data_dir = "~/.local/share/opencode"

            [acp.agents.claude]
            command = "claude-agent-acp"
            auth = "api-key"
            "#,
        )
        .unwrap();
        assert!(parsed.acp.enabled);
        assert_eq!(parsed.acp.turn_timeout().as_secs(), 30);
        assert_eq!(parsed.acp.max_turns_per_task, 2);
        assert_eq!(parsed.acp.max_turns_per_minute, 3);
        assert_eq!(parsed.acp.max_cpu_seconds, 45);
        assert_eq!(parsed.acp.max_file_bytes, 2048);
        assert_eq!(parsed.acp.max_open_files, 64);
        assert_eq!(parsed.acp.max_processes, 8);
        assert_eq!(parsed.acp.max_memory_bytes, 4096);
        let opencode = parsed.acp.agents.get("opencode").unwrap();
        assert_eq!(opencode.command, "opencode");
        assert_eq!(opencode.args, vec!["acp".to_string()]);
        assert_eq!(opencode.auth, AcpAuthMode::CliLogin);
        assert_eq!(opencode.provider_id.as_deref(), Some("opencode-go"));
        assert_eq!(
            parsed.acp.agents.get("claude").unwrap().auth,
            AcpAuthMode::ApiKey
        );

        // Round-trip: the default config serializes and parses back equal.
        let text = toml::to_string(&Config::default()).unwrap();
        let reparsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(reparsed, Config::default());
    }

    #[test]
    fn parses_the_shell_section() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n\n[shell]\nnetwork = true\nallow_unsandboxed = true\ntimeout_secs = 120\n",
        )
        .unwrap();

        let config = Config::load_or_create(&path).unwrap();
        assert!(config.shell.sandbox, "sandbox stays on unless disabled");
        assert!(config.shell.network);
        assert!(config.shell.allow_unsandboxed);
        assert_eq!(config.shell.timeout().as_secs(), 120);

        let text = std::fs::read_to_string(&path).unwrap();
        let reparsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(reparsed, config);
    }

    #[test]
    fn default_config_round_trips_with_the_budgets_field() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let created = Config::load_or_create(&path).unwrap();
        assert_eq!(created, Config::default());

        let text = std::fs::read_to_string(&path).unwrap();
        let reparsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(reparsed, created);
    }

    #[test]
    fn rejects_broken_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = \"not a number\"\n").unwrap();

        let err = Config::load_or_create(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn a_shell_timeout_above_an_hour_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[shell]\ntimeout_secs = 3600\n").unwrap();
        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(config.shell.timeout().as_secs(), 3600);
        std::fs::write(&path, "[shell]\ntimeout_secs = 3601\n").unwrap();
        let err = Config::load_or_create(&path).unwrap_err();
        assert!(
            matches!(err, ConfigError::ShellTimeoutTooLong { value: 3601 }),
            "{err}"
        );
        // u64::MAX is not even a TOML integer: refused at parse.
        std::fs::write(&path, "[shell]\ntimeout_secs = 18446744073709551615\n").unwrap();
        assert!(Config::load_or_create(&path).is_err());
        let huge = ShellConfig {
            timeout_secs: u64::MAX,
            ..ShellConfig::default()
        };
        assert_eq!(huge.timeout().as_secs(), 3600, "a built config is clamped");
    }

    #[test]
    fn rejects_unknown_log_level() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "log_level = \"loud\"\n").unwrap();

        let err = Config::load_or_create(&path).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownLogLevel { .. }));
    }

    #[test]
    fn rejects_oversized_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let big = vec![b'#'; (MAX_CONFIG_BYTES + 1) as usize];
        std::fs::write(&path, big).unwrap();

        let err = Config::load_or_create(&path).unwrap_err();
        assert!(matches!(err, ConfigError::TooLarge { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_char_device_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();

        let err = Config::load_or_create(&path).unwrap_err();
        assert!(matches!(err, ConfigError::NotRegularFile { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_config_without_hanging() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let err = Config::load_or_create(&path).unwrap_err();
        assert!(matches!(err, ConfigError::NotRegularFile { .. }));
    }

    #[test]
    fn web_defaults_are_the_documented_ones() {
        let web = WebConfig::default();
        assert_eq!(web.mode, WebMode::OpenRead);
        assert_eq!(web.mode.as_str(), "open_read");
        assert!(web.allow_domains.is_empty());
        assert!(web.deny_domains.is_empty());
        assert!(!web.https_only);
        assert_eq!(web.port_allowlist, vec![80, 443]);
        assert_eq!(web.max_redirects, 5);
        assert_eq!(web.max_bytes, 262_144);
        assert_eq!(web.timeout_secs, 15);
        assert_eq!(
            web.content_types,
            vec![
                "text/html".to_string(),
                "text/plain".to_string(),
                "application/json".to_string(),
                "application/xml".to_string(),
                "text/xml".to_string(),
            ]
        );
        assert_eq!(web.fetches_per_turn, 8);
        assert_eq!(web.fetches_per_day, 200);
        assert_eq!(web.per_host_per_minute, 10);
        assert_eq!(web.allow_expiry_days, 30);
        assert_eq!(web.max_url_bytes, 512);
        assert_eq!(web.max_query_bytes, 256);
        // A zero timeout keeps the documented default instead of disabling it.
        assert_eq!(
            WebConfig {
                timeout_secs: 0,
                ..WebConfig::default()
            }
            .timeout()
            .as_secs(),
            15
        );
        // The default config carries the safe section and round-trips.
        assert_eq!(Config::default().web, WebConfig::default());
        let text = toml::to_string(&Config::default()).unwrap();
        let reparsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(reparsed, Config::default());
    }

    #[test]
    fn parses_the_web_section() {
        let config: Config = toml::from_str(
            r#"
            version = 1
            [web]
            mode = "always_ask"
            allow_domains = ["docs.rs"]
            deny_domains = ["*.ads.example"]
            https_only = true
            port_allowlist = [443]
            max_redirects = 2
            max_bytes = 1024
            timeout_secs = 3
            content_types = ["text/plain"]
            fetches_per_turn = 1
            fetches_per_day = 2
            per_host_per_minute = 3
            allow_expiry_days = 7
            max_url_bytes = 64
            max_query_bytes = 32
            "#,
        )
        .unwrap();
        let web = config.web;
        assert_eq!(web.mode, WebMode::AlwaysAsk);
        assert_eq!(web.mode.as_str(), "always_ask");
        assert_eq!(web.allow_domains, vec!["docs.rs".to_string()]);
        assert_eq!(web.deny_domains, vec!["*.ads.example".to_string()]);
        assert!(web.https_only);
        assert_eq!(web.port_allowlist, vec![443]);
        assert!(!web.port_allowed(80));
        assert!(web.port_allowed(443));
        assert_eq!(web.max_redirects, 2);
        assert_eq!(web.max_bytes, 1024);
        assert_eq!(web.timeout_secs, 3);
        assert_eq!(web.timeout().as_secs(), 3);
        assert!(web.content_type_allowed("text/plain; charset=utf-8"));
        assert!(!web.content_type_allowed("application/json"));
        assert!(!web.content_type_allowed("text/html"));
        // P3-2: a missing/empty header is not a member of the allowlist.
        assert!(!web.content_type_allowed(""));
        assert!(!web.content_type_allowed("   "));
        // The owner opts in to the sniffer with an explicit empty entry; it
        // allows only the empty header, never another type.
        let sniffer = WebConfig {
            content_types: vec!["text/html".to_string(), String::new()],
            ..WebConfig::default()
        };
        assert!(sniffer.content_type_allowed(""));
        assert!(sniffer.content_type_allowed("text/html"));
        assert!(!sniffer.content_type_allowed("application/json"));
        assert_eq!(web.fetches_per_turn, 1);
        assert_eq!(web.fetches_per_day, 2);
        assert_eq!(web.per_host_per_minute, 3);
        assert_eq!(web.allow_expiry_days, 7);
        assert_eq!(web.max_url_bytes, 64);
        assert_eq!(web.max_query_bytes, 32);
    }

    #[test]
    fn every_documented_mode_parses() {
        for (label, mode) in [
            ("open_read", WebMode::OpenRead),
            ("smart", WebMode::Smart),
            ("ask_once_per_site", WebMode::AskOncePerSite),
            ("always_ask", WebMode::AlwaysAsk),
        ] {
            let config: Config = toml::from_str(&format!("[web]\nmode = \"{label}\"\n")).unwrap();
            assert_eq!(config.web.mode, mode, "{label}");
        }
    }

    #[test]
    fn rejects_unknown_web_mode() {
        // Unknown mode is a config error (fail closed), never a silent
        // fall back to `open_read`.
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[web]\nmode = \"yolo\"\n").unwrap();

        let err = Config::load_or_create(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
        // The error names the line, never the value (CONFIG-ERR-ECHO-1).
        let message = err.to_string();
        assert!(message.contains("config.toml, line 2"), "{message}");
        assert!(!message.contains("yolo"), "{message}");
    }

    #[test]
    fn telegram_channel_defaults_off_and_accepts_explicit_config() {
        let default = Config::default();
        assert!(!default.telegram.enabled);
        let enabled: Config =
            toml::from_str("[telegram]\nenabled = true\nowner_id = 42\n").unwrap();
        assert!(enabled.telegram.enabled);
        assert_eq!(enabled.telegram.owner_id, Some(42));
    }

    #[test]
    fn location_accepts_city_and_default_city_together() {
        let both: Config =
            toml::from_str("[location]\ncity = \"Lyon\"\ndefault_city = \"Pecs\"\n").unwrap();
        assert_eq!(both.location.city.as_deref(), Some("Lyon"));
        let wa_only: Config = toml::from_str("[location]\ndefault_city = \"Pecs\"\n").unwrap();
        assert_eq!(wa_only.location.city.as_deref(), Some("Pecs"));
        let unset: Config = toml::from_str("").unwrap();
        assert_eq!(unset.location.city, None);
    }
}
