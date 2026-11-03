//! Core building blocks for Auxesis: filesystem layout, configuration,
//! shared types, jobs, budgets, and the kill switch.

pub mod budget;
pub mod config;
pub mod config_lock;
pub mod endpoint;
pub mod env_file;
pub mod i18n;
pub mod job;
pub mod keychain;
pub mod killswitch;
pub mod logging;
pub mod paths;
pub mod privacy;
pub mod sync;
pub mod text;

pub use budget::{
    audit_denial, warning_threshold, AuditSink, BudgetCaps, BudgetError, BudgetGuard, Budgets,
    Decision, Denial, DenialReason, Reservation, ReservationLedger, ReserveOutcome, UsageActual,
    UsageKind, UsageLedger, UsageTotals, DEFAULT_DAILY_TOKENS_IN, DEFAULT_DAILY_TOKENS_OUT,
    DEFAULT_DAILY_USD_CENTS, ESTIMATED_UNIT, RESERVATION_TTL,
};
pub use config::{
    describe_toml_error, redact_toml_error, toml_error_kind, BriefConfig, Config, ConfigError,
    ContextConfig, LocationConfig, QuietConfig, ShellConfig, TelegramConfig, UiConfig, WebConfig,
    WebMode, DEFAULT_WEB_ALLOW_EXPIRY_DAYS, DEFAULT_WEB_CONTENT_TYPES, DEFAULT_WEB_FETCHES_PER_DAY,
    DEFAULT_WEB_FETCHES_PER_TURN, DEFAULT_WEB_MAX_BYTES, DEFAULT_WEB_MAX_QUERY_BYTES,
    DEFAULT_WEB_MAX_REDIRECTS, DEFAULT_WEB_MAX_URL_BYTES, DEFAULT_WEB_PER_HOST_PER_MINUTE,
    DEFAULT_WEB_PORTS, DEFAULT_WEB_TIMEOUT_SECS,
};
pub use config_lock::{with_config_lock, ConfigLockError, CONFIG_LOCK_FILE, CONFIG_LOCK_TIMEOUT};
pub use endpoint::{resolve_client_endpoint, ClientEndpoint, API_PORT_ENV};
pub use i18n::{Lang, Message};
pub use job::{Schedule, ScheduleError};
pub use paths::{
    auxesis_home, config_path, ensure_home, ensure_sandbox_guard, ensure_sandbox_home,
    ensure_sandbox_port, log_dir, real_user_home, sandbox_guard_active, store_path,
    verified_child_path, verified_home, verified_home_for, verified_home_or_verify, SandboxHome,
    REAL_DAEMON_PORT,
};
pub use sync::lock_recover;
pub use text::{clean_field, sanitize_text, truncate_chars};

/// Version of the Auxesis workspace, taken from Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
