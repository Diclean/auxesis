//! `auxd` — the Auxesis daemon.
//!
//! The binary (`src/main.rs`) owns the process entry point and signals. This
//! library holds the daemon's pieces — the scheduler, the instance lock, the
//! agent and brief job runners, shutdown cleanup and the **local API**
//! ([`api`]) — so the binary and the integration tests share one copy of each.

pub mod agent;
pub mod agent_job;
pub mod agent_skills;
/// D33: the chief and the four domain agents, seeded from config.
pub mod agents;
pub mod api;
pub mod apple_eventkit;
pub mod brains;
pub mod bridge;
/// The morning-brief job wiring on the existing job scheduler.
pub mod brief_job;
/// B3: the CRM timeline builders and the skill-only follow-up tool.
pub mod crm;
/// D33: the delegation record, its runner and the `delegate` tool.
pub mod delegation;
/// The deterministic `collect-receipts` runner (row C1).
pub mod docs;
/// Extensions at daemon startup (WO-13b).
pub mod extensions;
pub mod gateway;
#[cfg(feature = "google")]
pub mod google;
#[cfg(feature = "google")]
pub mod google_brief;
/// M2: the local (EventKit snapshot + mailbox) morning-brief source.
pub mod local_brief;
/// A single daemon per home: the `flock` held for the process lifetime.
pub mod lock;
/// The daemon's log writer: byte cap + the shared log-line redactor.
pub mod logging;
pub mod mcp;
/// AUX-EGRESS-TOOL: `privacy_record_summary`, the privacy record as counts.
pub mod privacy_record;
pub mod privacy_wiring;
/// The M2 job scheduler: claim due jobs, run each on its own connection.
pub mod scheduler;
/// Best-effort descendant cleanup when the daemon exits.
pub mod shutdown;
pub mod skill_executor;
pub mod turn_runtime;
/// WATCH-1: the chief's `watch` tool and the watcher payload.
pub mod watch;
