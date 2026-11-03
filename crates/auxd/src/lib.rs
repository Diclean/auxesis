//! `auxd` — the Auxesis daemon.
//!
//! The binary (`src/main.rs`) owns the process lifecycle: instance lock,
//! config, store, scheduler and signals. This library exposes the pieces the
//! binary and the integration tests share; today that is the **local API**
//! ([`api`]) — the HTTP+WS door the desktop app talks to.

pub mod agent;
pub mod agent_skills;
/// D33: the chief and the four domain agents, seeded from config.
pub mod agents;
pub mod api;
pub mod apple_eventkit;
pub mod brains;
pub mod bridge;
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
/// The daemon's log writer: byte cap + the shared log-line redactor.
pub mod logging;
pub mod mcp;
/// AUX-EGRESS-TOOL: `privacy_record_summary`, the privacy record as counts.
pub mod privacy_record;
pub mod privacy_wiring;
pub mod skill_executor;
pub mod turn_runtime;
/// WATCH-1: the chief's `watch` tool and the watcher payload.
pub mod watch;
