//! The app's runtime: the built-in tools and the level-1 fetch.
//!
//! The kernel owns the rules: `kernel-broker` has the [`Tool`] trait, the
//! registry and the broker, and `kernel-net` has the SSRF guard. This crate owns
//! the implementations the registry dispatches to.
//!
//! [`Tool`]: kernel_broker::Tool

pub mod contacts_import;
pub mod executor;
pub mod extensions;
pub mod fetch;
/// D33: the per-agent grant ceiling the daemon turns into broker rules.
pub mod grants;
pub mod known_names;
pub mod skills;
pub mod today;
pub mod tools;

mod net;
