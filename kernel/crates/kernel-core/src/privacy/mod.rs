//! Private mode: one gate for every data path.
//!
//! A data path either passes the privacy kernel (its registry row is `Allow`
//! and, in private mode, `Covered`) or is disabled. A path with no row is
//! disabled in **both** modes: unknown means closed (soul rule 5).
//!
//! This module is the library half of Wave 1a. Wave 1b wires it into the
//! tool engine, the channels, the providers and the daemon: each choke point
//! calls [`admit_call`] (for a call) or [`may_mount`] (for a registration).
//! The wiring table lives in `the daemon's privacy_wiring`.
//!
//! * [`PathId`]: one id per matrix row (`A1` … `I2`).
//! * [`REGISTRY`]: one [`PathPolicy`] per row. It holds the status and the
//!   private and open behaviour, and tests check that every row is present.
//! * [`admit`]: the one decision point. It returns [`Decision::Allow`] with an
//!   unforgeable [`Grant`], [`Decision::Ask`] with a [`Request`], or
//!   [`Decision::Deny`] with a [`Reason`].
//! * [`PrivacyMode`], [`resolve`] and [`may_set`]: the switch. The most
//!   restrictive layer wins, and a channel can only tighten its own
//!   conversation.
//! * [`disable_core_dumps`]: `RLIMIT_CORE=0`, so a crash leaves no memory image.
//!
//! ## Wave 1b wiring
//!
//! Every choke point calls [`admit_call`] before a call (or [`may_mount`]
//! before a registration). The provider, channel and tool wrappers live next
//! to their crates (`GatedChat`, `GatedText`, `retain_mountable`,
//! `gate_dispatch`). The table that says where each row is gated is
//! `the daemon's privacy_wiring::CHOKE_POINTS`, and a test there fails for any path
//! without one.
//!
//! The mode a long-running choke point uses is a [`ModeFn`], read again at
//! each call, never a value captured when the turn or job started.
//!
//! Not in Wave 1b (see the PR body): the broker mint for an approved `Ask`,
//! and executors that take `&Grant` together with SafeText (#169).

mod core_dumps;
mod gate;
mod mode;
mod path;
mod policy;
mod registry;
mod wiring;

pub use core_dumps::{core_dumps_disabled, disable_core_dumps};
pub use gate::{admit, Context, Decision, Destination, Grant, GrantPolicy, Needs, Reason, Request};
pub use mode::{may_set, resolve, Layer, ModeFn, Origin, PrivacyConfig, PrivacyMode};
pub use path::{PathId, UnknownPath};
pub use policy::{Behaviour, PathPolicy, RecipientRule, Status};
pub use registry::REGISTRY;
pub use wiring::{admit_call, may_mount, Refused};
