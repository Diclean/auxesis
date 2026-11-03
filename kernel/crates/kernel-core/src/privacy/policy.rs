//! The vocabulary of a registry row: how far a path is covered, and what the
//! gate does with it in each mode.

use super::path::PathId;

/// How far the privacy kernel covers a path today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Passes the kernel, or is absent and tested as absent.
    Covered,
    /// Some control, but not the kernel.
    Partial,
    /// Raw: nothing stands between the value and the destination.
    NotCovered,
}

/// Who may receive a value that `AskEachTime` releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientRule {
    /// The owner's own screen and chat only.
    OwnerOnly,
    /// The owner's own destinations, plus third parties that the recipient
    /// filter allows for this value.
    FilteredRecipients,
}

/// What the gate does with a path in one mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Runs, subject to the coverage check in private mode.
    Allow,
    /// Runs only after the owner approves each call. Third-party recipients
    /// also need the recipient filter.
    AskEachTime(RecipientRule),
    /// Not mounted and not run.
    Disabled,
}

/// One row of the registry: a data path and its behaviour in each mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicy {
    /// Matrix row id.
    pub id: PathId,
    /// Short name of the path, for logs and messages.
    pub label: &'static str,
    /// Coverage today.
    pub status: Status,
    /// Behaviour in private mode.
    pub private: Behaviour,
    /// Behaviour in open mode.
    pub open: Behaviour,
    /// The wave slice that moves this row, or `"none"`.
    pub slice: &'static str,
}
