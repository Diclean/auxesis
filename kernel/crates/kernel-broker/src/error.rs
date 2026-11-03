//! Errors produced by tools.

use thiserror::Error;

/// Errors returned while validating arguments or running a tool.
#[derive(Debug, Error)]
pub enum ToolError {
    /// The supplied arguments do not match the tool's schema.
    #[error("invalid arguments for `{tool}`: {message}")]
    InvalidArgs {
        /// Name of the tool that rejected the call.
        tool: String,
        /// Human-readable validation failure.
        message: String,
    },

    /// The underlying operation failed (filesystem, process spawn, ...).
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The path escapes the agent workspace; file tools never leave it.
    #[error("path is outside the agent workspace")]
    OutsideWorkspace {},

    /// The path is inside the workspace but unsafe to use (symlink or hard link).
    #[error("path `{path}` is not safe to use: {reason}")]
    UnsafePath {
        /// The offending path, as requested.
        path: String,
        /// Why it was refused.
        reason: String,
    },

    /// A network fetch could not run at all: refused address, bad scheme,
    /// DNS failure, timeout, redirect abuse, unsupported content.
    #[error("fetch failed: {message}")]
    Fetch {
        /// Human-readable reason, safe to show the model.
        message: String,
    },

    /// The per-agent daily connector-call allowance has been reached.
    #[error("Le budget quotidien de l’application connectée est épuisé ({used}/{cap} appels).")]
    ConnectorBudgetExhausted {
        /// Calls already charged today.
        used: u64,
        /// Maximum calls for this agent today.
        cap: u64,
    },

    /// The tool's privacy path is disabled in the mode read at this call.
    #[error("path {path} is disabled in private mode")]
    PrivacyDisabled {
        /// The matrix row id of the refused path, e.g. `B5`.
        path: &'static str,
    },

    /// The budget ledger could not be checked or recorded, so the request was
    /// refused before any connector call could start.
    #[error("Le suivi du budget de l’application connectée est indisponible; l’appel n’a pas été lancé.")]
    ConnectorMeterUnavailable,
}

impl ToolError {
    /// A stable, value-free classification suitable for owner-facing receipts.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidArgs { .. } => "invalid_args",
            Self::Io(_) => "io",
            Self::OutsideWorkspace {} => "outside_workspace",
            Self::UnsafePath { .. } => "unsafe_path",
            Self::Fetch { .. } => "fetch",
            Self::ConnectorBudgetExhausted { .. } => "connector_budget_exhausted",
            Self::ConnectorMeterUnavailable => "connector_meter_unavailable",
            Self::PrivacyDisabled { .. } => "privacy_disabled",
        }
    }

    /// Build an [`ToolError::InvalidArgs`] from a deserialization error.
    pub fn invalid_args(tool: &str, source: impl std::fmt::Display) -> Self {
        Self::InvalidArgs {
            tool: tool.to_string(),
            message: source.to_string(),
        }
    }

    /// Build a [`ToolError::Fetch`] with a human-readable reason.
    pub fn fetch(message: impl Into<String>) -> Self {
        Self::Fetch {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_args_names_the_tool() {
        let err = ToolError::invalid_args("shell", "command: missing field");
        assert_eq!(
            err.to_string(),
            "invalid arguments for `shell`: command: missing field"
        );
        assert!(matches!(err, ToolError::InvalidArgs { ref tool, .. } if tool == "shell"));
    }

    #[test]
    fn io_errors_convert_with_from() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let err: ToolError = io.into();
        assert!(matches!(err, ToolError::Io(e) if e.kind() == std::io::ErrorKind::NotFound));
    }

    #[test]
    fn fetch_errors_carry_their_reason() {
        let err = ToolError::fetch("refusing to fetch `127.0.0.1`");
        assert_eq!(
            err.to_string(),
            "fetch failed: refusing to fetch `127.0.0.1`"
        );
        assert!(matches!(err, ToolError::Fetch { ref message } if message.contains("127.0.0.1")));
    }
}
