//! Trust labels and the conversation taint model (WS-C).
//!
//! Tools can ingest content the owner never authored (fetched pages,
//! connector results, mail). [`Trust`] labels a tool's **output**; [`Taint`]
//! tracks whether such content entered a conversation. Taint is a one-way
//! ratchet — only a new conversation clears it, and an unknown provenance
//! ([`Taint::Unknown`]) fails closed by behaving exactly like taint.

use serde::{Deserialize, Serialize};

/// Trust level of the content a tool produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    /// Authored by the system or the owner; safe to act on.
    Trusted,
    /// Came from outside (web, connector, mail): may carry prompt injection.
    Untrusted,
}

impl Trust {
    /// Lowercase label used by the tool result metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Trusted => "trusted",
            Trust::Untrusted => "untrusted",
        }
    }

    /// True for [`Trust::Untrusted`].
    pub fn is_untrusted(self) -> bool {
        self == Trust::Untrusted
    }
}

/// What introduced untrusted content into a conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintSource {
    /// Tool whose output carried the untrusted content.
    pub tool: String,
    /// Where it came from (URL, host), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Facts for a synthetic web gate ask, separate from its display text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_approval: Option<WebApprovalContext>,
}

/// The conversation and policy facts behind a synthetic web gate ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebApprovalContext {
    /// The conversation contains untrusted content, or its state is unknown.
    pub untrusted: bool,
    /// Only private data made the web policy ask; no other gate requires a card.
    pub sensitive_only: bool,
}

impl TaintSource {
    /// Build a source for `tool`, with an optional origin detail.
    pub fn new(tool: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            tool: tool.into(),
            detail,
            web_approval: None,
        }
    }

    /// One-line summary for approval prompts and audit rows.
    pub fn summary(&self) -> String {
        match &self.detail {
            Some(detail) => format!("{}: {detail}", self.tool),
            None => self.tool.clone(),
        }
    }
}

/// Taint state of one conversation. Never returns to
/// [`Clean`](Self::Clean): a new conversation is the only reset.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Taint {
    /// No untrusted content observed.
    #[default]
    Clean,
    /// Provenance could not be established: fail closed, act as tainted.
    Unknown,
    /// Untrusted content is in context; sticky for the conversation.
    Tainted(TaintSource),
}

impl Taint {
    /// Record an untrusted-output tool run. The first known source is kept;
    /// later calls cannot clear or downgrade the state.
    pub fn record(&mut self, source: TaintSource) {
        if matches!(self, Taint::Clean) {
            *self = Taint::Tainted(source);
        }
    }

    /// Mark the state unknown (fail closed). A known taint stays tainted.
    pub fn mark_unknown(&mut self) {
        if matches!(self, Taint::Clean) {
            *self = Taint::Unknown;
        }
    }

    /// True when the conversation must be treated as tainted.
    pub fn forces_ask(&self) -> bool {
        !matches!(self, Taint::Clean)
    }

    /// The source that introduced the taint, when known.
    pub fn source(&self) -> Option<&TaintSource> {
        match self {
            Taint::Tainted(source) => Some(source),
            _ => None,
        }
    }

    /// Summary of the taint, `None` when clean.
    pub fn summary(&self) -> Option<String> {
        match self {
            Taint::Clean => None,
            Taint::Unknown => Some("unknown taint state (fail closed)".to_string()),
            Taint::Tainted(source) => Some(source.summary()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_is_sticky_and_keeps_the_first_source() {
        let mut taint = Taint::Clean;
        assert!(!taint.forces_ask());
        taint.record(TaintSource::new(
            "http_fetch",
            Some("https://a.example".into()),
        ));
        taint.record(TaintSource::new("mail_read", None));
        assert!(taint.forces_ask());
        assert_eq!(taint.source().unwrap().tool, "http_fetch");
        assert_eq!(
            taint.summary().as_deref(),
            Some("http_fetch: https://a.example")
        );
        assert!(Trust::Untrusted.is_untrusted() && !Trust::Trusted.is_untrusted());
    }

    #[test]
    fn unknown_fails_closed_and_is_never_downgraded() {
        let mut taint = Taint::Unknown;
        assert!(taint.summary().unwrap().contains("fail closed"));
        taint.record(TaintSource::new("http_fetch", None));
        assert!(matches!(taint, Taint::Unknown));
        let source = TaintSource::new("mcp__x", Some("inbox".into()));
        assert_eq!(
            serde_json::from_value::<TaintSource>(serde_json::to_value(&source).unwrap()).unwrap(),
            source
        );
        assert_eq!(source.summary(), "mcp__x: inbox");
    }
}
