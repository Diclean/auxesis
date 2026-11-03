//! Hard bounds and per-operation budgets for one MCP server connection.
//!
//! Every value here is a *default*: a call site (a test, or a per-server
//! config) may override any of them. The frame reader stops as soon as the
//! configured bound is crossed and returns [`McpError::FrameTooLarge`] — it
//! never hands back a partial frame for the caller to mis-parse.
//!
//! # What `read_frame` can and cannot prove
//!
//! [`read_frame`] reads until the reader reports EOF. It **cannot** tell a
//! complete body from a truncated-but-valid prefix: knowing whether a
//! `Content-Length` was satisfied or an SSE stream delivered its terminal
//! event is the transport's (S1's) job, not this crate's. Truncation
//! detection therefore lives in the transport; `read_frame` alone never proves
//! completeness.
//!
//! # `FrameTooLarge` is terminal for the connection
//!
//! When [`read_frame`] or [`read_sse_line`] returns
//! [`McpError::FrameTooLarge`], the reader has stopped at an unknown offset
//! (a body has no resync point, and a bounded SSE reader has discarded the
//! over-limit line). The connection **must be dropped and never resumed**;
//! resuming would parse the tail of an oversized frame as if it were a fresh
//! message. [`McpError::requires_connection_close`] encodes that rule.
//!
//! An I/O failure is reported as [`McpError::Io`], which carries only the
//! [`std::io::ErrorKind`] — never the raw `io::Error` string, which can embed
//! filesystem paths or secrets.

use std::io::{self, BufRead, Read};
use std::time::Duration;

use crate::error::McpError;

/// Largest accepted response body: 8 MiB.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Largest accepted single SSE line: 1 MiB.
pub const DEFAULT_MAX_SSE_LINE_BYTES: usize = 1024 * 1024;
/// Most tools accepted from one server before discovery stops.
pub const DEFAULT_MAX_TOOLS: usize = 500;
/// Most requests in flight against one server.
pub const DEFAULT_MAX_INFLIGHT: usize = 8;

/// `initialize` budget.
pub const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(15);
/// `tools/list` budget for one page.
pub const LIST_TOOLS_TIMEOUT: Duration = Duration::from_secs(20);
/// `tools/call` budget: voice renders and CRM writes are slow.
pub const CALL_TOOL_TIMEOUT: Duration = Duration::from_secs(120);
/// Aggregate wall-clock budget for one `list_tools` call across every page.
///
/// The per-page [`LIST_TOOLS_TIMEOUT`] bounds a single round trip; this bounds
/// the pagination loop as a whole, so a server that answers every page just
/// inside the per-page budget cannot hold the client for an unbounded time.
pub const LIST_TOOLS_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest accepted `nextCursor` (or resume cursor), in bytes.
///
/// A server cursor is echoed back in the next request body and kept as the
/// resume point, so an unbounded one would size both from third-party input.
/// Over-cap is a typed protocol error, never a silent truncation (a truncated
/// cursor could point at a different page).
pub const MAX_CURSOR_BYTES: usize = 4 * 1024;
/// Largest accepted [`crate::ServerInfo`] `name` / `version`, in bytes.
pub const MAX_SERVER_INFO_BYTES: usize = 256;
/// Largest accepted [`crate::ServerInfo`] `instructions`, in bytes.
pub const MAX_SERVER_INSTRUCTIONS_BYTES: usize = 4 * 1024;
/// Largest accepted [`crate::ServerInfo`] `max_tools`.
pub const MAX_SERVER_TOOLS: usize = 2000;

/// Smallest accepted timeout/deadline value: 1 ms. Zero would make every call
/// fail immediately, which is a config error rather than a real budget.
pub const MIN_TIMEOUT: Duration = Duration::from_millis(1);
/// Largest accepted timeout/deadline value: 24 hours.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Hard bounds for one server connection. `Default` is the production set;
/// tests build tiny ones instead.
///
/// The fields are public, so call [`Limits::validate`] before use to reject a
/// zero or absurd bound that a config could otherwise smuggle in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_sse_line_bytes: usize,
    pub max_tools: usize,
    pub max_inflight: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_sse_line_bytes: DEFAULT_MAX_SSE_LINE_BYTES,
            max_tools: DEFAULT_MAX_TOOLS,
            max_inflight: DEFAULT_MAX_INFLIGHT,
        }
    }
}

impl Limits {
    /// Largest bound accepted for one response body: 1 GiB.
    pub const MAX_FRAME_BYTES_CEILING: usize = 1024 * 1024 * 1024;
    /// Largest bound accepted for one SSE line: 1 GiB.
    pub const MAX_SSE_LINE_BYTES_CEILING: usize = 1024 * 1024 * 1024;
    /// Largest tool-discovery bound accepted: 100 000 tools.
    pub const MAX_TOOLS_CEILING: usize = 100_000;
    /// Largest in-flight bound accepted: 4 096 requests.
    pub const MAX_INFLIGHT_CEILING: usize = 4_096;

    /// A deliberately tiny preset for tests.
    pub fn tiny() -> Self {
        Self {
            max_frame_bytes: 64,
            max_sse_line_bytes: 32,
            max_tools: 3,
            max_inflight: 1,
        }
    }

    /// Build a validated set of bounds.
    pub fn new(
        max_frame_bytes: usize,
        max_sse_line_bytes: usize,
        max_tools: usize,
        max_inflight: usize,
    ) -> Result<Self, McpError> {
        let limits = Self {
            max_frame_bytes,
            max_sse_line_bytes,
            max_tools,
            max_inflight,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Reject a zero or absurd bound.
    ///
    /// Zero would make every frame (including an empty one) too large, and an
    /// unbounded value defeats the streaming bound entirely, so both fail
    /// closed with a typed [`McpError::InvalidLimit`].
    pub fn validate(&self) -> Result<(), McpError> {
        check_limit(
            "max_frame_bytes",
            self.max_frame_bytes,
            Self::MAX_FRAME_BYTES_CEILING,
        )?;
        check_limit(
            "max_sse_line_bytes",
            self.max_sse_line_bytes,
            Self::MAX_SSE_LINE_BYTES_CEILING,
        )?;
        check_limit("max_tools", self.max_tools, Self::MAX_TOOLS_CEILING)?;
        check_limit(
            "max_inflight",
            self.max_inflight,
            Self::MAX_INFLIGHT_CEILING,
        )?;
        Ok(())
    }
}

pub(crate) fn check_limit(
    field: &'static str,
    value: usize,
    ceiling: usize,
) -> Result<(), McpError> {
    if value == 0 || value > ceiling {
        return Err(McpError::InvalidLimit { field, value });
    }
    Ok(())
}

/// Reject a zero or absurd timeout/deadline with a typed config error.
pub fn check_timeout(field: &'static str, value: Duration) -> Result<(), McpError> {
    if value < MIN_TIMEOUT || value > MAX_TIMEOUT {
        return Err(McpError::InvalidTimeout {
            field,
            millis: value.as_millis(),
        });
    }
    Ok(())
}

/// Read one frame, refusing it as soon as it exceeds `limit` bytes.
///
/// The read is streaming: at most one extra read chunk is pulled before
/// [`McpError::FrameTooLarge`] is returned, so an unbounded server can never
/// drive an unbounded allocation. An I/O error is reported as
/// [`McpError::Io`] (kind only) rather than a partial frame.
///
/// The read runs to EOF, so this function alone cannot prove the body was
/// complete — a truncated-but-valid prefix looks identical to a whole body.
/// Detecting truncation (a `Content-Length` that was not met, or an SSE stream
/// without its terminal event) is the transport's duty.
///
/// A returned [`McpError::FrameTooLarge`] is terminal: the reader stopped at
/// an unknown offset, so the connection must be dropped, never resumed.
pub fn read_frame<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>, McpError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).map_err(io_error)?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > limit {
            return Err(McpError::FrameTooLarge {
                limit,
                seen: out.len() + n,
            });
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Read one newline-terminated SSE line, bounded by `limit`.
///
/// Returns `Ok(None)` at end of stream. The bound is checked while reading;
/// a line that crosses it yields [`McpError::FrameTooLarge`] and is never
/// returned partially.
///
/// LF, CR and CRLF terminators are all accepted. A CRLF split across two
/// `fill_buf` windows is read as two lines (the CR ends the first, the LF is an
/// empty second line); the streaming transport uses its own chunk-fed parser
/// that holds a trailing CR back to cover the split, so this bounded helper
/// exists only for the S0 line-bound tests.
///
/// The reader cannot re-sync past an over-limit line, so a returned
/// [`McpError::FrameTooLarge`] is terminal: the connection must be dropped,
/// never resumed.
pub fn read_sse_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>, McpError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(io_error)?;
        if available.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n' || b == b'\r') {
            let mut take = pos + 1;
            // Consume a visible CRLF pair as one terminator.
            if available[pos] == b'\r' && take < available.len() && available[take] == b'\n' {
                take += 1;
            }
            if line.len() + take > limit {
                return Err(McpError::FrameTooLarge {
                    limit,
                    seen: line.len() + take,
                });
            }
            line.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(Some(line));
        }
        let len = available.len();
        if line.len() + len > limit {
            return Err(McpError::FrameTooLarge {
                limit,
                seen: line.len() + len,
            });
        }
        line.extend_from_slice(available);
        reader.consume(len);
    }
}

fn io_error(err: io::Error) -> McpError {
    McpError::Io { kind: err.kind() }
}
