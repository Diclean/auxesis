//! Size cap for the daemon's log output.
//!
//! `aux install` points launchd's `StandardOutPath`/`StandardErrorPath` at
//! `~/.auxesis/logs/auxd.log` and nothing rotates it. A *persistent* failure
//! that logs once per request (e.g. a corrupt store: the API logs an `error!`
//! per failed read) writes ~12 MB/day at one request per second — hundreds of
//! MB for a UI polling five endpoints. The daemon cannot rename the file
//! launchd already opened, so it caps what *it* writes: after
//! [`LOG_BYTE_BUDGET`] bytes the writer swallows further records (after one
//! notice) until the process restarts. launchd keeps the daemon alive, so
//! each boot gets a fresh budget; an external `newsyslog` rotation also works
//! because this writer never needs to reopen the file.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// Total tracing bytes one daemon process may write (8 MiB).
pub const LOG_BYTE_BUDGET: u64 = 8 * 1024 * 1024;

/// One shared budget + destination across every writer the subscriber
/// creates (`tracing` asks for a fresh writer per event, so a fresh full
/// budget each time would cap nothing).
struct State<W> {
    inner: W,
    /// Budget the notice reports (immutable).
    budget: u64,
    /// Bytes still allowed.
    remaining: u64,
    /// The end-of-budget notice is written exactly once.
    notice_written: bool,
}

/// A `Write`/`MakeWriter` adapter that stops after a byte budget.
///
/// `Clone` shares the budget and the destination; it never requires `W` to
/// be `Clone` (`Stdout` is not), which is what lets the daemon pass stdout
/// directly.
pub struct CappedWriter<W> {
    state: Arc<Mutex<State<W>>>,
}

impl<W> Clone for CappedWriter<W> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<W: Write> CappedWriter<W> {
    /// Cap `inner` at `budget` bytes (the one end-of-budget notice is
    /// exempt).
    pub fn new(inner: W, budget: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                inner,
                budget,
                remaining: budget,
                notice_written: false,
            })),
        }
    }

    /// Bytes still available in the shared budget (tests/diagnostics).
    #[cfg(test)]
    pub fn remaining(&self) -> u64 {
        self.state.lock().map(|state| state.remaining).unwrap_or(0)
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let input_len = buf.len();
        let mut state = match self.state.lock() {
            Ok(state) => state,
            // A poisoned lock means a log write panicked; dropping records
            // is better than aborting the daemon.
            Err(_) => return Ok(input_len),
        };
        if state.remaining == 0 {
            // Pretend success: reporting a short write would make the
            // formatter emit a broken-writer error — the very flood this
            // caps.
            return Ok(input_len);
        }
        // A log record is still a surface. Error strings logged by
        // the daemon can quote store or provider text, so every record runs
        // through the shared pattern redactor as the API previews do.
        // [`kernel_broker::redact_log_line`] adds the identity layer
        // (WhatsApp JIDs and runs of eight or more digits), because the
        // `whatsapp-rust` stack logs peer numbers at INFO regardless of the
        // filter. Invalid UTF-8 (a formatter mid-codepoint split) passes
        // through: a split pattern cannot match anyway.
        // A redaction panic yields a fixed placeholder, never the raw record.
        let scrubbed = std::str::from_utf8(buf)
            .ok()
            .map(kernel_broker::redact_log_line_guarded);
        let buf = scrubbed.as_deref().map_or(buf, str::as_bytes);
        let take = (buf.len() as u64).min(state.remaining) as usize;
        state.inner.write_all(&buf[..take])?;
        state.remaining -= take as u64;
        if state.remaining == 0 && !state.notice_written {
            state.notice_written = true;
            let budget = state.budget;
            let _ = writeln!(
                state.inner,
                "[auxd] log cap of {budget} bytes reached; further records suppressed until the daemon restarts"
            );
            let _ = state.inner.flush();
        }
        // H-01: always report the *input* length. `Write::write` reports how
        // many bytes of `buf` were consumed, and `tracing`'s fmt layer calls
        // `write_all`: returning the scrubbed length made it re-send
        // `buf[scrubbed_len..]`, which is the raw tail of a record whose
        // redaction shrank it (a secret near the end of the line). Redaction
        // that grows the record (a short secret) made the old code report
        // `Ok(n)` with `n > buf.len()`, and `write_all` panicked slicing out
        // of range. The scrubbed bytes are written exactly once.
        Ok(input_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.state.lock() {
            Ok(mut state) => state.inner.flush(),
            Err(_) => Ok(()),
        }
    }
}

impl<'a, W: Write + Send + 'static> tracing_subscriber::fmt::MakeWriter<'a> for CappedWriter<W> {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::fmt::MakeWriter;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    fn make<W: Write + Send + 'static>(writer: &CappedWriter<W>) -> CappedWriter<W> {
        writer.make_writer()
    }

    #[test]
    fn log_records_are_scrubbed_of_secret_shapes() {
        // A daemon error line can quote store or provider text; the log file
        // is a surface too. The writer runs the *shared* entry point, so the
        // normalise layer (invisible/fullwidth folding)
        // applies here exactly as on the API surfaces.
        let mut out = Vec::new();
        let mut writer = CappedWriter::new(&mut out, 4096);
        let line = format!(
            "turn failed: X-Api-Key: {} and postgres://u:{}@db/internal\n",
            "CANARYLOG01ABCDEFGH", "CANARYLOG02"
        );
        writer.write_all(line.as_bytes()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("CANARYLOG01ABCDEFGH"), "{text}");
        assert!(!text.contains("CANARYLOG02"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");

        // More spellings: the normalise layer is the only thing that can
        // rescue them, and the log writer must run it like every API surface.
        let round_3: &[(&str, &str)] = &[
            ("token\u{200b}=CANARYLOGR301", "CANARYLOGR301"),
            ("api_\u{200b}key=CANARYLOGR302", "CANARYLOGR302"),
            ("api_\u{00ad}key=CANARYLOGR303", "CANARYLOGR303"),
            ("api_key\u{00a0}=CANARYLOGR304", "CANARYLOGR304"),
            ("api_key\u{1b}[0m=CANARYLOGR305", "CANARYLOGR305"),
            ("token=\u{202e}CANARYLOGR306", "CANARYLOGR306"),
            ("token=\u{feff}CANARYLOGR307", "CANARYLOGR307"),
            ("token=\u{2060}CANARYLOGR308", "CANARYLOGR308"),
            ("api_key＝CANARYLOGR309", "CANARYLOGR309"),
            ("api_key：CANARYLOGR310", "CANARYLOGR310"),
            (
                "{\n  \"api_key\":\n    \"CANARYLOGR311\"\n}",
                "CANARYLOGR311",
            ),
            (
                "{\"detail\":\"{\\\"api_key\\\":\\\"CANARYLOGR312\\\"}\"}",
                "CANARYLOGR312",
            ),
            ("session=CANARYLOGR313abcdefghij; Path=/", "CANARYLOGR313"),
            ("postgres%3A%2F%2Fu:CANARYLOGR314@h/d", "CANARYLOGR314"),
        ];
        for (raw, secret) in round_3 {
            let mut out = Vec::new();
            let mut writer = CappedWriter::new(&mut out, 1 << 20);
            writer.write_all(format!("{raw}\n").as_bytes()).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(!text.contains(secret), "log leaked {secret:?}: {text:?}");
        }
        for (raw, keep) in [
            ("token_id: 7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8", "7f2c1b3a"), // gitleaks:allow
            // Short numbers stay readable; eight digits and up are masked by
            // the identity layer (see `redact_identifiers`).
            ("listening on port 1234", "1234"),
            ("password: MySecretValue123", "MySecretValue123"),
            ("disk-usage is high", "disk-usage"),
            ("task-sk-1234", "task-sk-1234"),
        ] {
            let mut out = Vec::new();
            let mut writer = CappedWriter::new(&mut out, 1 << 20);
            writer.write_all(format!("{raw}\n").as_bytes()).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains(keep), "log mangled {keep:?}: {text:?}");
        }
    }

    #[test]
    fn a_github_token_in_a_logged_line_is_redacted() {
        // A token-shaped secret written through the daemon's log writer never
        // reaches the output; the redaction marker stands in for it.
        let token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
        let line = format!("provider error: token={token}\n");
        let mut output = Vec::new();
        {
            let mut writer = CappedWriter::new(&mut output, 4096);
            writer.write_all(line.as_bytes()).unwrap();
        }
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains(&token), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    #[test]
    fn shared_secret_redaction_canaries_are_redacted_in_logs() {
        redaction_canaries::assert_no_canaries(|input| {
            let mut output = Vec::new();
            {
                let mut writer = CappedWriter::new(&mut output, 4096);
                writer.write_all(input.as_bytes()).unwrap();
            }
            String::from_utf8(output).unwrap()
        });
    }

    #[test]
    fn a_record_is_consumed_once_even_when_redaction_changes_its_length() {
        // H-01: returning the *scrubbed* length from `write` made tracing's
        // `write_all` re-send `raw[scrubbed_len..]` — for a long secret near
        // the end of a record, that tail is the secret itself. Redaction that
        // *grows* the record (a short secret) made the old code report a
        // length larger than the input, and `write_all` panicked slicing out
        // of range.
        let secret = format!("CANARYLOGH01{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let line = format!("turn failed: X-Api-Key: {secret}\n");
        let mut out = Vec::new();
        let mut writer = CappedWriter::new(&mut out, 1 << 20);
        let consumed = writer.write(line.as_bytes()).unwrap();
        assert_eq!(consumed, line.len(), "write must consume the whole input");
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains("CANARYLOGH01"),
            "raw tail replayed: {text:?}"
        );
        assert_eq!(text, "turn failed: X-Api-Key: <redacted>\n", "{text:?}");

        // Redaction grows the record: `X-Api-Key: ab12\n` (16 bytes) becomes
        // `X-Api-Key: <redacted>\n` (22). `write_all` must not panic.
        let mut out = Vec::new();
        let mut writer = CappedWriter::new(&mut out, 1 << 20);
        writer.write_all(b"X-Api-Key: ab12\n").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "X-Api-Key: <redacted>\n");
    }

    #[test]
    fn stops_at_the_budget_and_writes_one_notice() {
        // If the cap is deleted this writes ~480 bytes of 'B' and fails.
        let mut out = Vec::new();
        let mut writer = CappedWriter::new(&mut out, 100);
        writer.write_all(&[b'A'; 240]).unwrap();
        writer.write_all(&[b'B'; 240]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with(&"A".repeat(100)), "budget must be exact");
        assert_eq!(text.bytes().filter(|byte| *byte == b'B').count(), 0);
        assert!(text.contains("log cap"), "{text}");
        assert!(text.len() < 300, "cap + notice only: {text:?}");
    }

    #[test]
    fn small_output_passes_through_untouched() {
        let mut out = Vec::new();
        let mut writer = CappedWriter::new(&mut out, 1024);
        writer.write_all(b"auxd ready\n").unwrap();
        let remaining = writer.remaining();
        drop(writer);
        assert_eq!(out, b"auxd ready\n");
        assert_eq!(remaining, 1024 - 11);
    }

    #[test]
    fn the_budget_is_shared_across_the_writers_the_subscriber_creates() {
        // `with_writer` calls `make_writer` per event; a fresh full budget
        // per call would never cap anything.
        let writer = CappedWriter::new(Vec::new(), 32);
        let mut first = make(&writer);
        let mut second = make(&writer);
        first.write_all(&[b'a'; 24]).unwrap();
        second.write_all(&[b'b'; 24]).unwrap();
        assert_eq!(writer.remaining(), 0, "budget must be shared");
    }
}
