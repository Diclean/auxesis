//! P3 batch-2, point 1: a tracing event that carries a WhatsApp number and a
//! JID is written masked, whatever the target.
//!
//! `whatsapp-rust` logs peer identities at `INFO` (`Identity change for
//! <number> …`); the daemon's writer must redact them even though the default
//! `EnvFilter` also caps that target. The record is emitted on the
//! `whatsapp_rust` target to prove the redaction is target-independent.
//!
//! Single test in its own process: a scoped subscriber plus the callsite
//! interest cache is only reliable when nothing else hits the callsite first.

use std::io::Write;
use std::sync::{Arc, Mutex};

use auxd::logging::{CappedWriter, LOG_BYTE_BUDGET};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn a_whatsapp_rust_info_event_is_written_masked() {
    // Assembled at runtime so no phone-number literal is committed.
    let number = ["336", "0000", "0000"].concat();
    let jid = format!("{number}@s.whatsapp.net");
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(CappedWriter::new(capture.clone(), LOG_BYTE_BUDGET))
        .with_max_level(tracing::Level::TRACE)
        .with_target(false)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            target: "whatsapp_rust",
            "Identity change for +{} ({})",
            number,
            jid
        );
    });

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("Identity change"),
        "no record written: {logs}"
    );
    assert!(!logs.contains(&number), "number leaked into logs: {logs}");
    assert!(logs.contains("<number>"), "no number mask: {logs}");
    assert!(logs.contains("<jid>"), "no JID mask: {logs}");
    assert!(
        logs.contains("s.whatsapp.net"),
        "the JID server (no identity) stays readable: {logs}"
    );
}
