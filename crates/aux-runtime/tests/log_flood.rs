//! RV4-02 regression: the production log filter must keep html5ever's
//! foster-parenting `warn!` flood out of the log.
//!
//! html5ever logs one `WARN` (`foster parenting not implemented`) per
//! character token that lands directly inside a `<table>`. A 512 KiB hostile
//! page produced 99,360 records / 8.85 MiB on disk through the daemon's
//! launchd-redirected stdout — a disk-fill vector, not just noise. The fix is
//! a default log filter (`kernel_core::logging`), so this test installs that
//! filter and asserts the captured output stays tiny.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// A `MakeWriter` collecting everything the subscriber emits.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn bytes(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The RV4-02 shape: every character token directly inside `<table>` is
/// foster-parented (and therefore logged) by html5ever. `<i>` keeps the
/// document in "in table" mode so the flood does not stop.
fn foster_parenting_flood(bytes: usize) -> Vec<u8> {
    let unit = b"<table>x<i>y";
    let mut html = Vec::with_capacity(bytes + unit.len());
    while html.len() < bytes {
        html.extend_from_slice(unit);
    }
    html.truncate(bytes);
    html
}

#[test]
fn foster_parenting_warns_are_silenced_by_the_production_filter() {
    let capture = Capture::default();
    // What `auxd` builds with its default config level: the parser-crate
    // silences prepended to the configured level.
    let filter = kernel_core::logging::with_parser_logs_silenced("info");
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_ansi(false)
        .with_writer(capture.clone())
        .try_init()
        .expect("only this test in the binary installs a global subscriber");

    // Prove the `log` -> `tracing` bridge is live, or the assertion below
    // would pass vacuously.
    log::warn!(target: "aux_runtime_log_flood_canary", "bridge canary");
    let canary = capture.bytes();
    assert!(canary > 0, "the log -> tracing bridge is not capturing");

    let hostile = foster_parenting_flood(64 * 1024);
    assert_eq!(hostile.len(), 64 * 1024);
    let _ = aux_runtime::fetch::extract_readable(&hostile);

    let logged = capture.bytes() - canary;
    assert!(
        logged < 4096,
        "the foster-parenting shape wrote {logged} bytes to the log under the production filter"
    );

    // The directives are defaults, not a lock: an explicit later directive
    // for the same target (what `RUST_LOG=html5ever=warn` produces) must
    // re-enable the crate. Scope a second subscriber to this thread rather
    // than re-initialising the global one.
    let reenabled = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            kernel_core::logging::with_parser_logs_silenced("html5ever=warn"),
        ))
        .with_ansi(false)
        .with_writer(reenabled.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let hostile = foster_parenting_flood(16 * 1024);
        let _ = aux_runtime::fetch::extract_readable(&hostile);
    });
    assert!(
        reenabled.bytes() > 4096,
        "an explicit `html5ever=warn` did not re-enable the parser's records ({} bytes)",
        reenabled.bytes()
    );
}
