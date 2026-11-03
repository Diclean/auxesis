//! The process panic hook. A panic payload is never printed: a payload can
//! quote the input it was built from (the std char-boundary message quotes a
//! slice of its string), so the hook writes the source location and nothing
//! else. Every installer in the workspace goes through
//! [`install_payload_free_panic_hook`].

use std::io::Write;
use std::panic::{Location, PanicHookInfo};
use std::sync::Once;

static INSTALLED: Once = Once::new();

/// Install the payload-free hook for the process. Idempotent: the daemon, the
/// WhatsApp and voice binaries and the engine's edited-tool runs all call it,
/// so the stock hook is replaced once and no installer clobbers another.
///
/// The hook does not forward to the hook it replaces. The stock hook prints
/// the payload, and forwarding would print the input a panic quotes.
pub fn install_payload_free_panic_hook() {
    INSTALLED.call_once(|| {
        std::panic::set_hook(Box::new(|info: &PanicHookInfo<'_>| {
            let line = location_line(info.location());
            // `writeln!` rather than `eprintln!`: a panic hook must never panic.
            let _ = writeln!(std::io::stderr(), "{line}");
        }));
    });
}

/// The one line a panic may write: `file:line`, or `<unknown>` without a
/// location.
pub(crate) fn location_line(location: Option<&Location<'_>>) -> String {
    location.map_or_else(
        || "<unknown>".to_string(),
        |location| format!("{}:{}", location.file(), location.line()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_panic_line_is_a_location_and_nothing_else() {
        let line = location_line(Some(Location::caller()));
        assert!(line.contains("panic_hook.rs:"), "{line}");
        assert!(!line.chars().any(char::is_whitespace), "{line}");
        assert_eq!(location_line(None), "<unknown>");
    }
}
