//! The unsandboxed fallback must be audible: this test installs a capturing
//! global subscriber in its own test process (the tracing callsite interest
//! cache is process-global and racing first registrations from parallel lib
//! tests can mask the event there) and asserts the launcher logs an ERROR
//! naming the unsandboxed run.

use kernel_broker::sandbox::{launch, ShellSandbox};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug)]
struct CapturedEvent {
    level: tracing::Level,
    message: String,
}

#[derive(Default)]
struct CapturedEvents {
    events: Mutex<Vec<CapturedEvent>>,
}

struct CaptureSubscriber(Arc<CapturedEvents>);

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct MessageVisitor(String);
        impl tracing::field::Visit for MessageVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.0.events.lock().unwrap().push(CapturedEvent {
            level: *event.metadata().level(),
            message: visitor.0,
        });
    }
}

#[test]
fn an_unsandboxed_run_is_logged_loudly() {
    // The double opt-in must be auditable: the run logs an ERROR naming the
    // unsandboxed fallback. A silent bypass would defeat the warning.
    let captured = Arc::new(CapturedEvents::default());
    tracing::subscriber::set_global_default(CaptureSubscriber(Arc::clone(&captured)))
        .expect("this test process has no other subscriber");

    let dir = tempfile::tempdir().unwrap();
    launch(
        "true",
        dir.path(),
        &ShellSandbox::new(false, false, true),
        Duration::from_secs(60),
    )
    .unwrap();

    let events = captured.events.lock().unwrap();
    assert!(
        events.iter().any(|event| {
            event.level == tracing::Level::ERROR && event.message.contains("UNSANDBOXED")
        }),
        "expected a loud ERROR log, got: {events:?}",
    );
}
