//! Approval plumbing: the cards the owner answers, the edited draft
//! that may replace a call, and the payload-free wrapper an edited
//! tool body runs in.

use crate::cancel::TurnCancel;
use crate::stop::StopCheck;
use aux_runtime::executor::{
    ApprovalCard, BrokerCardApprover, RunDecision, RunStop, SkillApprover,
};
use kernel_broker::Approver;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Installs the process-wide payload-free panic hook before an edited tool
/// body runs. The hook never forwards to the hook it replaces: a forwarding
/// hook could print the payload of a panic from a detached worker that outlives
/// the run. Whatever panics, stderr only ever receives the `file:line` location.
fn install_edited_tool_panic_hook() {
    kernel_broker::install_payload_free_panic_hook();
}

/// Installs the payload-free hook before the edited tool body runs. The hook
/// stays installed process-wide, so a detached worker that panics after this
/// future is dropped still only prints its source location.
pub(super) struct EditedToolFuture<F> {
    inner: F,
}

impl<F> EditedToolFuture<F> {
    pub(super) fn new(inner: F) -> Self {
        install_edited_tool_panic_hook();
        Self { inner }
    }
}

impl<F: Future> Future for EditedToolFuture<F> {
    type Output = F::Output;

    fn poll(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // SAFETY: `inner` is structurally pinned with `self` and is never moved.
        unsafe { self.map_unchecked_mut(|this| &mut this.inner) }.poll(context)
    }
}

/// The run card, answered by the owner. A cancelled turn refuses a pending card
/// at once, so the card can no longer be answered into a run.
pub(super) struct CancelAwareCard {
    pub(super) inner: BrokerCardApprover,
    pub(super) cancel: Option<Arc<TurnCancel>>,
}

#[async_trait::async_trait]
impl SkillApprover for CancelAwareCard {
    async fn decide(&self, card: &ApprovalCard) -> RunDecision {
        match &self.cancel {
            Some(cancel) => tokio::select! {
                biased;
                _ = cancel.cancelled() => RunDecision::Refused,
                decision = self.inner.decide(card) => decision,
            },
            None => self.inner.decide(card).await,
        }
    }
}

/// The executor's run check: the kill switch (STOP) or a cancelled turn. Read
/// after approval and before each connector call.
pub(super) struct TurnStop {
    pub(super) stop: Option<Arc<dyn StopCheck>>,
    pub(super) cancel: Option<Arc<TurnCancel>>,
}

impl RunStop for TurnStop {
    fn is_stopped(&self) -> bool {
        self.stop.as_ref().is_some_and(|stop| stop.is_stopped())
            || self
                .cancel
                .as_ref()
                .is_some_and(|cancel| cancel.is_cancelled())
    }
}

/// The broker approver for a skill run: the run-level card was the owner's
/// approval, so each inner call is already approved and must not ask again.
pub(super) struct PreApproved;

#[async_trait::async_trait]
impl Approver for PreApproved {
    async fn approve(
        &self,
        _request: &kernel_broker::ApprovalRequest,
    ) -> Result<bool, kernel_broker::ApproverError> {
        Ok(true)
    }
}

pub(super) const EDITED_TOOL_ERROR_MESSAGE: &str =
    "error: L'outil n'a pas pu utiliser le brouillon modifié.";

#[cfg(test)]
mod tests {
    use super::super::testsupport::*;
    use super::*;
    use async_trait::async_trait;
    use aux_providers::{ChatMessage, ChatResponse, FakeProvider, ToolCall};
    use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
    use serde_json::json;
    use std::future::Future;
    use std::panic::AssertUnwindSafe;
    use std::pin::Pin;
    use std::sync::Arc;

    #[cfg(unix)]
    static PANIC_HOOK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[cfg(unix)]
    fn lock_panic_hook_tests() -> tokio::sync::MutexGuard<'static, ()> {
        PANIC_HOOK_TEST_LOCK.blocking_lock()
    }

    /// Environment variable that turns a hook test into the child scenario
    /// executed by [`run_edited_panic_scenario`], so stderr can be captured.
    #[cfg(unix)]
    const EDITED_PANIC_SCENARIO_ENV: &str = "AUX_ENGINE_EDITED_PANIC_SCENARIO";

    /// Runs one panic scenario in a child copy of this test binary, driven by
    /// [`EDITED_PANIC_SCENARIO_ENV`], and returns the captured stderr.
    #[cfg(unix)]
    fn run_edited_panic_scenario(test_name: &str, scenario: &str) -> String {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(EDITED_PANIC_SCENARIO_ENV, scenario)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{scenario} child test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stderr).unwrap()
    }

    #[cfg(unix)]
    fn poll_once<F: Future>(mut future: Pin<&mut F>) -> std::task::Poll<F::Output> {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        future.as_mut().poll(&mut context)
    }

    struct PanicWithDraft;

    #[allow(dead_code)]
    #[derive(Debug)]
    struct DebugEditedPanicPayload {
        value: &'static str,
    }

    /// A JSON-escaped rendering of an edited value containing a real newline:
    /// the newline survives in the payload only as the two-character `\n` escape.
    #[cfg(unix)]
    fn json_escaped_edited_payload(canary: &str) -> String {
        serde_json::json!({ "draft": format!("first line\n{canary}\nlast line") }).to_string()
    }

    #[async_trait]
    impl Tool for PanicWithDraft {
        fn class(&self) -> ToolClass {
            ToolClass::default()
        }

        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "panic_with_draft"
        }

        fn schema(&self) -> serde_json::Value {
            json!({ "type": "object" })
        }

        async fn run(
            &self,
            args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            if args["child_thread"].as_bool().unwrap_or(false) {
                let canary = args["draft"].as_str().unwrap().to_string();
                let _ = std::thread::spawn(move || panic!("{canary}")).join();
                return Ok(ToolOutput::ok("child finished"));
            }
            panic!("tool panicked with edited draft: {}", args["draft"]);
        }

        fn risk(&self) -> Risk {
            Risk::Medium
        }
    }

    #[cfg(unix)]
    fn assert_redacted_location_lines(stderr: &str, expected_lines: usize, forbidden: &[&str]) {
        assert_eq!(
            stderr.lines().count(),
            expected_lines,
            "unexpected panic output: {stderr:?}"
        );
        for line in stderr.lines() {
            let line = line.trim_end();
            // A payload-free line carries the source location and nothing else:
            // no French prose, no panic message, no payload.
            assert!(
                !line.chars().any(char::is_whitespace),
                "the payload-free panic line must contain only the file:line location: {stderr:?}"
            );
            let (file, line_number) = line
                .rsplit_once(':')
                .unwrap_or_else(|| panic!("panic output is not a file:line location: {stderr:?}"));
            assert!(
                file.ends_with("approvals.rs"),
                "panic output did not point at the panic location: {stderr:?}"
            );
            assert!(
                !line_number.is_empty() && line_number.bytes().all(|byte| byte.is_ascii_digit()),
                "panic output did not carry a line number: {stderr:?}"
            );
            for value in forbidden {
                assert!(!line.contains(value), "panic payload escaped: {stderr:?}");
            }
        }
    }

    #[cfg(unix)]
    fn assert_redacted_location_line(stderr: &str, forbidden: &[&str]) {
        assert_redacted_location_lines(stderr, 1, forbidden);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_edited_tool_panic_does_not_escape_with_the_draft_value() {
        const CANARY: &str = "EDITED-DRAFT-CANARY-883104";
        let _panic_hook_test_lock = PANIC_HOOK_TEST_LOCK.lock().await;

        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(PanicWithDraft));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_1",
                        "panic_with_draft",
                        json!({ "draft": "requested value" }),
                    )],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let approver = EditingApprover::new(json!({ "draft": CANARY }));
        let mut session = harness.start(&provider, vec![], approver);
        let session_id = session.session.id;

        session.send("run the edited tool").await.unwrap();

        let requests = provider.requests();
        let next_request = requests.get(1).expect("the turn continues after the panic");
        assert!(
            !format!("{next_request:?}").contains(CANARY),
            "edited draft escaped into the next provider request"
        );
        assert!(next_request.messages.iter().any(|message| {
            message.role() == aux_providers::ChatRole::Tool
                && message.content().as_str() == EDITED_TOOL_ERROR_MESSAGE
        }));

        let tool_receipt = harness
            .store()
            .list_messages(session_id)
            .unwrap()
            .into_iter()
            .find(|message| message.role == "tool")
            .expect("the normal tool error receipt is persisted");
        assert_eq!(tool_receipt.content, EDITED_TOOL_ERROR_MESSAGE);
        assert!(!format!("{tool_receipt:?}").contains(CANARY));
        let metadata: serde_json::Value =
            serde_json::from_str(tool_receipt.meta.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["status"], "failed");
        assert_eq!(metadata["error_kind"], "tool_panic");
    }

    #[cfg(unix)]
    #[test]
    fn child_thread_edited_payloads_are_never_written_to_stderr() {
        const CANARY: &str = "EDITED-CHILD-THREAD-CANARY-R5-732910";
        const SHORT_PAYLOAD: &str = "XY";
        let _panic_hook_test_lock = lock_panic_hook_tests();
        if let Ok(case) = std::env::var("AUX_ENGINE_CHILD_PANIC_CASE") {
            install_edited_tool_panic_hook();
            let result = match case.as_str() {
                "plain" => {
                    std::thread::spawn(move || std::panic::panic_any(CANARY.to_string())).join()
                }
                "json" => {
                    let payload = json_escaped_edited_payload(CANARY);
                    std::thread::spawn(move || std::panic::panic_any(payload)).join()
                }
                "unicode" => {
                    let payload = CANARY
                        .chars()
                        .map(|character| format!("\\u{{{:x}}}", character as u32))
                        .collect::<String>();
                    std::thread::spawn(move || std::panic::panic_any(payload)).join()
                }
                "debug" => std::thread::spawn(move || {
                    std::panic::panic_any(DebugEditedPanicPayload { value: CANARY })
                })
                .join(),
                "short" => {
                    std::thread::spawn(move || std::panic::panic_any(SHORT_PAYLOAD.to_string()))
                        .join()
                }
                _ => panic!("unknown panic payload case"),
            };
            assert!(result.is_err(), "the child worker must panic");
            return;
        }

        let cases = [
            ("plain", CANARY.to_string()),
            ("json", json_escaped_edited_payload(CANARY)),
            (
                "unicode",
                CANARY
                    .chars()
                    .map(|character| format!("\\u{{{:x}}}", character as u32))
                    .collect::<String>(),
            ),
            (
                "debug",
                format!("{:?}", DebugEditedPanicPayload { value: CANARY }),
            ),
            ("short", SHORT_PAYLOAD.to_string()),
        ];
        for (case, expected_payload) in cases {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::approvals::tests::child_thread_edited_payloads_are_never_written_to_stderr",
                    "--nocapture",
                ])
                .env("AUX_ENGINE_CHILD_PANIC_CASE", case)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{case} child test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert_redacted_location_line(&stderr, &[&expected_payload, CANARY]);
        }
    }

    #[cfg(unix)]
    #[test]
    fn review_r5_unrelated_thread_panic_writes_only_the_location() {
        const CANARY: &str = "UNRELATED-THREAD-PANIC-CANARY-R5-301874";
        const TEST_NAME: &str =
            "engine::approvals::tests::review_r5_unrelated_thread_panic_writes_only_the_location";
        if let Ok(scenario) = std::env::var(EDITED_PANIC_SCENARIO_ENV) {
            assert_eq!(scenario, "unrelated");
            install_edited_tool_panic_hook();
            let result = std::thread::spawn(|| panic!("{CANARY}")).join();
            assert!(result.is_err(), "the worker thread must panic");
            return;
        }

        let stderr = run_edited_panic_scenario(TEST_NAME, "unrelated");
        assert_redacted_location_line(&stderr, &[CANARY]);
    }

    #[cfg(unix)]
    #[test]
    fn a_redaction_panic_writes_only_the_location() {
        const RAW: &str = "\u{20ac}06 12 34 56 78 REDACTION-PANIC-CANARY-R3";
        const TEST_NAME: &str =
            "engine::approvals::tests::a_redaction_panic_writes_only_the_location";
        if let Ok(scenario) = std::env::var(EDITED_PANIC_SCENARIO_ENV) {
            assert_eq!(scenario, "redaction");
            install_edited_tool_panic_hook();
            // The closure panics on the redaction step, quoting the whole input
            // line: the guard must return the fixed placeholder, and the hook
            // must not print that quote.
            let out = kernel_broker::guard_log_redaction(RAW, |line| {
                let _ = line
                    .get(1..2)
                    .unwrap_or_else(|| panic!("redaction failed on {line}"));
                kernel_broker::redact_log_line(line)
            });
            assert_eq!(out, "<redaction-error: line dropped>");
            return;
        }

        let stderr = run_edited_panic_scenario(TEST_NAME, "redaction");
        assert_redacted_location_line(&stderr, &["06 12 34 56 78", "REDACTION-PANIC-CANARY-R3"]);
    }

    #[cfg(unix)]
    #[test]
    fn panic_without_an_edited_value_writes_only_the_location() {
        const MESSAGE: &str = "unrelated panic with no active edited value R5";
        const TEST_NAME: &str =
            "engine::approvals::tests::panic_without_an_edited_value_writes_only_the_location";
        if let Ok(scenario) = std::env::var(EDITED_PANIC_SCENARIO_ENV) {
            assert_eq!(scenario, "no-edit-payload");
            install_edited_tool_panic_hook();
            let result = std::thread::spawn(|| std::panic::panic_any(MESSAGE.to_string())).join();
            assert!(result.is_err(), "the worker thread must panic");
            return;
        }

        let stderr = run_edited_panic_scenario(TEST_NAME, "no-edit-payload");
        assert_redacted_location_line(&stderr, &[MESSAGE]);
    }

    #[cfg(unix)]
    #[test]
    fn detached_thread_panic_after_an_edited_run_writes_only_the_location() {
        const CANARY: &str = "EDITED-DETACHED-AFTER-RUN-CANARY-R5-551207";
        const TEST_NAME: &str =
            "engine::approvals::tests::detached_thread_panic_after_an_edited_run_writes_only_the_location";
        if let Ok(scenario) = std::env::var(EDITED_PANIC_SCENARIO_ENV) {
            assert_eq!(scenario, "detached-after-run");
            install_edited_tool_panic_hook();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            // The worker is created inside the edited run and owns the value.
            let mut future = Box::pin(EditedToolFuture::new(async move {
                std::thread::spawn(move || {
                    let payload = CANARY.to_string();
                    let _ = release_rx.recv();
                    std::panic::panic_any(payload);
                })
            }));
            let worker = match poll_once(future.as_mut()) {
                std::task::Poll::Ready(worker) => worker,
                std::task::Poll::Pending => unreachable!("a ready edited run completes at once"),
            };
            // The edited run ends before the detached worker panics, so only
            // the payload-free hook is left to handle it.
            drop(future);
            release_tx
                .send(())
                .expect("the detached worker is still waiting");
            assert!(worker.join().is_err(), "the detached worker must panic");
            return;
        }

        let stderr = run_edited_panic_scenario(TEST_NAME, "detached-after-run");
        assert_redacted_location_line(&stderr, &[CANARY]);
    }

    #[cfg(unix)]
    #[test]
    fn overlapping_edited_runs_never_forward_panic_payloads() {
        const FIRST: &str = "EDITED-THREAD-PANIC-CANARY-FIRST-R5-664201";
        const SECOND: &str = "EDITED-THREAD-PANIC-CANARY-SECOND-R5-902355";
        const UNRELATED: &str = "UNRELATED-OVERLAPPING-PANIC-CANARY-R5-118472";
        const TEST_NAME: &str =
            "engine::approvals::tests::overlapping_edited_runs_never_forward_panic_payloads";
        if let Ok(scenario) = std::env::var(EDITED_PANIC_SCENARIO_ENV) {
            assert_eq!(scenario, "overlapping");
            install_edited_tool_panic_hook();
            let entered = Arc::new(std::sync::Barrier::new(3));
            let release = Arc::new(std::sync::Barrier::new(3));

            let first_entered = Arc::clone(&entered);
            let first_release = Arc::clone(&release);
            let first = std::thread::spawn(move || {
                let mut future = Box::pin(EditedToolFuture::new(async move {
                    first_entered.wait();
                    first_release.wait();
                    panic!("{FIRST}");
                }));
                let result =
                    std::panic::catch_unwind(AssertUnwindSafe(|| poll_once(future.as_mut())));
                assert!(result.is_err(), "the first edited future must panic");
            });

            let second_entered = Arc::clone(&entered);
            let second_release = Arc::clone(&release);
            let second = std::thread::spawn(move || {
                let mut future = Box::pin(EditedToolFuture::new(async move {
                    second_entered.wait();
                    second_release.wait();
                    panic!("{SECOND}");
                }));
                let result =
                    std::panic::catch_unwind(AssertUnwindSafe(|| poll_once(future.as_mut())));
                assert!(result.is_err(), "the second edited future must panic");
            });

            let unrelated_entered = Arc::clone(&entered);
            let unrelated_release = Arc::clone(&release);
            let unrelated = std::thread::spawn(move || {
                unrelated_entered.wait();
                let result = std::panic::catch_unwind(|| panic!("{UNRELATED}"));
                unrelated_release.wait();
                assert!(result.is_err(), "the unrelated worker must panic");
            });

            assert!(first.join().is_ok());
            assert!(second.join().is_ok());
            assert!(unrelated.join().is_ok());
            return;
        }

        let stderr = run_edited_panic_scenario(TEST_NAME, "overlapping");
        assert_redacted_location_lines(&stderr, 3, &[FIRST, SECOND, UNRELATED]);
    }
}
