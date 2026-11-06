//! After the budget stop returned true, an ACP turn runs no SQL: it is
//! abandoned by the runtime's grace, not killed, and may resume while the
//! process exits. This file holds one test, since the stop is for the process.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aux_acp::backend::{AcpBackend, AcpBackendConfig, AcpTurnRequest, AgentBackend};
use aux_acp::client::TurnObserver;
use aux_acp::config::{AcpAgentSpec, AcpLimits};
use aux_acp::ledger::{StoreTurnHost, TurnHost, TurnReservation};
use aux_acp::protocol::UsageUpdate;
use aux_acp::AcpError;
use aux_store::{Message, Store};
use kernel_broker::sandbox::ShellSandbox;
use kernel_broker::{ApprovalRequest, Approver, ApproverError};
use kernel_core::budget::Budgets;

/// Count every row written to a usage table, the event table included, and
/// the message and session taint rows a turn leaves.
const WATCH_WRITES: &str = "CREATE TABLE touched(n);
    CREATE TRIGGER t1 AFTER INSERT ON usage BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t2 AFTER INSERT ON events BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t3 AFTER INSERT ON usage_reservations BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t4 AFTER INSERT ON messages BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t5 AFTER INSERT ON session_taint BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t6 AFTER UPDATE ON session_taint BEGIN INSERT INTO touched VALUES (1); END;";

struct Deny;

#[async_trait::async_trait]
impl Approver for Deny {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(false)
    }
}

/// The stop is asked while the agent is answering, as a shutdown does.
struct StopMidTurn(Arc<AtomicBool>);

impl TurnObserver for StopMidTurn {
    fn message_chunk(&mut self, _chunk: &str) {
        let ended = aux_engine::stop_settle_worker(Duration::from_secs(10));
        self.0.store(ended, Ordering::SeqCst);
    }
}

/// A host whose admission and settle both completed before the stop: the
/// turn is paid for, and only its taint mark and its answer row are left.
struct PaidBeforeStop(StoreTurnHost);

impl TurnHost for PaidBeforeStop {
    fn reserve_turn(&mut self, _cost_cents: u64) -> Result<Option<TurnReservation>, AcpError> {
        Ok(None)
    }
    fn settle_turn(
        &mut self,
        _r: Option<TurnReservation>,
        _o: &UsageUpdate,
    ) -> Result<(), AcpError> {
        Ok(())
    }
    fn persist_assistant(&mut self, text: &str, meta: &str) -> Result<Message, AcpError> {
        self.0.persist_assistant(text, meta)
    }
    fn emit_message(&mut self, message: &Message) {
        self.0.emit_message(message);
    }
    fn emit_done(&mut self, message_id: i64) {
        self.0.emit_done(message_id);
    }
    fn taint_session(&mut self, source: &str) -> Result<(), AcpError> {
        self.0.taint_session(source)
    }
}

fn backend(host: Box<dyn TurnHost>, workspace: PathBuf) -> AcpBackend {
    let agent_path = workspace.join("fake-agent");
    std::fs::copy(env!("CARGO_BIN_EXE_acp-fake-agent"), &agent_path).unwrap();
    let mut agent = AcpAgentSpec::new("fake", agent_path.to_string_lossy().to_string(), vec![]);
    agent.args = vec!["happy".to_string()];
    let sandbox = if cfg!(target_os = "macos") {
        ShellSandbox::default()
    } else {
        ShellSandbox::new(false, false, true)
    };
    let limits = AcpLimits {
        turn_timeout: Duration::from_secs(30),
        max_processes: 0,
        ..AcpLimits::default()
    };
    let config = AcpBackendConfig {
        enabled: true,
        agent_name: "main".to_string(),
        agent,
        limits,
        sandbox,
        workspace,
        sandbox_home: None,
        read_only: false,
    };
    AcpBackend::new(config, Arc::new(Deny), host)
}

fn request() -> AcpTurnRequest {
    let grant = kernel_core::privacy::admit_call(
        kernel_core::privacy::PathId::C9,
        kernel_core::privacy::PrivacyMode::Private,
        kernel_core::privacy::Destination::LocalDisplay,
    )
    .expect("C9 is covered in private mode");
    let mut gate = kernel_privacy::Gate::for_tests(
        &grant,
        [7u8; 32],
        aux_providers::test_gate::names_checked(),
    );
    AcpTurnRequest {
        prompt: gate.text("hi").unwrap().0,
        cancel: None,
        turns_used: 0,
    }
}

fn host(path: &std::path::Path, budgets: Budgets) -> StoreTurnHost {
    let store = Arc::new(Mutex::new(Store::open(path).unwrap()));
    let session = store.lock().unwrap().create_session("main", None).unwrap();
    StoreTurnHost::new(store, "main".to_string(), session.id, budgets, None)
        .with_run_id("turn-after-stop")
}

#[tokio::test]
async fn an_acp_turn_after_the_stop_reserves_nothing_and_writes_no_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let capped = || {
        let mut capped = Budgets::default();
        capped.default.usd_cents = Some(50);
        capped
    };
    let mut unlimited = Budgets::default();
    unlimited.default.unlimited = true;
    let refusing = host(&path, capped());
    let mut capped = host(&path, capped());
    let mut unlimited = host(&path, unlimited);
    let paid = host(&path, Budgets::default());
    std::fs::create_dir(dir.path().join("ws")).unwrap();
    let workspace = dir.path().join("ws").canonicalize().unwrap();
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute_batch(WATCH_WRITES).unwrap();
    let touched = || -> i64 {
        raw.query_row("SELECT COUNT(*) FROM touched", [], |row| row.get(0))
            .unwrap()
    };
    // Admitted before the stop: this turn's reservation is held.
    let held = capped.reserve_turn(10).unwrap();
    assert!(held.is_some());
    // An unlimited turn admitted before the stop: no row, its estimate kept.
    assert!(unlimited.reserve_turn(10).unwrap().is_none());
    let before = touched();
    assert_eq!(before, 1, "the reservation");

    // Paid before the stop, which is asked while the agent answers: the taint
    // mark and the answer row are refused, the turn fails clearly.
    let stopped = Arc::new(AtomicBool::new(false));
    let mut observer = StopMidTurn(Arc::clone(&stopped));
    let mut paid = backend(Box::new(PaidBeforeStop(paid)), workspace.clone());
    let answered = paid.run_turn(request(), &mut observer).await;
    assert!(stopped.load(Ordering::SeqCst), "the stop returned true");
    let Err(AcpError::Io(err)) = answered else {
        panic!("the paid answer cannot be saved after the stop: {answered:?}");
    };
    assert!(err.to_string().contains("not saved"), "{err}");

    let refused = capped.reserve_turn(10);
    assert!(matches!(refused, Err(AcpError::BudgetDenied { .. })));
    // The unlimited turn: its usage write and failed-settle marker are refused.
    let settled = unlimited.settle_turn(None, &UsageUpdate::default());
    assert!(settled.is_err(), "refused, not lost silently");
    // A new unlimited turn is refused too: no paid call starts after the stop.
    assert!(
        unlimited.reserve_turn(10).is_err(),
        "no unlimited call after the stop"
    );
    // A whole turn after the stop is denied before the agent starts.
    let mut denied = backend(Box::new(refusing), workspace);
    let result = denied.run_turn(request(), &mut StopMidTurn(stopped)).await;
    assert!(matches!(result, Err(AcpError::BudgetDenied { .. })));
    assert_eq!(touched(), before, "no SQL write ran after the stop");
}
