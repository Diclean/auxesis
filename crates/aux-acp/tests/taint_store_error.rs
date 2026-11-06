//! A taint mark that fails for a store reason (not the stop gate) fails the
//! turn with the store error and stores no answer: the answer never lands in a
//! session that is not marked. The stop gate's own refusal is `stop_gate.rs`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aux_acp::backend::{AcpBackend, AcpBackendConfig, AcpTurnRequest, AgentBackend};
use aux_acp::client::NullObserver;
use aux_acp::config::{AcpAgentSpec, AcpLimits};
use aux_acp::ledger::{StoreTurnHost, TurnHost};
use aux_acp::AcpError;
use aux_store::Store;
use kernel_broker::sandbox::ShellSandbox;
use kernel_broker::{ApprovalRequest, Approver, ApproverError};
use kernel_core::budget::Budgets;

struct Deny;

#[async_trait::async_trait]
impl Approver for Deny {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(false)
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

#[tokio::test]
async fn a_taint_mark_that_fails_for_a_store_reason_fails_the_turn_and_stores_no_answer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
    let session = store.lock().unwrap().create_session("main", None).unwrap();
    let host = StoreTurnHost::new(
        Arc::clone(&store),
        "main".to_string(),
        session.id,
        Budgets::default(),
        None,
    );
    // The store refuses every taint mark, as a busy or broken database would.
    aux_store::open_keyed(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER refuse_mark BEFORE INSERT ON session_taint
             BEGIN SELECT RAISE(ABORT, 'database is busy'); END;",
        )
        .unwrap();
    std::fs::create_dir(dir.path().join("ws")).unwrap();
    let workspace = dir.path().join("ws").canonicalize().unwrap();
    let mut backend = backend(Box::new(host), workspace);

    let result = backend.run_turn(request(), &mut NullObserver).await;

    assert!(
        matches!(result, Err(AcpError::Store(_))),
        "a store error, not the stop path: {result:?}"
    );
    let rows = store.lock().unwrap().list_messages(session.id).unwrap();
    assert!(rows.is_empty(), "no answer was stored: {rows:?}");
}
