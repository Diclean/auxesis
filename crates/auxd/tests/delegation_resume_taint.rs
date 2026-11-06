//! A tainted caller's hand-off never resumes clean (BUDGET-SETTLE-7): the
//! hand-off records its own taint mark with the row, so after a crash and a
//! restart the resumed run marks the agent's workspace again before the agent
//! acts, even when the workspace mark is gone (trusted since, or never written).

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_store::Store;
use auxd::api::{self, ApiOptions};
use auxd::delegation::{DelegateTool, DelegationExecutor, DelegationRun};
use kernel_broker::{Tool, ToolCtx};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn taint_key(home: &std::path::Path, agent: &str) -> String {
    aux_engine::workspace::workspace_key(&aux_engine::workspace_dir(home, agent))
}

/// Notes whether the agent's workspace was tainted when the run started; the
/// first run (the hand-off) attempts nothing, as a crash before the agent's
/// first step leaves it.
struct Recording {
    home: std::path::PathBuf,
    tainted_at_start: Mutex<Vec<bool>>,
}

#[async_trait]
impl DelegationExecutor for Recording {
    async fn execute(&self, run: DelegationRun) -> Result<String, String> {
        let tainted = Store::open(&kernel_core::store_path(&self.home))
            .unwrap()
            .workspace_taint(&taint_key(&self.home, &run.agent))
            .unwrap()
            .is_some();
        let mut seen = self.tainted_at_start.lock().unwrap();
        seen.push(tainted);
        if seen.len() == 1 {
            return Err("the turn was cancelled".into());
        }
        Ok("done".into())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tainted_handoff_resumed_after_a_restart_runs_tainted() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let path = kernel_core::store_path(&home);
    drop(Store::open(&path).unwrap());
    let agent = Arc::new(Recording {
        home: home.clone(),
        tainted_at_start: Mutex::new(Vec::new()),
    });

    // A tainted caller hands Mail a task; the workspace is marked before Mail runs.
    let tool = DelegateTool::new(home.clone(), None, agent.clone(), Arc::default());
    let mut tainted = ToolCtx::new("main", home.clone());
    tainted.tainted = true;
    let args = serde_json::json!({ "agent": "mail", "task": "sort the inbox" });
    let _ = tool.run(&args, &tainted).await.unwrap();
    assert_eq!(*agent.tainted_at_start.lock().unwrap(), vec![true]);

    // A crash leaves the row open; the workspace mark is then gone (the owner
    // trusted the workspace, or the old order never wrote it).
    let store = Store::open(&path).unwrap();
    let id = store.list_delegations(None).unwrap()[0].id.clone();
    let marker = store.workspace_taint(&format!("delegation:{id}")).unwrap();
    assert_eq!(
        marker.as_deref(),
        Some("delegate: from main"),
        "the tainted row carries a tainted marker"
    );
    store
        .set_delegation_state(&id, aux_store::DelegationState::Queued)
        .unwrap();
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute(
        "DELETE FROM workspace_taint WHERE workspace = ?1",
        [taint_key(&home, "mail")],
    )
    .unwrap();
    assert!(store
        .workspace_taint(&taint_key(&home, "mail"))
        .unwrap()
        .is_none());
    drop((store, raw));

    // The restart retires the row to stopped; the owner resumes it.
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            delegations: Some(agent.clone() as Arc<dyn DelegationExecutor>),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let resumed = common::post(
        handle.addr(),
        &format!("/v1/delegations/{id}/resume"),
        Some(TOKEN),
        "{}",
    );
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    let deadline = Instant::now() + Duration::from_secs(10);
    while agent.tainted_at_start.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline, "the resumed run never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        *agent.tainted_at_start.lock().unwrap(),
        vec![true, true],
        "the resumed hand-off runs with the caller's taint"
    );
    handle.shutdown();
}
