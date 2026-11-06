//! A delegation live across the budget stop and a tainted caller's hand-off
//! after it write no row (BUDGET-SETTLE-7): the agent's steps, progress and
//! approval marks after the stop are refused, and a refused hand-off leaves no
//! taint mark. A hand-off that goes through still taints the agent's workspace
//! before the agent acts. One test, its own binary: the stop is for the process.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_store::Store;
use auxd::delegation::{DelegateTool, DelegationExecutor, DelegationRun};
use kernel_broker::{Tool, ToolCtx};
use tokio::sync::Notify;

const WATCH_WRITES: &str = "CREATE TABLE touched(what);
    CREATE TRIGGER t1 AFTER INSERT ON delegations BEGIN INSERT INTO touched VALUES ('delegation'); END;
    CREATE TRIGGER t2 AFTER UPDATE ON delegations BEGIN INSERT INTO touched VALUES ('delegation'); END;
    CREATE TRIGGER t3 AFTER INSERT ON workspace_taint BEGIN INSERT INTO touched VALUES ('taint'); END;
    CREATE TRIGGER t4 AFTER UPDATE ON workspace_taint BEGIN INSERT INTO touched VALUES ('taint'); END;";

fn taint_key(home: &std::path::Path, agent: &str) -> String {
    aux_engine::workspace::workspace_key(&aux_engine::workspace_dir(home, agent))
}

/// An agent that records steps. The `mail` agent records one step, then waits
/// for `resume` (the test stops the daemon meanwhile) and records more; every
/// agent notes whether its workspace was already tainted when it started.
struct RecordingAgent {
    home: PathBuf,
    runs: AtomicUsize,
    tainted_at_start: Mutex<Vec<(String, bool)>>,
    started: Notify,
    resume: Notify,
    after_stop: Mutex<Option<bool>>,
}

#[async_trait]
impl DelegationExecutor for RecordingAgent {
    async fn execute(&self, run: DelegationRun) -> Result<String, String> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let tainted = Store::open(&kernel_core::store_path(&self.home))
            .unwrap()
            .workspace_taint(&taint_key(&self.home, &run.agent))
            .unwrap()
            .is_some();
        self.tainted_at_start
            .lock()
            .unwrap()
            .push((run.agent.clone(), tainted));
        if run.agent != "mail" {
            return Ok("done".to_string());
        }
        assert!(run.step("read the inbox", "done"), "before the stop");
        self.started.notify_one();
        self.resume.notified().await;
        // Past the stop: no step, progress or approval row; the run is stopped.
        let going = run.step("sorted the inbox", "done");
        run.progress(1, 2);
        run.waiting("ap-after-stop");
        *self.after_stop.lock().unwrap() = Some(going);
        Ok("done".to_string())
    }
}

#[tokio::test]
async fn a_live_delegation_and_a_tainted_handoff_after_the_stop_write_no_row() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
    )
    .unwrap();
    let path = kernel_core::store_path(&home);
    drop(Store::open(&path).unwrap());
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute_batch(WATCH_WRITES).unwrap();
    let touched = |what: &str| -> i64 {
        raw.query_row(
            "SELECT COUNT(*) FROM touched WHERE what = ?1",
            [what],
            |row| row.get(0),
        )
        .unwrap()
    };
    let agent = Arc::new(RecordingAgent {
        home: home.clone(),
        runs: AtomicUsize::new(0),
        tainted_at_start: Mutex::new(Vec::new()),
        started: Notify::new(),
        resume: Notify::new(),
        after_stop: Mutex::new(None),
    });
    let tool = DelegateTool::new(home.clone(), None, agent.clone(), None);
    let mut tainted = ToolCtx::new("main", home.clone());
    tainted.tainted = true;

    // Before the stop: a tainted caller's hand-off taints the agent's workspace
    // before the agent acts, and the agent runs.
    let args = serde_json::json!({ "agent": "calendar", "task": "find a slot" });
    let handed = tool.run(&args, &tainted).await.unwrap();
    assert!(!handed.is_error, "{}", handed.content);
    assert_eq!(
        agent.tainted_at_start.lock().unwrap().as_slice(),
        &[("calendar".to_string(), true)],
        "the hand-off tainted the workspace before the agent ran"
    );
    assert!(touched("taint") >= 1);

    // A clean caller's delegation, live across the stop.
    let clean = ToolCtx::new("main", home.clone());
    let args = serde_json::json!({ "agent": "mail", "task": "sort the inbox" });
    let (live, before) = tokio::join!(tool.run(&args, &clean), async {
        agent.started.notified().await;
        let before = (touched("delegation"), touched("taint"));
        assert!(aux_engine::stop_settle_worker(Duration::from_secs(10)));
        agent.resume.notify_one();
        before
    });
    let live = live.unwrap();
    assert!(
        live.is_error,
        "the stopped task is no result: {}",
        live.content
    );
    assert_eq!(
        *agent.after_stop.lock().unwrap(),
        Some(false),
        "a step after the stop tells the agent to stop"
    );
    assert_eq!(
        (touched("delegation"), touched("taint")),
        before,
        "no step, progress, approval or state row after the stop"
    );

    // After the stop: a tainted caller's hand-off is refused, writes no
    // delegation row and leaves no taint mark; the agent never runs.
    let args = serde_json::json!({ "agent": "documents", "task": "file the receipt" });
    let refused = tool.run(&args, &tainted).await.unwrap();
    assert!(refused.is_error);
    assert!(refused.content.contains("stopping"), "{}", refused.content);
    assert_eq!(
        agent.runs.load(Ordering::SeqCst),
        2,
        "the agent did not run"
    );
    assert_eq!((touched("delegation"), touched("taint")), before);
    let documents = raw
        .query_row(
            "SELECT COUNT(*) FROM workspace_taint WHERE workspace LIKE '%documents%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(documents, 0, "no taint mark for a refused hand-off");
}
