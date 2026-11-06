//! After the budget stop returned true, a scheduler run and a delegation write
//! no row: no run row, no receipt, no reschedule, no session, no delegation,
//! and nothing panics. The job's runner and the delegated agent never run.
//! One test, its own binary: the stop is for the process. A run and a
//! delegation before the stop write their rows (the controls).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_store::{Job, Store};
use auxd::delegation::{DelegateTool, DelegationExecutor, DelegationRun};
use auxd::scheduler::{run_claimed_job, FileStoreOpener, JobRunner};
use kernel_broker::{Tool, ToolCtx};

const WATCH_WRITES: &str = "CREATE TABLE touched(what);
    CREATE TRIGGER t1 AFTER INSERT ON runs BEGIN INSERT INTO touched VALUES ('run'); END;
    CREATE TRIGGER t2 AFTER UPDATE ON runs BEGIN INSERT INTO touched VALUES ('run'); END;
    CREATE TRIGGER t3 AFTER UPDATE ON jobs BEGIN INSERT INTO touched VALUES ('job'); END;
    CREATE TRIGGER t4 AFTER INSERT ON events BEGIN INSERT INTO touched VALUES ('event'); END;
    CREATE TRIGGER t5 AFTER INSERT ON sessions BEGIN INSERT INTO touched VALUES ('session'); END;
    CREATE TRIGGER t6 AFTER INSERT ON delegations BEGIN INSERT INTO touched VALUES ('delegation'); END;
    CREATE TRIGGER t7 AFTER UPDATE ON delegations BEGIN INSERT INTO touched VALUES ('delegation'); END;";

/// A job runner that opens a job session (the agent runner's first write,
/// through the same gate) and then fails like a budget denial.
struct SessionRunner(AtomicUsize);

impl JobRunner for SessionRunner {
    fn run(&self, store: &Arc<Mutex<Store>>, job: &Job) -> Result<String, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        aux_engine::gated_store_write(|| {
            kernel_core::lock_recover(store).create_session_of_kind(&job.agent, None, "job")
        })
        .map_err(|err| err.to_string())?;
        Err("budget denied: daily usd_cents cap reached".to_string())
    }
}

struct CountingAgent(AtomicUsize);

#[async_trait]
impl DelegationExecutor for CountingAgent {
    async fn execute(&self, _run: DelegationRun) -> Result<String, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok("done".to_string())
    }
}

#[tokio::test]
async fn a_run_and_a_delegation_after_the_stop_write_no_row() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
    )
    .unwrap();
    let path = kernel_core::store_path(&home);
    let job = Store::open(&path)
        .unwrap()
        .create_job("main", "nightly", "every 15m", "{}", None)
        .unwrap();
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
    let opener = FileStoreOpener::from_verified(kernel_core::SandboxHome::open(&home).unwrap());
    let runner = SessionRunner(AtomicUsize::new(0));
    let now: Arc<auxd::scheduler::NowFn> = Arc::new(chrono::Utc::now);
    let lease = Duration::from_secs(60);
    let agent = Arc::new(CountingAgent(AtomicUsize::new(0)));
    let tool = DelegateTool::new(home.clone(), None, agent.clone(), Arc::default());
    let ctx = ToolCtx::new("main", home.clone());
    let args = serde_json::json!({ "agent": "mail", "task": "sort the inbox" });

    // Before the stop: the run, its session, receipt and reschedule are written.
    assert!(!run_claimed_job(&opener, Arc::clone(&now), &runner, lease, &job).unwrap());
    assert_eq!(runner.0.load(Ordering::SeqCst), 1);
    assert!(touched("run") >= 2, "start and finish rows");
    assert!(touched("session") == 1, "the run's session row");
    assert!(touched("event") >= 1, "the run receipt");
    assert!(touched("job") >= 1, "the reschedule");
    // Before the stop: the delegation row is created and the agent runs.
    let handed = tool.run(&args, &ctx).await.unwrap();
    assert!(!handed.is_error, "{}", handed.content);
    assert_eq!(agent.0.load(Ordering::SeqCst), 1);
    assert!(touched("delegation") >= 1, "the delegation row");
    let before: Vec<i64> = ["run", "session", "event", "job", "delegation"]
        .iter()
        .map(|what| touched(what))
        .collect();

    assert!(aux_engine::stop_settle_worker(Duration::from_secs(10)));

    // After the stop: the run is not recorded and its runner never runs.
    assert!(!run_claimed_job(&opener, Arc::clone(&now), &runner, lease, &job).unwrap());
    assert_eq!(runner.0.load(Ordering::SeqCst), 1, "the job did not run");
    // After the stop: no delegation row, the agent never runs, no panic.
    let refused = tool.run(&args, &ctx).await.unwrap();
    assert!(refused.is_error, "the stop is the call's error");
    assert!(
        refused.content.contains("stopping"),
        "the stop, not a budget denial: {}",
        refused.content
    );
    assert_eq!(agent.0.load(Ordering::SeqCst), 1, "the agent did not run");
    let after: Vec<i64> = ["run", "session", "event", "job", "delegation"]
        .iter()
        .map(|what| touched(what))
        .collect();
    assert_eq!(after, before, "no row was written after the stop");
    assert!(auxd::shutdown::daemon_stopping());
}
