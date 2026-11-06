//! Every hand-off records its taint marker, and a resume reads a missing
//! marker as unknown, never clean (BUDGET-SETTLE-8): a row written before the
//! markers existed resumes tainted even after the owner trusted the
//! workspace. A failed re-arm leaves the row stopped (resumable), only one of
//! two concurrent resumes runs, and a failed start is an error, not "stopped".

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_store::{DelegationState, Store};
use auxd::api::{self, ApiOptions};
use auxd::delegation::{DelegateTool, DelegationExecutor, DelegationRun};
use kernel_broker::{Tool, ToolCtx};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn taint_key(home: &std::path::Path, agent: &str) -> String {
    aux_engine::workspace::workspace_key(&aux_engine::workspace_dir(home, agent))
}

/// Notes whether the agent's workspace was tainted when each run started; the
/// first `fail_first` runs attempt nothing, as a crash before the first step.
struct Recording {
    home: std::path::PathBuf,
    fail_first: usize,
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
        if seen.len() <= self.fail_first {
            return Err("the turn was cancelled".into());
        }
        Ok("done".into())
    }
}

struct World {
    _dir: tempfile::TempDir,
    home: std::path::PathBuf,
    agent: Arc<Recording>,
}

fn world(fail_first: usize) -> World {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    drop(Store::open(&kernel_core::store_path(&home)).unwrap());
    let agent = Arc::new(Recording {
        home: home.clone(),
        fail_first,
        tainted_at_start: Mutex::new(Vec::new()),
    });
    World {
        _dir: dir,
        home,
        agent,
    }
}

/// A stopped row as an old build left it: no `delegation:<id>` marker.
fn old_row(home: &std::path::Path) -> String {
    let store = Store::open(&kernel_core::store_path(home)).unwrap();
    let id = "dlg-old-row".to_string();
    store
        .create_delegation(
            &id,
            "main",
            "mail",
            "sort the inbox",
            None,
            kernel_core::privacy::PrivacyMode::Open,
        )
        .unwrap();
    store
        .set_delegation_state(&id, DelegationState::Stopped)
        .unwrap();
    id
}

fn serve(w: &World) -> api::ApiHandle {
    api::spawn(
        &w.home,
        ApiOptions {
            port: 0,
            delegations: Some(w.agent.clone() as Arc<dyn DelegationExecutor>),
            ..ApiOptions::default()
        },
    )
    .unwrap()
}

fn resume(handle: &api::ApiHandle, id: &str) -> common::HttpResponse {
    common::post(
        handle.addr(),
        &format!("/v1/delegations/{id}/resume"),
        Some(TOKEN),
        "{}",
    )
}

async fn wait_runs(agent: &Recording, n: usize) {
    let deadline = Instant::now() + common::LOADED_RUNNER_WAIT;
    while agent.tainted_at_start.lock().unwrap().len() < n {
        assert!(Instant::now() < deadline, "the resumed run never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn state(home: &std::path::Path, id: &str) -> DelegationState {
    Store::open(&kernel_core::store_path(home))
        .unwrap()
        .delegation(id)
        .unwrap()
        .unwrap()
        .state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_row_with_no_marker_resumes_tainted_in_a_trusted_workspace() {
    let w = world(0);
    let id = old_row(&w.home);
    // The workspace is trusted (no mark), and the row has no marker.
    let store = Store::open(&kernel_core::store_path(&w.home)).unwrap();
    assert!(store
        .workspace_taint(&taint_key(&w.home, "mail"))
        .unwrap()
        .is_none());
    let handle = serve(&w);
    let resumed = resume(&handle, &id);
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    wait_runs(&w.agent, 1).await;
    assert_eq!(
        *w.agent.tainted_at_start.lock().unwrap(),
        vec![true],
        "no marker is unknown: the resumed run starts tainted"
    );
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_handoff_records_its_marker_and_resumes_clean() {
    let w = world(1);
    let tool = DelegateTool::new(w.home.clone(), None, w.agent.clone(), Arc::default());
    let clean = ToolCtx::new("main", w.home.clone());
    let args = serde_json::json!({ "agent": "mail", "task": "sort the inbox" });
    let _ = tool.run(&args, &clean).await.unwrap();
    let store = Store::open(&kernel_core::store_path(&w.home)).unwrap();
    let id = store.list_delegations(None).unwrap()[0].id.clone();
    assert!(
        store
            .workspace_taint(&format!("delegation:{id}"))
            .unwrap()
            .is_some(),
        "a clean hand-off records its marker too"
    );
    assert_eq!(state(&w.home, &id), DelegationState::Stopped);
    let handle = serve(&w);
    let resumed = resume(&handle, &id);
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    wait_runs(&w.agent, 2).await;
    assert_eq!(
        *w.agent.tainted_at_start.lock().unwrap(),
        vec![false, false]
    );
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_rearm_leaves_the_row_stopped_and_the_agent_idle() {
    let w = world(0);
    let id = old_row(&w.home);
    let handle = serve(&w);
    let raw = aux_store::open_keyed(&kernel_core::store_path(&w.home)).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER no_mark BEFORE INSERT ON workspace_taint
         BEGIN SELECT RAISE(ABORT, 'no mark'); END;",
    )
    .unwrap();
    let resumed = resume(&handle, &id);
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    let deadline = Instant::now() + common::LOADED_RUNNER_WAIT;
    while state(&w.home, &id) == DelegationState::Queued {
        assert!(Instant::now() < deadline, "the row stayed queued");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        state(&w.home, &id),
        DelegationState::Stopped,
        "resumable, not failed"
    );
    assert!(w.agent.tainted_at_start.lock().unwrap().is_empty());
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_resumes_run_the_task_once() {
    let w = world(0);
    let id = old_row(&w.home);
    let handle = Arc::new(serve(&w));
    let both: Vec<_> = (0..2)
        .map(|_| {
            let (handle, id) = (Arc::clone(&handle), id.clone());
            std::thread::spawn(move || resume(&handle, &id).status)
        })
        .collect();
    let mut codes: Vec<u16> = both.into_iter().map(|t| t.join().unwrap()).collect();
    codes.sort_unstable();
    assert_eq!(codes, vec![200, 409]);
    wait_runs(&w.agent, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(w.agent.tainted_at_start.lock().unwrap().len(), 1);
    // The second resume of a row that is no longer stopped is refused too.
    assert_eq!(resume(&handle, &id).status, 409);
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_fails_in_sql_is_an_error_not_a_stop() {
    let w = world(0);
    let raw = aux_store::open_keyed(&kernel_core::store_path(&w.home)).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER no_start BEFORE UPDATE OF state ON delegations
         WHEN NEW.state = 'working' BEGIN SELECT RAISE(ABORT, 'no start'); END;",
    )
    .unwrap();
    let tool = DelegateTool::new(w.home.clone(), None, w.agent.clone(), Arc::default());
    let clean = ToolCtx::new("main", w.home.clone());
    let args = serde_json::json!({ "agent": "mail", "task": "sort the inbox" });
    match tool.run(&args, &clean).await {
        Err(err) => assert!(!err.to_string().contains("stopped"), "{err}"),
        Ok(out) => panic!("a failed start is an error: {}", out.content),
    }
    assert!(w.agent.tainted_at_start.lock().unwrap().is_empty());
    let store = Store::open(&kernel_core::store_path(&w.home)).unwrap();
    let id = store.list_delegations(None).unwrap()[0].id.clone();
    assert_eq!(state(&w.home, &id), DelegationState::Stopped, "resumable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resume_whose_start_fails_in_sql_goes_back_to_stopped() {
    let w = world(0);
    let id = old_row(&w.home);
    let handle = serve(&w);
    let raw = aux_store::open_keyed(&kernel_core::store_path(&w.home)).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER no_start BEFORE UPDATE OF state ON delegations
         WHEN NEW.state = 'working' BEGIN SELECT RAISE(ABORT, 'no start'); END;",
    )
    .unwrap();
    let resumed = resume(&handle, &id);
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    let deadline = Instant::now() + common::LOADED_RUNNER_WAIT;
    while state(&w.home, &id) == DelegationState::Queued {
        assert!(Instant::now() < deadline, "the row stayed queued");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(state(&w.home, &id), DelegationState::Stopped);
    assert!(w.agent.tainted_at_start.lock().unwrap().is_empty());
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tainted_handoff_marks_the_workspace_first_and_a_failed_insert_leaves_no_row_or_marker() {
    let w = world(0);
    let raw = aux_store::open_keyed(&kernel_core::store_path(&w.home)).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER no_row BEFORE INSERT ON delegations
         BEGIN SELECT RAISE(ABORT, 'no row'); END;",
    )
    .unwrap();
    let tool = DelegateTool::new(w.home.clone(), None, w.agent.clone(), Arc::default());
    let mut tainted = ToolCtx::new("main", w.home.clone());
    tainted.tainted = true;
    let args = serde_json::json!({ "agent": "mail", "task": "sort the inbox" });
    assert!(
        tool.run(&args, &tainted).await.is_err(),
        "a failed insert is an error"
    );
    let store = Store::open(&kernel_core::store_path(&w.home)).unwrap();
    assert!(
        store
            .workspace_taint(&taint_key(&w.home, "mail"))
            .unwrap()
            .is_some(),
        "the workspace taint is written before the row"
    );
    assert!(store.list_delegations(None).unwrap().is_empty(), "no row");
    let markers: i64 = raw
        .query_row(
            "SELECT count(*) FROM workspace_taint WHERE workspace LIKE 'delegation:%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(markers, 0, "the transaction rolled the marker back");
    assert!(w.agent.tainted_at_start.lock().unwrap().is_empty());
}
