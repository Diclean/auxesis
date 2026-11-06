//! A resume never runs beside a stopped run that is still finishing
//! (BUDGET-SETTLE-9): the old run's late writes can no longer land on the
//! new run's row, and a resume while a run is live is a conflict.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_store::{DelegationState, Store};
use auxd::api::{self, ApiOptions};
use auxd::delegation::{DelegationExecutor, DelegationRun};
use tokio::sync::Notify;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Run `n` ignores its cancel and answers `run<n>` only once released, as
/// an executor slow to notice a Stop.
struct Slow {
    runs: Mutex<usize>,
    release: Vec<Arc<Notify>>,
}

#[async_trait]
impl DelegationExecutor for Slow {
    async fn execute(&self, _run: DelegationRun) -> Result<String, String> {
        let n = {
            let mut runs = self.runs.lock().unwrap();
            *runs += 1;
            *runs
        };
        self.release[n - 1].notified().await;
        Ok(format!("run{n}"))
    }
}

fn post(handle: &api::ApiHandle, id: &str, action: &str) -> u16 {
    common::post(
        handle.addr(),
        &format!("/v1/delegations/{id}/{action}"),
        Some(TOKEN),
        "{}",
    )
    .status
}

fn row(home: &std::path::Path, id: &str) -> aux_store::Delegation {
    Store::open(&kernel_core::store_path(home))
        .unwrap()
        .delegation(id)
        .unwrap()
        .unwrap()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_stopped_run_never_lands_on_the_resumed_row() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let id = "dlg-live".to_string();
    {
        let store = Store::open(&kernel_core::store_path(&home)).unwrap();
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
    }
    let agent = Arc::new(Slow {
        runs: Mutex::new(0),
        release: (0..3).map(|_| Arc::new(Notify::new())).collect(),
    });
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            delegations: Some(agent.clone() as Arc<dyn DelegationExecutor>),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let runs = || *agent.runs.lock().unwrap();

    // Run #1 starts, then the owner stops it; it is slow to cancel.
    assert_eq!(post(&handle, &id, "resume"), 200);
    until("run #1 never started", || runs() == 1).await;
    assert_eq!(post(&handle, &id, "stop"), 200);
    assert_eq!(row(&home, &id).state, DelegationState::Stopped);
    assert_eq!(
        post(&handle, &id, "resume"),
        409,
        "run #1 is still finishing: no second run beside it"
    );

    // Run #1 finishes late: its result never lands on the stopped row.
    agent.release[0].notify_one();
    until("the resume never became possible", || {
        post(&handle, &id, "resume") == 200
    })
    .await;
    until("run #2 never started", || runs() == 2).await;
    let live = row(&home, &id);
    assert_eq!(live.state, DelegationState::Working, "{live:?}");
    assert_eq!(live.result, None, "run #1's late result landed: {live:?}");
    assert_eq!(post(&handle, &id, "resume"), 409, "run #2 is live");

    // Run #2's own result is the one the row keeps.
    agent.release[1].notify_one();
    until("run #2 never finished", || {
        row(&home, &id).state == DelegationState::Done
    })
    .await;
    assert_eq!(row(&home, &id).result.as_deref(), Some("run2"));
    assert_eq!(runs(), 2);
    handle.shutdown();
}
