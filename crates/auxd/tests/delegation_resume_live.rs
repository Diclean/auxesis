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
    let deadline = Instant::now() + common::LOADED_RUNNER_WAIT;
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
    common::assert_error(
        &common::post(
            handle.addr(),
            &format!("/v1/delegations/{id}/resume"),
            Some(TOKEN),
            "{}",
        ),
        409,
        "delegation_still_stopping",
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

const CHIEF_CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "aux"
approvals = "ask"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"

[[rules]]
agent = "aux"
tool = "delegate"
action = "allow"
"#;

/// A run the chief's `delegate` tool started registers in the daemon's cancel
/// registry (the runner cannot have delegations without it), so a resume of
/// it is refused while it still lives and accepted once it ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tool_started_run_gates_its_resume_until_it_ends() {
    use aux_providers::{ChatMessage, ChatResponse, FakeProvider};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(kernel_core::config_path(&home), CHIEF_CONFIG).unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![aux_providers::ToolCall::new(
                    "call_1",
                    "delegate",
                    serde_json::json!({ "agent": "mail", "task": "sort the inbox" }),
                )],
            )),
            ChatResponse::assistant("Done."),
        ],
    ));
    let agent = Arc::new(Slow {
        runs: Mutex::new(0),
        release: (0..2).map(|_| Arc::new(Notify::new())).collect(),
    });
    let handle = Arc::new(
        api::spawn(
            &home,
            ApiOptions {
                port: 0,
                provider: Some(provider),
                delegations: Some(agent.clone() as Arc<dyn DelegationExecutor>),
                ..ApiOptions::default()
            },
        )
        .unwrap(),
    );
    let runs = || *agent.runs.lock().unwrap();
    let chat = {
        let handle = Arc::clone(&handle);
        tokio::task::spawn_blocking(move || {
            common::post(
                handle.addr(),
                "/v1/threads/aux/messages",
                Some(TOKEN),
                r#"{"content":"ask Mail"}"#,
            )
            .status
        })
    };
    until("the tool never started the run", || runs() == 1).await;
    let id = Store::open(&kernel_core::store_path(&home))
        .unwrap()
        .list_delegations(None)
        .unwrap()[0]
        .id
        .clone();

    // Stopped mid-turn: the run is slow to notice, so it still lives.
    assert_eq!(post(&handle, &id, "stop"), 200);
    common::assert_error(
        &common::post(
            handle.addr(),
            &format!("/v1/delegations/{id}/resume"),
            Some(TOKEN),
            "{}",
        ),
        409,
        "delegation_still_stopping",
    );

    // Once it ends, the resume is accepted and runs once.
    agent.release[0].notify_one();
    until("the resume never became possible", || {
        post(&handle, &id, "resume") == 200
    })
    .await;
    until("the resumed run never started", || runs() == 2).await;
    agent.release[1].notify_one();
    until("the resumed run never finished", || {
        row(&home, &id).state == DelegationState::Done
    })
    .await;
    assert_eq!(row(&home, &id).result.as_deref(), Some("run2"));
    let _ = chat.await;
    handle.shutdown();
}

/// Past the bound a stopped run is `delegation_stuck`, never run beside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_stuck_past_the_bound_says_so_and_still_blocks_the_resume() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let id = "dlg-stuck".to_string();
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
        release: (0..2).map(|_| Arc::new(Notify::new())).collect(),
    });
    let bound = Duration::from_secs(2);
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            delegations: Some(agent.clone() as Arc<dyn DelegationExecutor>),
            delegation_stuck_after: Some(bound),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let runs = || *agent.runs.lock().unwrap();
    let resume = || {
        common::post(
            handle.addr(),
            &format!("/v1/delegations/{id}/resume"),
            Some(TOKEN),
            "{}",
        )
    };

    assert_eq!(post(&handle, &id, "resume"), 200);
    until("run #1 never started", || runs() == 1).await;
    assert_eq!(post(&handle, &id, "stop"), 200);
    common::assert_error(&resume(), 409, "delegation_still_stopping");

    // Past the bound the run is stuck: a distinct code, still no second run.
    tokio::time::sleep(bound + Duration::from_millis(300)).await;
    common::assert_error(&resume(), 409, "delegation_stuck");
    assert_eq!(runs(), 1, "a second run started beside the stuck one");

    agent.release[0].notify_one();
    until("the resume never became possible", || {
        post(&handle, &id, "resume") == 200
    })
    .await;
    until("run #2 never started", || runs() == 2).await;
    agent.release[1].notify_one();
    handle.shutdown();
}

/// A brain that ignores its cancel until its sender drops, as a hung one.
struct Hung {
    entered: std::sync::atomic::AtomicBool,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

#[async_trait]
impl aux_providers::ChatProvider for Hung {
    async fn complete(
        &self,
        _req: &aux_providers::ChatRequest,
    ) -> Result<aux_providers::ChatResponse, aux_providers::ProviderError> {
        self.entered
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.release.lock().unwrap().recv();
        Ok(aux_providers::ChatResponse::assistant("late"))
    }

    fn name(&self) -> &str {
        "fakey"
    }
}

fn seeded_home(dir: &tempfile::TempDir, id: &str) -> std::path::PathBuf {
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"aux\"\n\n[[providers]]\n\
         id = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let store = Store::open(&kernel_core::store_path(&home)).unwrap();
    let mode = kernel_core::privacy::PrivacyMode::Open;
    store
        .create_delegation(id, "aux", "mail", "sort the inbox", None, mode)
        .unwrap();
    store
        .set_delegation_state(id, DelegationState::Stopped)
        .unwrap();
    home
}

/// A deadline stops a hung turn like an owner Stop: its stuck clock starts
/// then, so once the row is stopped a resume past the bound reads
/// `delegation_stuck` (not "still finishing" forever), and never runs beside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_hung_run_reads_stuck_through_the_resume_route() {
    let dir = tempfile::tempdir().unwrap();
    let id = "dlg-deadline";
    let home = seeded_home(&dir, id);
    let (release, release_rx) = std::sync::mpsc::channel();
    let brain = Arc::new(Hung {
        entered: Default::default(),
        release: Mutex::new(release_rx),
    });
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            provider: Some(brain.clone()),
            delegation_timeout: Some(Duration::from_secs(1)),
            // Shorter than the deadline's 5 s stop grace: the deadline's own
            // stamp is already past it once the row retires.
            delegation_stuck_after: Some(Duration::from_secs(3)),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let resume = || {
        common::post(
            handle.addr(),
            &format!("/v1/delegations/{id}/resume"),
            Some(TOKEN),
            "{}",
        )
    };

    assert_eq!(resume().status, 200);
    until("the turn never reached its brain", || {
        brain.entered.load(std::sync::atomic::Ordering::SeqCst)
    })
    .await;
    // The deadline retires the row (it took a step: failed) while the turn
    // still hangs; the owner then stops it, which keeps the earlier stamp.
    until("the deadline never retired the row", || {
        row(&home, id).state == DelegationState::Failed
    })
    .await;
    assert_eq!(post(&handle, id, "stop"), 200);
    assert_eq!(row(&home, id).state, DelegationState::Stopped);
    common::assert_error(&resume(), 409, "delegation_stuck");

    // Once the hung turn returns, the claim frees and a resume runs.
    drop(release);
    until("the resume never became possible", || {
        resume().status == 200
    })
    .await;
    handle.shutdown();
}

/// `api::spawn` adopts an injected delegating runner's own registry: a run
/// live in it gates the resume route, and its end frees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spawn_adopts_an_injected_delegating_runners_registry() {
    let dir = tempfile::tempdir().unwrap();
    let id = "dlg-adopted";
    let home = seeded_home(&dir, id);
    let agent = Arc::new(Slow {
        runs: Mutex::new(0),
        release: vec![Arc::new(Notify::new())],
    });
    let cancels = Arc::new(auxd::delegation::DelegationCancels::new());
    let runner =
        api::EngineTurnRunner::new(&home).with_delegations(agent.clone(), Arc::clone(&cancels));
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            runner: Some(Arc::new(runner)),
            delegations: Some(agent.clone() as Arc<dyn DelegationExecutor>),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let live = cancels.register(id, aux_engine::TurnCancel::new());
    common::assert_error(
        &common::post(
            handle.addr(),
            &format!("/v1/delegations/{id}/resume"),
            Some(TOKEN),
            "{}",
        ),
        409,
        "delegation_still_stopping",
    );
    drop(live);
    assert_eq!(post(&handle, id, "resume"), 200);
    until("the run never started", || *agent.runs.lock().unwrap() == 1).await;
    agent.release[0].notify_one();
    handle.shutdown();
}
