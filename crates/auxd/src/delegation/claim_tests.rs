use std::sync::mpsc;

use aux_providers::{ChatProvider, ChatRequest, ChatResponse, ProviderError};
use kernel_core::privacy::PrivacyMode;

use super::*;

/// A brain that ignores its cancel, as a hung provider would.
struct Hung {
    entered: Mutex<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[async_trait]
impl ChatProvider for Hung {
    async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let _ = kernel_core::lock_recover(&self.entered).send(());
        let _ = kernel_core::lock_recover(&self.release).recv();
        Ok(ChatResponse::assistant("late"))
    }

    fn name(&self) -> &str {
        "fakey"
    }
}

fn home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"aux\"\n\n[[providers]]\n\
         id = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n",
    )
    .unwrap();
    (dir, home)
}

fn row(home: &std::path::Path, state: DelegationState) -> Delegation {
    let store = Store::open(&kernel_core::store_path(home)).unwrap();
    let row = store
        .create_delegation(
            "dl-hung",
            "aux",
            "mail",
            "sort the inbox",
            None,
            PrivacyMode::Open,
        )
        .unwrap();
    store.set_delegation_state(&row.id, state).unwrap();
    store.delegation(&row.id).unwrap().unwrap()
}

/// The deadline returns `execute` while the blocking turn still runs: the
/// claim (what a resume takes) stays held until that turn returns, then frees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_keeps_the_claim_until_the_hung_turn_returns() {
    let (_dir, home) = home();
    let row = row(&home, DelegationState::Working);
    let cancels = Arc::new(DelegationCancels::new());
    let claim = Arc::new(cancels.claim(&row.id, TurnCancel::new()).unwrap());
    let db = kernel_core::store_path(&home);
    let run = DelegationRun::open(&row, &home, &db, None, claim.token())
        .unwrap()
        .holding(Arc::clone(&claim));
    drop(claim);
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let brain = Arc::new(Hung {
        entered: Mutex::new(entered_tx),
        release: Mutex::new(release_rx),
    });
    let executor = EngineDelegationExecutor::new(home.clone(), Some(brain), None)
        .with_deadline(Duration::from_secs(3));

    let outcome = executor.execute(run).await;
    assert!(
        outcome
            .as_ref()
            .is_err_and(|err| err.contains("did not finish")),
        "{outcome:?}"
    );
    entered
        .try_recv()
        .expect("the turn reached its brain before the deadline");
    // `execute`'s own shares (its run, the aborted drain) are gone by now.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        cancels.claim(&row.id, TurnCancel::new()).is_none(),
        "a resume could run beside the hung turn"
    );

    release.send(()).unwrap();
    let until = Instant::now() + Duration::from_secs(60);
    while cancels.claim(&row.id, TurnCancel::new()).is_none() {
        assert!(Instant::now() < until, "the claim never freed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Only a row that really moved from queued is announced stopped.
#[test]
fn retire_queued_announces_only_a_row_it_moved() {
    let (_dir, home) = home();
    let db = kernel_core::store_path(&home);
    let (events, mut frames) = broadcast::channel(8);
    let queued = row(&home, DelegationState::Queued);
    retire_queued(&db, &events, &queued.id, "mail", "could not start");
    let frame: serde_json::Value = serde_json::from_str(&frames.try_recv().unwrap()).unwrap();
    assert_eq!(frame["type"], "delegation.stopped");
    let store = Store::open(&db).unwrap();
    assert_eq!(
        store.delegation(&queued.id).unwrap().unwrap().state,
        DelegationState::Stopped
    );
    // Already stopped (or live): nothing moves, nothing is announced.
    retire_queued(&db, &events, &queued.id, "mail", "could not start");
    store
        .set_delegation_state(&queued.id, DelegationState::Working)
        .unwrap();
    retire_queued(&db, &events, &queued.id, "mail", "could not start");
    assert!(frames.try_recv().is_err(), "an unmoved row was announced");
    assert_eq!(
        store.delegation(&queued.id).unwrap().unwrap().state,
        DelegationState::Working
    );
}

/// The API adopts a delegating runner's own registry, never a second one.
#[test]
fn a_delegating_runner_hands_over_its_own_registry() {
    let (_dir, home) = home();
    let cancels = Arc::new(DelegationCancels::new());
    let executor = Arc::new(EngineDelegationExecutor::new(home.clone(), None, None));
    let runner = EngineTurnRunner::new(&home).with_delegations(executor, Arc::clone(&cancels));
    let adopted = TurnRunner::delegation_cancels(&runner).expect("a delegating runner");
    assert!(Arc::ptr_eq(&adopted, &cancels));
    assert!(TurnRunner::delegation_cancels(&EngineTurnRunner::new(&home)).is_none());
}
