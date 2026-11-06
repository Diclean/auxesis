//! After the budget stop returned true, the shell judge's admission refuses
//! before it touches the store. One test: the stop is for the process. The
//! store's lock is held meanwhile, so a judge reaching it (even to read, which
//! leaves no row) waits and misses its deadline.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aux_engine::judge::{JudgeBudget, OwnerMessages, ShellJudge, Verdict};
use aux_providers::{ChatProvider, FakeProvider};
use aux_store::Store;
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::{ModeFn, PrivacyMode};
use kernel_privacy::NameDictionary;

const WATCH_WRITES: &str = "CREATE TABLE touched(n);
    CREATE TRIGGER t1 AFTER INSERT ON usage_reservations BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t2 AFTER INSERT ON usage_calls BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t3 AFTER INSERT ON events BEGIN INSERT INTO touched VALUES (1); END;";

#[tokio::test]
async fn the_judge_after_the_stop_touches_no_store_and_calls_no_provider() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute_batch(WATCH_WRITES).unwrap();
    let touched = || -> i64 {
        raw.query_row("SELECT COUNT(*) FROM touched", [], |row| row.get(0))
            .unwrap()
    };
    let provider = Arc::new(FakeProvider::echo("fake"));
    let mode: ModeFn = Arc::new(|| PrivacyMode::Open);
    let owner: OwnerMessages = Arc::new(|| vec!["list my files".to_string()]);
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).unwrap());
    let budget = JudgeBudget {
        store: Arc::clone(&store),
        agent: "main".to_string(),
        run_id: None,
        budgets: Budgets::default(),
        prices: PriceTable::default(),
    };
    let judge = ShellJudge::new(
        Arc::clone(&provider) as Arc<dyn ChatProvider>,
        mode,
        1,
        names,
        owner,
        dir.path().to_path_buf(),
        budget,
    );

    judge.judge("ls").await; // before the stop it hits the store
    let before = touched();
    assert!(before > 0 && provider.request_count() == 1);

    assert!(aux_engine::stop_settle_worker(Duration::from_secs(10)));

    let held = store.lock().unwrap();
    let (verdict, answer) = std::sync::mpsc::channel();
    let asked = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        verdict.send(runtime.block_on(judge.judge("ls"))).unwrap();
    });
    let verdict = answer.recv_timeout(Duration::from_secs(10));
    drop(held);
    asked.join().unwrap();
    assert_eq!(
        verdict,
        Ok(Verdict::Failed("budget")),
        "refused with no store access"
    );
    assert_eq!(
        provider.request_count(),
        1,
        "no provider call after the stop"
    );
    assert_eq!(touched(), before, "no row after the stop");
}
