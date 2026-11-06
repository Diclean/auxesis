//! After the budget stop returned true, an ACP turn stores no user row and no
//! receipt row: it gets the budget refusal before it writes anything. One test:
//! the stop is for the process. The agent is `/usr/bin/true`, which dies at the
//! handshake, so a turn before the stop leaves its rows (the control).
#![cfg(feature = "acp")]

use std::time::Duration;

use aux_store::Store;
use auxd::api::{EngineTurnRunner, TurnError, TurnRunner};

const WATCH_WRITES: &str = "CREATE TABLE touched(n);
    CREATE TRIGGER t1 AFTER INSERT ON messages BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t2 AFTER INSERT ON events BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t3 AFTER INSERT ON usage BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t4 AFTER INSERT ON usage_reservations BEGIN INSERT INTO touched VALUES (1); END;";

#[test]
fn an_acp_turn_after_the_stop_stores_no_user_row_and_no_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n\n\
         [budgets.default]\nusd_cents = 5000\n\n\
         [acp]\nenabled = true\n\n\
         [acp.agents.crasher]\ncommand = \"/usr/bin/true\"\nprovider_id = \"acp-test\"\n\n\
         [[providers]]\nid = \"acp-test\"\nkind = \"acp\"\n",
    )
    .unwrap();
    let path = kernel_core::store_path(&home);
    let thread = Store::open(&path)
        .unwrap()
        .create_session("main", Some("after the stop"))
        .unwrap();
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute_batch(WATCH_WRITES).unwrap();
    let touched = || -> i64 {
        raw.query_row("SELECT COUNT(*) FROM touched", [], |row| row.get(0))
            .unwrap()
    };
    let runner = EngineTurnRunner::new(&home);

    // Before the stop the failed turn leaves its user row and its receipt.
    assert!(runner
        .run_turn("main", Some(thread.id), "first", None)
        .is_err());
    let before = touched();
    assert!(before >= 2, "the control turn writes rows: {before}");

    assert!(aux_engine::stop_settle_worker(Duration::from_secs(10)));

    let result = runner.run_turn("main", Some(thread.id), "after the stop", None);
    assert!(
        matches!(result, Err(TurnError::BudgetDenied { .. })),
        "the budget refusal, not a provider error: {result:?}"
    );
    assert_eq!(touched(), before, "no row was written after the stop");
}
