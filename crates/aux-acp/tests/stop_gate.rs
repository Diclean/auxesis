//! After the budget stop returned true, an ACP turn runs no SQL: it is
//! abandoned by the runtime's grace, not killed, and may resume while the
//! process exits. This file holds one test, since the stop is for the process.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aux_acp::ledger::{StoreTurnHost, TurnHost};
use aux_acp::protocol::UsageUpdate;
use aux_store::Store;
use kernel_core::budget::Budgets;

/// Count every row written to a usage table, the event table included.
const WATCH_WRITES: &str = "CREATE TABLE touched(n);
    CREATE TRIGGER t1 AFTER INSERT ON usage BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t2 AFTER INSERT ON events BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t3 AFTER INSERT ON usage_reservations BEGIN INSERT INTO touched VALUES (1); END;";

fn host(path: &std::path::Path, budgets: Budgets) -> StoreTurnHost {
    let store = Arc::new(Mutex::new(Store::open(path).unwrap()));
    let session = store.lock().unwrap().create_session("main", None).unwrap();
    StoreTurnHost::new(store, "main".to_string(), session.id, budgets, None)
        .with_run_id("turn-after-stop")
}

#[test]
fn an_acp_turn_after_the_stop_reserves_nothing_and_writes_no_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let mut capped = Budgets::default();
    capped.default.usd_cents = Some(50);
    let mut unlimited = Budgets::default();
    unlimited.default.unlimited = true;
    let mut capped = host(&path, capped);
    let mut unlimited = host(&path, unlimited);
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute_batch(WATCH_WRITES).unwrap();
    let touched = || -> i64 {
        raw.query_row("SELECT COUNT(*) FROM touched", [], |row| row.get(0))
            .unwrap()
    };
    // Admitted before the stop: this turn's reservation is held.
    let held = capped.reserve_turn(10).unwrap();
    assert!(held.is_some());
    let before = touched();
    assert_eq!(before, 1, "the reservation");

    assert!(aux_engine::stop_settle_worker(Duration::from_secs(10)));

    // Fail closed: no reservation, so no model call, and no audit row.
    let refused = capped.reserve_turn(10);
    assert!(refused.is_err(), "no reservation after the stop");
    // The unlimited turn's direct usage write is refused, and the
    // `usage.settle_failed` marker it would leave is dropped.
    assert!(unlimited.reserve_turn(10).unwrap().is_none());
    let settled = unlimited.settle_turn(None, &UsageUpdate::default());
    assert!(settled.is_err(), "refused, not lost silently");
    assert_eq!(touched(), before, "no SQL write ran after the stop");
}
