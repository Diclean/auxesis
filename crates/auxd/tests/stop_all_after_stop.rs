//! `POST /v1/stop-all` after the budget stop runs no SQL (BUDGET-SETTLE-8):
//! the kill switch still engages, but no open delegation row is rewritten and
//! no `daemon.stop_all` audit row is written. One test, its own binary: the
//! stop is for the process.

mod common;

use std::time::Duration;

use aux_store::{DelegationState, Store};
use auxd::api::{self, ApiOptions};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_all_after_the_stop_writes_no_row() {
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
    let store = Store::open(&path).unwrap();
    store
        .create_delegation(
            "dlg-live",
            "main",
            "mail",
            "sort the inbox",
            None,
            kernel_core::privacy::PrivacyMode::Open,
        )
        .unwrap();
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..ApiOptions::default()
        },
    )
    .unwrap();
    store
        .set_delegation_state("dlg-live", DelegationState::Working)
        .unwrap();
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute_batch(
        "CREATE TABLE touched(what);
         CREATE TRIGGER d AFTER UPDATE ON delegations BEGIN INSERT INTO touched VALUES ('delegation'); END;
         CREATE TRIGGER e AFTER INSERT ON events WHEN NEW.kind = 'daemon.stop_all'
           BEGIN INSERT INTO touched VALUES ('audit'); END;",
    )
    .unwrap();

    assert!(aux_engine::stop_settle_worker(Duration::from_secs(10)));
    let stopped = common::post(handle.addr(), "/v1/stop-all", Some(TOKEN), "{}");
    assert_eq!(stopped.status, 200, "body: {}", stopped.body);
    assert!(
        kernel_core::killswitch::is_stopped(&home),
        "the switch engaged"
    );
    let touched: i64 = raw
        .query_row("SELECT COUNT(*) FROM touched", [], |row| row.get(0))
        .unwrap();
    assert_eq!(touched, 0, "no delegation or audit row after the stop");
    assert_eq!(
        store.delegation("dlg-live").unwrap().unwrap().state,
        DelegationState::Working
    );
    handle.shutdown();
}
