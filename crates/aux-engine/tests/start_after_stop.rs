//! After the budget stop returned true, starting a session writes nothing: no
//! session row, no system prompt row, no private or taint mark. One test: the
//! stop is for the process.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use aux_engine::{AutoApproveApprover, ChatError, ChatSession, ChatSetup};
use aux_providers::{ChatProvider, FakeProvider};
use aux_store::{Store, StoreHandle};
use kernel_broker::ToolRegistry;
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::PrivacyMode;
use kernel_core::ContextConfig;

const WATCH_WRITES: &str = "CREATE TABLE touched(n);
    CREATE TRIGGER t1 AFTER INSERT ON messages BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t2 AFTER INSERT ON sessions BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t3 AFTER UPDATE ON sessions BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t4 AFTER INSERT ON session_taint BEGIN INSERT INTO touched VALUES (1); END;
    CREATE TRIGGER t5 AFTER INSERT ON session_private_data BEGIN INSERT INTO touched VALUES (1); END;";

#[test]
fn a_session_started_after_the_stop_writes_no_row_and_no_mark() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
    let (before_a, before_b, before_c) = {
        let store = store.lock().unwrap();
        (
            store.create_session("main", None).unwrap().id,
            store.create_session("main", None).unwrap().id,
            store.create_session("main", None).unwrap().id,
        )
    };
    let raw = aux_store::open_keyed(&path).unwrap();
    raw.execute_batch(WATCH_WRITES).unwrap();
    let touched = || -> i64 {
        raw.query_row("SELECT COUNT(*) FROM touched", [], |row| row.get(0))
            .unwrap()
    };
    let provider = FakeProvider::echo("fake");
    let registry = Arc::new(RwLock::new(ToolRegistry::with_defaults()));
    let budgets = Budgets::default();
    let prices = PriceTable::default();
    let start = |mode: PrivacyMode, session_id: i64| {
        ChatSession::start(ChatSetup {
            mode: Arc::new(move || mode),
            contacts: aux_runtime::known_names::owner_contacts(),
            store: StoreHandle::Shared(Arc::clone(&store)),
            provider: &provider as &dyn ChatProvider,
            registry: Arc::clone(&registry),
            rules: Vec::new(),
            approver: Arc::new(AutoApproveApprover),
            agent: "main".to_string(),
            home: dir.path().join("home"),
            skills: Vec::new(),
            budgets: &budgets,
            prices: &prices,
            context: ContextConfig::default(),
            title: None,
            stop: None,
            cancel: None,
            session_id: Some(session_id),
            events: None,
            run_id: None,
        })
    };

    // Before the stop an open start stores its system prompt row.
    assert!(start(PrivacyMode::Open, before_a).is_ok());
    let before = touched();
    assert!(before > 0, "the start writes before the stop");

    assert!(aux_engine::stop_settle_worker(Duration::from_secs(10)));

    for (mode, id) in [
        (PrivacyMode::Open, before_b),
        (PrivacyMode::Private, before_c),
    ] {
        let refused = start(mode, id);
        assert!(
            matches!(refused, Err(ChatError::BudgetDenied { .. })),
            "a start after the stop is refused"
        );
    }
    assert_eq!(
        touched(),
        before,
        "no row or mark was written after the stop"
    );
}
