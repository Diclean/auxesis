use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_providers::{ChatProvider, ChatResponse, FakeProvider, ProviderError, ToolCall};
use aux_store::{DelegationState, Store};
use auxd::api::{ApprovalRegistry, EngineTurnRunner, ToolRegistryHook, TurnRunner};
use auxd::delegation::{DelegationCancels, EngineDelegationExecutor};
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::store_path;
use serde_json::{json, Value};
use tokio::sync::broadcast;

const OWNER: &str = "tell camille i'm late and push the meeting 30 min";
const CONFIG: &str = "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"aux\"\n\n\
[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n";

struct CardTool {
    name: &'static str,
    home: std::path::PathBuf,
}

#[rustfmt::skip]
#[async_trait]
impl Tool for CardTool {
    fn name(&self) -> &str { self.name }
    fn schema(&self) -> Value { json!({ "type": "object" }) }
    async fn run(&self, _: &Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
        use std::io::Write;
        let mut log = std::fs::OpenOptions::new().create(true).append(true)
            .open(self.home.join("card-runs.log")).map_err(ToolError::Io)?;
        let _ = writeln!(log, "{}", self.name);
        Ok(ToolOutput::ok("ran"))
    }
    fn risk(&self) -> Risk { Risk::Medium }
    fn path_id(&self) -> kernel_core::privacy::PathId { kernel_core::privacy::PathId::B1 }
    fn class(&self) -> ToolClass { ToolClass::default() }
}

fn home() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(kernel_core::config_path(&home), CONFIG).unwrap();
    (dir, home)
}

fn call(name: &str, args: Value) -> ChatResponse {
    ChatResponse::new(aux_providers::ChatMessage::assistant_with_tool_calls(
        "",
        vec![ToolCall::new("call-1", name, args)],
    ))
}
fn delegate(agent: &str, task: &str) -> ChatResponse {
    call("delegate", json!({"agent": agent, "task": task}))
}
fn say(text: &str) -> ChatResponse {
    ChatResponse::assistant(text)
}

fn cards(home: &Path) -> Vec<String> {
    let conn = aux_store::open_keyed_readonly(&store_path(home)).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT payload FROM events \
        WHERE kind = 'approval.pending' ORDER BY id",
        )
        .unwrap();
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
    rows.map(|raw| {
        serde_json::from_str::<Value>(&raw.unwrap()).unwrap()["tool"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    })
    .collect()
}

fn answer(record: &auxd::api::TurnRecord) -> String {
    record
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "assistant" && !m.content.is_empty())
        .map(|m| m.content.clone())
        .unwrap_or_default()
}

fn runner_with(
    home: &Path,
    provider: Arc<dyn ChatProvider>,
    deadline: Duration,
    approvals: Arc<ApprovalRegistry>,
) -> EngineTurnRunner {
    let (events, _rx) = broadcast::channel(256);
    let bridge = Arc::new(auxd::bridge::Bridge::new(
        home.to_path_buf(),
        events.clone(),
    ));
    let card_home = home.to_path_buf();
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register(Box::new(CardTool {
            name: "calendar_update_event",
            home: card_home.clone(),
        }));
        registry.register(Box::new(CardTool {
            name: "mail_send",
            home: card_home.clone(),
        }));
    });
    let executor = EngineDelegationExecutor::new(
        home.to_path_buf(),
        Some(Arc::clone(&provider)),
        Some(Arc::clone(&approvals)),
    )
    .with_bridge(Arc::clone(&bridge))
    .with_deadline(deadline)
    .with_tools(Arc::clone(&tools));
    EngineTurnRunner::new(home)
        .with_provider(provider)
        .with_approvals(approvals)
        .with_events(events)
        .with_bridge(bridge)
        .with_delegations(Arc::new(executor), Arc::new(DelegationCancels::new()))
        .with_tools(tools)
}

fn runner(home: &Path, provider: Arc<dyn ChatProvider>, deadline: Duration) -> EngineTurnRunner {
    runner_with(
        home,
        provider,
        deadline,
        ApprovalRegistry::new(Duration::from_secs(1)),
    )
}

/// Waits for the first approval card to reach the registry, polling the actual
/// condition instead of a fixed tick count. The old 300 x 10 ms loop gave up
/// after ~3 s: under a parallel test run the delegated turn can take longer
/// than that to publish its card, and the answerer then exited without ever
/// resolving it. The deadline only bounds a turn that is truly stuck.
fn wait_for_card(approvals: &ApprovalRegistry, deadline: Duration) -> auxd::api::PendingApproval {
    let started = Instant::now();
    loop {
        if let Some(card) = approvals.list_pending().first().cloned() {
            return card;
        }
        assert!(
            started.elapsed() < deadline,
            "no approval card appeared within {deadline:?}: the delegated turn never asked"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs one step on its own thread and fails the test when it overruns its
/// budget: a regressed chief loop must not hold the CI job until the job
/// limit, and the panic names the step that stalled.
fn within<T: Send + 'static>(
    step: &str,
    budget: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    match rx.recv_timeout(budget) {
        Ok(value) => value,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("{step} did not finish within {budget:?}: the loop looks stuck")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{step} panicked on its worker thread: see the panic above")
        }
    }
}

type Ran = (
    auxd::api::TurnRecord,
    Vec<aux_providers::ChatRequest>,
    Vec<String>,
);

fn run(home: &Path, script: Vec<ChatResponse>) -> Ran {
    let provider = Arc::new(FakeProvider::scripted("fake", script));
    let shared: Arc<dyn ChatProvider> = provider.clone();
    let record = runner(home, shared, Duration::from_secs(5))
        .run_turn("aux", None, OWNER, None)
        .unwrap();
    (record, provider.requests(), cards(home))
}

#[test]
fn one_meeting_with_camille_raises_the_move_and_the_mail_cards() {
    let (_dir, home) = home();
    let script = vec![
        delegate("calendar", "push the meeting with Camille 30 min"),
        call("calendar_update_event", json!({})),
        say("The move card is waiting."),
        delegate("mail", "tell Camille I'm late"),
        call("mail_send", json!({})),
        say("The mail card is waiting."),
        say("The move and the message are waiting for your OK."),
    ];
    let (record, _, cards) = run(&home, script);
    assert_eq!(cards, ["calendar_update_event", "mail_send"], "two cards");
    let told = answer(&record);
    assert!(!told.contains('?'), "{told}");
}

#[test]
fn two_meetings_with_camille_ask_once_and_raise_no_card() {
    let (_dir, home) = home();
    let script = vec![
        delegate("calendar", "push the meeting with Camille 30 min"),
        say("I found two meetings with Camille."),
        say("Which one — the 09:30 call or the design review at 14:00?"),
    ];
    let (record, _, cards) = run(&home, script);
    assert!(cards.is_empty(), "{cards:?}");
    let told = answer(&record);
    assert_eq!(told.matches('?').count(), 1, "{told}");
}

#[test]
fn a_card_waiting_for_the_owner_pauses_the_deadline_and_executes_once() {
    let (_dir, home) = home();
    let approvals = ApprovalRegistry::new(Duration::from_secs(30));
    let provider = Arc::new(FakeProvider::scripted(
        "fake",
        vec![
            delegate("calendar", "push the meeting with Camille 30 min"),
            call("calendar_update_event", json!({})),
            say("The move card was answered."),
            say("Done."),
        ],
    ));
    let answerer = {
        let approvals = Arc::clone(&approvals);
        std::thread::spawn(move || {
            let card = wait_for_card(&approvals, Duration::from_secs(30));
            std::thread::sleep(Duration::from_secs(2));
            let _ = approvals.resolve(&card.id, auxd::api::Resolution::allow_once());
        })
    };
    let started = Instant::now();
    let record = runner_with(&home, provider, Duration::from_secs(1), approvals)
        .run_turn("aux", None, OWNER, None)
        .unwrap();
    answerer.join().unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(2),
        "the card was not waited for: {elapsed:?}"
    );
    let told = answer(&record);
    assert!(told.contains("Done"), "{told}");
    let rows = Store::open(&store_path(&home))
        .unwrap()
        .list_delegations(None)
        .unwrap();
    assert_eq!(rows[0].state, DelegationState::Done);
    let runs = std::fs::read_to_string(home.join("card-runs.log")).unwrap_or_default();
    assert_eq!(runs.matches("calendar_update_event").count(), 1, "{runs}");
}

#[derive(Default)]
struct HangSecond(AtomicUsize);

#[async_trait]
impl ChatProvider for HangSecond {
    async fn complete(
        &self,
        _: &aux_providers::ChatRequest,
    ) -> Result<ChatResponse, ProviderError> {
        match self.0.fetch_add(1, Ordering::SeqCst) {
            0 => Ok(delegate("calendar", "push the meeting with Camille 30 min")),
            1 => std::future::pending::<Result<ChatResponse, ProviderError>>().await,
            _ => Ok(say(
                "The calendar move is still pending; nothing was sent or moved.",
            )),
        }
    }
    fn name(&self) -> &str {
        "hang"
    }
}

#[test]
fn a_delegated_turn_that_never_finishes_is_cut_and_nothing_runs() {
    let (_dir, home) = home();
    let started = Instant::now();
    let record = runner(
        &home,
        Arc::new(HangSecond::default()),
        Duration::from_secs(1),
    )
    .run_turn("aux", None, OWNER, None)
    .unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(6), "{elapsed:?}");
    let told = answer(&record);
    assert!(told.contains("still pending"), "{told}");
    assert!(cards(&home).is_empty());
    let rows = Store::open(&store_path(&home))
        .unwrap()
        .list_delegations(None)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, DelegationState::Failed);
    assert!(rows[0].result.is_none());
}

#[test] // WAITING-ROW-DELEGATE: the delegated card reaches the chief's channel whole.
fn a_delegated_cards_frame_reaches_the_chiefs_channel() {
    let (_dir, home) = home();
    let approvals = ApprovalRegistry::new(Duration::from_secs(1));
    let provider: Arc<dyn ChatProvider> = Arc::new(FakeProvider::scripted(
        "fake",
        vec![
            delegate("calendar", "push the meeting with Camille 30 min"),
            call("calendar_update_event", json!({})),
            say("done"),
            // The chief's last round: the turn now runs to its end, so the
            // script must have an answer for it (it used to die here).
            say("The move card is waiting for your OK."),
        ],
    ));
    let (events, mut rx) = broadcast::channel(256);
    let bridge = Arc::new(auxd::bridge::Bridge::new(home.clone(), events.clone()));
    let card_home = home.clone();
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register(Box::new(CardTool {
            name: "calendar_update_event",
            home: card_home.clone(),
        }));
    });
    let executor = EngineDelegationExecutor::new(
        home.clone(),
        Some(Arc::clone(&provider)),
        Some(Arc::clone(&approvals)),
    )
    .with_bridge(Arc::clone(&bridge))
    .with_deadline(Duration::from_secs(5))
    .with_tools(Arc::clone(&tools));
    let runner = EngineTurnRunner::new(&home)
        .with_provider(provider)
        .with_approvals(approvals)
        .with_events(events)
        .with_bridge(bridge)
        .with_delegations(Arc::new(executor), Arc::new(DelegationCancels::new()))
        .with_tools(tools);
    // The frame is published while the turn runs, so watch the channel from a
    // side thread and run the turn here, like the rest of this file: it must be
    // over before the test returns and drops the temp home. The old shape left
    // a detached worker writing its store after the home was gone (SIGSEGV in
    // SQLCipher, CI run 41323206909).
    let watcher = std::thread::spawn(move || -> Result<String, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match rx.try_recv() {
                Ok(text) if text.contains("\"type\":\"approval.new\"") => return Ok(text),
                Ok(_) => {}
                Err(broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                // A lag skips the count, not the channel: keep reading.
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(broadcast::error::TryRecvError::Closed) => {
                    return Err("channel closed before the frame arrived".to_string());
                }
            }
        }
        Err("no approval.new reached the chief's channel within 10s".to_string())
    });
    let record = within("the chief's run_turn", Duration::from_secs(60), move || {
        runner.run_turn("aux", None, OWNER, None)
    })
    .expect("the chief's turn must run to the end: the temp home outlives it");
    let frame = watcher
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        .unwrap_or_else(|err| panic!("{err}"));
    let parsed: Value = serde_json::from_str(&frame).expect("the approval frame is whole JSON");
    assert_eq!(parsed["type"], "approval.new");
    let told = answer(&record);
    assert!(told.contains("waiting"), "{told}");
    // The delegated turn finished and wrote its row while the store was still
    // there: exactly the property the crash broke (a turn still writing to a
    // store the test had already deleted).
    let rows = Store::open(&store_path(&home))
        .unwrap()
        .list_delegations(None)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, DelegationState::Done);
}
