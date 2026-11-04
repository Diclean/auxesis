//! Each step says where it ran, from the child turn's provider
//! contact record, never from the tool name or the brain config.

use super::*;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, FakeProvider, FallbackAdmission,
    FallbackProvider, NoopAdmission, NoopLedger, ProviderError, ToolCall,
};
use kernel_core::privacy::{Grant, PathId, PrivacyMode};

const CLOUD: &str = "api.cloud.test";
const LOCAL: &str = "127.0.0.1";

/// Which calls fail (by index) and with what.
type Failure = (fn(usize) -> bool, fn() -> ProviderError);

/// A brain at `host` (known to run on this Mac when `local`) that answers
/// its script; it fails the calls `fail` picks, and on `stop` cancels the
/// delegation after the request reached it and never answers.
struct Brain {
    host: &'static str,
    local: bool,
    script: FakeProvider,
    fail: Option<Failure>,
    stop: Option<Arc<TurnCancel>>,
    calls: std::sync::atomic::AtomicUsize,
}

fn brain(host: &'static str, local: bool, script: Vec<ChatResponse>) -> Brain {
    let (script, calls) = (FakeProvider::scripted("b", script), Default::default());
    Brain {
        host,
        local,
        script,
        fail: None,
        stop: None,
        calls,
    }
}

fn answers(host: &'static str, script: Vec<ChatResponse>) -> Brain {
    brain(host, false, script)
}

fn fails(host: &'static str, fail: fn() -> ProviderError) -> Brain {
    Brain {
        fail: Some((|_| true, fail)),
        ..brain(host, false, Vec::new())
    }
}

#[async_trait]
impl ChatProvider for Brain {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(stop) = &self.stop {
            stop.cancel();
            std::future::pending::<()>().await;
        }
        match self.fail {
            Some((fails, fail)) if fails(call) => Err(fail()),
            _ => self.script.complete(req).await,
        }
    }

    fn name(&self) -> &str {
        self.host
    }

    fn endpoint_host(&self) -> Option<String> {
        Some(self.host.to_string())
    }

    fn on_this_mac(&self) -> bool {
        self.local
    }
}

fn chain(brains: Vec<Brain>) -> FallbackProvider {
    let boxed = brains
        .into_iter()
        .map(|b| Box::new(b) as Box<dyn ChatProvider>);
    FallbackProvider::new(boxed.collect())
}

fn tool_then_done() -> Vec<ChatResponse> {
    let call = ToolCall::new("c1", "read_file", serde_json::json!({ "path": "a" }));
    vec![
        ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![call])),
        ChatResponse::assistant("Done."),
    ]
}

fn timeout() -> ProviderError {
    ProviderError::Timeout {
        provider: "l".into(),
    }
}

/// Refuses every fallback hop, as the kernel refuses a disabled path.
struct RefuseHops;

impl FallbackAdmission for RefuseHops {
    fn admit(&self, provider: &str, _: PathId) -> Result<Option<Grant>, ProviderError> {
        Err(ProviderError::PrivacyDisabled {
            provider: provider.into(),
            path: "A1",
        })
    }
}

async fn steps_for(provider: impl ChatProvider + 'static) -> Vec<serde_json::Value> {
    steps_in(provider, "newest mail", TurnCancel::new()).await
}

async fn steps_in(
    provider: impl ChatProvider + 'static,
    task: &str,
    cancel: Arc<TurnCancel>,
) -> Vec<serde_json::Value> {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    // SANDBOX-GATEWAY-EXEMPT: cfg(test)-only fake-home fixture.
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"aux\"\n\n[[providers]]\n\
         id = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n",
    )
    .unwrap();
    let db = kernel_core::store_path(&home);
    let (id, mode) = (new_id(), PrivacyMode::Open);
    let store = Store::open(&db).unwrap();
    let row = store.create_delegation(&id, "aux", "mail", task, None, mode);
    let run = DelegationRun::open(&row.unwrap(), &home, &db, None, cancel).unwrap();
    let executor = EngineDelegationExecutor::new(home.clone(), Some(Arc::new(provider)), None);
    let _ = executor.execute(run).await;
    let stored = store.delegation(&id).unwrap().unwrap();
    delegation_json(&home, &stored)["steps"]
        .as_array()
        .unwrap()
        .clone()
}

fn place<'a>(steps: &'a [serde_json::Value], text: &str) -> Vec<&'a str> {
    let rows = steps
        .iter()
        .filter(|s| s["text"].as_str().unwrap().starts_with(text));
    rows.map(|s| s["where"].as_str().unwrap()).collect()
}

fn reply() -> Vec<ChatResponse> {
    vec![ChatResponse::assistant("One new mail.")]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_round_is_local_only_on_a_brain_known_to_run_on_this_mac() {
    // Without a contact log only an off-Mac answer is provable; a loopback
    // brain that may forward (Ollama `*-cloud`) is never `local`.
    let cases = [
        (chain(vec![brain(LOCAL, true, reply())]), "local"),
        (chain(vec![brain(LOCAL, false, reply())]), "unknown"),
    ];
    for (provider, want) in cases {
        let steps = steps_for(provider).await;
        assert_eq!(place(&steps, "asking its brain"), [want], "{steps:?}");
        assert_eq!(place(&steps, "wrote its answer"), [want], "{steps:?}");
    }
    for (host, want) in [(CLOUD, "out"), (LOCAL, "unknown")] {
        let steps = steps_for(answers(host, reply())).await;
        assert_eq!(place(&steps, "asking its brain"), [want], "{steps:?}");
    }
}

/// One round tries the local brain, then hops to the cloud: an admitted
/// hop is `out`; a refused hop sent nothing, so the round stayed `local`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_then_cloud_round_is_out_and_a_refused_hop_is_never_out() {
    let hops: [(Arc<dyn FallbackAdmission>, &str); 2] = [
        (Arc::new(NoopAdmission), "out"),
        (Arc::new(RefuseHops), "local"),
    ];
    for (admission, want) in hops {
        let local = Brain {
            fail: Some((|_| true, timeout)),
            ..brain(LOCAL, true, Vec::new())
        };
        let brains: Vec<Box<dyn ChatProvider>> =
            vec![Box::new(local), Box::new(answers(CLOUD, reply()))];
        let chain = FallbackProvider::with_admission(brains, Arc::new(NoopLedger), admission);
        let steps = steps_for(chain).await;
        assert_eq!(place(&steps, "asking its brain"), [want], "{steps:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_refused_before_any_contact_is_unknown() {
    // A static host is configuration, not a contact: nothing proves a place.
    let refused = || RefuseHops.admit("c", PathId::A1).unwrap_err();
    let steps = steps_for(fails(CLOUD, refused)).await;
    assert_eq!(place(&steps, "asking its brain"), ["unknown"], "{steps:?}");
    assert!(steps.iter().all(|s| s["where"] != "out"), "{steps:?}");
}

/// The cloud gets every round's request before it times out, so
/// every round is `out` although the local brain answers; tool steps stay
/// unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_round_that_reached_the_cloud_is_out_even_when_local_answers() {
    let steps = steps_for(chain(vec![
        fails(CLOUD, timeout),
        brain(LOCAL, true, tool_then_done()),
    ]))
    .await;
    assert_eq!(place(&steps, "asking its brain"), ["out"], "{steps:?}");
    assert_eq!(place(&steps, "asked its brain again"), ["out"], "{steps:?}");
    assert_eq!(place(&steps, "wrote its answer"), ["out"], "{steps:?}");
    let tools = [place(&steps, "running "), place(&steps, "finished ")].concat();
    assert!(tools.iter().all(|w| *w == "unknown"), "{steps:?}");
}

/// Round 1 is served by the cloud; round 2 tries the cloud, which times
/// out, then the local brain answers: round 2 is still `out`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_round_that_falls_back_from_cloud_to_local_is_out() {
    let cloud = Brain {
        fail: Some((|n| n >= 1, timeout)),
        ..answers(CLOUD, tool_then_done())
    };
    let local = brain(LOCAL, true, vec![ChatResponse::assistant("Done.")]);
    let steps = steps_for(chain(vec![cloud, local])).await;
    assert_eq!(place(&steps, "asking its brain"), ["out"], "{steps:?}");
    assert_eq!(place(&steps, "asked its brain again"), ["out"], "{steps:?}");
    assert_eq!(place(&steps, "wrote its answer"), ["out"], "{steps:?}");
}

/// The save guard drops the cloud's reply without a message and
/// asks again; the re-asked round keeps the first mark, so the cloud
/// attempt still counts and both steps are `out`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_round_a_guard_re_asks_keeps_its_cloud_attempt() {
    let local = Brain {
        fail: Some((|n| n == 0, timeout)),
        ..brain(LOCAL, true, vec![ChatResponse::assistant("Noted.")])
    };
    let cloud = answers(CLOUD, vec![ChatResponse::assistant("Saved.")]);
    let task = "remember that the fictional meeting moved to Friday";
    let steps = steps_in(chain(vec![local, cloud]), task, TurnCancel::new()).await;
    assert_eq!(place(&steps, "asking its brain"), ["out"], "{steps:?}");
    assert!(
        place(&steps, "wrote its answer")
            .iter()
            .all(|w| *w == "out"),
        "{steps:?}"
    );
    assert!(steps.iter().all(|s| s["where"] != "local"), "{steps:?}");
}

/// Stop lands while the cloud holds the request; the dropped hop
/// was logged before it was sent, so the step is never `local`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hop_stopped_in_flight_is_on_record() {
    let cancel = TurnCancel::new();
    let local = Brain {
        fail: Some((|_| true, timeout)),
        ..brain(LOCAL, true, Vec::new())
    };
    let cloud = Brain {
        stop: Some(Arc::clone(&cancel)),
        ..answers(CLOUD, Vec::new())
    };
    let steps = steps_in(chain(vec![local, cloud]), "newest mail", cancel).await;
    assert_eq!(place(&steps, "asking its brain"), ["out"], "{steps:?}");
}

#[test]
fn a_step_without_a_recorded_place_reads_unknown() {
    for (stored, shown) in [
        (None, "unknown"),
        (Some("elsewhere"), "unknown"),
        (Some("out"), "out"),
    ] {
        let step = DelegationStep {
            text: "read".into(),
            at: "now".into(),
            state: "done".into(),
            where_ran: stored.map(str::to_string),
        };
        assert_eq!(where_label(&step), shown);
    }
}

#[test]
fn contacts_classify_out_local_or_unknown() {
    use crate::api::turn_events::step_where;
    let at = |host: &str, on_this_mac: bool| aux_providers::Contact {
        host: Some(host.into()),
        on_this_mac,
    };
    let unknown_host = aux_providers::Contact {
        host: None,
        on_this_mac: true,
    };
    assert_eq!(step_where(&[]), "unknown");
    assert_eq!(
        step_where(&[at("localhost", true), at("[::1]", true)]),
        "local"
    );
    assert_eq!(step_where(&[at(LOCAL, false)]), "unknown");
    assert_eq!(
        step_where(&[at(LOCAL, true), unknown_host.clone()]),
        "unknown"
    );
    assert_eq!(step_where(&[at(LOCAL, true), at(CLOUD, false)]), "out");
    assert_eq!(step_where(&[at("127.0.0.1.example.com", true)]), "out");
    assert_eq!(
        step_where(&[unknown_host, at("localhost.test", true)]),
        "out"
    );
}
