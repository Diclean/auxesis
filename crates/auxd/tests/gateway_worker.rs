//! The router worker: the local-display fallback when no remote is paired,
//! the bounded low-priority lane, and the hard-bounded urgent lane.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_notify::{FakeNotifier, Notification, Notifier};
use auxd::gateway::local::LocalGateway;
use auxd::gateway::policy::{Level, NotifyPolicy, PolicyConfig};
use auxd::gateway::router::{
    run_worker, GatewaySink, NotifyRouter, Pending, Sink, SystemClock, OUTBOUND_QUEUE_CAPACITY,
    OUTBOUND_URGENT_CAPACITY,
};
use auxd::gateway::{
    ApprovalCard, Capabilities, ChatId, Gateway, GatewayError, InboundText, OutboundText, OwnerId,
};
use kernel_core::privacy::{ModeFn, PathId, PrivacyMode};
use tokio::sync::Notify;

fn open_mode() -> ModeFn {
    Arc::new(|| PrivacyMode::Open)
}

fn no_quiet() -> PolicyConfig {
    PolicyConfig {
        window_secs: 0,
        quiet_start_hour: 0,
        quiet_end_hour: 0,
        daily_cap: 20,
    }
}

#[tokio::test]
async fn an_unpaired_remote_falls_back_to_the_local_sink() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(FakeNotifier::new());
    let local: Arc<dyn Gateway> = Arc::new(LocalGateway::new(fake.clone()));
    // No owner and no chat: never paired, so the worker must use local.
    let remote: Arc<dyn Gateway> = Arc::new(NoopGateway);
    let (sink, rx) = GatewaySink::channel();
    let router = Arc::new(NotifyRouter::new(
        Arc::new(sink),
        NotifyPolicy::new(no_quiet()),
        kernel_core::SandboxHome::open(dir.path()).unwrap(),
        Arc::new(SystemClock),
    ));
    let worker = tokio::spawn(run_worker(vec![remote], local, open_mode(), rx));

    router.brief("Bonjour Camille");
    drop(router);
    worker.await.unwrap();

    assert_eq!(fake.count(), 1);
    assert_eq!(fake.last().unwrap().body, "Bonjour Camille");
}

#[tokio::test]
async fn queued_text_payloads_are_bounded_in_bytes() {
    let (sink, rx) = GatewaySink::channel();
    sink.try_enqueue(Pending::Alert {
        level: Level::Urgent,
        text: "é".repeat(OUTBOUND_QUEUE_CAPACITY * 1024),
    })
    .unwrap();

    match rx.recv().await.unwrap() {
        Pending::Alert { text, .. } => {
            assert!(text.len() <= auxd::gateway::router::MAX_PENDING_TEXT_BYTES);
            assert!(text.is_char_boundary(text.len()));
        }
        other => panic!("unexpected pending item: {other:?}"),
    }
}

/// A remote that is paired and stalls until released.
struct StalledGateway {
    stall: AtomicBool,
    entered: Notify,
    release: Notify,
    seen: Mutex<Vec<String>>,
}

impl StalledGateway {
    fn new() -> Self {
        Self {
            stall: AtomicBool::new(true),
            entered: Notify::new(),
            release: Notify::new(),
            seen: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Gateway for StalledGateway {
    fn id(&self) -> &'static str {
        "stalled"
    }

    fn egress_path(&self) -> PathId {
        PathId::C5
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            text: true,
            ..Capabilities::default()
        }
    }

    fn owner(&self) -> Option<OwnerId> {
        Some(OwnerId(1))
    }

    fn is_paired_owner(&self, _sender: OwnerId, _chat: ChatId) -> bool {
        true
    }

    async fn send(&self, outbound: &OutboundText) -> Result<(), GatewayError> {
        self.entered.notify_waiters();
        while self.stall.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        self.seen.lock().unwrap().push(outbound.text().to_string());
        Ok(())
    }

    async fn deliver_approval(&self, _card: &ApprovalCard) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn deliver_brief(&self, brief: &OutboundText) -> Result<(), GatewayError> {
        self.send(brief).await
    }

    async fn next_inbound(&self) -> Option<InboundText> {
        None
    }
}

struct NoopGateway;

#[async_trait]
impl Gateway for NoopGateway {
    fn id(&self) -> &'static str {
        "noop"
    }

    fn egress_path(&self) -> PathId {
        PathId::C10
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    fn owner(&self) -> Option<OwnerId> {
        None
    }

    fn is_paired_owner(&self, _sender: OwnerId, _chat: ChatId) -> bool {
        false
    }

    async fn send(&self, _outbound: &OutboundText) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn deliver_approval(&self, _card: &ApprovalCard) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn deliver_brief(&self, _brief: &OutboundText) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn next_inbound(&self) -> Option<InboundText> {
        None
    }
}

#[tokio::test]
async fn a_full_low_lane_stays_bounded_and_keeps_urgent() {
    let stalled = Arc::new(StalledGateway::new());
    let local: Arc<dyn Gateway> = Arc::new(NoopGateway);
    let (sink, rx) = GatewaySink::channel();
    let remote: Arc<dyn Gateway> = stalled.clone();
    let worker = tokio::spawn(run_worker(vec![remote], local, open_mode(), rx));

    // No await while filling, so the worker cannot drain mid-loop.
    for i in 0..1000 {
        sink.try_enqueue(Pending::Alert {
            level: Level::Info,
            text: format!("n{i}"),
        })
        .unwrap();
    }
    assert_eq!(sink.queued_len(), OUTBOUND_QUEUE_CAPACITY);
    sink.try_enqueue(Pending::Alert {
        level: Level::Urgent,
        text: "urgent".to_string(),
    })
    .unwrap();
    assert_eq!(sink.queued_len(), OUTBOUND_QUEUE_CAPACITY + 1);
    let drops = sink.take_drops();
    assert_eq!(drops.count, 1000 - OUTBOUND_QUEUE_CAPACITY);

    // The worker reaches the stalled first send, then the gateway recovers.
    stalled.entered.notified().await;
    stalled.stall.store(false, Ordering::SeqCst);
    stalled.release.notify_waiters();
    drop(sink);
    worker.await.unwrap();

    let seen = stalled.seen.lock().unwrap();
    assert_eq!(seen.len(), OUTBOUND_QUEUE_CAPACITY + 1);
    assert!(seen.iter().any(|text| text == "urgent"));
}

#[tokio::test]
async fn a_full_urgent_lane_backpressures_and_delivers_everything() {
    let stalled = Arc::new(StalledGateway::new());
    let local: Arc<dyn Gateway> = Arc::new(NoopGateway);
    let (sink, rx) = GatewaySink::channel();
    let sink = Arc::new(sink);
    let remote: Arc<dyn Gateway> = stalled.clone();
    let worker = tokio::spawn(run_worker(vec![remote], local, open_mode(), rx));

    let max_seen = Arc::new(AtomicUsize::new(0));
    let producer_sink = Arc::clone(&sink);
    let producer_max = Arc::clone(&max_seen);
    let producer = tokio::spawn(async move {
        for i in 0..1000 {
            producer_sink
                .enqueue(Pending::Alert {
                    level: Level::Urgent,
                    text: format!("u{i}"),
                })
                .await;
            producer_max.fetch_max(producer_sink.queued_len(), Ordering::SeqCst);
        }
    });

    // The worker stalls on the first send; the lane fills and the producer
    // then blocks on backpressure until room frees.
    stalled.entered.notified().await;
    for _ in 0..1000 {
        if sink.queued_len() >= OUTBOUND_URGENT_CAPACITY {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(sink.queued_len(), OUTBOUND_URGENT_CAPACITY);

    stalled.stall.store(false, Ordering::SeqCst);
    stalled.release.notify_waiters();
    producer.await.unwrap();
    assert!(
        max_seen.load(Ordering::SeqCst) <= OUTBOUND_URGENT_CAPACITY,
        "the urgent lane never grew past its bound"
    );

    drop(sink);
    worker.await.unwrap();
    let seen = stalled.seen.lock().unwrap();
    assert_eq!(seen.len(), 1000, "every urgent notice was delivered");
}

#[tokio::test]
async fn urgent_backpressure_never_loses_a_wakeup() {
    // A racing consumer drains while many producers wait; a lost wakeup hangs.
    for _ in 0..1000 {
        let (sink, rx) = GatewaySink::channel();
        let sink = Arc::new(sink);
        let consumer = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let mut producers = Vec::new();
        for _ in 0..8 {
            let sink = Arc::clone(&sink);
            producers.push(tokio::spawn(async move {
                for i in 0..32 {
                    sink.enqueue(Pending::Alert {
                        level: Level::Urgent,
                        text: format!("u{i}"),
                    })
                    .await;
                }
            }));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            for producer in producers {
                producer.await.unwrap();
            }
        })
        .await
        .expect("no producer lost its wakeup");
        drop(sink);
        tokio::time::timeout(Duration::from_secs(5), consumer)
            .await
            .expect("the consumer exits")
            .unwrap();
    }
}

#[tokio::test]
async fn urgent_alerts_await_the_overflow_and_all_arrive() {
    let dir = tempfile::tempdir().unwrap();
    let stalled = Arc::new(StalledGateway::new());
    let local: Arc<dyn Gateway> = Arc::new(NoopGateway);
    let (sink, rx) = GatewaySink::channel();
    let sink = Arc::new(sink);
    let router = Arc::new(NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(no_quiet()),
        kernel_core::SandboxHome::open(dir.path()).unwrap(),
        Arc::new(SystemClock),
    ));
    let remote: Arc<dyn Gateway> = stalled.clone();
    let worker = tokio::spawn(run_worker(vec![remote], local, open_mode(), rx));

    let producer = {
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            for i in 0..300 {
                router.alert(Level::Urgent, &format!("u{i}")).await;
            }
        })
    };

    // The worker stalls on the first alert; the lane fills and the producer
    // then awaits until the gateway resumes.
    stalled.entered.notified().await;
    tokio::task::yield_now().await;
    stalled.stall.store(false, Ordering::SeqCst);
    stalled.release.notify_waiters();
    producer.await.unwrap();

    drop(router);
    drop(sink);
    worker.await.unwrap();
    let seen = stalled.seen.lock().unwrap();
    assert_eq!(seen.len(), 300, "all urgent alerts were delivered");
}

#[tokio::test]
async fn a_cancelled_urgent_alert_is_not_counted_or_delivered() {
    let dir = tempfile::tempdir().unwrap();
    let stalled = Arc::new(StalledGateway::new());
    let local: Arc<dyn Gateway> = Arc::new(NoopGateway);
    let (sink, rx) = GatewaySink::channel();
    let sink = Arc::new(sink);
    let router = Arc::new(NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(no_quiet()),
        kernel_core::SandboxHome::open(dir.path()).unwrap(),
        Arc::new(SystemClock),
    ));
    let remote: Arc<dyn Gateway> = stalled.clone();
    let worker = tokio::spawn(run_worker(vec![remote], local, open_mode(), rx));

    let producer = {
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            for i in 0..100 {
                router.alert(Level::Urgent, &format!("fill {i}")).await;
            }
        })
    };

    // The worker stalls on the first send; wait until the lane is full.
    stalled.entered.notified().await;
    for _ in 0..1000 {
        if sink.queued_len() >= OUTBOUND_URGENT_CAPACITY {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(sink.queued_len(), OUTBOUND_URGENT_CAPACITY);

    // An alert waits for a slot, then is cancelled before it is admitted.
    let cancelled = {
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            router.alert(Level::Urgent, "cancelled").await;
        })
    };
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    cancelled.abort();
    let _ = cancelled.await;

    stalled.stall.store(false, Ordering::SeqCst);
    stalled.release.notify_waiters();
    producer.await.unwrap();
    drop(router);
    drop(sink);
    worker.await.unwrap();

    let seen = stalled.seen.lock().unwrap();
    assert_eq!(seen.len(), 100, "the cancelled alert was never delivered");
    assert!(!seen.iter().any(|text| text == "cancelled"));
    drop(seen);

    let state = std::fs::read_to_string(dir.path().join("notify_policy.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&state).unwrap();
    assert_eq!(
        value["policy"]["sent_today"], 100,
        "the cancelled alert was not counted"
    );
}

#[tokio::test]
async fn shutdown_drains_a_queued_urgent_alert() {
    let dir = tempfile::tempdir().unwrap();
    let stalled = Arc::new(StalledGateway::new());
    let local: Arc<dyn Gateway> = Arc::new(NoopGateway);
    let (sink, rx) = GatewaySink::channel();
    let sink = Arc::new(sink);
    let router = Arc::new(NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(no_quiet()),
        kernel_core::SandboxHome::open(dir.path()).unwrap(),
        Arc::new(SystemClock),
    ));
    let remote: Arc<dyn Gateway> = stalled.clone();
    let worker = tokio::spawn(run_worker(vec![remote], local, open_mode(), rx));

    // One alert is in flight (the worker stalls on it); the target is queued.
    let first = {
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            router.alert(Level::Urgent, "blocker").await;
        })
    };
    stalled.entered.notified().await;
    let second = {
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            router.alert(Level::Urgent, "shutdown-target").await;
        })
    };
    for _ in 0..1000 {
        if sink.queued_len() >= 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(sink.queued_len() >= 1, "the target alert is queued");

    // Shutdown: close the queue, release the gateway, drain with a timeout.
    router.close();
    stalled.stall.store(false, Ordering::SeqCst);
    stalled.release.notify_waiters();
    let _ = first.await;
    let _ = second.await;
    drop(router);
    drop(sink);
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("the worker drains and exits")
        .unwrap();

    let seen = stalled.seen.lock().unwrap();
    assert!(
        seen.iter().any(|text| text == "shutdown-target"),
        "{seen:?}"
    );
}

/// A paired remote that records every text it is handed.
struct RecordingRemote {
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl Gateway for RecordingRemote {
    fn id(&self) -> &'static str {
        "recording"
    }

    fn egress_path(&self) -> PathId {
        PathId::C5
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            text: true,
            approvals: true,
            brief: true,
            ..Capabilities::default()
        }
    }

    fn owner(&self) -> Option<OwnerId> {
        Some(OwnerId(1))
    }

    fn is_paired_owner(&self, _sender: OwnerId, _chat: ChatId) -> bool {
        true
    }

    async fn send(&self, outbound: &OutboundText) -> Result<(), GatewayError> {
        self.seen.lock().unwrap().push(outbound.text().to_string());
        Ok(())
    }

    async fn deliver_approval(&self, card: &ApprovalCard) -> Result<(), GatewayError> {
        self.seen.lock().unwrap().push(format!("card {card:?}"));
        Ok(())
    }

    async fn deliver_brief(&self, brief: &OutboundText) -> Result<(), GatewayError> {
        self.send(brief).await
    }

    async fn next_inbound(&self) -> Option<InboundText> {
        None
    }
}

/// Runs an approval notice and a brief through the router with Open mode and
/// a ready remote; returns what the remote and the local sink were handed.
async fn run_open_mode(sandboxed: bool) -> (Vec<String>, usize) {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(RecordingRemote {
        seen: Mutex::new(Vec::new()),
    });
    let fake = Arc::new(FakeNotifier::new());
    let local: Arc<dyn Gateway> = Arc::new(LocalGateway::new(fake.clone()));
    // Stands for an enabled, valid `[imessage]` config in the home.
    let built = auxd::gateway::build_unless_sandboxed(sandboxed, || Some(remote.clone()));
    let remotes: Vec<Arc<dyn Gateway>> = built
        .into_iter()
        .map(|gateway| gateway as Arc<dyn Gateway>)
        .collect();
    let (sink, rx) = GatewaySink::channel();
    let router = Arc::new(NotifyRouter::new(
        Arc::new(sink),
        NotifyPolicy::new(no_quiet()),
        kernel_core::SandboxHome::open(dir.path()).unwrap(),
        Arc::new(SystemClock),
    ));
    let worker = tokio::spawn(run_worker(remotes, local, open_mode(), rx));

    // An approval opens: the registry hands the router the fixed phone notice
    // (`ApprovalRegistry::set_phone_notifier`), which is a plain `Notifier` call.
    router
        .notify(&Notification::new(
            "Auxesis",
            "1 approval is waiting. Open Auxesis to see it.",
        ))
        .unwrap();
    // The notice is batched; the minute tick flushes it to the worker.
    router.flush();
    router.brief("Good morning");
    drop(router);
    worker.await.unwrap();

    let seen = remote.seen.lock().unwrap().clone();
    (seen, fake.count())
}

#[tokio::test]
async fn a_sandbox_run_sends_nothing_to_a_remote_in_open_mode() {
    let (remote_seen, _local) = run_open_mode(true).await;
    assert!(
        remote_seen.is_empty(),
        "sandbox reached a remote: {remote_seen:?}"
    );
}

#[tokio::test]
async fn outside_a_sandbox_the_same_remote_gets_the_approval_and_the_brief() {
    let (remote_seen, _local) = run_open_mode(false).await;
    assert!(
        remote_seen.iter().any(|text| text.contains("Good morning")),
        "{remote_seen:?}"
    );
    assert!(
        remote_seen.iter().any(|text| text.contains("approval")),
        "{remote_seen:?}"
    );
}

/// Runs one urgent alert and one brief through the real router and worker
/// with Open mode and a paired remote; returns what the remote was handed.
async fn remote_alert_and_brief(alert: &str, brief: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(RecordingRemote {
        seen: Mutex::new(Vec::new()),
    });
    let local: Arc<dyn Gateway> = Arc::new(LocalGateway::new(Arc::new(FakeNotifier::new())));
    let (sink, rx) = GatewaySink::channel();
    let router = Arc::new(NotifyRouter::new(
        Arc::new(sink),
        NotifyPolicy::new(no_quiet()),
        kernel_core::SandboxHome::open(dir.path()).unwrap(),
        Arc::new(SystemClock),
    ));
    let remotes = vec![remote.clone() as Arc<dyn Gateway>];
    let worker = tokio::spawn(run_worker(remotes, local, open_mode(), rx));
    router.alert(Level::Urgent, alert).await;
    router.brief(brief);
    drop(router);
    worker.await.unwrap();
    let seen = remote.seen.lock().unwrap().clone();
    seen
}

/// An alert and a brief bound for a paired phone carry no key,
/// IBAN, card, national ID or health term in Open mode.
#[tokio::test]
async fn gateway_remote_alert_and_brief_never_carry_a_key_an_iban_a_card_an_id_or_health_data() {
    let key = format!(
        "sk-proj-{}",
        "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3iJk6l"
    ); // gitleaks:allow
    let values = [
        key.as_str(),
        "FR14 2004 1010 0505 0001 3M02 606",
        "4111 1111 1111 1111",
        "1 85 05 78 006 084 91",
        "diabetes",
    ];
    let text = format!(
        "Alert. Key {}. Pay to {}, card {}. NIR {}. The client has {}.",
        values[0], values[1], values[2], values[3], values[4]
    );
    let seen = remote_alert_and_brief(&text, &text.replacen("Alert.", "Brief.", 1)).await;
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen[0].starts_with("Alert."), "{seen:?}");
    assert!(seen[1].starts_with("Brief."), "{seen:?}");
    for sent in &seen {
        let compact: String = sent.chars().filter(|c| !c.is_whitespace()).collect();
        for value in values {
            let squeezed: String = value.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(
                !sent.contains(value) && !compact.contains(&squeezed),
                "{value} reached the phone: {sent}"
            );
        }
        assert!(
            !sent.contains("4111") && !sent.contains("Ab3dEf6h"),
            "{sent}"
        );
    }
}

/// A plain alert and brief reach the phone as written.
#[tokio::test]
async fn gateway_remote_plain_alert_and_brief_go_out_unchanged() {
    let alert = "Camille replied: the meeting moves to Thursday at 10:00.";
    let brief = "Good morning. 2 meetings today, 3 unread mails.";
    assert_eq!(
        remote_alert_and_brief(alert, brief).await,
        vec![alert.to_string(), brief.to_string()]
    );
}
