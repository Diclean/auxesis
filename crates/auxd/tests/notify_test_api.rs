//! `POST /v1/notify/test` sends one fixed text through the
//! brief's notify router, from auxd itself.
//!
//! Sandbox only: a temp home and a fake sink. No gateway, no Messages, no
//! real home or daemon port.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use auxd::api::{self, ApiOptions};
use auxd::gateway::policy::{NotifyPolicy, PolicyConfig};
use auxd::gateway::router::{BriefOutcome, NotifyRouter, Pending, QueueFull, Sink, SystemClock};
use auxd::gateway::SendCause;
use common::{http, HttpResponse};
use kernel_core::{config_path, SandboxHome};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_TEXT: &str = "Auxesis test: if you can read this, the morning brief can reach you.";

/// Records every brief text; reports `report` for each, or cannot report.
struct FakeSink {
    texts: Mutex<Vec<String>>,
    report: Option<BriefOutcome>,
}

impl Sink for FakeSink {
    fn try_enqueue(&self, pending: Pending) -> Result<(), QueueFull> {
        if let Pending::Brief { text } = pending {
            self.texts.lock().unwrap().push(text);
        }
        Ok(())
    }

    fn enqueue_brief(&self, text: String) -> Result<Option<u64>, QueueFull> {
        self.texts.lock().unwrap().push(text);
        Ok(self.report.map(|_| 1))
    }

    fn wait_brief(&self, _ticket: u64, _timeout: Duration) -> Option<BriefOutcome> {
        self.report
    }
}

fn home(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"open\"\n\n[ui]\nlanguage = \"en\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    home
}

fn spawn(home: &Path, report: Option<BriefOutcome>) -> (api::ApiHandle, Arc<FakeSink>) {
    let sink = Arc::new(FakeSink {
        texts: Mutex::default(),
        report,
    });
    let router = NotifyRouter::new(
        sink.clone(),
        NotifyPolicy::new(PolicyConfig::default()),
        SandboxHome::open(home).unwrap(),
        Arc::new(SystemClock),
    );
    let options = ApiOptions {
        port: 0,
        notify_router: Some(Arc::new(router)),
        ..ApiOptions::default()
    };
    (api::spawn(home, options).unwrap(), sink)
}

async fn post(addr: SocketAddr, token: Option<&str>, body: Option<&str>) -> HttpResponse {
    let token = token.map(str::to_string);
    let body = body.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        http(
            addr,
            "POST",
            "/v1/notify/test",
            token.as_deref(),
            body.as_deref(),
        )
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_test_send_is_owner_only_bodyless_fixed_and_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let home = home(dir.path());
    let (handle, sink) = spawn(&home, None);
    let addr = handle.addr();

    let anonymous = post(addr, None, None).await;
    assert_eq!(anonymous.status, 401, "{}", anonymous.body);
    let with_body = post(addr, Some(TOKEN), Some(r#"{"text":"hi","to":"+15550100"}"#)).await;
    assert_eq!(with_body.status, 400, "{}", with_body.body);
    assert_eq!(with_body.json()["error"]["code"], "body_not_allowed");
    assert!(sink.texts.lock().unwrap().is_empty(), "nothing sent yet");

    let first = post(addr, Some(TOKEN), None).await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(
        first.json()["delivered"],
        false,
        "a sink that cannot report"
    );
    assert!(!first.body.contains("Auxesis test"), "{}", first.body);
    assert_eq!(*sink.texts.lock().unwrap(), vec![TEST_TEXT.to_string()]);

    let second = post(addr, Some(TOKEN), None).await;
    assert_eq!(second.status, 429, "{}", second.body);
    assert_eq!(sink.texts.lock().unwrap().len(), 1, "the 429 sent nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_send_answers_its_cause_and_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let home = home(dir.path());
    let (handle, _sink) = spawn(&home, Some(BriefOutcome::Failed(Some(SendCause::Timeout))));

    let response = post(handle.addr(), Some(TOKEN), None).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let value = response.json();
    assert_eq!(value["delivered"], false, "{value}");
    assert_eq!(value["cause"], "timeout", "{value}");

    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
    let rows = store.recent_event_payloads("notify.test", 10).unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].contains("timeout") && !rows[0].contains("Auxesis test"));
}
