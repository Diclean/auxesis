//! WO-ROUTINES-1 acceptance: the owner creates, pauses and deletes recurring
//! tasks ("routines") through the local API.
//!
//! A real server on an ephemeral loopback port, a temp home, no network, no
//! Keychain, no real `~/.auxesis`. Prompts and names are fictional.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use chrono::{DateTime, Datelike, Local, NaiveDateTime, TimeZone, Timelike, Utc, Weekday};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};

use common::HttpResponse;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PROMPT: &str = "Summarise my week's meetings with Camille Exemple.";

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    _handle: ApiHandle,
}

impl TestApi {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("agents").join("main")).unwrap();
        std::fs::write(config_path(&home), "version = 1\n").unwrap();
        std::fs::write(api::token_path(&home), TOKEN).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        let handle = api::spawn(
            &home,
            ApiOptions {
                port: 0,
                event_poll: Duration::from_millis(25),
                ..ApiOptions::default()
            },
        )
        .unwrap();
        Self {
            addr: handle.addr(),
            _dir: dir,
            home,
            _handle: handle,
        }
    }

    fn store(&self) -> Store {
        Store::open(&store_path(&self.home)).unwrap()
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> HttpResponse {
        let (addr, method, path) = (self.addr, method.to_string(), path.to_string());
        let body = body.map(|value| value.to_string());
        tokio::task::spawn_blocking(move || {
            common::http(addr, &method, &path, Some(TOKEN), body.as_deref())
        })
        .await
        .unwrap()
    }

    async fn create(&self, schedule: &str) -> HttpResponse {
        self.call(
            "POST",
            "/v1/jobs",
            Some(json!({"agent": "main", "name": "weekly digest", "schedule": schedule, "prompt": PROMPT})),
        )
        .await
    }

    async fn listed(&self) -> Vec<Value> {
        let listed = self.call("GET", "/v1/jobs", None).await;
        assert_eq!(listed.status, 200, "{}", listed.body);
        listed.json().as_array().unwrap().clone()
    }
}

/// The stored UTC `next_run_at` as a local wall-clock time.
fn next_run_utc(next_run_at: &str) -> DateTime<Utc> {
    let naive = NaiveDateTime::parse_from_str(next_run_at, "%Y-%m-%d %H:%M:%S").unwrap();
    Utc.from_utc_datetime(&naive)
}

fn local_wall(next_run_at: &str) -> NaiveDateTime {
    next_run_utc(next_run_at)
        .with_timezone(&Local)
        .naive_local()
}

#[tokio::test]
async fn a_weekly_routine_is_created_listed_paused_and_deleted() {
    let api = TestApi::start();
    let requested_at = Utc::now();

    let created = api.create("weekly mon 09:00").await;
    assert_eq!(created.status, 201, "{}", created.body);
    let row = created.json();
    let id = row["id"].as_i64().unwrap();
    assert_eq!(row["schedule"], "weekly mon 09:00");
    assert_eq!(row["enabled"], true);
    assert!(row.get("prompt").is_none() && !created.body.contains("Camille"));

    // Listed, with the next Monday 09:00 local time.
    let jobs = api.listed().await;
    let listed = jobs.iter().find(|job| job["id"] == id).expect("listed");
    let next_at = listed["next_run_at"].as_str().unwrap();
    let next = local_wall(next_at);
    assert_eq!(
        (next.weekday(), next.hour(), next.minute()),
        (Weekday::Mon, 9, 0)
    );
    assert!(next_run_utc(next_at) > requested_at);

    // The stored payload is a normal agent job carrying the owner's prompt.
    let stored = api.store().job_by_id(id).unwrap().unwrap();
    let payload: Value = serde_json::from_str(&stored.payload).unwrap();
    assert_eq!(payload, json!({"kind": "agent", "prompt": PROMPT}));

    // Pause: disabled, so the scheduler never claims it.
    let paused = api
        .call(
            "PATCH",
            &format!("/v1/jobs/{id}"),
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(paused.status, 200, "{}", paused.body);
    assert_eq!(paused.json()["enabled"], false);
    assert!(api
        .store()
        .due_jobs("9999-01-01 00:00:00")
        .unwrap()
        .is_empty());

    // Resume recomputes the next run from now; a stale one would fire at once.
    api.store()
        .reschedule_job(id, None, Some("2020-01-01 00:00:00"))
        .unwrap();
    let resumed = api
        .call(
            "PATCH",
            &format!("/v1/jobs/{id}"),
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(resumed.status, 200, "{}", resumed.body);
    assert!(resumed.json()["next_run_at"].as_str().unwrap() > "2024");

    let deleted = api.call("DELETE", &format!("/v1/jobs/{id}"), None).await;
    assert_eq!(deleted.status, 200, "{}", deleted.body);
    assert!(api.listed().await.iter().all(|job| job["id"] != id));
    assert_eq!(
        api.call("DELETE", &format!("/v1/jobs/{id}"), None)
            .await
            .status,
        404
    );
    assert_eq!(
        api.call(
            "PATCH",
            &format!("/v1/jobs/{id}"),
            Some(json!({"enabled": true}))
        )
        .await
        .status,
        404
    );
}

#[tokio::test]
async fn system_jobs_cannot_be_deleted_or_edited() {
    let api = TestApi::start();
    let store = api.store();
    let brief = store
        .create_job(
            "main",
            "morning-brief",
            "daily 08:00",
            r#"{"kind":"morning-brief","name":"morning-brief"}"#,
            None,
        )
        .unwrap();
    let timeline = store
        .create_job(
            "main",
            "crm-timeline",
            "every 15m",
            r#"{"kind":"crm-timeline","name":"crm-timeline"}"#,
            None,
        )
        .unwrap();

    for job in [&brief, &timeline] {
        let path = format!("/v1/jobs/{}", job.id);
        let deleted = api.call("DELETE", &path, None).await;
        assert_eq!(
            (deleted.status, deleted.json()["error"]["code"].clone()),
            (403, json!("system_job"))
        );
        let patched = api
            .call("PATCH", &path, Some(json!({"enabled": false})))
            .await;
        assert_eq!(patched.status, 403, "{}", patched.body);
        assert!(store.job_by_id(job.id).unwrap().unwrap().enabled);
    }
    // A routine cannot take a system job's name either.
    let clash = api
        .call("POST", "/v1/jobs", Some(json!({"agent": "main", "name": "morning-brief", "schedule": "daily 08:00", "prompt": PROMPT})))
        .await;
    assert_eq!(clash.status, 422, "{}", clash.body);
}

#[tokio::test]
async fn bad_routines_are_422_and_good_cron_is_accepted() {
    let api = TestApi::start();
    for schedule in [
        "every 1m",
        "every 4m",
        "*/3 * * * *",
        "0,2 9 * * *",
        "0 25 * * *",
        "0 9 31 2 *",
        "weekly funday 09:00",
        "daily 25:99",
        "whenever",
        "",
    ] {
        let response = api.create(schedule).await;
        assert_eq!(response.status, 422, "{schedule:?} -> {}", response.body);
        assert_eq!(
            response.json()["error"]["code"],
            "invalid_schedule",
            "{schedule:?}"
        );
    }
    let no_prompt = api
        .call(
            "POST",
            "/v1/jobs",
            Some(json!({"agent": "main", "name": "x", "schedule": "daily 09:00", "prompt": "  "})),
        )
        .await;
    assert_eq!(no_prompt.status, 422);
    let no_agent = api
        .call(
            "POST",
            "/v1/jobs",
            Some(
                json!({"agent": "ghost", "name": "x", "schedule": "daily 09:00", "prompt": PROMPT}),
            ),
        )
        .await;
    assert_eq!(no_agent.status, 422);
    assert!(api.listed().await.is_empty(), "nothing was created");

    for schedule in [
        "every 5m",
        "every 2h",
        "daily 08:30",
        "weekdays 07:45",
        "0 9 * * 1",
    ] {
        let response = api.create(schedule).await;
        assert_eq!(response.status, 201, "{schedule:?} -> {}", response.body);
        assert!(response.json()["next_run_at"].is_string(), "{schedule:?}");
        // A second routine with the same name is refused.
        let again = api.create(schedule).await;
        assert_eq!(again.status, 409, "{}", again.body);
        let id = response.json()["id"].as_i64().unwrap();
        assert_eq!(
            api.call("DELETE", &format!("/v1/jobs/{id}"), None)
                .await
                .status,
            200
        );
    }
}

#[tokio::test]
async fn writes_are_audited_without_the_prompt_and_need_the_token() {
    let api = TestApi::start();
    let id = api.create("daily 08:30").await.json()["id"]
        .as_i64()
        .unwrap();
    api.call(
        "PATCH",
        &format!("/v1/jobs/{id}"),
        Some(json!({"enabled": false})),
    )
    .await;
    api.call("DELETE", &format!("/v1/jobs/{id}"), None).await;

    let store = api.store();
    for kind in ["routine.created", "routine.updated", "routine.deleted"] {
        let payloads = store.event_payloads(kind).unwrap();
        assert_eq!(payloads.len(), 1, "{kind}");
        assert!(payloads[0].contains("weekly digest") && payloads[0].contains("daily 08:30"));
        assert!(
            !payloads[0].contains("Camille") && !payloads[0].contains("meetings"),
            "{kind}: {}",
            payloads[0]
        );
    }

    let addr = api.addr;
    let anonymous = tokio::task::spawn_blocking(move || {
        common::http(addr, "POST", "/v1/jobs", None, Some("{}"))
    })
    .await
    .unwrap();
    assert_eq!(anonymous.status, 401);
}
