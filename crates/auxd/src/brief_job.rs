//! Morning-brief job wiring on the existing job scheduler.

use aux_brief::{cap_chars, BriefResult, BriefSource};
use aux_store::{Job, Store};
use chrono::{DateTime, Local, Utc};
use kernel_core::Config;
use serde_json::Value;
use std::sync::{Arc, Mutex};

use crate::api::brief::{run_brief_traced, BriefNowError, BriefTrigger};
use crate::gateway::router::NotifyRouter;
use crate::scheduler::JobRunner;

const BRIEF_JOB: &str = "morning-brief";
const BRIEF_PAYLOAD: &str = r#"{"kind":"morning-brief","name":"morning-brief"}"#;
const MAX_FAILURE_CHARS: usize = 240;
/// What the phone is told when the brief fails: a fixed phrase.
/// The scrubbed reason goes to the run history only.
const BRIEF_FAILED_TITLE: &str = "Morning brief";
const BRIEF_FAILED_BODY: &str = "Today's brief could not be made. Open Auxesis for details.";

/// Keep the config-owned brief job in sync with the existing `jobs` table.
/// Fresh configs do not create a runnable job because `[brief].enabled` is
/// false by default.
pub fn sync_job(store: &Store, config: &Config, now: DateTime<Utc>) -> anyhow::Result<()> {
    let existing = store
        .list_jobs()?
        .into_iter()
        .find(|job| job.agent == "main" && job.name == BRIEF_JOB);
    if !config.brief.enabled && existing.is_none() {
        return Ok(());
    }
    let next = if config.brief.enabled {
        Some(
            aux_brief::next_run(&config.brief, now)
                .map_err(anyhow::Error::msg)?
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        )
    } else {
        None
    };
    match existing {
        Some(mut job) => {
            let schedule = aux_brief::schedule(&config.brief);
            let needs_retime = job.schedule != schedule || (config.brief.enabled && !job.enabled);
            job.schedule = schedule;
            job.payload = BRIEF_PAYLOAD.to_string();
            job.enabled = config.brief.enabled;
            // Preserve a due occurrence on daemon restart so the scheduler
            // can perform its normal single catch-up. Only a changed time or
            // re-enabling the job establishes a new next occurrence.
            if needs_retime {
                if let Some(next) = &next {
                    job.next_run_at = Some(next.clone());
                }
            }
            if !config.brief.enabled {
                // Keep the previous date as a user-visible schedule hint;
                // the enabled bit is the actual execution gate.
            } else if job.next_run_at.is_none() {
                if let Some(next) = &next {
                    job.next_run_at = Some(next.clone());
                }
            }
            store.update_job(&job)?;
        }
        None => {
            let schedule = aux_brief::schedule(&config.brief);
            let job =
                store.create_job("main", BRIEF_JOB, &schedule, BRIEF_PAYLOAD, next.as_deref())?;
            if !config.brief.enabled {
                store.set_job_enabled(job.id, false)?;
            }
        }
    }
    Ok(())
}

/// Dispatch morning-brief jobs to the offline brief runner and everything
/// else to the existing agent-job engine.
pub struct DispatchJobRunner {
    agent: Arc<dyn JobRunner>,
    config: Config,
    source: Arc<dyn BriefSource>,
    router: Arc<NotifyRouter>,
    /// Local time of the run; tests pass their own.
    now: Arc<dyn Fn() -> DateTime<Local> + Send + Sync>,
    home: std::path::PathBuf,
}

impl DispatchJobRunner {
    pub fn new(
        agent: Arc<dyn JobRunner>,
        config: Config,
        source: Arc<dyn BriefSource>,
        router: Arc<NotifyRouter>,
        home: std::path::PathBuf,
    ) -> Self {
        Self {
            agent,
            config,
            source,
            router,
            now: Arc::new(Local::now),
            home,
        }
    }

    #[cfg(test)]
    fn with_now(mut self, now: Arc<dyn Fn() -> DateTime<Local> + Send + Sync>) -> Self {
        self.now = now;
        self
    }

    fn is_stopped(&self) -> bool {
        aux_engine::marker_engaged(&self.home)
    }
}

impl JobRunner for DispatchJobRunner {
    fn run(&self, store: &Arc<Mutex<Store>>, job: &Job) -> Result<String, String> {
        let payload: Value =
            serde_json::from_str(&job.payload).map_err(|_| "invalid job payload".to_string())?;
        // B3: the periodic CRM timeline refresh reads mail headers and the
        // EventKit snapshot locally; no model is involved.
        if payload.get("kind").and_then(Value::as_str) == Some(crate::crm::TIMELINE_JOB) {
            return crate::crm::run_job(&self.home, store);
        }
        if payload.get("kind").and_then(Value::as_str) != Some("morning-brief") {
            return self.agent.run(store, job);
        }
        // The enabled flag and source budgets come from the daemon's loaded
        // config; only `[ui].language` is re-read here so an edit to
        // config.toml takes effect on the next send without a restart.
        let mut config = self.config.clone();
        if let Ok(live) = aux_engine::config::load_or_create(&kernel_core::config_path(&self.home))
        {
            config.ui.language = live.ui.language;
        }
        if !config.brief.enabled {
            return Err("morning brief is disabled".to_string());
        }
        // The exact inner path shared with `POST /v1/brief/run`: the F2
        // privacy gate, the source reads, the daily idempotency and the
        // counts-only notification through the same router. The store guard
        // is held only for the run itself.
        let brief_store = kernel_core::sync::lock_recover(store);
        let run = run_brief_traced(
            &self.home,
            &config,
            &self.source,
            self.router.as_ref(),
            &brief_store,
            (self.now)(),
            || self.is_stopped(),
            BriefTrigger::Scheduled,
        );
        drop(brief_store);
        let result = match run {
            Ok(result) => result,
            Err(BriefNowError::Refused(reason)) => return Err(reason),
            Err(BriefNowError::Run(error)) => {
                let reason = cap_chars(
                    &kernel_broker::scrub_external_preview(
                        &self.home,
                        &error.localized_message(config.ui.language),
                        MAX_FAILURE_CHARS * 4,
                    ),
                    MAX_FAILURE_CHARS,
                );
                // The phone gets a fixed phrase; the reason stays in the run
                // history.
                self.router
                    .alert_batched(&format!("{BRIEF_FAILED_TITLE}\n{BRIEF_FAILED_BODY}"));
                return Err(reason);
            }
        };
        let lang = config.ui.language;
        match result {
            BriefResult::Sent { day, .. } => Ok(format!(
                "{} — {day}",
                kernel_core::i18n::text(kernel_core::Message::BriefSent, lang)
            )),
            BriefResult::AlreadySent { day } => Ok(format!(
                "{} — {day}",
                kernel_core::i18n::text(kernel_core::Message::BriefAlreadySent, lang)
            )),
            BriefResult::QuietHours { day } => Ok(format!(
                "{} — {day}",
                kernel_core::i18n::text(kernel_core::Message::BriefQuietHours, lang)
            )),
            BriefResult::BudgetStopped { day } => Ok(format!(
                "{} — {day}",
                kernel_core::i18n::text(kernel_core::Message::BriefPaused, lang)
            )),
            BriefResult::Stopped => Err("stopped by kill switch".to_string()),
        }
    }

    fn reschedule_at(&self, job: &Job, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if job.name != BRIEF_JOB {
            return None;
        }
        aux_brief::next_quiet_end(now.with_timezone(&chrono::Local), &self.config.quiet)
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_job::NoProviderRunner;
    use crate::gateway::policy::{NotifyPolicy, PolicyConfig};
    use crate::gateway::router::{Clock as RouterClock, NotifyRouter, Pending, QueueFull, Sink};
    use crate::scheduler::{tick, StopSwitch};
    use aux_brief::{run_once, FakeBriefSource};
    use aux_notify::FakeNotifier;
    use chrono::Timelike;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// An open-mode home, for the tests that need the open-mode paths.
    fn open_home(home: &std::path::Path) {
        std::fs::create_dir_all(home).unwrap();
        std::fs::write(
            kernel_core::config_path(home),
            "version = 1\nprivacy.mode = \"open\"\n",
        )
        .unwrap();
    }

    struct FixedClock(Mutex<DateTime<Utc>>);

    impl FixedClock {
        fn set_local(&self, hour: u32, minute: u32) {
            let now = Local::now()
                .date_naive()
                .and_hms_opt(hour, minute, 0)
                .unwrap()
                .and_local_timezone(Local)
                .single()
                .unwrap()
                .to_utc();
            *self.0.lock().unwrap() = now;
        }

        fn set_next_local_day(&self, hour: u32, minute: u32) {
            let current = self.now_utc().with_timezone(&Local).date_naive();
            let next = current
                .succ_opt()
                .unwrap()
                .and_hms_opt(hour, minute, 0)
                .unwrap()
                .and_local_timezone(Local)
                .single()
                .unwrap()
                .to_utc();
            *self.0.lock().unwrap() = next;
        }
    }

    impl FixedClock {
        fn now_utc(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }

        fn now_local(&self) -> DateTime<Local> {
            self.now_utc().with_timezone(&Local)
        }

        /// A local time source that follows this clock.
        fn local_reader(self: &Arc<Self>) -> Arc<dyn Fn() -> DateTime<Local> + Send + Sync> {
            let clock = Arc::clone(self);
            Arc::new(move || clock.now_local())
        }
    }

    impl RouterClock for FixedClock {
        fn now_local_secs(&self) -> i64 {
            let utc = self.now_utc();
            let offset = utc.with_timezone(&Local).offset().local_minus_utc();
            utc.timestamp() + i64::from(offset)
        }
    }

    /// Records what the router queued, so a job test needs no gateway.
    #[derive(Default)]
    struct RecordingSink {
        items: Mutex<Vec<Pending>>,
    }

    impl Sink for RecordingSink {
        fn try_enqueue(&self, pending: Pending) -> Result<(), QueueFull> {
            self.items.lock().unwrap().push(pending);
            Ok(())
        }
    }

    impl RecordingSink {
        fn briefs(&self) -> Vec<String> {
            self.items
                .lock()
                .unwrap()
                .iter()
                .filter_map(|pending| match pending {
                    Pending::Brief { text } => Some(text.clone()),
                    _ => None,
                })
                .collect()
        }

        fn alerts(&self) -> Vec<String> {
            self.items
                .lock()
                .unwrap()
                .iter()
                .filter_map(|pending| match pending {
                    Pending::Alert { text, .. } => Some(text.clone()),
                    _ => None,
                })
                .collect()
        }
    }

    fn fixed_failure_text() -> String {
        "Morning brief\nToday's brief could not be made. Open Auxesis for details.".to_string()
    }

    fn test_router(
        home: &std::path::Path,
        clock: Arc<FixedClock>,
    ) -> (Arc<NotifyRouter>, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        let handle = kernel_core::SandboxHome::open(home).expect("open the test home");
        let router = Arc::new(NotifyRouter::new(
            sink.clone(),
            NotifyPolicy::new(PolicyConfig::default()),
            handle,
            clock,
        ));
        (router, sink)
    }

    #[test]
    fn scheduler_fires_at_eight_once_even_after_restart() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        open_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        let path = dir.path().join("brief.sqlite");
        let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
        let mut config = Config::default();
        assert!(!config.brief.enabled);
        assert!(store.lock().unwrap().list_jobs().unwrap().is_empty());
        sync_job(&store.lock().unwrap(), &config, Utc::now()).unwrap();
        assert!(store.lock().unwrap().list_jobs().unwrap().is_empty());
        config.brief.enabled = true;

        let clock = Arc::new(FixedClock(Mutex::new(Utc::now())));
        clock.set_local(7, 59);
        sync_job(&store.lock().unwrap(), &config, clock.now_utc()).unwrap();
        let (router, sink) = test_router(&home, clock.clone());
        let dispatch = DispatchJobRunner::new(
            Arc::new(NoProviderRunner::new("unused")),
            config.clone(),
            Arc::new(FakeBriefSource::default()),
            router.clone(),
            home.clone(),
        )
        .with_now(clock.local_reader());
        let stop = StopSwitch::new(&home);

        assert_eq!(
            tick(
                &store,
                &|| clock.now_utc(),
                &dispatch,
                std::time::Duration::from_secs(600),
                &stop
            )
            .unwrap()
            .claimed,
            0
        );
        clock.set_local(8, 0);
        assert_eq!(
            tick(
                &store,
                &|| clock.now_utc(),
                &dispatch,
                std::time::Duration::from_secs(600),
                &stop
            )
            .unwrap()
            .succeeded,
            1
        );
        assert_eq!(sink.briefs().len(), 1);
        // The 08:00 job leaves a content-free run record for `aux brief status`.
        let runs = store
            .lock()
            .unwrap()
            .recent_event_payloads("brief.run", 10)
            .unwrap();
        assert_eq!(runs.len(), 1, "{runs:?}");
        assert!(runs[0].contains(r#""trigger":"scheduled""#), "{runs:?}");
        assert!(runs[0].contains(r#""result":"written""#), "{runs:?}");

        // Restarted scheduler sees tomorrow's next occurrence; direct retry
        // still consults the persisted per-day message marker.
        drop(store);
        let reopened = Arc::new(Mutex::new(Store::open(&path).unwrap()));
        clock.set_local(8, 1);
        let restarted = DispatchJobRunner::new(
            Arc::new(NoProviderRunner::new("unused")),
            config,
            Arc::new(FakeBriefSource::default()),
            router.clone(),
            home,
        )
        .with_now(clock.local_reader());
        assert_eq!(
            tick(
                &reopened,
                &|| clock.now_utc(),
                &restarted,
                std::time::Duration::from_secs(600),
                &stop
            )
            .unwrap()
            .claimed,
            0
        );
        let duplicate = run_once(
            &reopened.lock().unwrap(),
            &FakeBriefSource::default(),
            &FakeNotifier::new(),
            &Config::default(),
            clock.now_local(),
            aux_brief::MAX_SOURCE_READS,
            || false,
        )
        .unwrap();
        assert!(matches!(duplicate, BriefResult::AlreadySent { .. }));
        assert_eq!(sink.briefs().len(), 1);
    }

    #[test]
    fn quiet_hours_skip_writes_and_notifications() {
        let dir = tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("brief.sqlite")).unwrap(),
        ));
        let notifier = FakeNotifier::new();
        let clock = FixedClock(Mutex::new(Utc::now()));
        clock.set_local(4, 0);
        let result = run_once(
            &store.lock().unwrap(),
            &FakeBriefSource::default(),
            &notifier,
            &Config::default(),
            clock.now_local(),
            aux_brief::MAX_SOURCE_READS,
            || false,
        )
        .unwrap();
        assert!(matches!(result, BriefResult::QuietHours { .. }));
        assert!(store.lock().unwrap().list_sessions().unwrap().is_empty());
        assert_eq!(notifier.count(), 0);
    }

    #[test]
    fn an_overnight_catch_up_waits_until_seven_and_runs_once() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        open_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("brief.sqlite")).unwrap(),
        ));
        let mut config = Config::default();
        config.brief.enabled = true;
        let clock = Arc::new(FixedClock(Mutex::new(Utc::now())));
        clock.set_local(7, 59);
        sync_job(&store.lock().unwrap(), &config, clock.now_utc()).unwrap();
        let (router, sink) = test_router(&home, clock.clone());
        let dispatch = DispatchJobRunner::new(
            Arc::new(NoProviderRunner::new("unused")),
            config.clone(),
            Arc::new(FakeBriefSource::default()),
            router.clone(),
            home.clone(),
        )
        .with_now(clock.local_reader());
        let stop = StopSwitch::new(&home);

        clock.set_local(23, 0);
        let deferred = tick(
            &store,
            &|| clock.now_utc(),
            &dispatch,
            std::time::Duration::from_secs(600),
            &stop,
        )
        .unwrap();
        assert_eq!(deferred.succeeded, 1);
        assert_eq!(sink.briefs().len(), 0);
        let next = store
            .lock()
            .unwrap()
            .list_jobs()
            .unwrap()
            .remove(0)
            .next_run_at
            .unwrap();
        let next_utc = chrono::NaiveDateTime::parse_from_str(&next, "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc();
        assert_eq!(next_utc.with_timezone(&Local).time().hour(), 7, "{next}");

        clock.set_next_local_day(7, 0);
        let delivered = tick(
            &store,
            &|| clock.now_utc(),
            &dispatch,
            std::time::Duration::from_secs(600),
            &stop,
        )
        .unwrap();
        assert_eq!(delivered.succeeded, 1);
        assert_eq!(sink.briefs().len(), 1);
        let session = store.lock().unwrap().list_sessions().unwrap()[0].id;
        assert_eq!(
            store.lock().unwrap().list_messages(session).unwrap().len(),
            1
        );
    }

    #[test]
    fn failed_brief_emits_one_scrubbed_notification() {
        struct CanarySource;
        impl aux_brief::BriefSource for CanarySource {
            fn calendar_today(
                &self,
                _day: &str,
            ) -> Result<Vec<aux_brief::CalendarItem>, aux_brief::BriefSourceError> {
                Ok(Vec::new())
            }
            fn weather(
                &self,
                _city: &str,
                _country: &str,
                _day: &str,
            ) -> Result<aux_brief::WeatherSummary, aux_brief::BriefSourceError> {
                Err(aux_brief::BriefSourceError::Unavailable)
            }
            fn mail_headers(
                &self,
                _day: &str,
            ) -> Result<Vec<aux_brief::MailHeader>, aux_brief::BriefSourceError> {
                Ok(vec![aux_brief::MailHeader {
                    sender: "private-brief-mail-canary".into(),
                    subject: "private-brief-mail-canary subject".into(),
                    received: String::new(),
                    unread: true,
                }])
            }
        }

        let dir = tempdir().unwrap();
        assert!(kernel_broker::scrub::register_known_secret(
            "private-brief-mail-canary"
        ));
        let home = dir.path().join("home");
        open_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("brief.sqlite")).unwrap(),
        ));
        let mut config = Config::default();
        config.brief.enabled = true;
        let clock = Arc::new(FixedClock(Mutex::new(Utc::now())));
        clock.set_local(8, 0);
        let (router, sink) = test_router(&home, clock.clone());
        let dispatch = DispatchJobRunner::new(
            Arc::new(NoProviderRunner::new("unused")),
            config,
            Arc::new(CanarySource),
            router.clone(),
            home,
        )
        .with_now(clock.local_reader());
        let job = store
            .lock()
            .unwrap()
            .create_job("main", BRIEF_JOB, "daily 08:00", BRIEF_PAYLOAD, None)
            .unwrap();

        dispatch.run(&store, &job).unwrap();
        assert_eq!(sink.briefs().len(), 1);
        assert!(!sink.briefs()[0].contains("private-brief-mail-canary"));
    }

    #[test]
    fn brief_failure_sends_only_the_fixed_phrase() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        open_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("brief.sqlite")).unwrap(),
        ));
        let mut config = Config::default();
        config.brief.enabled = true;
        config.quiet.start = "private-brief-error-canary".into();
        assert!(kernel_broker::scrub::register_known_secret(
            "private-brief-error-canary"
        ));
        let clock = Arc::new(FixedClock(Mutex::new(Utc::now())));
        clock.set_local(8, 0);
        let (router, sink) = test_router(&home, clock.clone());
        let dispatch = DispatchJobRunner::new(
            Arc::new(NoProviderRunner::new("unused")),
            config,
            Arc::new(FakeBriefSource::default()),
            router.clone(),
            home,
        )
        .with_now(clock.local_reader());
        let job = store
            .lock()
            .unwrap()
            .create_job("main", BRIEF_JOB, "daily 08:00", BRIEF_PAYLOAD, None)
            .unwrap();

        assert!(dispatch.run(&store, &job).is_err());
        clock.set_local(9, 0);
        router.flush();
        assert_eq!(sink.alerts(), vec![fixed_failure_text()]);
    }

    #[test]
    fn brief_failure_notification_never_echoes_invalid_quiet_time() {
        // Unlike `brief_failure_sends_only_the_fixed_phrase`, this canary
        // is deliberately NOT registered as a known secret: the error message
        // itself must stay free of the raw configuration value.
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        open_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("brief.sqlite")).unwrap(),
        ));
        let mut config = Config::default();
        config.brief.enabled = true;
        config.quiet.start = "canari-PERSO-123".into();
        let clock = Arc::new(FixedClock(Mutex::new(Utc::now())));
        clock.set_local(8, 0);
        let (router, sink) = test_router(&home, clock.clone());
        let dispatch = DispatchJobRunner::new(
            Arc::new(NoProviderRunner::new("unused")),
            config,
            Arc::new(FakeBriefSource::default()),
            router.clone(),
            home,
        )
        .with_now(clock.local_reader());
        let job = store
            .lock()
            .unwrap()
            .create_job("main", BRIEF_JOB, "daily 08:00", BRIEF_PAYLOAD, None)
            .unwrap();

        let error = dispatch.run(&store, &job).unwrap_err();
        assert!(!error.contains("canari-PERSO-123"));
        assert!(error.contains("HH:MM"));
        clock.set_local(9, 0);
        router.flush();
        // The reason ("HH:MM") stays in the run error; the phone gets only
        // the fixed phrase.
        assert_eq!(sink.alerts(), vec![fixed_failure_text()]);
    }

    #[test]
    fn exhausted_source_budget_latches_and_only_notifies_quota() {
        let dir = tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("brief.sqlite")).unwrap(),
        ));
        let notifier = FakeNotifier::new();
        let clock = FixedClock(Mutex::new(Utc::now()));
        clock.set_local(8, 0);
        let result = run_once(
            &store.lock().unwrap(),
            &FakeBriefSource::default(),
            &notifier,
            &Config::default(),
            clock.now_local(),
            0,
            || false,
        )
        .unwrap();
        assert!(matches!(result, BriefResult::BudgetStopped { .. }));
        let day = clock.now_local().format("%Y-%m-%d").to_string();
        assert!(store
            .lock()
            .unwrap()
            .budget_stop_reason("main", &day)
            .unwrap()
            .is_some());
        assert!(store.lock().unwrap().list_sessions().unwrap().is_empty());
        assert_eq!(notifier.count(), 1);
        assert!(notifier.last().unwrap().body.contains("quota"));
    }

    #[test]
    fn failed_source_still_writes_an_english_degradation_line() {
        let dir = tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("brief.sqlite")).unwrap(),
        ));
        let notifier = FakeNotifier::new();
        let clock = FixedClock(Mutex::new(Utc::now()));
        clock.set_local(8, 0);
        let source = FakeBriefSource {
            fail: Some("calendar".to_string()),
        };
        assert!(matches!(
            run_once(
                &store.lock().unwrap(),
                &source,
                &notifier,
                &Config::default(),
                clock.now_local(),
                3,
                || false
            )
            .unwrap(),
            BriefResult::Sent { .. }
        ));
        let session = store.lock().unwrap().list_sessions().unwrap().remove(0);
        let body = store
            .lock()
            .unwrap()
            .list_messages(session.id)
            .unwrap()
            .remove(0)
            .content;
        assert!(body.contains("Calendar: source unavailable."));
        assert!(body.contains("To decide"));
        assert!(body.contains("For your information"));
        assert_eq!(notifier.count(), 1);
    }

    #[test]
    fn the_timeline_job_records_a_private_skip() {
        // A scheduled crm-timeline run in Private mode makes no
        // network call (the integration test proves the zero dial) and the
        // scheduler records the skip reason in the run row.
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            kernel_core::config_path(&home),
            "version = 1\nprivacy.mode = \"private\"\n",
        )
        .unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("timeline.sqlite")).unwrap(),
        ));
        let now = Utc::now();
        crate::crm::sync_job(&store.lock().unwrap(), now).unwrap();
        let job = store.lock().unwrap().list_jobs().unwrap().remove(0);

        let clock = Arc::new(FixedClock(Mutex::new(now + chrono::Duration::minutes(5))));
        // G1: the runner now takes the gateway's notify router; the private
        // skip fails the run before it would ever queue anything.
        let (router, _sink) = test_router(&home, clock.clone());
        let dispatch = DispatchJobRunner::new(
            Arc::new(NoProviderRunner::new("unused")),
            Config::default(),
            Arc::new(FakeBriefSource::default()),
            router,
            home.clone(),
        )
        .with_now(clock.local_reader());
        let stop = StopSwitch::new(&home);
        let report = tick(
            &store,
            &|| clock.now_utc(),
            &dispatch,
            std::time::Duration::from_secs(600),
            &stop,
        )
        .unwrap();
        assert_eq!(report.claimed, 1);
        assert_eq!(report.failed, 1, "the private skip is recorded as a run");
        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, aux_store::RUN_FAILED);
        let summary = runs[0].summary.as_deref().unwrap_or_default();
        assert!(
            summary.contains("not available in private mode"),
            "unexpected run summary: {summary}"
        );
    }
}
