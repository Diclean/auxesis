//! `auxd` — the Auxesis daemon.
//!
//! M0 scope: resolve the home, initialize config and store, announce
//! readiness on stdout, then wait for Ctrl-C or SIGTERM.
//!
//! M2 scope: a scheduler task ticks every [`TICK_INTERVAL`], claims due jobs,
//! runs each one through an [`auxd::scheduler::JobRunner`] on its own store
//! connection and records each run in the store. Scheduled `agent` jobs execute
//! a real turn through `aux-engine` ([`auxd::agent_job::AgentJobRunner`]). The daemon
//! holds a single-instance lock ([`auxd::lock::InstanceLock`]) so two daemons can
//! never share one home. The local API and channels still arrive later.

use aux_notify::{system_notifier, Notifier, StopSwitchNotifier};
use aux_store::Store;
use auxd::agent_job::daemon_runner;
use auxd::api;
use auxd::brief_job;
use auxd::gateway::imessage::{self, MessagesGateway};
use auxd::gateway::local::LocalGateway;
use auxd::gateway::policy::{NotifyPolicy, PolicyConfig};
use auxd::gateway::router::{GatewaySink, NotifyRouter, SystemClock as RouterClock};
use auxd::gateway::Gateway;
use auxd::lock::InstanceLock;
use auxd::logging;
use auxd::scheduler;
use auxd::scheduler::{FileStoreOpener, StopSwitch, CLAIM_LEASE, TICK_INTERVAL};
use auxd::shutdown;
use clap::Parser;
use kernel_core::{config_path, ensure_home, killswitch, Config};
use std::io::Write;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, MutexGuard};
use tracing_subscriber::EnvFilter;

/// How long shutdown waits for in-flight work before the process exits.
///
/// Blocking jobs (provider turns, tool calls) cannot be cancelled; after
/// this grace the runtime is abandoned and the process exits, so `aux
/// uninstall` / `launchctl bootout` / Ctrl-C are never blocked by a run.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Debug, Parser)]
#[command(name = "auxd", version, about = "Auxesis daemon")]
struct Args {}

fn main() -> ExitCode {
    // A panic in a background channel task must not echo its input payload to
    // launchd logs: the shared hook writes only the source location.
    kernel_broker::install_payload_free_panic_hook();
    // I2: no core dump, whatever the mode. The mode can be switched while the
    // daemon runs, so this is not a private-mode-only call.
    if let Err(err) = kernel_core::privacy::disable_core_dumps() {
        eprintln!("auxd: cannot disable core dumps: {err}");
    }
    // NEW-A3L: take a private process group before anything can be spawned,
    // so every child (the notifier's osascript included) inherits a group
    // whose members can be terminated by pgid at shutdown even after a
    // TERM-trapping descendant forks and reparents them.
    let group = shutdown::OwnedGroup::establish();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("auxd: cannot start the runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run());
    // A task abandoned by the runtime can have spawned a child process (a
    // hung `osascript`, a shell tool command): terminate the whole descendant
    // tree before the process exits, so SIGTERM never orphans it (NEW-A3).
    // The sweep runs twice around the runtime's grace: work that *finishes*
    // during the grace spawns its notifier after the first snapshot, so only
    // the post-grace sweep can collect it (NEW-A3R). It also sweeps the
    // daemon's process group (NEW-A3L).
    shutdown::shutdown_everything(std::process::id(), group, move || {
        // Never await a blocking job on shutdown: give the runtime a short
        // grace, then abandon it and let the process exit.
        runtime.shutdown_timeout(SHUTDOWN_GRACE);
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("auxd: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let _args = Args::parse();

    // The one shared sandbox guard (J-02): before anything is read or
    // created, resolve the verified home, refuse the real ~/.auxesis and
    // refuse the real daemon port (a sandbox passes AUXESIS_API_PORT=0).
    let mut api_options = api::ApiOptions::from_env();
    let home = match kernel_core::ensure_sandbox_guard(Some(api_options.port)) {
        Ok(home) => home,
        Err(err) => anyhow::bail!("{err}"),
    };
    // WO-07: a pre-rename `dots/` folder moves to `agents/` before anything
    // creates `agents/`. Both folders present is a refusal, never a merge.
    match aux_engine::layout::migrate_legacy_agents_dir(&home) {
        Ok(Some(moved)) => eprintln!(
            "auxd: moved {} to {}",
            moved.from.display(),
            moved.to.display()
        ),
        Ok(None) => {}
        Err(err) => anyhow::bail!("auxd: {err}"),
    }
    let verified = ensure_home(&home)?;

    // Single instance per home: a second `auxd` (launchd + a manual start,
    // two sessions, a debugging copy) must refuse to run rather than
    // double-claim jobs. The lock is held for the whole process lifetime.
    let _instance_lock = InstanceLock::acquire(&home.join("auxd.lock"))?;
    tracing::debug!(lock = %_instance_lock.path().display(), "auxd: instance lock acquired");

    let config_file = config_path(&home);
    let config = Config::load_or_create_verified(&verified)?;
    // Default-silence the HTML/XML parser crates: html5ever logs one `WARN`
    // per foster-parented token, so a hostile 512 KiB page used to write
    // ~8.85 MiB into the launchd-redirected log file (RV4-02). P3 batch-2 adds
    // the WhatsApp transport targets: `whatsapp-rust`/`wacore*` log peer
    // numbers (`Identity change for <number> …`) at INFO. `RUST_LOG` stays the
    // base filter when set, and because the silence directives are prepended,
    // an explicit later directive (`RUST_LOG=html5ever=warn`) re-enables the
    // crate (last directive for a target wins).
    let base = std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone());
    // P2-3: `async-imap` logs the encoded `LOGIN` command — the password
    // included — at TRACE, and its proto/TLS helpers log the same connection.
    // Force those targets off *after* the base filter (the last directive for a
    // target wins), so even `RUST_LOG=async_imap=trace` cannot write a
    // credential into auxd.log. See the log-hygiene note in
    // `crates/aux-mail/src/mailbox.rs`.
    const MAIL_LIB_LOG_DIRECTIVES: &str = "async_imap=off,async_native_tls=off,imap_proto=off";
    let mail_silenced = format!("{base},{MAIL_LIB_LOG_DIRECTIVES}");
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(kernel_core::logging::with_noisy_logs_silenced(
                &mail_silenced,
            ))
            .unwrap_or_else(|_| {
                EnvFilter::new(kernel_core::logging::with_noisy_logs_silenced(&format!(
                    "info,{MAIL_LIB_LOG_DIRECTIVES}"
                )))
            }),
        )
        .with_target(false)
        // F-17/C P3-5: launchd never rotates auxd.log; cap what this process
        // writes so a persistent per-request error cannot fill the disk.
        .with_writer(logging::CappedWriter::new(
            std::io::stdout(),
            logging::LOG_BYTE_BUDGET,
        ))
        .init();

    #[cfg(feature = "ner-gliner")]
    match kernel_privacy::load_vetted_local_model(&home, &home.join("models/gliner2-pii")) {
        Some(model) => aux_engine::install_deep_detector(Arc::new(model)),
        None => {
            tracing::info!("local Deep privacy model unavailable; using Standard egress detection")
        }
    }

    // H-04/L-1: register every secret this home holds (`AUX_KEY_*` in
    // `.env` and the process environment, the API token once the API starts)
    // with the exact-value scrubber. Values are never logged; the count is
    // not secret.
    let registered = kernel_broker::scrub::register_known_secrets_from_home(&home);
    tracing::debug!(
        registered,
        "known secrets registered for exact-value redaction"
    );

    // G4: the native Google read tools are offered on every chat turn while
    // this home holds an authorization. The daemon never opens a browser —
    // connecting is `aux connect google` or the app's explicit click, both of
    // which name an opener the daemon does not own. With the `google` feature
    // off, the whole surface is compiled out.
    #[cfg(feature = "google")]
    if aux_google::MacConnection::at(&home).connected() {
        tracing::info!("Google is connected; the read tools will be offered");
    } else {
        tracing::debug!("Google is not connected");
    }

    // CAL-AGENT-INSTALL: a built-in agent gets each shipped file it is missing
    // (the Calendar agent's agent.md and send-invite skill), on a fresh home
    // and on one created before they shipped. Existing files are never touched.
    match auxd::agents::install_shipped_files(&home) {
        Ok(added) => {
            for rel in added {
                tracing::info!(file = %rel.display(), "added a shipped agent file");
            }
        }
        Err(err) => tracing::warn!(error = %err, "shipped agent files not installed"),
    }

    // Weather has no built-in city: an install that never set one (or relied
    // on an old default) gets weather only after it does. The line names no city.
    if config.location.city.is_none() {
        tracing::warn!("location not set: weather needs a city (set [location] city, or default_city, in config)");
    }

    // P2: the user's MCP servers. A missing file means none; an invalid file
    // is logged and the daemon keeps running without MCP. A server that fails
    // discovery is isolated.
    // The slot is shared by the API, the job runner and the privacy watch, which
    // rebuilds the runtime when the mode changes.
    let mcp: auxd::mcp::McpSlot = Arc::new(std::sync::RwLock::new(
        auxd::mcp::start(
            &home,
            &config.web,
            &aux_engine::shell_sandbox(&config.shell),
        )
        .await,
    ));
    // The watch and the API share this ordering: a mode rebuild and a config
    // mutation (revoke, shrink, delete) can never interleave.
    let mcp_ordering = auxd::mcp::McpOrdering::new();
    let _mcp_watch =
        auxd::mcp::spawn_privacy_watch(home.clone(), Arc::clone(&mcp), mcp_ordering.clone());

    // WO-13b: start one sandboxed session per mounted, unfrozen extension and
    // verify its pinned tool identities. An empty mount table is a no-op, so a
    // default install starts no child.
    let extensions: auxd::extensions::ExtSlot = auxd::extensions::start(&home).await;
    let _extensions_watch =
        auxd::extensions::spawn_privacy_watch(home.clone(), Arc::clone(&extensions));
    let extension_count = auxd::extensions::current(&extensions).running().len();
    tracing::info!(running = extension_count, "extensions started");

    // The owner's channel is the Gateway (D34). Every daemon-originated
    // message is decided by the notify policy and delivered through it; the
    // state file keeps the daily counter across a restart.
    // The local macOS display is the fallback channel: when no remote gateway
    // is paired, briefs and alerts still reach the owner here (C10).
    let local_notifier: Arc<dyn Notifier> = Arc::new(StopSwitchNotifier::new(
        system_notifier(kernel_core::sandbox_guard_active()),
        killswitch::stop_path(&home),
    ));
    let local_gateway: Arc<dyn Gateway> = Arc::new(LocalGateway::new(Arc::clone(&local_notifier)));
    let (notify_sink, notify_rx) = GatewaySink::channel();
    let notify_router = Arc::new(NotifyRouter::new(
        Arc::new(notify_sink),
        NotifyPolicy::new(PolicyConfig::default()),
        verified.clone(),
        Arc::new(RouterClock),
    ));
    // D34/G2: the Messages (iMessage) gateway is one more remote, off unless
    // `[imessage]` in gateways.toml is enabled and valid. A chat.db that
    // cannot be opened read-only or a sender that cannot be configured keeps
    // it off rather than failing the daemon.
    // A sandbox run builds no remote gateway at all (approvals, briefs and
    // alerts stay on the local sink), whatever the home config says.
    let messages_gateway =
        auxd::gateway::build_unless_sandboxed(kernel_core::sandbox_guard_active(), || {
            build_messages_gateway(&verified, &aux_imessage::config::load(&home))
        });
    let mut notify_remotes: Vec<Arc<dyn Gateway>> = Vec::new();
    if let Some(gateway) = &messages_gateway {
        let remote: Arc<dyn Gateway> = gateway.clone();
        notify_remotes.push(remote);
    }
    // With no paired remote, a waiting approval goes to the local display now
    // through the same aux-notify sink, not the phone router
    // (APPROVAL-NO-GATEWAY).
    if !notify_remotes.iter().any(|gateway| gateway.is_paired()) {
        api_options.approval_local = Some(local_notifier);
    }
    let notify_worker = tokio::spawn(auxd::gateway::router::run_worker(
        notify_remotes,
        local_gateway,
        auxd::privacy_wiring::live_mode_fn(&home),
        notify_rx,
    ));
    let notify_flush = {
        let router = Arc::clone(&notify_router);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                router.flush();
            }
        })
    };
    // Scheduled jobs run through the engine, with notifications gated by the
    // kill switch and routed through the policy and the gateway; configuration
    // problems degrade to a runner that fails jobs with a clear reason instead
    // of taking the daemon down.
    let notifier: Arc<dyn Notifier> = Arc::new(StopSwitchNotifier::new(
        Arc::clone(&notify_router),
        killswitch::stop_path(&home),
    ));
    let agent_runner = daemon_runner(
        &home,
        &config_file,
        &config,
        Arc::clone(&notifier),
        Some(Arc::clone(&mcp)),
    );

    let store = Store::open_verified(&verified)?;
    // A claim left by a dead process is `uncertain`, never silently sendable.
    store.recover_mail_draft_claims()?;
    let store = Arc::new(Mutex::new(store));
    // DOC-SAFE-1: seal evidence blobs left in plaintext by an older build. A
    // failure leaves them to be sealed on their first read.
    // Only counts are logged, never a name or a byte.
    match aux_docs::migrate_blobs(&home) {
        Ok((sealed, stray)) => {
            if sealed > 0 {
                tracing::info!(sealed, "evidence blobs sealed at rest");
            }
            if stray > 0 {
                tracing::warn!(stray, "evidence files that do not open; purge them");
            }
        }
        Err(_) => tracing::warn!("evidence blobs not sealed at start; each is sealed on read"),
    }
    {
        let store = lock_store(&store);
        brief_job::sync_job(&store, &config, chrono::Utc::now())?;
    }
    {
        // B3: keep the CRM timeline refresh scheduled. It is local reads plus a
        // local write and does nothing when no mailbox or snapshot exists.
        let store = lock_store(&store);
        auxd::crm::sync_job(&store, chrono::Utc::now())?;
    }
    // M2: with Google parked, the brief reads the local EventKit snapshot and
    // the configured mailbox. A Google grant still wins when the frozen
    // integration is compiled in and connected.
    #[cfg(feature = "google")]
    let brief_source: Arc<dyn aux_brief::BriefSource> =
        if aux_google::MacConnection::at(&home).connected() {
            Arc::new(auxd::google_brief::GoogleBriefSource::new(
                home.clone(),
                Arc::clone(&store),
            ))
        } else {
            Arc::new(auxd::local_brief::LocalBriefSource::new(home.clone()))
        };
    #[cfg(not(feature = "google"))]
    let brief_source: Arc<dyn aux_brief::BriefSource> =
        Arc::new(auxd::local_brief::LocalBriefSource::new(home.clone()));
    // M2: `POST /v1/brief/run` runs the same source and router as the job.
    api_options.brief_source = Some(Arc::clone(&brief_source));
    api_options.notify_router = Some(Arc::clone(&notify_router));
    let job_runner = brief_job::DispatchJobRunner::new(
        agent_runner,
        config.clone(),
        brief_source,
        Arc::clone(&notify_router),
        home.clone(),
    );
    {
        let store = lock_store(&store);
        store.log_event(
            "daemon.started",
            &format!(r#"{{"version":"{}"}}"#, kernel_core::VERSION),
        )?;
        let interrupted = scheduler::recover_interrupted_runs(&store, &chrono::Utc::now)?;
        if interrupted > 0 {
            tracing::warn!(interrupted, "marked runs left by a previous process");
        }
    }

    let _ = writeln!(
        std::io::stdout(),
        "auxd ready — version {}, home {}, schema v{}",
        kernel_core::VERSION,
        home.display(),
        lock_store(&store).schema_version()?
    );
    tracing::info!("auxd ready");

    // B11: a home that is private at start holds no EventKit item. The sweep runs
    // before the API listens, so no request can meet a legacy or encrypted copy.
    if let Err(err) = auxd::apple_eventkit::sweep_stored(&home) {
        tracing::warn!(error = %err, "EventKit at-rest sweep failed at start");
    }
    let _at_rest_watch = auxd::apple_eventkit::spawn_at_rest_watch(home.clone());

    // The local API is the app's only door.
    // A bind failure (port taken) degrades: the scheduler keeps running and
    // the error is logged loudly, so an always-on daemon never dies because
    // another process squats the port.
    let api = match api::spawn(&home, {
        api_options.mcp = Some(Arc::clone(&mcp));
        api_options.mcp_ordering = mcp_ordering;
        api_options.extensions = Some(Arc::clone(&extensions));
        api_options
    }) {
        Ok(handle) => {
            let _ = writeln!(std::io::stdout(), "auxd api on http://{}", handle.addr());
            tracing::info!(addr = %handle.addr(), "local API listening");
            Some(handle)
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "auxd: local API not started: {err}");
            tracing::error!(error = %err, "local API not started");
            None
        }
    };

    // CLOSURE-4: the daemon reads documents itself. The Mac app's extraction
    // worker and the documents routes used to be the only callers of the
    // sweep, so a receipt that arrived while the app was closed stayed
    // `[unread]`. The registry is local; this reuses the exact chain the API
    // runs (XML in Rust, other formats queued for the on-device bridge).
    let _docs_sweep = auxd::docs::spawn_sweep(home.clone(), verified.clone());

    // Each claimed job runs on its own connection: the shared store mutex
    // is never held while a turn executes, so ticks, STOP and shutdown stay
    // responsive.
    let scheduler_handle = tokio::spawn(scheduler::run_loop(
        Arc::clone(&store),
        Arc::new(FileStoreOpener::from_verified(verified.clone())),
        Arc::new(chrono::Utc::now),
        job_runner,
        TICK_INTERVAL,
        CLAIM_LEASE,
        StopSwitch::new(&home),
    ));

    // D34/G2: the Messages reader polls the pinned chat and runs a tainted turn
    // per owner message. It holds no kernel path of its own, so a private home
    // stops the poll (and the admissions above hold every send).
    let messages = match (&messages_gateway, api.as_ref()) {
        (Some(gateway), Some(handle)) => Some(supervise_messages(
            home.clone(),
            Arc::clone(&store),
            handle.channel_access(),
            Arc::clone(gateway),
        )),
        _ => None,
    };

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    if let Some(messages) = messages {
        messages.shutdown().await;
    }

    scheduler_handle.abort();
    // Close the outbound queue and let the worker drain it (bounded), so a
    // queued urgent alert is not lost to shutdown.
    notify_router.close();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), notify_worker).await;
    notify_flush.abort();
    if let Some(api) = api {
        api.shutdown();
    }
    lock_store(&store).log_event("daemon.stopped", "{}")?;
    let _ = writeln!(std::io::stdout(), "auxd stopping");
    Ok(())
}

/// Build the Messages gateway when `[imessage]` is enabled and valid. A
/// `chat.db` that cannot be opened read-only or a sender that cannot be built
/// keeps the channel off; there is no writable fallback.
fn build_messages_gateway(
    verified: &kernel_core::SandboxHome,
    config: &aux_imessage::config::GatewaysConfig,
) -> Option<Arc<MessagesGateway>> {
    if !config.imessage_usable() {
        return None;
    }
    let section = &config.imessage;
    let reader = match aux_imessage::reader::ChatDbReader::open_read_only(&section.chat_db_path()) {
        Ok(reader) => Arc::new(reader),
        Err(err) => {
            tracing::warn!(error = %err, "imessage not started: chat.db is not readable read-only");
            return None;
        }
    };
    let sender = match aux_imessage::sender::AppleScriptSender::new(
        Arc::new(aux_imessage::sender::ProcessRunner::default()),
        section.mode,
        section.owner_handles.clone(),
        section.agent_handle.clone(),
    ) {
        Ok(sender) => Arc::new(sender),
        Err(err) => {
            tracing::warn!(error = %err, "imessage not started: the sender is not configured");
            return None;
        }
    };
    let pacer = aux_imessage::pacing::Pacer::new(
        Arc::new(aux_imessage::pacing::SystemClock),
        section.min_gap_secs,
    );
    let cursor = aux_imessage::cursor::CursorStore::new(verified.clone(), section.cursor_file());
    match MessagesGateway::new(section, reader, sender, pacer, Some(cursor)) {
        Ok(gateway) => Some(Arc::new(gateway)),
        Err(err) => {
            tracing::warn!(error = %err, "imessage not started");
            None
        }
    }
}

struct MessagesSupervisor {
    stop: tokio::sync::watch::Sender<bool>,
    poller: tokio::task::JoinHandle<()>,
    turns: tokio::task::JoinHandle<()>,
}

impl MessagesSupervisor {
    async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.poller).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.turns).await;
    }
}

/// Poll the pinned chat and run one tainted turn per owner message. Private
/// mode keeps polling: the turn is tokenised by the session gate and the reply
/// is the fixed notice only.
fn supervise_messages(
    home: std::path::PathBuf,
    store: Arc<Mutex<Store>>,
    api: api::ChannelApiHandle,
    gateway: Arc<MessagesGateway>,
) -> MessagesSupervisor {
    let (stop, _) = tokio::sync::watch::channel(false);
    let poller = {
        let stop = stop.subscribe();
        let home = home.clone();
        let held = api.private_answers();
        let gateway = Arc::clone(&gateway);
        tokio::spawn(async move {
            let mut stop = stop;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    changed = stop.changed() => if changed.is_err() || *stop.borrow() { break; }
                }
                if !auxd::privacy_wiring::private_now(&home) {
                    held.clear();
                }
                match imessage::poll_offloaded(Arc::clone(&gateway), imessage::POLL_LIMIT).await {
                    Ok(report) if report.accepted > 0 => {
                        tracing::info!(accepted = report.accepted, "imessage inbound queued");
                    }
                    Ok(_) => {}
                    Err(err) => tracing::warn!(error = %err, "imessage poll failed"),
                }
                match imessage::receipts_offloaded(Arc::clone(&gateway), imessage::RECEIPT_LIMIT)
                    .await
                {
                    Ok(_) => {}
                    Err(err) => tracing::warn!(error = %err, "imessage read receipts failed"),
                }
            }
        })
    };
    let turns = {
        let stop = stop.subscribe();
        tokio::spawn(async move {
            let mut stop = stop;
            loop {
                let inbound = tokio::select! {
                    inbound = gateway.next_inbound() => inbound,
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() { break; }
                        continue;
                    }
                };
                let Some(inbound) = inbound else {
                    break;
                };
                let Some(session) = imessage::session_for(&home, &store, &gateway) else {
                    continue;
                };
                let content = inbound.text().to_owned();
                let api = api.clone();
                let home = home.clone();
                let gateway = Arc::clone(&gateway);
                tokio::spawn(async move {
                    let held = api.private_answers();
                    imessage::answer_inbound(
                        &home,
                        &gateway,
                        &held,
                        session,
                        content,
                        move |id, text, quiet| match quiet {
                            true => api.run_turn_quiet(id, text),
                            false => api.run_turn(id, text),
                        },
                    )
                    .await;
                });
            }
        })
    };
    MessagesSupervisor {
        stop,
        poller,
        turns,
    }
}

/// Lock the shared store, tolerating a poisoned mutex (a panic elsewhere is
/// not a reason to abandon the daemon).
fn lock_store(store: &Arc<Mutex<Store>>) -> MutexGuard<'_, Store> {
    kernel_core::lock_recover(store)
}
