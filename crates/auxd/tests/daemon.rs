//! End-to-end daemon tests: single-instance lock, prompt SIGTERM and the
//! shutdown-grace descendant sweep.
//!
//! The real `auxd` binary is spawned in a throwaway home, with a fake
//! provider (offline). Tests that need to observe the notifier child run
//! only with the explicit, non-default `test-notify` feature: it points the
//! transport at a shim `osascript` (via `AUXESIS_NOTIFY_OSASCRIPT`) that
//! sleeps to model a slow step of a job. In a default build those tests are
//! ignored, because the transport always runs the real
//! `/usr/bin/osascript` and a test must never show a real notification.
//! No Keychain, launchd or network is involved.

mod common;

use aux_store::{Store, RUN_RUNNING};
use kernel_core::{config_path, store_path};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the daemon may take to become ready or to exit after SIGTERM.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);

struct Sandbox {
    dir: tempfile::TempDir,
    home: PathBuf,
    shim_dir: PathBuf,
    marker: PathBuf,
    pids: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        // A scheduled job runs only in open mode: the default `private` refuses
        // its agent run before any provider is built (agent_job F1), so the
        // turn would never reach a provider or the notifier.
        std::fs::write(
            config_path(&home),
            r#"
            version = 1
            privacy.mode = "open"
            default_agent = "main"

            [[providers]]
            id = "fakey"
            base_url = "http://127.0.0.1:9/v1"
            model = "fake-model"
            kind = "fake"
            "#,
        )
        .unwrap();

        // PATH shim: the daemon's notification call blocks here, modelling a
        // slow step of a turn (the A-03 repro). It records its pid so a test
        // can check whether it outlived the daemon (the A3R repro).
        let shim_dir = dir.path().join("shim");
        std::fs::create_dir_all(&shim_dir).unwrap();
        let marker = dir.path().join("osascript.called");
        let pids = dir.path().join("osascript.pids");
        let shim = shim_dir.join("osascript");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\necho called >> {}\necho $$ >> {}\n/bin/sleep 10\n",
                marker.display(),
                pids.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            dir,
            home,
            shim_dir,
            marker,
            pids,
        }
    }

    /// Point the daemon at an OpenAI-compatible loopback provider.
    fn use_openai_compat_provider(&self, base_url: &str) {
        std::fs::write(
            config_path(&self.home),
            format!(
                "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n\n\
                 [[providers]]\nid = \"local\"\nbase_url = \"{base_url}/v1\"\n\
                 model = \"test-model\"\nkind = \"openai-compat\"\n\n[prices.models.\"test-model\"]\ninput_cents_per_million = 1\noutput_cents_per_million = 1\n"
            ),
        )
        .unwrap();
    }

    fn store(&self) -> Store {
        Store::open(&store_path(&self.home)).unwrap()
    }

    fn daemon_path(&self) -> String {
        format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.shim_dir.display())
    }

    /// Spawn the daemon against this sandbox, isolated from the real home.
    fn spawn(&self) -> Child {
        self.command().spawn().unwrap()
    }

    /// Like [`Sandbox::spawn`], but stdout is piped so a test can watch the
    /// daemon's lifecycle lines ("auxd stopping").
    fn spawn_with_stdout(&self) -> Child {
        self.command().stdout(Stdio::piped()).spawn().unwrap()
    }

    fn command(&self) -> Command {
        let mut command =
            common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), self.dir.path(), &self.home);
        command
            .env("PATH", self.daemon_path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // Only the explicit non-default test seam may point the notifier at
        // the shim; a default build never reads this variable.
        #[cfg(feature = "test-notify")]
        command.env("AUXESIS_NOTIFY_OSASCRIPT", self.shim_dir.join("osascript"));
        command
    }
}

/// Poll `check` until it is true or `timeout` elapses; returns the last value.
fn wait_until(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if check() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn sigterm(child: &Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
}

fn shutdown(child: &mut Child, timeout: Duration) {
    sigterm(child);
    if !wait_until(timeout, || {
        child
            .try_wait()
            .map(|status| status.is_some())
            .unwrap_or(true)
    }) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the daemon did not exit within {timeout:?} of SIGTERM");
    }
}

fn stderr_of(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
}

/// Watch the child's stdout on a background thread; the flag flips to true
/// once a line contains `needle`. The thread also drains the pipe so the
/// daemon can never block writing to it.
fn watch_stdout(child: &mut Child, needle: &'static str) -> Arc<AtomicBool> {
    let seen = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&seen);
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if line.contains(needle) {
                    flag.store(true, Ordering::SeqCst);
                }
            }
        });
    }
    seen
}

/// True while `pid` can be signalled (live, or a zombie not yet reaped).
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Pid list written by the `osascript` shim (`echo $$ >> file`).
fn read_pids(path: &std::path::Path) -> Vec<u32> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .filter_map(|line| line.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Pids whose command line references the sandbox `osascript` shim. Catches a
/// shim that was spawned and orphaned without writing its pid file.
fn surviving_shims(shim_dir: &std::path::Path) -> Vec<u32> {
    let needle = shim_dir.join("osascript");
    let needle = needle.to_string_lossy();
    let output = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=", "-o", "command="])
        .output()
        .expect("/bin/ps");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, command) = line.split_once(char::is_whitespace)?;
            if command.contains(needle.as_ref()) {
                pid.parse().ok()
            } else {
                None
            }
        })
        .collect()
}

/// A minimal blocking OpenAI-compatible server: it accepts one request,
/// records that it arrived, and answers only once released. Used to keep a
/// daemon turn in flight across SIGTERM.
struct DelayedProvider {
    uri: String,
    addr: std::net::SocketAddr,
    accepted: PathBuf,
    release: PathBuf,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl DelayedProvider {
    fn start(dir: &std::path::Path) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = dir.join("provider.accepted");
        let release = dir.join("provider.release");
        let thread_accepted = accepted.clone();
        let thread_release = release.clone();
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = std::fs::write(&thread_accepted, b"1");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let deadline = Instant::now() + Duration::from_secs(20);
            while !thread_release.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let body =
                r#"{"choices":[{"message":{"role":"assistant","content":"released in grace"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
        Self {
            uri: format!("http://{addr}"),
            addr,
            accepted,
            release,
            handle: Some(handle),
        }
    }

    fn release(&self) {
        let _ = std::fs::write(&self.release, b"1");
    }
}

impl Drop for DelayedProvider {
    fn drop(&mut self) {
        // Unblock a listener that never saw a connection, release a parked
        // request, then join: no thread outlives the test.
        let _ = std::net::TcpStream::connect(self.addr);
        self.release();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// SIGTERM while a job's turn is parked in the provider: the daemon must leave
/// in under 3 s instead of waiting for the turn. The provider writes its
/// `accepted` marker on arrival and never answers before the daemon has exited.
#[test]
fn sigterm_exits_promptly_while_a_job_is_blocked() {
    let sandbox = Sandbox::new();
    let provider = DelayedProvider::start(sandbox.dir.path());
    sandbox.use_openai_compat_provider(&provider.uri);
    let job = sandbox
        .store()
        .create_job(
            "main",
            "slow",
            "every 1h",
            r#"{"kind":"agent","prompt":"hello"}"#,
            Some("2000-01-01 00:00:00"),
        )
        .unwrap();
    let job_id = job.id;
    let reader = sandbox.store();
    let mut child = sandbox.spawn();

    // The turn is in flight once the provider holds its request and the run
    // row is `running` (it stays so until the turn returns).
    let blocked = wait_until(READY_TIMEOUT, || {
        provider.accepted.exists()
            && reader
                .runs_for_job(job_id)
                .map(|runs| runs.iter().any(|run| run.status == RUN_RUNNING))
                .unwrap_or(false)
    });
    if !blocked {
        let _ = child.kill();
        let _ = child.wait();
        let stderr = stderr_of(&mut child);
        panic!("the daemon never parked the job's turn in the provider; stderr: {stderr}");
    }

    let started = Instant::now();
    sigterm(&child);
    let exited = wait_until(EXIT_TIMEOUT, || {
        child
            .try_wait()
            .map(|status| status.is_some())
            .unwrap_or(true)
    });
    let elapsed = started.elapsed();
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!("SIGTERM while a job was blocked took longer than {EXIT_TIMEOUT:?}");
    }

    assert!(
        elapsed < Duration::from_secs(3),
        "SIGTERM must exit in < 3 s, took {elapsed:?}"
    );
    // The clean shutdown path ran even though the job never finished.
    assert!(
        reader.event_count("daemon.stopped").unwrap() >= 1,
        "daemon.stopped must be logged"
    );
}

/// Real daemon: a run that finishes during the 500 ms shutdown grace must
/// still have its notifier swept, so no child survives the daemon. Here the
/// provider is held until the daemon has already left its run loop ("auxd
/// stopping" on stdout), then released: the turn finishes inside the grace
/// and its `osascript` shim must be swept before exit.
/// An unrelated sibling process must survive.
#[test]
#[ignore = "obsolete: job notifications now go through NotifyRouter, and the osascript shim runs only when the gateway worker drains its channel (60 s flush), so no blocked run can be observed; needs a new blocking seam"]
fn a_notifier_spawned_during_the_shutdown_grace_is_not_orphaned() {
    let sandbox = Sandbox::new();
    let provider = DelayedProvider::start(sandbox.dir.path());
    sandbox.use_openai_compat_provider(&provider.uri);

    let job = sandbox
        .store()
        .create_job(
            "main",
            "slow",
            "every 1h",
            r#"{"kind":"agent","prompt":"hello"}"#,
            Some("2000-01-01 00:00:00"),
        )
        .unwrap();
    let reader = sandbox.store();

    // A process that is a sibling of the daemon, never a descendant.
    let mut sibling = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut child = sandbox.spawn_with_stdout();
    let stopped = watch_stdout(&mut child, "auxd stopping");

    // The turn must be parked in the provider before SIGTERM...
    let in_flight = wait_until(READY_TIMEOUT, || provider.accepted.exists())
        && wait_until(READY_TIMEOUT, || {
            reader
                .runs_for_job(job.id)
                .map(|runs| runs.iter().any(|run| run.status == RUN_RUNNING))
                .unwrap_or(false)
        });
    if !in_flight {
        let _ = child.kill();
        let _ = child.wait();
        let stderr = stderr_of(&mut child);
        let _ = sibling.kill();
        panic!("the daemon never parked a turn in the provider; stderr: {stderr}");
    }

    // SIGTERM, then release the provider only after the run loop has returned
    // but while the shutdown grace still runs: the notifier shim is born
    // inside the window.
    sigterm(&child);
    let reaching_grace = wait_until(EXIT_TIMEOUT, || stopped.load(Ordering::SeqCst));
    provider.release();

    // The shim announces itself (pid file written before it sleeps); the
    // turn may be released so late that the post-grace sweep kills it before
    // it writes anything, which is fine — the `ps` scan below is the other
    // detector.
    let _ = wait_until(EXIT_TIMEOUT, || sandbox.pids.exists());
    let shim_pids = read_pids(&sandbox.pids);
    let exited = wait_until(EXIT_TIMEOUT, || {
        child
            .try_wait()
            .map(|status| status.is_some())
            .unwrap_or(true)
    });
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Once the daemon process is gone, any surviving shim is an orphan. The
    // short pause lets a just-signalled child be reaped before we look.
    if exited {
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut orphans: Vec<u32> = shim_pids
        .iter()
        .copied()
        .filter(|pid| pid_alive(*pid))
        .collect();
    orphans.extend(surviving_shims(&sandbox.shim_dir));
    orphans.sort_unstable();
    orphans.dedup();
    for pid in &orphans {
        unsafe {
            libc::kill(*pid as i32, libc::SIGKILL);
        }
    }
    let sibling_alive = pid_alive(sibling.id());
    let _ = sibling.kill();
    let _ = sibling.wait();

    assert!(
        reaching_grace,
        "the daemon never logged that it left its run loop"
    );
    assert!(
        exited,
        "the daemon must exit within {EXIT_TIMEOUT:?} of SIGTERM"
    );
    assert!(
        orphans.is_empty(),
        "a notifier spawned during the shutdown grace was orphaned: {orphans:?}"
    );
    assert!(
        sibling_alive,
        "an unrelated sibling process must never be killed"
    );
}

/// Real daemon: the `osascript` shim traps SIGTERM,
/// forks a `sleep 60` from its trap and exits. The forked child is
/// reparented to launchd, so the ppid walk cannot see it — but the daemon
/// took a private process group at startup and every child inherits it, so
/// the group sweep still terminates the escapee before the daemon exits.
#[test]
#[ignore = "obsolete: job notifications now go through NotifyRouter, and the osascript shim runs only when the gateway worker drains its channel (60 s flush), so no blocked run can be observed; needs a new blocking seam"]
fn a_term_trapping_notifier_fork_is_swept_with_the_group() {
    let sandbox = Sandbox::new();

    // Replace the default shim: trap TERM, fork an escapee from the trap,
    // record its pid and exit. This is the exact shape a process uses to escape a ppid walk.
    let shim = sandbox.shim_dir.join("osascript");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho called >> {}\n\
             trap 'sleep 60 & echo $! >> {}; exit 0' TERM\n\
             while :; do sleep 0.05; done\n",
            sandbox.marker.display(),
            sandbox.pids.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

    let job = sandbox
        .store()
        .create_job(
            "main",
            "slow",
            "every 1h",
            r#"{"kind":"agent","prompt":"hello"}"#,
            Some("2000-01-01 00:00:00"),
        )
        .unwrap();
    let reader = sandbox.store();
    let mut child = sandbox.spawn();

    // The daemon is blocked inside the turn once the trap shim is entered.
    let blocked = wait_until(READY_TIMEOUT, || {
        sandbox.marker.exists()
            && reader
                .runs_for_job(job.id)
                .map(|runs| runs.iter().any(|run| run.status == RUN_RUNNING))
                .unwrap_or(false)
    });
    if !blocked {
        let _ = child.kill();
        let _ = child.wait();
        let stderr = stderr_of(&mut child);
        panic!("the daemon never reached the blocked job; stderr: {stderr}");
    }

    sigterm(&child);
    let exited = wait_until(EXIT_TIMEOUT, || {
        child
            .try_wait()
            .map(|status| status.is_some())
            .unwrap_or(true)
    });
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }

    // The trap forks and exits while the sweep runs: the pid file appears
    // before the daemon is done. Read it, then verify the escapee is gone.
    let _ = wait_until(EXIT_TIMEOUT, || !read_pids(&sandbox.pids).is_empty());
    let forked = read_pids(&sandbox.pids);
    let swept = wait_until(EXIT_TIMEOUT, || forked.iter().all(|pid| !pid_alive(*pid)));
    for pid in &forked {
        if pid_alive(*pid) {
            unsafe {
                libc::kill(*pid as i32, libc::SIGKILL);
            }
        }
    }

    assert!(exited, "the daemon must exit within {EXIT_TIMEOUT:?}");
    assert!(
        !forked.is_empty(),
        "the shim never trapped SIGTERM and forked its escapee"
    );
    assert!(
        swept,
        "a forked child that reparented to launchd must be swept with the group: {forked:?}"
    );
}

#[test]
fn a_second_daemon_refuses_to_start() {
    let sandbox = Sandbox::new();
    let mut first = sandbox.spawn_with_stdout();

    // Wait on the daemon's own readiness line, never on a store
    // poll. Polling `sandbox.store()` in a tight loop opens and drops a
    // connection repeatedly, so the closing connection unlinks the
    // `store.db-wal`/`store.db-shm` sidecars; the daemon's startup symlink
    // scan does `readdir` then `fstatat` per entry, and a sidecar unlinked
    // inside that window makes `ensure_home` fail with ENOENT — the daemon
    // exited ("auxd: No such file or directory") before it could log
    // readiness. `auxd ready` is printed *after* `daemon.started` is
    // committed, so the readiness signal keeps the same strength.
    let ready = watch_stdout(&mut first, "auxd ready");
    if !wait_until(READY_TIMEOUT, || ready.load(Ordering::SeqCst)) {
        let _ = first.kill();
        let _ = first.wait();
        let stderr = stderr_of(&mut first);
        panic!("the first daemon never started; stderr: {stderr}");
    }
    // The daemon now holds its own store, so the sidecars stay in place; a
    // single assertion read after readiness cannot race its startup scan.
    assert!(
        sandbox
            .store()
            .event_count("daemon.started")
            .map(|count| count >= 1)
            .unwrap_or(false),
        "the first daemon must log daemon.started"
    );

    let mut second = sandbox.spawn();
    let exited = wait_until(Duration::from_secs(5), || {
        second
            .try_wait()
            .map(|status| status.is_some())
            .unwrap_or(true)
    });
    if !exited {
        let _ = second.kill();
        let _ = second.wait();
        panic!("the second daemon kept running instead of refusing the lock");
    }
    let status = second.wait().unwrap();
    assert!(!status.success(), "the second daemon must fail: {status}");
    let stderr = stderr_of(&mut second);
    assert!(
        stderr.contains("already running"),
        "the refusal must explain itself, got: {stderr}"
    );

    shutdown(&mut first, EXIT_TIMEOUT);
}

/// A `.auxesis` under the *sandbox* HOME is exactly the
/// invocation the tripwire recommends — `auxd` must start (the old test
/// pinned the inverted behaviour). Refusing the real `~/.auxesis` is
/// unit-tested in `kernel_core::paths`; no daemon is ever pointed at it here.
#[test]
fn sandbox_tripwire_allows_a_lookalike_under_the_sandbox_home() {
    let dir = tempfile::tempdir().unwrap();
    let lookalike = dir.path().join(".auxesis");
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir.path(), &lookalike)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let ready = watch_stdout(&mut child, "auxd ready");
    if !wait_until(READY_TIMEOUT, || ready.load(Ordering::SeqCst)) {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "auxd refused a sandbox home; stderr: {}",
            stderr_of(&mut child)
        );
    }
    assert!(
        lookalike.join("store.db").exists(),
        "the accepted daemon must create its store under the sandbox home"
    );
    shutdown(&mut child, EXIT_TIMEOUT);
}

/// Read the ephemeral API port the daemon announces on stdout ("auxd api on
/// http://127.0.0.1:<port>"). The reader thread drains the pipe to EOF.
fn wait_for_api_port(child: &mut Child, timeout: Duration) -> Option<u16> {
    let stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(rest) = line.strip_prefix("auxd api on http://127.0.0.1:") {
                    if let Ok(port) = rest.trim().parse::<u16>() {
                        return Some(port);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// Restart-after-SIGKILL: a brutal kill writes no shutdown record and runs no
/// cleanup. The kernel still drops the `flock`, so a second daemon on the same
/// `AUXESIS_HOME` must acquire the lock, re-run the idempotent migration ladder
/// without error, and serve the API again with the store's rows intact.
///
/// The sandbox is a `tempfile::TempDir`; dropping it at the end of the test
/// removes the whole home (the second daemon is shut down first, so nothing is
/// left running or on disk).
#[test]
fn a_sigkilled_daemon_restarts_cleanly_on_the_same_home() {
    let sandbox = Sandbox::new();
    let expected_schema = aux_store::SCHEMA_VERSION;

    // Seed a row so "the store survived" has something concrete to check. A
    // far-future next_run keeps the scheduler from claiming it.
    let job = sandbox
        .store()
        .create_job(
            "main",
            "restart-probe",
            "every 1h",
            r#"{"kind":"agent","prompt":"hello"}"#,
            Some("2999-01-01 00:00:00"),
        )
        .unwrap();

    // --- first run: ready, API answers, schema migrated ---
    let mut first = common::KillOnDrop::new(sandbox.spawn_with_stdout());
    let first_port = match wait_for_api_port(&mut first, READY_TIMEOUT) {
        Some(port) => port,
        None => {
            let _ = first.kill();
            let _ = first.wait();
            panic!(
                "the first daemon never announced the API; stderr: {}",
                stderr_of(&mut first)
            );
        }
    };
    let first_addr: SocketAddr = format!("127.0.0.1:{first_port}").parse().unwrap();
    let token = std::fs::read_to_string(auxd::api::token_path(&sandbox.home))
        .unwrap()
        .trim()
        .to_string();
    let health = common::get(first_addr, "/v1/health", Some(&token));
    assert_eq!(health.status, 200, "first /v1/health body: {}", health.body);
    assert_eq!(health.json()["pid"].as_u64().unwrap() as u32, first.id());

    // --- brutal kill: no shutdown path at all ---
    unsafe {
        libc::kill(first.id() as i32, libc::SIGKILL);
    }
    let status = first.wait().unwrap();
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the first daemon must die by SIGKILL, got {status}"
    );

    // --- second run on the SAME home ---
    let mut second = common::KillOnDrop::new(sandbox.spawn_with_stdout());
    let second_port = match wait_for_api_port(&mut second, READY_TIMEOUT) {
        Some(port) => port,
        None => {
            let _ = second.kill();
            let _ = second.wait();
            panic!(
                "the daemon did not restart on the killed home; stderr: {}",
                stderr_of(&mut second)
            );
        }
    };
    let second_addr: SocketAddr = format!("127.0.0.1:{second_port}").parse().unwrap();
    let token = std::fs::read_to_string(auxd::api::token_path(&sandbox.home))
        .unwrap()
        .trim()
        .to_string();
    let health = common::get(second_addr, "/v1/health", Some(&token));
    assert_eq!(
        health.status, 200,
        "restart /v1/health body: {}",
        health.body
    );
    assert_eq!(
        health.json()["pid"].as_u64().unwrap() as u32,
        second.id(),
        "the restarted daemon must serve its own pid"
    );

    // A failed migration exits the daemon before the API line; the surviving
    // schema version and row prove the store came back clean.
    let store = sandbox.store();
    assert_eq!(store.schema_version().unwrap(), expected_schema);
    assert!(
        store.job_by_id(job.id).unwrap().is_some(),
        "the seeded job must survive the kill"
    );
    assert!(
        store.event_count("daemon.started").unwrap() >= 2,
        "both daemons must have logged daemon.started"
    );

    shutdown(&mut second, EXIT_TIMEOUT);
}

/// The kill-on-drop guard must actually reap the child it wraps: a released
/// guard leaves no live pid, so a panicking test can never orphan a daemon
/// after its `TempDir` home has been removed.
#[test]
fn a_released_kill_on_drop_guard_kills_its_child() {
    let child = common::KillOnDrop::new(
        Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = child.id() as i32;
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        0,
        "the wrapped child must be alive before the guard is released"
    );

    drop(child);

    assert!(
        wait_until(Duration::from_secs(5), || unsafe {
            libc::kill(pid, 0) != 0
        }),
        "a released guard must kill and reap pid {pid}"
    );
}

/// Start the sandbox daemon, wait until it serves the API, then stop it.
fn start_and_stop(sandbox: &Sandbox) {
    let mut child = common::KillOnDrop::new(sandbox.spawn_with_stdout());
    if wait_for_api_port(&mut child, READY_TIMEOUT).is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "the daemon never announced the API; stderr: {}",
            stderr_of(&mut child)
        );
    }
    shutdown(&mut child, EXIT_TIMEOUT);
}

/// A home made before the invite shipped holds only the
/// Calendar agent's soul. At start the daemon adds the shipped agent.md and
/// send-invite skill, so the agent offers `skill__send-invite`; the soul stays
/// byte-identical, and a later start keeps an edited agent.md as it is.
#[test]
fn a_soul_only_calendar_home_gets_the_invite_files_at_start() {
    let sandbox = Sandbox::new();
    let agent_dir = sandbox.home.join("agents").join("calendar");
    std::fs::create_dir_all(&agent_dir).unwrap();
    let soul = "# Calendar\nThe owner's own words.\n";
    std::fs::write(agent_dir.join("soul.md"), soul).unwrap();

    start_and_stop(&sandbox);
    assert!(
        agent_dir.join("agent.md").is_file(),
        "the daemon must add the Calendar agent.md at start"
    );
    let skill = std::fs::read(agent_dir.join("skills").join("send-invite.md"))
        .expect("the daemon must add skills/send-invite.md at start");
    assert_eq!(
        skill,
        include_bytes!("../../aux-runtime/src/skills/fixtures/skills/send-invite.md"),
        "the shipped skill is the one the hero tests run"
    );
    assert_eq!(
        std::fs::read_to_string(agent_dir.join("soul.md")).unwrap(),
        soul
    );
    let agent = aux_runtime::skills::load_agent(&agent_dir).unwrap();
    let load = aux_runtime::skills::load_skills(&agent_dir, &agent, None);
    assert!(load.errors.is_empty(), "{:?}", load.errors);
    let offered: Vec<String> = load
        .skills
        .iter()
        .map(|skill| aux_runtime::skills::skill_tool_name(&skill.name))
        .collect();
    assert_eq!(offered, ["skill__move-event", "skill__send-invite"]);

    // The owner edits agent.md; the next start leaves every file as it is.
    let edited = "---\nname: calendar\ntools: [calendar.list_events]\n---\nMine.\n";
    std::fs::write(agent_dir.join("agent.md"), edited).unwrap();
    start_and_stop(&sandbox);
    assert_eq!(
        std::fs::read_to_string(agent_dir.join("agent.md")).unwrap(),
        edited
    );
    assert_eq!(
        std::fs::read(agent_dir.join("skills").join("send-invite.md")).unwrap(),
        skill
    );
    assert_eq!(
        std::fs::read_to_string(agent_dir.join("soul.md")).unwrap(),
        soul
    );
}
