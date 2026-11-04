//! End-to-end ACP tests against the fake agent binary (`acp-fake-agent`).
//!
//! The fake agent speaks real JSON-RPC over stdio; the tests exercise the
//! whole stack: supervisor (env/sandbox/reaping), framing caps, the client
//! handshake and prompt pump, broker-backed `fs/*` and `terminal/*`, the
//! approval flow, cancellation and the backend's persistence/budget path.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aux_acp::backend::{AcpBackend, AcpBackendConfig, AcpTurnRequest, AgentBackend};
use aux_acp::client::{AcpClient, NullObserver, TurnObserver};
use aux_acp::config::{AcpAgentSpec, AcpLimits};
use aux_acp::handlers::{HandlerLimits, TurnState};
use aux_acp::ledger::StoreTurnHost;
use aux_acp::protocol::{PlanEntry, ToolCallUpdate};
use aux_acp::{AcpError, SupervisorSpec, ACP_UNTRUSTED_TAG};
use aux_store::Store;
use kernel_broker::sandbox::ShellSandbox;
use kernel_broker::{ApprovalRequest, Approver, ApproverError, CancelToken};
use kernel_core::budget::{Budgets, UsageKind};
use kernel_privacy::SafeText;

fn safe(text: &str) -> SafeText {
    let grant = kernel_core::privacy::admit_call(
        kernel_core::privacy::PathId::C9,
        kernel_core::privacy::PrivacyMode::Private,
        kernel_core::privacy::Destination::LocalDisplay,
    )
    .expect("C9 is covered in private mode");
    kernel_privacy::Gate::for_tests(&grant, [7u8; 32], aux_providers::test_gate::names_checked())
        .text(text)
        .unwrap()
        .0
}

// ---- helpers ----

struct TestEnv {
    /// Keeps the temp tree alive; the path is read by the macOS-gated
    /// sandbox tests.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    workspace: PathBuf,
}

fn test_env() -> TestEnv {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    TestEnv { dir, workspace }
}

/// Sandbox used by tests: the real Seatbelt profile on macOS (so the sandbox
/// tests are real), the explicit unsandboxed opt-in elsewhere (CI Linux has
/// no `sandbox-exec`; the fail-closed path is covered by unit tests).
fn test_sandbox() -> ShellSandbox {
    if cfg!(target_os = "macos") {
        ShellSandbox::default()
    } else {
        ShellSandbox::new(false, false, true)
    }
}

/// The compiled fake agent. It is a bin of this package, so `cargo test`
/// builds it and exports its path as `CARGO_BIN_EXE_…`; the assert names the
/// one-liner for a direct test-binary run that skipped that build.
fn fake_agent_binary() -> PathBuf {
    let source = PathBuf::from(env!("CARGO_BIN_EXE_acp-fake-agent"));
    assert!(
        source.is_file(),
        "the fake agent {} is missing; build it with \
         `cargo build -p aux-acp --bin acp-fake-agent`",
        source.display()
    );
    source
}

fn copy_fake_agent(workspace: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COPY_SEQ: AtomicU64 = AtomicU64::new(0);

    let source = fake_agent_binary();
    // Every spec gets its own copy under a unique name. A fixed destination is
    // rewritten by the second `start_client` of a test while the first child
    // may still be executing it, and a `fork` in a parallel test can inherit
    // the write fd; either race surfaces as ETXTBSY ("Text file busy") on the
    // next exec. A fresh inode per copy removes the shared writer entirely.
    let seq = COPY_SEQ.fetch_add(1, Ordering::Relaxed);
    let destination = workspace.join(format!("fake-agent-{}-{seq}", std::process::id()));
    std::fs::copy(&source, &destination).expect("copying the fake agent");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    destination
}

fn spec_for(env: &TestEnv, scenario: &str, arg: Option<&str>) -> SupervisorSpec {
    let agent = copy_fake_agent(&env.workspace);
    let mut spec = SupervisorSpec::new(agent.to_string_lossy().to_string(), env.workspace.clone());
    spec.args = match arg {
        Some(arg) => vec![scenario.to_string(), arg.to_string()],
        None => vec![scenario.to_string()],
    };
    spec.sandbox = test_sandbox();
    spec.kill_grace = Duration::from_millis(500);
    // `RLIMIT_NPROC` is a *per-user* total on macOS and Linux, and these tests
    // share the user with every other build and process on the machine. The
    // production default adds a fixed 64-process headroom over the live count
    // observed at spawn; under a parallel suite that headroom is already gone
    // and the child fails to fork ("Cannot fork"), so the pid file never
    // appears. Tests disable the cap; the dedicated fork-bomb test in
    // `supervisor.rs` keeps its own real limit to prove the cap still works.
    spec.max_processes = 0;
    spec
}

fn test_limits() -> AcpLimits {
    AcpLimits {
        turn_timeout: Duration::from_secs(30),
        // `RLIMIT_NPROC` is a per-user total and these tests share the user
        // with the whole machine; a fixed headroom over the live count is
        // exhausted under a parallel suite, so the agent cannot fork and its
        // pid file never appears. Disabled for tests only (the backend builds
        // its spec from these limits); `supervisor.rs` keeps the fork-bomb
        // test's own real cap.
        max_processes: 0,
        ..AcpLimits::default()
    }
}

fn handler_limits() -> HandlerLimits {
    HandlerLimits {
        sandbox: test_sandbox(),
        permission_timeout: Duration::from_secs(5),
        ..HandlerLimits::default()
    }
}

async fn start_client(
    env: &TestEnv,
    scenario: &str,
    arg: Option<&str>,
    approver: Arc<dyn Approver>,
) -> AcpClient {
    start_client_with(
        env,
        scenario,
        arg,
        approver,
        handler_limits(),
        test_limits(),
    )
    .await
}

async fn start_client_with(
    env: &TestEnv,
    scenario: &str,
    arg: Option<&str>,
    approver: Arc<dyn Approver>,
    handlers: HandlerLimits,
    limits: AcpLimits,
) -> AcpClient {
    let spec = spec_for(env, scenario, arg);
    start_acp(&spec, &limits, approver, handlers).await
}

/// Spawn an ACP client, retrying a transient `ETXTBSY`.
///
/// Linux refuses to `exec` a file that any process holds open for writing. The
/// fake agent is copied per test and `Command::spawn` forks with a `pre_exec`
/// hook, so a `fork` in a parallel test can inherit the write fd of this test's
/// in-flight copy; the exec then fails with `ETXTBSY` ("Text file busy") until
/// that sibling reaches its own exec and closes the inherited fd. Every other
/// spawn error is reported immediately.
async fn start_acp(
    spec: &SupervisorSpec,
    limits: &AcpLimits,
    approver: Arc<dyn Approver>,
    handlers: HandlerLimits,
) -> AcpClient {
    const ATTEMPTS: usize = 50;
    for attempt in 0..ATTEMPTS {
        match AcpClient::start(
            spec,
            "main",
            limits,
            approver.clone(),
            handlers.clone(),
            Arc::new(TurnState::default()),
            false,
        )
        .await
        {
            Ok(client) => return client,
            Err(AcpError::Spawn(err))
                if err.raw_os_error() == Some(libc::ETXTBSY) && attempt + 1 < ATTEMPTS =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(err) => panic!("starting the ACP client: {err:?}"),
        }
    }
    unreachable!("the ETXTBSY retry loop must return or panic")
}

/// Canned approver recording every request.
struct CannedApprover {
    decisions: Mutex<Vec<bool>>,
    seen: Mutex<Vec<ApprovalRequest>>,
}

impl CannedApprover {
    fn new(decisions: Vec<bool>) -> Arc<Self> {
        Arc::new(Self {
            decisions: Mutex::new(decisions),
            seen: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl Approver for CannedApprover {
    async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
        self.seen.lock().unwrap().push(request.clone());
        Ok(self.decisions.lock().unwrap().pop().unwrap_or(false))
    }
}

struct SlowApprover;

#[async_trait::async_trait]
impl Approver for SlowApprover {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(true)
    }
}

/// Approves after a delay: models the owner reading the approval card while
/// the agent acts.
struct DelayedApprover {
    delay: Duration,
}

#[async_trait::async_trait]
impl Approver for DelayedApprover {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        tokio::time::sleep(self.delay).await;
        Ok(true)
    }
}

/// The agent text with the untrusted tag stripped, for exact assertions.
fn untagged(text: &str) -> &str {
    let body = text.strip_prefix(ACP_UNTRUSTED_TAG).unwrap_or(text);
    body.strip_prefix('\n').unwrap_or(body)
}

/// Known-secret registry tests must not run concurrently in this binary.
fn secret_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

#[derive(Default)]
struct RecordingObserver {
    chunks: Vec<String>,
    thoughts: Vec<String>,
    tools: Vec<ToolCallUpdate>,
    plans: Vec<Vec<PlanEntry>>,
}

impl TurnObserver for RecordingObserver {
    fn message_chunk(&mut self, chunk: &str) {
        self.chunks.push(chunk.to_string());
    }

    fn thought_chunk(&mut self, chunk: &str) {
        self.thoughts.push(chunk.to_string());
    }

    fn tool_call(&mut self, call: &ToolCallUpdate) {
        self.tools.push(call.clone());
    }

    fn plan(&mut self, entries: &[PlanEntry]) {
        self.plans.push(entries.to_vec());
    }
}

fn process_gone(pid: i32) -> bool {
    // A killed process may briefly be a zombie; poll until it is reaped.
    for _ in 0..200 {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn read_pid(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
}

async fn wait_for_pid(path: &Path) -> i32 {
    for _ in 0..400 {
        if let Some(pid) = read_pid(path) {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("pid file {} never appeared", path.display());
}

// ---- handshake, streaming, tool calls, plan ----

#[tokio::test]
async fn handshake_and_streaming_turn() {
    let env = test_env();
    let mut client = start_client(&env, "happy", None, CannedApprover::new(vec![])).await;
    assert_eq!(client.session_id(), "sess-1");
    let outcome = client
        .prompt(&safe("say hi"), None, &mut NullObserver)
        .await
        .unwrap();
    assert_eq!(untagged(&outcome.text), "hello world");
    assert_eq!(outcome.stop_reason.as_deref(), Some("end_turn"));
    assert_eq!(outcome.usage.used, Some(42));
    assert_eq!(outcome.usage.size, Some(1000));
    assert_eq!(outcome.stats.chunks, 2);
    client.shutdown().await;
    assert!(!client.is_running(), "the agent must be reaped");
}

#[tokio::test]
async fn tool_calls_and_plans_stream_to_the_observer() {
    let env = test_env();
    let mut client = start_client(&env, "tool", None, CannedApprover::new(vec![])).await;
    let mut observer = RecordingObserver::default();
    let outcome = client
        .prompt(&safe("use a tool"), None, &mut observer)
        .await
        .unwrap();
    assert_eq!(untagged(&outcome.text), "workingdone");
    assert_eq!(outcome.stats.tool_calls, 2);
    assert_eq!(observer.tools.len(), 2);
    assert_eq!(observer.tools[0].id, "t1");
    assert_eq!(observer.tools[1].status.as_deref(), Some("completed"));
    client.shutdown().await;

    let mut client = start_client(&env, "plan", None, CannedApprover::new(vec![])).await;
    let mut observer = RecordingObserver::default();
    client
        .prompt(&safe("plan"), None, &mut observer)
        .await
        .unwrap();
    assert_eq!(observer.plans.len(), 1);
    assert_eq!(observer.plans[0][0].content, "step one");
    client.shutdown().await;
}

#[tokio::test]
async fn thoughts_stream_but_stay_out_of_the_answer() {
    let env = test_env();
    let mut client = start_client(&env, "happy", None, CannedApprover::new(vec![])).await;
    let mut observer = RecordingObserver::default();
    client
        .prompt(&safe("hi"), None, &mut observer)
        .await
        .unwrap();
    assert!(observer.thoughts.is_empty());
    client.shutdown().await;
}

// ---- permissions ----

#[tokio::test]
async fn permission_approved_maps_to_allow_once() {
    let env = test_env();
    let approver = CannedApprover::new(vec![true]);
    let mut client = start_client(&env, "permission", None, approver.clone()).await;
    let outcome = client
        .prompt(&safe("do it"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("selected"), "{}", outcome.text);
    assert!(outcome.text.contains("a1"), "{}", outcome.text);
    {
        let seen = approver.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].tool, "acp.permission");
        assert!(seen[0].tainted, "agent output taints the ask");
    }
    client.shutdown().await;
}

#[tokio::test]
async fn permission_denied_maps_to_reject_once() {
    let env = test_env();
    let approver = CannedApprover::new(vec![false]);
    let mut client = start_client(&env, "permission", None, approver.clone()).await;
    let outcome = client
        .prompt(&safe("do it"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("r1"), "{}", outcome.text);
    client.shutdown().await;
}

#[tokio::test]
async fn permission_timeout_fails_closed() {
    let env = test_env();
    let handlers = HandlerLimits {
        permission_timeout: Duration::from_millis(100),
        ..handler_limits()
    };
    let mut client = start_client_with(
        &env,
        "permission",
        None,
        Arc::new(SlowApprover),
        handlers,
        test_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("do it"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("r1"), "{}", outcome.text);
    client.shutdown().await;
}

// ---- fs broker ----

#[tokio::test]
async fn fs_read_inside_workspace_works_and_outside_is_refused() {
    let env = test_env();
    let inside = env.workspace.join("notes.txt");
    std::fs::write(&inside, "hello").unwrap();
    let mut client = start_client(
        &env,
        "fs-read",
        Some(&inside.display().to_string()),
        CannedApprover::new(vec![]),
    )
    .await;
    let outcome = client
        .prompt(&safe("read"), None, &mut NullObserver)
        .await
        .unwrap();
    assert_eq!(untagged(&outcome.text), "read=hello");
    client.shutdown().await;

    // Outside the workspace.
    let outside = tempfile::NamedTempFile::new().unwrap();
    let outside_path = outside.path().canonicalize().unwrap();
    let mut client = start_client(
        &env,
        "fs-read",
        Some(&outside_path.display().to_string()),
        CannedApprover::new(vec![]),
    )
    .await;
    let outcome = client
        .prompt(&safe("read"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(
        outcome.text.contains("read-error=error:-32602"),
        "{}",
        outcome.text
    );
    client.shutdown().await;
}

#[tokio::test]
async fn fs_read_through_a_symlink_escape_is_refused() {
    let env = test_env();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let link = env.workspace.join("escape.txt");
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    let mut client = start_client(
        &env,
        "fs-read",
        Some(&link.display().to_string()),
        CannedApprover::new(vec![]),
    )
    .await;
    let outcome = client
        .prompt(&safe("read"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(
        outcome.text.contains("read-error=error:-32602"),
        "{}",
        outcome.text
    );
    client.shutdown().await;
}

#[tokio::test]
async fn fs_write_is_never_auto_approved() {
    let env = test_env();
    let target = env.workspace.join("agent.txt");
    let approver = CannedApprover::new(vec![false]);
    let mut client = start_client(
        &env,
        "fs-write",
        Some(&target.display().to_string()),
        approver,
    )
    .await;
    let outcome = client
        .prompt(&safe("write"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("write-error"), "{}", outcome.text);
    assert!(!target.exists(), "a denied write must not touch the disk");
    client.shutdown().await;

    let approver = CannedApprover::new(vec![true]);
    let mut client = start_client(
        &env,
        "fs-write",
        Some(&target.display().to_string()),
        approver,
    )
    .await;
    let outcome = client
        .prompt(&safe("write"), None, &mut NullObserver)
        .await
        .unwrap();
    assert_eq!(untagged(&outcome.text), "write=ok");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "written-by-agent"
    );
    client.shutdown().await;
}

#[tokio::test]
async fn fs_write_symlink_swap_during_approval_escapes_nothing() {
    let env = test_env();
    let target = env.workspace.join("victim.txt");
    let outside_dir = tempfile::tempdir().unwrap();
    let outside = outside_dir.path().join("outside.txt");
    std::fs::write(&outside, "original").unwrap();
    let args =
        serde_json::to_string(&[target.display().to_string(), outside.display().to_string()])
            .unwrap();
    let mut client = start_client_with(
        &env,
        "fs-write-race",
        Some(&args),
        Arc::new(DelayedApprover {
            delay: Duration::from_millis(500),
        }),
        handler_limits(),
        test_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("write"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    assert!(
        outcome.text.contains("swap=ok"),
        "the test needs the agent to have swapped the path: {}",
        outcome.text
    );
    assert!(
        outcome.text.contains("write-error"),
        "the swapped write must fail: {}",
        outcome.text
    );
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "original",
        "the outside canary must never be written"
    );
}

// ---- terminals ----

#[tokio::test]
async fn terminal_create_wait_and_output() {
    let env = test_env();
    if !test_sandbox().available() {
        return; // The broker refuses unsandboxed terminals; macOS-only path.
    }
    let mut client = start_client(&env, "terminal", None, CannedApprover::new(vec![])).await;
    let outcome = client
        .prompt(&safe("run"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("exit=0"), "{}", outcome.text);
    assert!(outcome.text.contains("terminal-ok"), "{}", outcome.text);
    client.shutdown().await;
}

#[tokio::test]
async fn terminal_kill_is_refused_safely() {
    let env = test_env();
    if !test_sandbox().available() {
        return; // The broker refuses unsandboxed terminals; macOS-only path.
    }
    let mut client = start_client(&env, "terminal-kill", None, CannedApprover::new(vec![])).await;
    let outcome = client
        .prompt(&safe("run"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("killed=true"), "{}", outcome.text);
    client.shutdown().await;
}

// ---- cancellation and reaping ----

#[tokio::test]
async fn cancellation_kills_the_whole_agent_tree() {
    let env = test_env();
    let pidfile = env.workspace.join("child.pid");
    let spec = spec_for(&env, "spawn-child", Some(&pidfile.display().to_string()));
    let cancel = CancelToken::new();
    let cancel_task = {
        let cancel = Arc::clone(&cancel);
        let pidfile = pidfile.clone();
        tokio::spawn(async move {
            wait_for_pid(&pidfile).await;
            cancel.cancel();
        })
    };
    let mut client = start_acp(
        &spec,
        &test_limits(),
        CannedApprover::new(vec![]),
        handler_limits(),
    )
    .await;
    let agent_pid = client.pid() as i32;
    let result = client
        .prompt(&safe("start a child"), Some(cancel), &mut NullObserver)
        .await;
    assert!(matches!(result, Err(AcpError::Cancelled)), "{result:?}");
    let child_pid = wait_for_pid(&pidfile).await;
    client.shutdown().await;
    cancel_task.await.unwrap();
    assert!(process_gone(child_pid), "the orphaned child must be reaped");
    assert!(process_gone(agent_pid), "the agent must be reaped");
}

#[tokio::test]
async fn agent_crash_is_an_error_not_a_hang() {
    let env = test_env();
    let mut client = start_client(&env, "crash", None, CannedApprover::new(vec![])).await;
    let result = client.prompt(&safe("boom"), None, &mut NullObserver).await;
    assert!(
        matches!(
            result,
            Err(AcpError::Disconnected) | Err(AcpError::Rpc { .. })
        ),
        "{result:?}"
    );
    client.shutdown().await;
}

#[tokio::test]
async fn orphan_grandchild_with_closed_fds_does_not_survive_shutdown() {
    let env = test_env();
    let pidfile = env.workspace.join("grandchild.pid");
    let mut client = start_client(
        &env,
        "orphan-fdcless",
        Some(&pidfile.display().to_string()),
        CannedApprover::new(vec![]),
    )
    .await;
    let outcome = client
        .prompt(&safe("go"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("orphan-started"), "{}", outcome.text);
    let grandchild = wait_for_pid(&pidfile).await;
    client.shutdown().await;
    assert!(
        process_gone(grandchild),
        "the fd-closed orphan must not survive the reaper"
    );
}

#[tokio::test]
async fn env_marked_grandchildren_do_not_survive_shutdown() {
    // GLM round-2 F2: mid→grandchild (setsid, close fds, chdir out) with the
    // mid exiting immediately. The per-turn environment marker is the anchor.
    let env = test_env();
    let pidfile = env.workspace.join("orphans.pid");
    let mut client = start_client(
        &env,
        "orphan-envmarker",
        Some(&pidfile.display().to_string()),
        CannedApprover::new(vec![]),
    )
    .await;
    let outcome = client
        .prompt(&safe("go"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("orphans-started"), "{}", outcome.text);
    let mut pids = Vec::new();
    for _ in 0..200 {
        pids = std::fs::read_to_string(&pidfile)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.trim().parse::<i32>().ok())
            .collect();
        if pids.len() >= 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!pids.is_empty(), "the orphans must record their pids");
    client.shutdown().await;
    for pid in &pids {
        assert!(
            process_gone(*pid),
            "the env-marked grandchild {pid} must not survive the reaper"
        );
    }
}

#[tokio::test]
async fn fs_read_control_heavy_reply_still_reaches_the_agent() {
    // GLM round-2 F1: a NUL-heavy file's JSON-escaped reply exceeds the
    // outbound frame cap; the broker must answer (truncated), never hang.
    let env = test_env();
    let binary = env.workspace.join("binary.bin");
    std::fs::write(&binary, vec![0u8; 200 * 1024]).unwrap();
    let limits = AcpLimits {
        turn_timeout: Duration::from_secs(5),
        ..test_limits()
    };
    let mut client = start_client_with(
        &env,
        "fs-read-len",
        Some(&binary.display().to_string()),
        CannedApprover::new(vec![]),
        handler_limits(),
        limits,
    )
    .await;
    let outcome = client
        .prompt(&safe("read"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    assert!(
        outcome.text.contains("read-len="),
        "the reply must reach the agent: {}",
        outcome.text
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // serializes the global known-secret registry
async fn split_secret_never_reaches_the_answer_or_the_observers() {
    // The canary is split across consecutive frames of every
    // agent-originated stream.
    let _guard = secret_test_lock();
    kernel_broker::scrub::clear_known_secrets();
    let canary = "CANARY_ACP_STREAM_0123456789abcdef";
    kernel_broker::scrub::register_known_secret(canary);
    let env = test_env();
    let mut client = start_client(&env, "secret-split", None, CannedApprover::new(vec![])).await;
    let mut observer = RecordingObserver::default();
    let outcome = client
        .prompt(&safe("go"), None, &mut observer)
        .await
        .unwrap();
    client.shutdown().await;
    assert!(!outcome.text.contains(canary), "{}", outcome.text);
    let thoughts = observer.thoughts.join("");
    assert!(!thoughts.contains(canary), "{thoughts}");
    let tools = observer
        .tools
        .iter()
        .map(|call| format!("{call:?}"))
        .collect::<String>();
    assert!(!tools.contains(canary), "{tools}");
    let plans = observer
        .plans
        .iter()
        .flat_map(|entries| entries.iter().map(|entry| entry.content.clone()))
        .collect::<String>();
    assert!(!plans.contains(canary), "{plans}");

    // The persisted assistant row must be scrubbed too.
    let (mut backend, store, session_id) =
        backend_for_scenario(&env, test_limits(), "secret-split", None);
    let result = backend
        .run_turn(
            AcpTurnRequest {
                prompt: safe("go"),
                cancel: None,
                turns_used: 0,
            },
            &mut NullObserver,
        )
        .await
        .unwrap();
    kernel_broker::scrub::clear_known_secrets();
    assert!(!result.text.contains(canary), "{}", result.text);
    let guard = store.lock().unwrap();
    let rows = guard.list_messages(session_id).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].content.contains(canary), "{}", rows[0].content);
}

// ---- framing robustness and hygiene ----

#[tokio::test]
async fn malformed_and_oversized_frames_do_not_break_the_turn() {
    let env = test_env();
    let mut client = start_client(&env, "malformed", None, CannedApprover::new(vec![])).await;
    let outcome = client
        .prompt(&safe("go"), None, &mut NullObserver)
        .await
        .unwrap();
    assert_eq!(untagged(&outcome.text), "survived");
    client.shutdown().await;
}

#[tokio::test]
async fn stderr_secrets_are_scrubbed_before_storage() {
    let env = test_env();
    let mut client = start_client(&env, "stderr-secret", None, CannedApprover::new(vec![])).await;
    client
        .prompt(&safe("go"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    let stderr = client.stderr_lines().join("\n");
    assert!(
        !stderr.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
        "raw secret in stderr: {stderr}"
    );
    assert!(
        stderr.contains("<redacted>"),
        "expected a redaction: {stderr}"
    );
}

#[tokio::test]
async fn child_environment_has_no_aux_keys_and_no_auxesis_home() {
    let env = test_env();
    // A canary in our own environment: the child must not see it.
    std::env::set_var("AUX_KEY_ACP_INTEGRATION_TEST", "canary");
    let mut client = start_client(&env, "env", None, CannedApprover::new(vec![])).await;
    let outcome = client
        .prompt(&safe("report"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    std::env::remove_var("AUX_KEY_ACP_INTEGRATION_TEST");
    assert!(outcome.text.contains("aux_keys=0"), "{}", outcome.text);
    assert!(outcome.text.contains(".acp-home"), "{}", outcome.text);
    assert!(outcome.text.contains(".acp-tmp"), "{}", outcome.text);
    assert!(
        !outcome.text.contains("canary"),
        "the canary leaked: {}",
        outcome.text
    );
}

// ---- real sandbox (macOS) ----

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sandbox_runs_an_agent_installed_outside_the_workspace() {
    let env = test_env();
    // The agent lives in its own program dir (like `~/.opencode/bin`), which
    // the profile must allow read+exec without allowing the whole home.
    let bin_dir = env.dir.path().join("outside-bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let agent = bin_dir.join("fake-agent");
    std::fs::copy(fake_agent_binary(), &agent).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut spec = SupervisorSpec::new(agent.to_string_lossy().to_string(), env.workspace.clone());
    spec.args = vec!["happy".to_string()];
    spec.sandbox = ShellSandbox::default();
    // Same per-user `RLIMIT_NPROC` reason as `spec_for`: tests must not rely on
    // production headroom they share with every other process of this user.
    spec.max_processes = 0;
    let mut client = start_acp(
        &spec,
        &test_limits(),
        CannedApprover::new(vec![]),
        handler_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("hi"), None, &mut NullObserver)
        .await
        .unwrap();
    assert_eq!(untagged(&outcome.text), "hello world");
    client.shutdown().await;
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sandbox_denies_the_auxesis_home_and_allows_the_vendor_dir() {
    let env = test_env();
    let fake_home = env.dir.path().join("home");
    let auxesis = fake_home.join(".auxesis");
    let vendor = fake_home.join(".local/share/opencode");
    std::fs::create_dir_all(&auxesis).unwrap();
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(auxesis.join("secret.txt"), "s3cret").unwrap();
    std::fs::write(vendor.join("auth.json"), "{}").unwrap();
    let auxesis_secret = auxesis.join("secret.txt").canonicalize().unwrap();
    let vendor_file = vendor.join("auth.json").canonicalize().unwrap();

    // Without a vendor read allowance, both paths are denied.
    let mut spec = spec_for(
        &env,
        "probe-read",
        Some(&auxesis_secret.display().to_string()),
    );
    spec.sandbox_home = Some(fake_home.clone());
    let mut client = start_acp(
        &spec,
        &test_limits(),
        CannedApprover::new(vec![]),
        handler_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("probe"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("probe=denied"), "{}", outcome.text);
    client.shutdown().await;

    let mut spec = spec_for(&env, "probe-read", Some(&vendor_file.display().to_string()));
    spec.sandbox_home = Some(fake_home.clone());
    let mut client = start_acp(
        &spec,
        &test_limits(),
        CannedApprover::new(vec![]),
        handler_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("probe"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("probe=denied"), "{}", outcome.text);
    client.shutdown().await;

    // With the vendor read allowance, only that tree is readable.
    let mut spec = spec_for(&env, "probe-read", Some(&vendor_file.display().to_string()));
    spec.sandbox_home = Some(fake_home.clone());
    spec.vendor_data_read = Some(vendor.clone());
    let mut client = start_acp(
        &spec,
        &test_limits(),
        CannedApprover::new(vec![]),
        handler_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("probe"), None, &mut NullObserver)
        .await
        .unwrap();
    assert!(outcome.text.contains("probe=ok"), "{}", outcome.text);
    client.shutdown().await;
}

// ---- backend: persistence, budgets, caps ----

fn backend_for(env: &TestEnv, limits: AcpLimits) -> (AcpBackend, Arc<Mutex<Store>>, i64) {
    backend_for_scenario(env, limits, "happy", None)
}

fn backend_for_scenario(
    env: &TestEnv,
    limits: AcpLimits,
    scenario: &str,
    arg: Option<&str>,
) -> (AcpBackend, Arc<Mutex<Store>>, i64) {
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let session_id = {
        let guard = store.lock().unwrap();
        guard.create_session("main", Some("acp test")).unwrap().id
    };
    let agent_path = copy_fake_agent(&env.workspace);
    let mut agent = AcpAgentSpec::new("fake", agent_path.to_string_lossy().to_string(), vec![]);
    // The scenario is the first argument.
    agent.args = match arg {
        Some(arg) => vec![scenario.to_string(), arg.to_string()],
        None => vec![scenario.to_string()],
    };
    let host = StoreTurnHost::new(
        Arc::clone(&store),
        "main".to_string(),
        session_id,
        Budgets::default(),
        None,
    );
    let backend = AcpBackend::new(
        AcpBackendConfig {
            enabled: true,
            agent_name: "main".to_string(),
            agent,
            limits,
            sandbox: test_sandbox(),
            workspace: env.workspace.clone(),
            sandbox_home: None,
            read_only: false,
        },
        CannedApprover::new(vec![]),
        Box::new(host),
    );
    (backend, store, session_id)
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // serializes the global known-secret registry
async fn backend_scrubs_and_tags_agent_output_before_persistence() {
    let _guard = secret_test_lock();
    kernel_broker::scrub::clear_known_secrets();
    let canary = "CANARY_ACP_SCRUB_0123456789abcdef";
    kernel_broker::scrub::register_known_secret(canary);
    let env = test_env();
    let (mut backend, store, session_id) =
        backend_for_scenario(&env, test_limits(), "secret-echo", Some(canary));
    let result = backend
        .run_turn(
            AcpTurnRequest {
                prompt: safe("hi"),
                cancel: None,
                turns_used: 0,
            },
            &mut NullObserver,
        )
        .await
        .unwrap();
    kernel_broker::scrub::clear_known_secrets();
    assert!(
        result.text.starts_with(ACP_UNTRUSTED_TAG),
        "the returned text must carry the untrusted tag: {}",
        result.text
    );
    assert!(!result.text.contains(canary), "{}", result.text);
    assert!(
        !result.text.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
        "{}",
        result.text
    );
    assert!(result.text.contains("<redacted>"), "{}", result.text);
    let stop_reason = result.stop_reason.clone().unwrap_or_default();
    assert!(
        !stop_reason.contains(canary),
        "the returned stopReason must be scrubbed: {stop_reason}"
    );
    let guard = store.lock().unwrap();
    let rows = guard.list_messages(session_id).unwrap();
    assert_eq!(rows.len(), 1, "exactly one assistant message");
    assert!(
        rows[0].content.starts_with(ACP_UNTRUSTED_TAG),
        "the stored row must carry the untrusted tag: {}",
        rows[0].content
    );
    assert!(!rows[0].content.contains(canary));
    assert!(!rows[0]
        .content
        .contains("sk-abcdefghijklmnopqrstuvwxyz012345"));
    let meta = rows[0].meta.clone().unwrap_or_default();
    assert!(
        !meta.contains(canary),
        "the persisted metadata must be scrubbed: {meta}"
    );
    assert!(!meta.contains("sk-abcdefghijklmnopqrstuvwxyz012345"));
    assert_eq!(
        rows[0].content, result.text,
        "stored and returned texts agree"
    );
}

#[tokio::test]
async fn backend_persists_one_message_settles_and_taints() {
    let env = test_env();
    let (mut backend, store, session_id) = backend_for(&env, test_limits());
    let result = backend
        .run_turn(
            AcpTurnRequest {
                prompt: safe("hi"),
                cancel: None,
                turns_used: 0,
            },
            &mut NullObserver,
        )
        .await
        .unwrap();
    assert_eq!(untagged(&result.text), "hello world");
    assert_eq!(result.stop_reason.as_deref(), Some("end_turn"));

    let guard = store.lock().unwrap();
    let rows = guard.list_messages(session_id).unwrap();
    assert_eq!(rows.len(), 1, "exactly one assistant message");
    let meta: serde_json::Value = serde_json::from_str(rows[0].meta.as_deref().unwrap()).unwrap();
    assert_eq!(meta["tainted"], true);
    assert_eq!(meta["acp"]["agent"], "fake");
    let taint = guard.session_taint(session_id).unwrap().unwrap();
    assert_eq!(taint.tool, "acp");
    let day = guard.local_day().unwrap();
    let totals = guard.usage_totals("main", &day).unwrap();
    assert_eq!(
        totals.usd_cents,
        kernel_core::config::DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS,
        "the fixed conservative estimate is settled"
    );
    assert_eq!(totals.get(UsageKind::TokensIn), 0);
}

#[tokio::test]
async fn backend_wall_clock_timeout_kills_the_tree_and_settles() {
    let env = test_env();
    let pidfile = env.workspace.join("child.pid");
    let mut limits = test_limits();
    limits.turn_timeout = Duration::from_secs(3);
    let (mut backend, store, session_id) = backend_for(&env, limits);
    // Point the fake agent at the "hang" scenario with a pid file.
    backend.agent_mut().args = vec!["hang".to_string(), pidfile.display().to_string()];
    let result = backend
        .run_turn(
            AcpTurnRequest {
                prompt: safe("never answer"),
                cancel: None,
                turns_used: 0,
            },
            &mut NullObserver,
        )
        .await;
    assert!(
        matches!(result, Err(AcpError::TurnTimeout { .. })),
        "{result:?}"
    );
    let child_pid = wait_for_pid(&pidfile).await;
    assert!(process_gone(child_pid), "the timed-out tree must be reaped");
    let guard = store.lock().unwrap();
    assert!(guard.list_messages(session_id).unwrap().is_empty());
    let day = guard.local_day().unwrap();
    let totals = guard.usage_totals("main", &day).unwrap();
    assert_eq!(
        totals.usd_cents,
        kernel_core::config::DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS,
        "a timed-out turn still settles conservatively"
    );
}

#[tokio::test]
async fn a_turn_dropped_after_dispatch_still_charges_its_reserve() {
    let env = test_env();
    let pidfile = env.workspace.join("child.pid");
    let (mut backend, store, _session_id) = backend_for(&env, test_limits());
    // The "hang" agent takes the prompt (its pid file appears), then never answers.
    backend.agent_mut().args = vec!["hang".to_string(), pidfile.display().to_string()];
    let mut observer = NullObserver;
    let request = AcpTurnRequest {
        prompt: safe("never answer"),
        cancel: None,
        turns_used: 0,
    };
    let child_pid = tokio::select! {
        result = backend.run_turn(request, &mut observer) => panic!("no answer: {result:?}"),
        pid = wait_for_pid(&pidfile) => pid,
    };
    assert!(process_gone(child_pid), "the dropped turn's tree is reaped");
    let guard = store.lock().unwrap();
    assert_eq!(guard.reservation_count().unwrap(), 0, "not left to expire");
    let day = guard.local_day().unwrap();
    assert_eq!(
        guard.usage_totals("main", &day).unwrap().usd_cents,
        kernel_core::config::DEFAULT_ACP_TURN_COST_ESTIMATE_CENTS,
        "the fixed estimate is charged once"
    );
}

#[tokio::test]
async fn a_gated_prompt_is_the_only_text_the_agent_sees() {
    // The backend takes a `SafeText`, so the agent can only receive what a gate
    // issued: the e-mail address is masked before the prompt leaves the process.
    let env = test_env();
    let (mut backend, _store, _session_id) =
        backend_for_scenario(&env, test_limits(), "echo", None);
    let prompt = safe("écris à elise.vautrin@example.invalid");
    let result = backend
        .run_turn(
            AcpTurnRequest {
                prompt,
                cancel: None,
                turns_used: 0,
            },
            &mut NullObserver,
        )
        .await
        .unwrap();
    assert!(!result.text.contains("elise.vautrin"), "{}", result.text);
    assert!(result.text.contains("echo:"), "{}", result.text);
    assert!(result.text.contains("⟦EMAIL_"), "{}", result.text);
}

/// The FAKE canary values with these ids in `qa/privacy-eval/canaries.json`.
fn canary_values(ids: &[&str]) -> Vec<String> {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("../../../qa/privacy-eval/canaries.json")).unwrap();
    let entries = file["canaries"].as_array().unwrap();
    ids.iter()
        .map(|id| {
            entries
                .iter()
                .find(|entry| entry["id"] == *id)
                .and_then(|entry| entry["value"].as_str())
                .unwrap_or_else(|| panic!("canary {id} is missing"))
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn no_raw_canary_reaches_the_acp_agent() {
    // Canary capture for the ACP path: the echo agent repeats the prompt it
    // received, so its reply shows exactly what crossed the process boundary.
    let env = test_env();
    let (mut backend, _store, _session_id) =
        backend_for_scenario(&env, test_limits(), "echo", None);
    let values = canary_values(&[
        "canary-02",
        "canary-03",
        "canary-04",
        "canary-05",
        "canary-07",
        "canary-08",
    ]);
    let message = format!(
        "Mon e-mail : {}. Tél : {}. IBAN : {}. NIR : {}. Autre : {}, {}.",
        values[0], values[1], values[2], values[3], values[4], values[5]
    );
    let result = backend
        .run_turn(
            AcpTurnRequest {
                prompt: safe(&message),
                cancel: None,
                turns_used: 0,
            },
            &mut NullObserver,
        )
        .await
        .unwrap();
    for value in &values {
        assert!(
            !result.text.contains(value.as_str()),
            "raw canary reached the ACP agent: {}",
            result.text
        );
    }
    assert!(result.text.contains("⟦EMAIL_"), "{}", result.text);
    assert!(result.text.contains("⟦PHONE_"), "{}", result.text);
    assert!(result.text.contains("⟦IBAN_"), "{}", result.text);
}

// ---- private mode: the host gate (D2, D4) ----

/// A stand-in session gate: "FR76-FAKE" <-> "⟦IBAN_1⟧".
#[derive(Debug)]
struct SwapGate;

impl aux_acp::HostGate for SwapGate {
    fn tokenise(&self, _kind: aux_acp::HostText, text: &str) -> Result<String, String> {
        Ok(text.replace("FR76-FAKE", "⟦IBAN_1⟧"))
    }

    fn reveal(&self, text: &str) -> String {
        text.replace("⟦IBAN_1⟧", "FR76-FAKE")
    }
}

#[tokio::test]
async fn a_host_gate_tokenises_the_file_the_agent_reads_and_reveals_the_ask_to_the_owner() {
    let env = test_env();
    let note = env.workspace.join("note.txt");
    std::fs::write(&note, "iban FR76-FAKE").unwrap();
    let approver = CannedApprover::new(vec![true]);
    let handlers = HandlerLimits {
        host_gate: Some(Arc::new(SwapGate)),
        ..handler_limits()
    };
    let mut client = start_client_with(
        &env,
        "private-probe",
        Some(&note.display().to_string()),
        approver.clone(),
        handlers,
        test_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("pay the invoice"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;

    // D2: the agent got the token, never the value.
    let received = std::fs::read_to_string(note.with_extension("received")).unwrap();
    assert!(received.contains("file=iban ⟦IBAN_1⟧"), "{received}");
    assert!(!received.contains("FR76-FAKE"), "{received}");
    assert!(!outcome.text.contains("FR76-FAKE"), "{}", outcome.text);
    // D4: the owner's card shows the value; the agent was told only the option.
    let seen = approver.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let card = seen[0].arguments.to_string();
    assert!(card.contains("Share FR76-FAKE"), "{card}");
    assert!(card.contains("\"who\":\"FR76-FAKE\""), "{card}");
    assert!(
        !received.contains("FR76-FAKE"),
        "the answer to the agent stays tokenised"
    );
}

#[tokio::test]
async fn a_host_gate_that_refuses_a_file_gives_the_agent_an_error_not_the_content() {
    #[derive(Debug)]
    struct Refuse;
    impl aux_acp::HostGate for Refuse {
        fn tokenise(&self, _: aux_acp::HostText, _: &str) -> Result<String, String> {
            Err("detector down".to_string())
        }
        fn reveal(&self, text: &str) -> String {
            text.to_string()
        }
    }
    let env = test_env();
    let inside = env.workspace.join("notes.txt");
    std::fs::write(&inside, "iban FR76-FAKE").unwrap();
    let handlers = HandlerLimits {
        host_gate: Some(Arc::new(Refuse)),
        ..handler_limits()
    };
    let mut client = start_client_with(
        &env,
        "fs-read",
        Some(&inside.display().to_string()),
        CannedApprover::new(vec![]),
        handlers,
        test_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("read"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    assert!(outcome.text.contains("read-error"), "{}", outcome.text);
    assert!(!outcome.text.contains("FR76-FAKE"), "{}", outcome.text);
}

#[tokio::test]
async fn a_host_gate_reveals_what_runs_on_the_mac_and_tokenises_what_comes_back() {
    let env = test_env();
    let handlers = || HandlerLimits {
        host_gate: Some(Arc::new(SwapGate)),
        ..handler_limits()
    };

    // A write the agent names by token lands under the value, after approval.
    let target = env.workspace.join("⟦IBAN_1⟧.txt");
    let mut client = start_client_with(
        &env,
        "fs-write",
        Some(&target.display().to_string()),
        CannedApprover::new(vec![true]),
        handlers(),
        test_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("write"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    assert_eq!(untagged(&outcome.text), "write=ok");
    assert!(!target.exists(), "the token is not a file name on the Mac");
    assert_eq!(
        std::fs::read_to_string(env.workspace.join("FR76-FAKE.txt")).unwrap(),
        "written-by-agent"
    );

    // A command the agent names by token runs with the value; the agent reads
    // the output as a token.
    if !test_sandbox().available() {
        return; // The broker refuses unsandboxed terminals; macOS-only path.
    }
    let mut client = start_client_with(
        &env,
        "terminal-echo",
        Some("⟦IBAN_1⟧"),
        CannedApprover::new(vec![]),
        handlers(),
        test_limits(),
    )
    .await;
    let outcome = client
        .prompt(&safe("run"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    assert!(outcome.text.contains("⟦IBAN_1⟧"), "{}", outcome.text);
    assert!(!outcome.text.contains("FR76-FAKE"), "{}", outcome.text);
}

#[tokio::test]
async fn a_private_agent_installed_inside_the_workspace_is_refused() {
    let env = test_env();
    let scratch = env.dir.path().join("scratch-overlap");
    std::fs::create_dir_all(&scratch).unwrap();
    let scratch = scratch.canonicalize().unwrap();
    // The agent binary sits in the host workspace: its read grant would cover
    // the owner's files, bypassing the gated fs handlers.
    let agent = copy_fake_agent(&env.workspace);
    let mut spec = SupervisorSpec::new(agent.to_string_lossy().to_string(), scratch);
    spec.args = vec!["echo".to_string()];
    spec.host_workspace = Some(env.workspace.clone());
    spec.sandbox = test_sandbox();
    spec.kill_grace = Duration::from_millis(500);
    let handlers = HandlerLimits {
        host_gate: Some(Arc::new(SwapGate)),
        ..handler_limits()
    };
    let started = AcpClient::start(
        &spec,
        "main",
        &test_limits(),
        CannedApprover::new(vec![]),
        handlers,
        Arc::new(TurnState::default()),
        false,
    )
    .await;
    let err = started.err().expect("private mode must refuse the overlap");
    assert!(err.to_string().contains("overlaps the workspace"), "{err}");
}

#[tokio::test]
async fn a_private_agent_reads_the_workspace_only_through_the_gated_host_handlers() {
    let env = test_env();
    if !test_sandbox().available() {
        return; // The agent's own sandbox is the macOS Seatbelt profile.
    }
    let note = env.workspace.join("note.txt");
    std::fs::write(&note, "iban FR76-FAKE").unwrap();
    let scratch = env.dir.path().join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let scratch = scratch.canonicalize().unwrap();
    let start = |scenario: &str| {
        let agent = copy_fake_agent(&scratch);
        let mut spec = SupervisorSpec::new(agent.to_string_lossy().to_string(), scratch.clone());
        spec.args = vec![scenario.to_string(), note.display().to_string()];
        spec.host_workspace = Some(env.workspace.clone());
        spec.sandbox = test_sandbox();
        spec.kill_grace = Duration::from_millis(500);
        spec.max_processes = 0;
        let handlers = HandlerLimits {
            host_gate: Some(Arc::new(SwapGate)),
            ..handler_limits()
        };
        async move { start_acp(&spec, &test_limits(), CannedApprover::new(vec![]), handlers).await }
    };

    // The agent's own read of the real workspace is stopped by its sandbox.
    let mut client = start("probe-read").await;
    let outcome = client
        .prompt(&safe("read"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    assert!(outcome.text.contains("probe=denied"), "{}", outcome.text);

    // The host handler serves the same file, tokenised.
    let mut client = start("fs-read").await;
    let outcome = client
        .prompt(&safe("read"), None, &mut NullObserver)
        .await
        .unwrap();
    client.shutdown().await;
    assert_eq!(untagged(&outcome.text), "read=iban ⟦IBAN_1⟧");
}

#[tokio::test]
async fn a_private_terminal_runs_with_no_network_and_an_open_one_keeps_it() {
    let env = test_env();
    let sandbox = ShellSandbox::new(true, true, false);
    if !sandbox.available() {
        return; // The broker refuses unsandboxed terminals; macOS-only path.
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let command = format!("/usr/bin/nc -z -w 2 127.0.0.1 {port}");
    let run = |gate: Option<Arc<dyn aux_acp::HostGate>>| {
        let handlers = HandlerLimits {
            sandbox: sandbox.clone(),
            host_gate: gate,
            ..handler_limits()
        };
        let command = command.clone();
        let env = &env;
        async move {
            let mut client = start_client_with(
                env,
                "terminal-cmd",
                Some(&command),
                CannedApprover::new(vec![]),
                handlers,
                test_limits(),
            )
            .await;
            let outcome = client
                .prompt(&safe("run"), None, &mut NullObserver)
                .await
                .unwrap();
            client.shutdown().await;
            outcome.text
        }
    };
    let open = run(None).await;
    assert!(
        open.contains("exit=0"),
        "open mode keeps the network: {open}"
    );
    let private = run(Some(Arc::new(SwapGate))).await;
    assert!(
        !private.contains("exit=0"),
        "a private terminal reached the network: {private}"
    );
}
