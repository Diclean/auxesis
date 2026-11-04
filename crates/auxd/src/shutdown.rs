//! Best-effort descendant cleanup on daemon shutdown.
//!
//! `auxd` abandons blocking tasks after a short grace: a run stuck in a
//! provider call or a hung `osascript` notification cannot be cancelled, and
//! the process exits without waiting for it. Child *processes* spawned by
//! those tasks (the notifier's `osascript`, a shell tool command) would
//! otherwise survive as orphans, including one whose run finishes during the
//! grace and spawns its notifier after any pre-grace sweep.
//!
//! Shutdown therefore sweeps twice ([`shutdown_runtime`]): once before the
//! grace, so an already-hung tree dies instead of holding the grace, and
//! again after it, so children spawned by work that finished inside the
//! window are collected before the process exits. Each sweep walks the
//! process table and terminates every descendant of `auxd`: SIGTERM first,
//! then SIGKILL for whatever is still alive after a short grace. It is
//! deliberately a whole-tree sweep rather than a per-notifier handle: the
//! child is spawned deep inside the notifier, the shell tool spawns
//! processes too, and every descendant is work this process started and is
//! now abandoning. The cleanup is best effort by contract — a missing `ps`
//! or a permission error never blocks shutdown.
//!
//! The ppid walk alone has a hole: a descendant that traps SIGTERM, forks a
//! child and exits reparents that child to launchd, so no later
//! `descendants()` snapshot can see it. The daemon therefore takes a private
//! process group at startup ([`OwnedGroup::establish`]) that every child it
//! spawns inherits, and the shutdown sweep terminates the group by pgid as
//! well. The forked child keeps the group id across reparenting, so it is
//! still found. Known residuals, documented rather than hidden:
//!
//! - the shell tool spawns each command with `setsid()` (its own session and
//!   group, a deliberate anti-TIOCSTI measure). Those groups are not
//!   registered with the daemon, so the group sweep cannot see them; the ppid
//!   walk still covers every live tree, and the tool kills its own group on
//!   timeout — but a command that traps SIGTERM, forks and exits during a
//!   *daemon* shutdown is still an escape;
//! - a descendant that deliberately calls `setsid()` leaves the group and
//!   becomes invisible to both walks once reparented;
//! - an interactive run (a TTY on stdin or stderr) keeps the shell's
//!   job-control group so Ctrl-C still works; it falls back to the ppid walk
//!   only.

use std::time::{Duration, Instant};

/// How long descendants get to exit after SIGTERM before SIGKILL.
const TERM_GRACE: Duration = Duration::from_millis(250);

/// How often the wait loop re-checks the descendants.
const POLL: Duration = Duration::from_millis(10);

/// How long the post-grace sweep keeps collecting late spawns.
const FINAL_SWEEP_BUDGET: Duration = Duration::from_millis(500);

/// How long to pause between post-grace sweep passes.
const FINAL_SWEEP_POLL: Duration = Duration::from_millis(25);

/// How long the post-grace loop waits for a possible late child after the
/// last sweep found none: a task that finishes just after the grace spawns
/// its notifier a few milliseconds later, and that spawn must still be seen.
const FINAL_SWEEP_QUIET: Duration = Duration::from_millis(50);

/// A private process group owned by the daemon.
///
/// The daemon calls `setpgid(0, 0)` before it can spawn anything, so every
/// child that does not deliberately leave the group inherits it. When the
/// daemon is interactive (a TTY on stdin or stderr) the group is *not* taken:
/// the terminal delivers Ctrl-C to the foreground group only, so detaching
/// would break it. The same guard means a daemon launched by launchd or by a
/// test harness (no TTY) gets the private group.
#[derive(Debug, Clone, Copy)]
pub struct OwnedGroup {
    pgid: u32,
}

impl OwnedGroup {
    /// Take a private process group, or `None` when the daemon cannot own one
    /// (interactive run, or `setpgid` refused and the current group is
    /// shared with the parent).
    pub fn establish() -> Option<Self> {
        let interactive = unsafe { libc::isatty(0) == 1 || libc::isatty(2) == 1 };
        if interactive {
            return None;
        }
        // Best effort: a process that already leads its group stays there.
        unsafe {
            libc::setpgid(0, 0);
        }
        let pid = unsafe { libc::getpid() } as u32;
        let pgid = unsafe { libc::getpgrp() } as u32;
        // Only a group led by this process is guaranteed to contain nothing
        // but this process and its descendants.
        (pgid == pid).then_some(Self { pgid })
    }

    /// The group id to sweep at shutdown.
    pub fn pgid(&self) -> u32 {
        self.pgid
    }
}

/// One process-table row from the `ps` snapshot.
#[derive(Debug, Clone, Copy)]
struct ProcessRow {
    pid: u32,
    ppid: u32,
    pgid: u32,
}

/// Terminate every descendant of `root` (not `root` itself), best effort.
///
/// One sweep: snapshot, SIGTERM, wait up to [`TERM_GRACE`], SIGKILL what is
/// left. The daemon shutdown uses [`shutdown_everything`] (which also sweeps
/// the process group); this is the test entry point for the ppid walk alone.
#[cfg(test)]
pub fn terminate_descendants(root: u32) {
    let pids = descendants(root);
    terminate_pids(&pids);
}

/// Terminate a process group (not `exclude`), best effort.
///
/// Re-snapshots the group while waiting, so a member that is forked *during*
/// the sweep (a TERM trap) is still collected. The daemon passes its own pid
/// as `exclude`; tests pass the test process id.
fn terminate_group(pgid: u32, exclude: u32) {
    let deadline = Instant::now() + TERM_GRACE;
    loop {
        let members = group_members(pgid, exclude);
        if members.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            for pid in members {
                signal(pid, libc::SIGKILL);
            }
            return;
        }
        for pid in &members {
            signal(*pid, libc::SIGTERM);
        }
        std::thread::sleep(POLL);
    }
}

/// SIGTERM then SIGKILL one snapshot of pids.
fn terminate_pids(pids: &[u32]) {
    if pids.is_empty() {
        return;
    }
    for pid in pids {
        signal(*pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        if pids.iter().all(|pid| !alive(*pid)) {
            return;
        }
        std::thread::sleep(POLL);
    }
    for pid in pids {
        if alive(*pid) {
            signal(*pid, libc::SIGKILL);
        }
    }
}

/// The full shutdown cleanup: sweep, run `grace` (the runtime shutdown that
/// lets finishing work complete), sweep again.
///
/// The first sweep kills a tree that is already hung, so the grace is not
/// spent waiting on it. The post-grace sweeps cover this: a run
/// that finishes during the grace spawns its notifier child *after* the
/// first snapshot, and only a sweep after the grace can see it. The loop
/// keeps sweeping while descendants appear, and stays alive for a short
/// quiet window after the last sighting (bounded by
/// [`FINAL_SWEEP_BUDGET`]) so a child spawned just after the grace is still
/// collected; the bound keeps a process that keeps spawning children from
/// stalling exit forever.
///
/// Test entry point for the ppid walk alone; the daemon uses
/// [`shutdown_everything`] with its private process group.
#[cfg(test)]
pub fn shutdown_runtime(root: u32, grace: impl FnOnce()) {
    shutdown_everything(root, None, grace);
}

/// [`shutdown_runtime`] with the daemon's private process group:
/// the sweep targets ppid-descendants *and* group members, so a forked child
/// that reparented to launchd is still terminated.
pub fn shutdown_everything(root: u32, group: Option<OwnedGroup>, grace: impl FnOnce()) {
    let pgid = group.map(|group| group.pgid());
    terminate_targets(root, pgid);
    grace();
    let deadline = Instant::now() + FINAL_SWEEP_BUDGET;
    let mut last_sighting = Instant::now();
    loop {
        let targets = targets(root, pgid);
        if !targets.is_empty() {
            terminate_pids(&targets);
            last_sighting = Instant::now();
        } else if last_sighting.elapsed() >= FINAL_SWEEP_QUIET {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(FINAL_SWEEP_POLL);
    }
}

/// Terminate the descendant tree plus (when owned) the process group.
fn terminate_targets(root: u32, group: Option<u32>) {
    let targets = targets(root, group);
    terminate_pids(&targets);
    if let Some(pgid) = group {
        terminate_group(pgid, root);
    }
}

/// Every process the shutdown owns: ppid-descendants of `root`, plus every
/// member of `group` (when given).
fn targets(root: u32, group: Option<u32>) -> Vec<u32> {
    let mut pids = descendants(root);
    if let Some(pgid) = group {
        for pid in group_members(pgid, root) {
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
    }
    pids
}

/// Transitive children of `root`, from one `ps` snapshot.
///
/// Returns an empty list when `ps` is unavailable or unparsable: shutdown
/// must never be blocked (or failed) by the cleanup itself.
fn descendants(root: u32) -> Vec<u32> {
    let Some(rows) = process_snapshot() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for row in &rows {
            if row.ppid == parent && !found.contains(&row.pid) {
                found.push(row.pid);
                frontier.push(row.pid);
            }
        }
    }
    found
}

/// Members of process group `pgid`, excluding `exclude` (the caller).
fn group_members(pgid: u32, exclude: u32) -> Vec<u32> {
    let Some(rows) = process_snapshot() else {
        return Vec::new();
    };
    rows.iter()
        .filter(|row| row.pgid == pgid && row.pid != exclude && row.pid != 0)
        .map(|row| row.pid)
        .collect()
}

/// Absolute first: the daemon may run with a PATH that a test or attack
/// harness has shimmed, and cleanup must not be redirectable through a fake
/// `ps`.
fn process_snapshot() -> Option<Vec<ProcessRow>> {
    for candidate in ["/bin/ps", "/usr/bin/ps", "ps"] {
        if let Some(rows) = snapshot(candidate) {
            return Some(rows);
        }
    }
    None
}

/// One `ps` snapshot with pid, ppid and pgid; `None` when the program is
/// missing or fails.
fn snapshot(program: &str) -> Option<Vec<ProcessRow>> {
    let output = std::process::Command::new(program)
        .args(["-A", "-o", "pid=", "-o", "ppid=", "-o", "pgid="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(pid), Some(ppid), Some(pgid)) = (fields.next(), fields.next(), fields.next()) {
            if let (Ok(pid), Ok(ppid), Ok(pgid)) =
                (pid.parse::<u32>(), ppid.parse::<u32>(), pgid.parse::<u32>())
            {
                rows.push(ProcessRow { pid, ppid, pgid });
            }
        }
    }
    if rows.is_empty() {
        return None;
    }
    Some(rows)
}

/// True while the pid can be signalled (live, or a zombie not yet reaped).
fn alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Send one signal, ignoring errors (a process may already be gone).
fn signal(pid: u32, sig: libc::c_int) {
    unsafe {
        libc::kill(pid as i32, sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    /// Setup waits get a generous bound: a loaded CI runner can take seconds to
    /// start a freshly spawned shell. Every wait is still bounded, so a real
    /// regression fails the test instead of hanging the suite.
    const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

    /// Wait (bounded) for a pid to die.
    fn wait_for_exit(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(pid) {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(POLL);
        }
        true
    }

    /// Poll `check` until it yields a value, or fail with `what` after
    /// [`SETUP_TIMEOUT`]. Used for conditions a slow runner must not turn into
    /// a flake (a shell arming its trap, a trap forking its child).
    fn wait_until<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        loop {
            if let Some(value) = check() {
                return value;
            }
            assert!(Instant::now() < deadline, "{what} within {SETUP_TIMEOUT:?}");
            std::thread::sleep(POLL);
        }
    }

    /// A pid file written by the test shells (`echo $! > file`).
    fn read_pid(path: &std::path::Path) -> Option<u32> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    /// Live pids whose full command line contains `marker` (`pgrep -f`).
    ///
    /// Used to prove on its own that a test left no `auxd-*.pid-*` shell
    /// behind — the same `pgrep -f auxd-a3l-fork` the build host runs. A
    /// missing `pgrep` reports nothing (the test relies on
    /// the RAII guard, not on this probe).
    fn pids_matching(marker: &str) -> Vec<u32> {
        let Ok(output) = Command::new("pgrep")
            .arg("-f")
            .arg(marker)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect()
    }

    /// Unique temp path per test run.
    fn temp_file(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("auxd-{label}-{}-{nonce}", std::process::id()))
    }

    /// Send one signal to a whole process group (negative pid), ignoring
    /// errors.
    fn signal_group(pgid: u32, sig: libc::c_int) {
        unsafe {
            libc::kill(-(pgid as i32), sig);
        }
    }

    /// A spawned child with a guaranteed cleanup on drop.
    ///
    /// A failed assertion mid-test (before the explicit cleanup) must never
    /// leave a sleeper behind after `cargo test -p auxd shutdown`. On drop this
    /// SIGKILLs the child's process group when it leads one (a reparented
    /// escapee stays in that group and is collected too), sweeps any
    /// descendants otherwise, then reaps the child.
    ///
    /// `Deref`/`DerefMut` to [`std::process::Child`] keep the call sites
    /// (`id()`, `kill()`, `wait()`) unchanged.
    struct ChildGuard {
        child: std::process::Child,
        group_leader: bool,
    }

    impl ChildGuard {
        fn new(child: std::process::Child, group_leader: bool) -> Self {
            Self {
                child,
                group_leader,
            }
        }
    }

    impl std::ops::Deref for ChildGuard {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            &self.child
        }
    }

    impl std::ops::DerefMut for ChildGuard {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.child
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // Skipping the signal once the child has already exited keeps a
            // recycled pgid out of reach; a reparented escapee still holding
            // the group means the id cannot have been recycled, and it is
            // swept below because the child has not exited yet (or the group
            // is not the child's own, so the descendant walk applies).
            if !matches!(self.child.try_wait(), Ok(Some(_))) {
                if self.group_leader {
                    signal_group(self.child.id(), libc::SIGKILL);
                } else {
                    terminate_descendants(self.child.id());
                }
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Removes a test pid file on drop: a failing assertion must not leave
    /// `auxd-*.pid-*` litter in `$TMPDIR`.
    struct PidFileGuard(std::path::PathBuf);

    impl PidFileGuard {
        fn new(path: std::path::PathBuf) -> Self {
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
    }

    impl Drop for PidFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Spawn `sh -c 'read -r _; <body>'` with stdin piped: the shell blocks in
    /// the builtin `read` with no descendant, and the returned writer releases
    /// it later.
    fn blocked_shell(body: &str) -> (ChildGuard, std::process::ChildStdin) {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(format!("read -r _; {body}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let stdin = child.stdin.take().expect("piped stdin");
        (ChildGuard::new(child, false), stdin)
    }

    #[cfg(unix)]
    #[test]
    fn parent_map_finds_the_current_process() {
        let rows = process_snapshot().expect("a ps snapshot must succeed on unix");
        assert!(
            rows.iter().any(|row| row.pid == std::process::id()),
            "the snapshot must include this process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_terminates_a_hung_grandchild_tree() {
        // `sh -c 'sleep 10 & wait'` gives us root = sh, descendant = sleep,
        // exactly the shape of a hung PATH-shimmed `osascript`.
        // Bounded lifetime + `ChildGuard`: the test's own RAII cleanup kills
        // the tree even if an assertion below fails.
        let mut root = ChildGuard::new(
            Command::new("sh")
                .arg("-c")
                .arg("sleep 10 & wait")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sh"),
            false,
        );

        // The sleep may not exist yet: poll for the descendant.
        let deadline = Instant::now() + Duration::from_secs(5);
        let grandchild = loop {
            let pids = descendants(root.id());
            if let Some(pid) = pids.first() {
                break *pid;
            }
            assert!(Instant::now() < deadline, "sh never spawned its child");
            std::thread::sleep(POLL);
        };
        assert!(alive(grandchild));

        terminate_descendants(root.id());

        assert!(
            wait_for_exit(grandchild),
            "the hung descendant must be terminated"
        );
        // The walker never signals the root; `sh` returns once its child is
        // gone. Reap it either way.
        let _ = root.wait();
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_spares_a_process_without_descendants() {
        // `sh -c 'sleep 10'` typically execs into `sleep`, so the spawned pid
        // is the target itself. terminate_descendants must not kill it.
        let mut root = ChildGuard::new(
            Command::new("sh")
                .arg("-c")
                .arg("sleep 10")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sh"),
            false,
        );

        terminate_descendants(root.id());

        assert!(
            alive(root.id()),
            "the root process must never be signalled by the walker"
        );
        let _ = root.kill();
        let _ = root.wait();
    }

    /// A child spawned *during* the shutdown grace (after
    /// the pre-grace sweep) used to survive as an orphan. The shell blocks in
    /// its builtin `read` — no descendant exists at the first sweep — and the
    /// grace releases it, so its child is born inside the window exactly like
    /// a run that finishes during the grace and spawns its notifier.
    #[cfg(unix)]
    #[test]
    fn a_child_spawned_during_the_grace_is_swept_after_it() {
        let pidfile = PidFileGuard::new(temp_file("grace-spawn.pid"));
        let (mut root, mut stdin) = blocked_shell(&format!(
            "sleep 10 & echo $! > {}; wait",
            pidfile.0.display()
        ));

        let started = Instant::now();
        let grace_pidfile = pidfile.0.clone();
        shutdown_runtime(root.id(), move || {
            writeln!(stdin, "go").expect("release the shell");
            let _ = stdin.flush();
            // Wait until the child exists: the pid file is written after the
            // fork, so once it is there the grace-window spawn is real.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !grace_pidfile.exists() {
                assert!(
                    Instant::now() < deadline,
                    "the shell never spawned its child"
                );
                std::thread::sleep(POLL);
            }
            std::thread::sleep(POLL);
        });
        let bounded = started.elapsed() < Duration::from_secs(3);

        let late = read_pid(&pidfile.0);
        let swept = late.is_some_and(wait_for_exit);
        // Clean up (and the guards do it again on the way out) even when the
        // assertions below fail: a regression here must not leak a sleeper
        // into the rest of the suite.
        if let Some(pid) = late {
            if !swept {
                signal(pid, libc::SIGKILL);
            }
        }
        let _ = root.kill();
        let _ = root.wait();
        assert!(
            bounded,
            "shutdown must stay bounded, took {:?}",
            started.elapsed()
        );
        assert!(
            swept,
            "a child spawned during the grace must be swept after it"
        );
    }

    /// The post-grace sweep must never touch a process that is not a
    /// descendant of `root`: an unrelated sibling of the daemon survives.
    #[cfg(unix)]
    #[test]
    fn shutdown_spares_an_unrelated_process() {
        let (mut root, mut stdin) = blocked_shell("sleep 10 & echo $! > /dev/null; wait");
        let mut sibling = ChildGuard::new(
            Command::new("sleep")
                .arg("10")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sibling"),
            false,
        );

        shutdown_runtime(root.id(), move || {
            writeln!(stdin, "go").expect("release the shell");
        });

        let sibling_alive = alive(sibling.id());
        // Clean up before asserting so a regression cannot leak sleepers.
        let _ = sibling.kill();
        let _ = sibling.wait();
        let _ = root.kill();
        let _ = root.wait();
        assert!(
            sibling_alive,
            "an unrelated process must never be signalled"
        );
    }

    /// A descendant that traps SIGTERM, forks a child and
    /// exits reparents that child to launchd, so the ppid walk can no longer
    /// see it. The child keeps the process group, and `terminate_group` finds
    /// it there.
    #[cfg(unix)]
    #[test]
    fn group_sweep_terminates_a_reparented_fork() {
        let pidfile = PidFileGuard::new(temp_file("a3l-fork.pid"));
        // The shim records its own pid here once the TERM trap is installed.
        // Signalling a shell that has not run `trap` yet takes the default
        // action: it dies without forking (the CI flake this wait removes).
        let ready = PidFileGuard::new(temp_file("a3l-ready.pid"));

        // Root traps TERM: the trap forks `sleep 10`, records its pid and
        // exits. This is the exact shape a process can use to escape the ppid
        // walk (`shim traps SIGTERM; its trap forks sleep and exits`).
        let mut root = ChildGuard::new(
            Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "trap 'sleep 10 & echo $! >> {}; exit 0' TERM; \
                     echo $$ > {}; \
                     while :; do sleep 0.05; done",
                    pidfile.0.display(),
                    ready.0.display()
                ))
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn trap shim"),
            true,
        );
        let pgid = root.id();
        assert_eq!(
            unsafe { libc::getpgid(root.id() as i32) } as u32,
            pgid,
            "the trap shim must lead its own group"
        );

        // Wait for the shim to arm its trap before the sweep signals it. The
        // wait is the condition, not a sleep: a slow runner may take seconds
        // to start the shell, and a fixed pause would just move the race.
        let armed = wait_until("the trap shim never armed its TERM trap", || {
            read_pid(&ready.0)
        });
        assert_eq!(
            armed, pgid,
            "the ready shim must be the group leader that was spawned"
        );

        // Trigger the trap directly instead of leaving it to the group
        // sweep's 250 ms TERM window: a loaded runner can take longer than
        // that to schedule the shim, and the sweep would SIGKILL it before it
        // forks. That is a race against the scheduler, not a sweep bug.
        signal(root.id(), libc::SIGTERM);

        // The trap fires on TERM, forks the escapee, and exits; the escapee
        // is reparented but stays in the group. Wait for that child to exist,
        // then let the group sweep prove it still finds and kills it.
        let escapee = wait_until("the trap shim never forked its escapee", || {
            read_pid(&pidfile.0)
        });
        terminate_group(pgid, std::process::id());
        let swept = wait_for_exit(escapee);
        // Clean up any escapee before asserting so a regression cannot leak a
        // sleeper into the rest of the suite; `root`'s Drop SIGKILLs the whole
        // group again on the way out.
        if !swept {
            signal(escapee, libc::SIGKILL);
        }
        let _ = root.wait();

        // No pidfile-named shell survives the test (the build host runs
        // `pgrep -f auxd-a3l-fork`). The name is unique per run, so only this
        // test's processes
        // can match.
        let marker = pidfile
            .0
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let stragglers = pids_matching(marker);
        assert!(
            stragglers.is_empty(),
            "the test left an auxd-a3l-fork shell behind: {stragglers:?}"
        );
        assert!(
            swept,
            "a forked child that reparented to launchd must be swept with the group"
        );
    }

    /// The group sweep must never touch a process outside the group.
    #[cfg(unix)]
    #[test]
    fn group_sweep_spares_a_process_outside_the_group() {
        let mut root = ChildGuard::new(
            Command::new("sh")
                .arg("-c")
                .arg("sleep 10")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn grouped root"),
            true,
        );
        let mut sibling = ChildGuard::new(
            Command::new("sleep")
                .arg("10")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sibling"),
            false,
        );

        terminate_group(root.id(), std::process::id());

        let sibling_alive = alive(sibling.id());
        let _ = sibling.kill();
        let _ = sibling.wait();
        let _ = root.kill();
        let _ = root.wait();
        assert!(sibling_alive, "a process outside the group must survive");
    }

    /// The group snapshot sees the test process itself when asked for its own
    /// group.
    #[cfg(unix)]
    #[test]
    fn group_members_finds_this_process() {
        let pgid = unsafe { libc::getpgrp() } as u32;
        let members = group_members(pgid, 0);
        assert!(
            members.contains(&std::process::id()),
            "the snapshot must include this process in its own group"
        );
    }
}
