//! Process-tree reaping for ACP agents (the TreeReaper approach).
//!
//! Adapted from the shell tool's reaper (`crates/aux-tools/src/tools/shell.rs`)
//! so ACP turns get the same guarantee: kill by process group, by ppid walk,
//! by session, and by the per-agent read-only **marker descriptor** that
//! survives `exec` and catches double-fork + `setsid()` orphans that
//! reparented to launchd. Keeping the logic here (rather than widening
//! `aux-tools`' private surface) keeps A0's blast radius to the new crate; the
//! two implementations are covered by their own tests.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Identity of the read-only marker file the agent inherits as an open
/// descriptor. A process that still holds the same `(device, inode)` belongs
/// to the agent, even after it reparented and called `setsid()`.
#[derive(Clone, Copy, Debug)]
pub struct Marker {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl Marker {
    /// Identity of `file` (an unlinked private tempfile).
    #[cfg(unix)]
    pub fn from_file(file: &std::fs::File) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata()?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    /// Identity of `file` (non-Unix: the reaper cannot scan, so it is a no-op
    /// handle).
    #[cfg(not(unix))]
    pub fn from_file(_file: &std::fs::File) -> std::io::Result<Self> {
        Ok(Self {})
    }
}

/// Identity of a live process: the pid plus its start time, which
/// disambiguates a pid the OS reused for an unrelated program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidIdentity {
    /// Process id.
    pub pid: i32,
    /// Start time (`pbi_start_tvsec` on macOS, `/proc/<pid>/stat` field 22 on
    /// Linux), as reported by [`pid_ppid_uid_start`].
    pub start: u64,
}

/// Reads `(ppid, uid, start)` for a pid. Production code uses
/// [`pid_ppid_uid_start`]; the seam lets a test make a live pid look recycled
/// without racing the real kernel.
type StartLookup<'a> = &'a dyn Fn(i32) -> Option<(i32, u32, u64)>;

impl PidIdentity {
    /// The identity of `pid` right now, when it is visible and owned by this
    /// user.
    pub fn of(pid: i32) -> Option<Self> {
        Self::of_with(pid, &pid_ppid_uid_start)
    }

    fn of_with(pid: i32, lookup: StartLookup<'_>) -> Option<Self> {
        let (_, uid, start) = lookup(pid)?;
        // SAFETY: `geteuid` is a side-effect-free read of this process's
        // effective uid; it cannot fail and touches no memory.
        (uid == unsafe { libc::geteuid() }).then_some(Self { pid, start })
    }

    /// `pid` still exists, is ours, and is the same process as when the
    /// identity was recorded (start time matches). A reused pid is rejected.
    pub fn still_alive(&self) -> bool {
        self.still_alive_with(&pid_ppid_uid_start)
    }

    fn still_alive_with(&self, lookup: StartLookup<'_>) -> bool {
        let Some((_, uid, start)) = lookup(self.pid) else {
            return false;
        };
        // SAFETY: `geteuid` is a side-effect-free read of this process's
        // effective uid; it cannot fail and touches no memory.
        uid == unsafe { libc::geteuid() } && start == self.start
    }
}

/// Number of live processes owned by this user, used to compute an
/// `RLIMIT_NPROC` headroom.
pub fn user_process_count() -> u64 {
    let euid = unsafe { libc::geteuid() };
    all_pids()
        .into_iter()
        .filter(|pid| matches!(pid_ppid_uid_start(*pid), Some((_, uid, _)) if uid == euid))
        .count() as u64
}

/// SIGKILL the agent's whole process tree: descendants, the dedicated process
/// group and session it leads, and reparented orphans holding the marker
/// descriptor.
///
/// `start` is the agent's start time, recorded when it was spawned. Every
/// signal is gated on the identity still matching immediately before it: if
/// the root exited and its pid was recycled, nothing is signalled — in
/// particular the tree walk and the group/session sweeps are skipped, so an
/// unrelated program can never inherit the agent's pid and be killed through
/// it.
pub fn kill_process_tree(pid: Option<u32>, start: Option<u64>, marker: &Marker) {
    kill_process_tree_with(pid, start, marker, &pid_ppid_uid_start);
}

/// Kill processes still holding this turn's marker without using a root PID.
/// Use this after the root `Child` has been waited/reaped: its former process
/// group ID may already have been recycled.
pub fn kill_marker_holders(marker: &Marker) {
    #[cfg(unix)]
    {
        const MAX_ROUNDS: usize = 8;
        const REPARENT_WAIT: std::time::Duration = std::time::Duration::from_millis(20);
        for round in 0..MAX_ROUNDS {
            let holders = orphan_pids_holding_marker(marker);
            if holders.is_empty() {
                return;
            }
            for pid in holders {
                let Some(identity) = PidIdentity::of(pid) else {
                    continue;
                };
                if identity.still_alive() {
                    // SAFETY: the marker identifies this process as belonging
                    // to the agent; identity was rechecked immediately before
                    // signalling.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
            if round + 1 < MAX_ROUNDS {
                std::thread::sleep(REPARENT_WAIT);
            }
        }
        if !orphan_pids_holding_marker(marker).is_empty() {
            tracing::warn!("marker holders remain after {MAX_ROUNDS} cleanup rounds");
        }
    }
    #[cfg(not(unix))]
    let _ = marker;
}

fn kill_process_tree_with(
    pid: Option<u32>,
    start: Option<u64>,
    marker: &Marker,
    lookup: StartLookup<'_>,
) {
    #[cfg(unix)]
    if let Some(pid) = pid {
        let pid = pid as i32;
        let root = start.and_then(|start| {
            PidIdentity::of_with(pid, lookup).filter(|identity| identity.start == start)
        });
        if let Some(root) = root {
            for pass in 0..2 {
                for tracked in tracked_pids(pid, marker, lookup) {
                    if tracked.pid == pid || tracked.pid <= 1 {
                        continue;
                    }
                    // Re-verify immediately before this signal: a descendant
                    // has no unreaped `Child` pinning its pid, so the scan
                    // result alone is not enough.
                    if !tracked.still_alive_with(lookup) {
                        continue;
                    }
                    // SAFETY: `kill` is the documented libc signal call. The
                    // pid was re-checked one statement above; the remaining
                    // window is the two adjacent syscalls between that check
                    // and this signal, where the OS could recycle the pid for
                    // an unrelated process.
                    unsafe {
                        libc::kill(tracked.pid, libc::SIGKILL);
                    }
                }
                if pass == 0 {
                    std::thread::yield_now();
                }
            }
            // The dedicated group, as a whole, after the ppid walk: the walk
            // still finds live descendants, and the group signal then catches
            // whichever of them left the ppid tree when they reparent. The
            // caller holds this root's unreaped `Child` for the whole call, so
            // its pid and pgid stay reserved and the group signal cannot land
            // on a recycled group. Re-check the root immediately before the
            // signal anyway.
            if root.still_alive_with(lookup) {
                // SAFETY: `getpgid`/`kill` are the documented libc process
                // calls; the target is the agent's own group, gated on the
                // identity check immediately above.
                if unsafe { libc::getpgid(pid) } == pid {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
            }
            // Only the dedicated session this root leads (it called `setsid()`
            // before exec): never a session inherited from someone else.
            // SAFETY: `getsid` is the documented libc session query.
            if unsafe { libc::getsid(pid) } == pid {
                for member in session_pids(pid) {
                    if member == pid || member <= 1 {
                        continue;
                    }
                    let Some(identity) = PidIdentity::of_with(member, lookup) else {
                        continue;
                    };
                    if !identity.still_alive_with(lookup) {
                        continue;
                    }
                    // SAFETY: `kill` is the documented libc signal call; the
                    // member was re-checked immediately above.
                    unsafe {
                        libc::kill(member, libc::SIGKILL);
                    }
                }
            }
            // SAFETY: `kill` is the documented libc signal call. The root is
            // still the exact process whose identity was verified, and the
            // caller's unreaped `Child` pins the pid until after the return.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        // Marker-holding orphans are identified by the marker inode itself, so
        // they are safe to sweep even when the root is gone; the pid is still
        // re-checked immediately before each signal.
        for orphan in orphan_pids_holding_marker(marker) {
            let Some(identity) = PidIdentity::of_with(orphan, lookup) else {
                continue;
            };
            if !identity.still_alive_with(lookup) {
                continue;
            }
            // SAFETY: `kill` is the documented libc signal call; the orphan
            // was re-checked immediately above.
            unsafe {
                libc::kill(orphan, libc::SIGKILL);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (pid, start, marker, lookup);
}

/// Send SIGTERM to the dedicated process group the agent leads (graceful
/// shutdown first). Never signals a group the agent did not create: the
/// leader must still be the exact process we spawned, and its pgid must be
/// its own pid.
pub fn terminate_group(pid: u32, start: Option<u64>) {
    terminate_group_with(pid, start, &pid_ppid_uid_start);
}

fn terminate_group_with(pid: u32, start: Option<u64>, lookup: StartLookup<'_>) {
    #[cfg(unix)]
    {
        let pid = pid as i32;
        let Some(start) = start else {
            return;
        };
        let Some(identity) = PidIdentity::of_with(pid, lookup) else {
            return;
        };
        if identity.start != start {
            return;
        }
        // SAFETY: `getpgid` is the documented libc query; the group is only
        // signalled when the leader is the exact verified process and leads
        // its own group.
        if unsafe { libc::getpgid(pid) } != pid {
            return;
        }
        // Re-check immediately before the signal: the caller still holds the
        // root's unreaped `Child`, so the pgid is pinned for the residual
        // window.
        if !identity.still_alive_with(lookup) {
            return;
        }
        // SAFETY: `kill` is the documented libc signal call; the leader was
        // re-checked immediately above and its group is its own.
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    let _ = (pid, start, lookup);
}

/// SIGKILL every recorded identity that is **still the same process**.
///
/// The start time (and owner) is re-checked immediately before each kill, so
/// a pid the OS recycled for an unrelated program is dropped instead of
/// killed. Only the exact process is signalled: process groups/sessions are
/// swept exclusively in [`kill_process_tree`], where the agent leads them.
pub fn kill_tracked(identities: &[PidIdentity]) {
    #[cfg(unix)]
    {
        let me = std::process::id() as i32;
        for identity in identities {
            if identity.pid <= 1 || identity.pid == me {
                continue;
            }
            if !identity.still_alive() {
                continue; // exited, or the pid now belongs to someone else
            }
            unsafe {
                libc::kill(identity.pid, libc::SIGKILL);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = identities;
}

/// A background sampler that remembers every pid seen below the agent while
/// it runs. The sweeps themselves only see what is reachable at kill time;
/// this closes the window where a fast grandchild reparents and `setsid()`s
/// before anyone looks.
pub struct TreeTracker {
    /// `pid -> start time` for every process seen under the agent while it
    /// ran. Exited and reused pids are pruned on every sample.
    pids: Arc<Mutex<HashMap<i32, u64>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TreeTracker {
    /// Start sampling descendants/session members of `root` every 25 ms.
    pub fn start(root: u32) -> Self {
        let pids = Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let pids = Arc::clone(&pids);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("acp-tree-tracker".to_string())
                .spawn(move || {
                    let root = root as i32;
                    while !stop.load(Ordering::SeqCst) {
                        let mut found = descendant_pids(root);
                        found.extend(session_pids(root));
                        let mut seen = pids.lock().unwrap_or_else(|err| err.into_inner());
                        // Drop pids that exited or were recycled: a stale
                        // entry must never be signalled later.
                        seen.retain(|pid, start| {
                            PidIdentity {
                                pid: *pid,
                                start: *start,
                            }
                            .still_alive()
                        });
                        for pid in found {
                            if let Some(identity) = PidIdentity::of(pid) {
                                seen.insert(identity.pid, identity.start);
                            }
                        }
                        drop(seen);
                        std::thread::sleep(Duration::from_millis(25));
                    }
                })
                .ok()
        };
        Self { pids, stop, handle }
    }

    /// Every still-attributable process observed under the agent so far,
    /// with the start time that proves it is the same process.
    pub fn identities(&self) -> Vec<PidIdentity> {
        self.pids
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .iter()
            .map(|(pid, start)| PidIdentity {
                pid: *pid,
                start: *start,
            })
            .collect()
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for TreeTracker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Every process that belongs to the agent: descendants by `ppid` walk, the
/// agent's session, and reparented orphans holding the marker. Each entry
/// carries the start time read at scan time, so the caller can re-verify it
/// immediately before a signal.
fn tracked_pids(root: i32, marker: &Marker, lookup: StartLookup<'_>) -> Vec<PidIdentity> {
    let mut seen = HashSet::new();
    seen.insert(root);
    let mut pids = Vec::new();
    if let Some(identity) = PidIdentity::of_with(root, lookup) {
        pids.push(identity);
    }
    for pid in descendant_pids(root)
        .into_iter()
        .chain(session_pids(root))
        .chain(orphan_pids_holding_marker(marker))
    {
        if seen.insert(pid) {
            if let Some(identity) = PidIdentity::of_with(pid, lookup) {
                pids.push(identity);
            }
        }
    }
    pids
}

/// Live processes that reparented to launchd (`ppid == 1`), belong to this
/// user, and still hold the agent's marker descriptor.
fn orphan_pids_holding_marker(marker: &Marker) -> Vec<i32> {
    let me = unsafe { libc::geteuid() };
    let mut pids = Vec::new();
    for pid in all_pids() {
        let Some((ppid, uid, _start)) = pid_ppid_uid_start(pid) else {
            continue;
        };
        if ppid != 1 || uid != me {
            continue;
        }
        if process_holds_marker(pid, marker) {
            pids.push(pid);
        }
    }
    pids
}

/// True when a `proc_pidfdinfo` call filled the whole expected buffer: only
/// then is the `MaybeUninit` fully initialised and safe to `assume_init`. A
/// short write (an older/smaller kernel struct) leaves the tail
/// uninitialised, so the entry must be skipped. Pure and platform-independent
/// so the check is unit-tested on every OS.
#[cfg(any(target_os = "macos", test))]
fn pidfdinfo_filled_buffer(rc: libc::c_int, expected: usize) -> bool {
    expected > 0 && rc == expected as libc::c_int
}

/// True when `pid` holds the marker file as an open descriptor (macOS).
#[cfg(target_os = "macos")]
fn process_holds_marker(pid: i32, marker: &Marker) -> bool {
    const PROC_PIDLISTFDS: libc::c_int = 1;
    const PROC_PIDFDVNODEINFO: libc::c_int = 1;

    /// `struct proc_fileinfo` prefix of `vnode_fdinfo` (not re-exported by
    /// `libc`); only its size and alignment matter here.
    #[repr(C)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[repr(C)]
    struct VnodeFdInfo {
        pfi: ProcFileInfo,
        pvi: libc::vnode_info,
    }

    let mut buf = vec![0u8; 8 * 4096];
    // SAFETY: `buf` is a live allocation and `proc_pidinfo` writes at most
    // `buf.len()` bytes into it, returning the count written.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as libc::c_int,
        )
    };
    if n <= 0 {
        return false;
    }
    for entry in buf[..n as usize].as_chunks::<8>().0 {
        let fd = i32::from_ne_bytes([entry[0], entry[1], entry[2], entry[3]]);
        if fd < 0 {
            continue;
        }
        let mut info = std::mem::MaybeUninit::<VnodeFdInfo>::zeroed();
        // SAFETY: `info` is a live, correctly sized `MaybeUninit` and
        // `proc_pidfdinfo` writes at most `size_of::<VnodeFdInfo>()` bytes
        // into it.
        let rc = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDVNODEINFO,
                info.as_mut_ptr().cast(),
                std::mem::size_of::<VnodeFdInfo>() as libc::c_int,
            )
        };
        // A partial write means the kernel's struct is smaller than ours: the
        // uninitialised tail must never be read.
        if !pidfdinfo_filled_buffer(rc, std::mem::size_of::<VnodeFdInfo>()) {
            continue;
        }
        // SAFETY: the check above proved the kernel wrote every byte of
        // `info`, so it is fully initialised.
        let info = unsafe { info.assume_init() };
        if u64::from(info.pvi.vi_stat.vst_dev) == marker.dev
            && info.pvi.vi_stat.vst_ino == marker.ino
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn process_holds_marker(pid: i32, marker: &Marker) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(metadata) = std::fs::metadata(entry.path()) else {
            continue;
        };
        if metadata.dev() == marker.dev && metadata.ino() == marker.ino {
            return true;
        }
    }
    false
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_holds_marker(_pid: i32, _marker: &Marker) -> bool {
    false
}

/// Direct children of `pid` (macOS: `proc_listchildpids`).
#[cfg(target_os = "macos")]
fn child_pids(pid: i32) -> Vec<i32> {
    let hint = unsafe { libc::proc_listchildpids(pid, std::ptr::null_mut(), 0) };
    let mut capacity = hint.max(16) as usize + 16;
    for _ in 0..4 {
        let mut buf = vec![0i32; capacity];
        let n = unsafe {
            libc::proc_listchildpids(
                pid,
                buf.as_mut_ptr().cast(),
                (buf.len() * std::mem::size_of::<i32>()) as i32,
            )
        };
        if n < 0 {
            return Vec::new();
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
            return buf;
        }
        capacity = capacity.saturating_mul(2);
    }
    Vec::new()
}

/// Direct children of `pid` on Linux, read from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn child_pids(pid: i32) -> Vec<i32> {
    let mut children = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(candidate) = name.parse::<i32>() else {
            continue;
        };
        if candidate == pid {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{candidate}/stat")) else {
            continue;
        };
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        let mut fields = stat[close + 1..].split_whitespace();
        let _state = fields.next();
        if fields.next().and_then(|ppid| ppid.parse::<i32>().ok()) == Some(pid) {
            children.push(candidate);
        }
    }
    children
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn child_pids(_pid: i32) -> Vec<i32> {
    Vec::new()
}

/// Every live process below `pid`, breadth-first.
fn descendant_pids(pid: i32) -> Vec<i32> {
    let mut seen = HashSet::new();
    let mut stack = vec![pid];
    let mut descendants = Vec::new();
    while let Some(parent) = stack.pop() {
        for child in child_pids(parent) {
            if seen.insert(child) {
                descendants.push(child);
                stack.push(child);
            }
        }
    }
    descendants
}

/// Every live process in the agent's session (the direct child calls
/// `setsid()` before exec, so its sid is its pid).
#[cfg(unix)]
fn session_pids(sid: i32) -> Vec<i32> {
    let mut pids = Vec::new();
    for pid in all_pids() {
        if pid == sid {
            continue;
        }
        if unsafe { libc::getsid(pid) } == sid {
            pids.push(pid);
        }
    }
    pids
}

#[cfg(not(unix))]
fn session_pids(_sid: i32) -> Vec<i32> {
    Vec::new()
}

/// All live pids (macOS: `proc_listpids`; Linux: `/proc`).
#[cfg(target_os = "macos")]
fn all_pids() -> Vec<i32> {
    /// `PROC_ALL_PIDS` from `<libproc.h>`; not re-exported by `libc`.
    const PROC_ALL_PIDS: u32 = 1;

    let mut capacity = 1024usize;
    for _ in 0..4 {
        let mut buf = vec![0i32; capacity];
        let n = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                buf.as_mut_ptr().cast(),
                (buf.len() * std::mem::size_of::<i32>()) as i32,
            )
        };
        if n <= 0 {
            return Vec::new();
        }
        let n = n as usize / std::mem::size_of::<i32>();
        if n < capacity {
            buf.truncate(n);
            return buf;
        }
        capacity = capacity.saturating_mul(2);
    }
    Vec::new()
}

#[cfg(target_os = "linux")]
fn all_pids() -> Vec<i32> {
    let mut pids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) {
                pids.push(pid);
            }
        }
    }
    pids
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn all_pids() -> Vec<i32> {
    Vec::new()
}

/// `(ppid, uid, start)` for a live process, if visible. `start` is in
/// **microseconds** (K-03): `pbi_start_tvsec` + `pbi_start_tvusec` on macOS,
/// `/proc/<pid>/stat` start ticks converted with the clock tick on Linux.
#[cfg(target_os = "macos")]
fn pid_ppid_uid_start(pid: i32) -> Option<(i32, u32, u64)> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if n != size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let start = info
        .pbi_start_tvsec
        .saturating_mul(1_000_000)
        .saturating_add(info.pbi_start_tvusec);
    Some((info.pbi_ppid as i32, info.pbi_uid, start))
}

#[cfg(target_os = "linux")]
fn pid_ppid_uid_start(pid: i32) -> Option<(i32, u32, u64)> {
    use std::os::unix::fs::MetadataExt;

    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let mut fields = stat[close + 1..].split_whitespace();
    let _state = fields.next()?;
    let ppid: i32 = fields.next()?.parse().ok()?;
    let start_ticks: u64 = fields.nth(17)?.parse().ok()?;
    let uid = std::fs::metadata(format!("/proc/{pid}")).ok()?.uid();
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz > 0 { hz as u64 } else { 100 };
    let start = start_ticks.saturating_mul(1_000_000) / hz;
    Some((ppid, uid, start))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn pid_ppid_uid_start(_pid: i32) -> Option<(i32, u32, u64)> {
    None
}

/// A fresh random marker for one turn's environment
/// (`AUXESIS_ACP_TURN=<marker>`). Read from `/dev/urandom`; the fallback
/// (pid/time/counter) is only for platforms without it.
pub fn new_turn_marker() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_ok()
    {
        let mut out = String::with_capacity(32);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        return out;
    }
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(
        "fallback-{}-{now}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// The environment variable carrying the per-turn marker.
pub const TURN_MARKER_ENV: &str = "AUXESIS_ACP_TURN";

/// SIGKILL every same-user process whose **environment** carries the turn
/// marker and that started at or after `min_start` (microseconds).
///
/// This is the anchor a child cannot drop by closing file descriptors or
/// changing its working directory: it must deliberately scrub its own
/// environment to escape (documented residual). Every candidate is
/// identity-checked immediately before the kill, so an unrelated process —
/// or a recycled pid — is never signalled.
pub fn kill_marked_processes(marker: &str, min_start: u64) {
    #[cfg(unix)]
    {
        if marker.is_empty() {
            return;
        }
        let needle = format!("{TURN_MARKER_ENV}={marker}");
        let me = std::process::id() as i32;
        let euid = unsafe { libc::geteuid() };
        for pid in all_pids() {
            if pid <= 1 || pid == me {
                continue;
            }
            let Some((_ppid, uid, start)) = pid_ppid_uid_start(pid) else {
                continue;
            };
            if uid != euid || start < min_start {
                continue;
            }
            if !process_env_contains(pid, &needle) {
                continue;
            }
            // Re-check identity right before the kill: the process must still
            // be the one whose environment we just read.
            let Some(identity) = PidIdentity::of(pid) else {
                continue;
            };
            if identity.start != start || identity.start < min_start {
                continue;
            }
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (marker, min_start);
}

/// True when `pid`'s environment (not argv, not the exec path) contains
/// `needle`.
#[cfg(target_os = "macos")]
fn process_env_contains(pid: i32, needle: &str) -> bool {
    const KERN_PROCARGS2: libc::c_int = 49;
    let mut mib = [libc::CTL_KERN, KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    // Bound the read: an environment larger than this is not ours anyway.
    const MAX_ENV_BYTES: libc::size_t = 4 * 1024 * 1024;
    if rc != 0 || !(4..=MAX_ENV_BYTES).contains(&size) {
        return false;
    }
    let mut buf = vec![0u8; size];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return false;
    }
    let buf = &buf[..size];
    // Layout: argc (int), exec path, NUL padding, argc argv strings, then the
    // environment as NUL-separated strings.
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]).max(0) as usize;
    let mut cursor = 4;
    // Exec path.
    while cursor < buf.len() && buf[cursor] != 0 {
        cursor += 1;
    }
    // Skip the exec-path terminator and the alignment padding after it.
    while cursor < buf.len() && buf[cursor] == 0 {
        cursor += 1;
    }
    // Skip argv strings.
    for _ in 0..argc {
        while cursor < buf.len() && buf[cursor] != 0 {
            cursor += 1;
        }
        cursor += 1;
        if cursor > buf.len() {
            return false;
        }
    }
    buf[cursor..]
        .split(|byte| *byte == 0)
        .any(|entry| entry == needle.as_bytes())
}

#[cfg(target_os = "linux")]
fn process_env_contains(pid: i32, needle: &str) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return false;
    };
    raw.split(|byte| *byte == 0)
        .any(|entry| entry == needle.as_bytes())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_env_contains(_pid: i32, _needle: &str) -> bool {
    false
}

/// Mark every open descriptor >= 3 close-on-exec, except `keep_fd` (the
/// read-only per-agent marker).
#[cfg(unix)]
pub fn mark_inherited_fds_close_on_exec(keep_fd: i32) {
    #[cfg(target_os = "macos")]
    {
        const PROC_PIDLISTFDS: libc::c_int = 1;
        let mut buf = [0u8; 4096 * 8];
        let n = unsafe {
            libc::proc_pidinfo(
                std::process::id() as libc::c_int,
                PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast(),
                buf.len() as libc::c_int,
            )
        };
        if n > 0 {
            for entry in buf[..n as usize].as_chunks::<8>().0 {
                let fd = i32::from_ne_bytes([entry[0], entry[1], entry[2], entry[3]]);
                if fd < 3 {
                    continue;
                }
                set_close_on_exec(fd, fd != keep_fd);
            }
            return;
        }
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let max = unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            limit.rlim_cur.min(65_536) as i32
        } else {
            1024
        }
    };
    for fd in 3..max {
        set_close_on_exec(fd, fd != keep_fd);
    }
}

#[cfg(not(unix))]
pub fn mark_inherited_fds_close_on_exec(_keep_fd: i32) {}

#[cfg(unix)]
fn set_close_on_exec(fd: i32, close: bool) {
    let flags = if close { libc::FD_CLOEXEC } else { 0 };
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, flags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_identity_is_stable_for_an_open_file() {
        let file = tempfile::tempfile().unwrap();
        let marker = Marker::from_file(&file).unwrap();
        let again = Marker::from_file(&file).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(marker.dev, again.dev);
            assert_eq!(marker.ino, again.ino);
        }
        #[cfg(not(unix))]
        let _ = again;
    }

    #[test]
    fn pidfdinfo_result_must_fill_the_whole_struct() {
        // Marker scan: only an exact full write may be `assume_init`ed.
        let size = 128usize;
        assert!(pidfdinfo_filled_buffer(size as libc::c_int, size));
        assert!(!pidfdinfo_filled_buffer(0, size), "an error is not a fill");
        assert!(
            !pidfdinfo_filled_buffer((size - 1) as libc::c_int, size),
            "a short write must be skipped"
        );
        assert!(
            !pidfdinfo_filled_buffer((size + 1) as libc::c_int, size),
            "an oversized result is not our struct"
        );
        assert!(
            !pidfdinfo_filled_buffer(0, 0),
            "an empty buffer is not a fill"
        );
    }

    #[test]
    fn killing_an_exited_pid_is_harmless() {
        // A pid that certainly does not exist: 2^31-1 is not a valid pid.
        let marker = Marker::from_file(&tempfile::tempfile().unwrap()).unwrap();
        kill_process_tree(Some(i32::MAX as u32), None, &marker);
        kill_process_tree(Some(i32::MAX as u32), Some(1), &marker);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn spawn_marker_tree(script: &str) -> (Marker, std::process::Child) {
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};

        let file = tempfile::tempfile().unwrap();
        let marker = Marker::from_file(&file).unwrap();
        // Make the marker descriptor available to exec'd descendants.
        let fd = file.as_raw_fd();
        // SAFETY: fcntl only reads/updates descriptor flags for this live fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        // SAFETY: same live descriptor, preserving all flags except CLOEXEC.
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );

        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Close the caller's copy so the spawned tree is the only marker
        // holder once the root exits.
        drop(file);
        (marker, child)
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn marker_holders_disappear_within(marker: &Marker, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if orphan_pids_holding_marker(marker).is_empty() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn post_reap_marker_only_cleanup_kills_orphan_holder() {
        let (marker, mut root) = spawn_marker_tree("sleep 30 & exit 0");
        root.wait().unwrap();

        kill_marker_holders(&marker);

        assert!(marker_holders_disappear_within(
            &marker,
            Duration::from_secs(10)
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn post_reap_cleanup_finds_grandchild_after_parent_is_killed() {
        let (marker, mut root) = spawn_marker_tree("sh -c 'sleep 30 & wait' & exit 0");
        root.wait().unwrap();

        kill_marker_holders(&marker);

        let cleaned = marker_holders_disappear_within(&marker, Duration::from_secs(10));
        if !cleaned {
            // Keep a failed regression test from leaving its deliberate test
            // process alive while still reporting the observed failure.
            for pid in orphan_pids_holding_marker(&marker) {
                if let Some(identity) = PidIdentity::of(pid) {
                    if identity.still_alive() {
                        // SAFETY: this is the test's unique marker holder and
                        // its identity was rechecked immediately above.
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                }
            }
        }
        assert!(
            cleaned,
            "no process may remain with the marker after cleanup"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_reused_pid_with_a_foreign_start_time_is_never_killed() {
        use std::process::{Command, Stdio};

        // A live process that stands in for an unrelated owner process that
        // inherited a recycled pid: the tracker recorded this pid while it
        // was the agent's child, then the child exited and the OS handed the
        // pid to something else.
        let mut child = Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let real_start = pid_ppid_uid_start(pid)
            .expect("the sleep process must be visible")
            .2;

        // Simulated reuse: same pid, different start time. It must survive.
        // `try_wait` (not `kill(pid, 0)`) is the liveness check: a SIGKILLed
        // child stays a zombie and would still satisfy `kill(pid, 0) == 0`.
        let stale = PidIdentity {
            pid,
            start: real_start.wrapping_add(1),
        };
        kill_tracked(&[stale]);
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            matches!(child.try_wait(), Ok(None)),
            "a recycled pid must never be killed"
        );

        // The matching identity (the process we actually recorded) is killed.
        let live = PidIdentity {
            pid,
            start: real_start,
        };
        kill_tracked(&[live]);
        let mut gone = false;
        for _ in 0..100 {
            if let Ok(Some(_)) = child.try_wait() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(gone, "the matching identity must still be killed");
    }

    /// True when `pid` exists but has exited and waits to be reaped. A
    /// signalled non-child is reaped by init, so this is how the test tells a
    /// wrong kill from a survivor.
    #[cfg(all(unix, target_os = "linux"))]
    fn is_zombie(pid: i32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let Some(close) = stat.rfind(')') else {
            return false;
        };
        stat[close + 1..].split_whitespace().next() == Some("Z")
    }

    #[cfg(all(unix, target_os = "macos"))]
    fn is_zombie(pid: i32) -> bool {
        const SZOMB: u32 = 5;
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: `info` is a live, correctly sized buffer and `proc_pidinfo`
        // writes at most `size` bytes into it.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                // Non-zero `arg`: with 0, a zombie fails with ESRCH, so this
                // could never see one.
                1,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if n != size {
            return false;
        }
        // SAFETY: the exact-size return proves the whole struct was written.
        let info = unsafe { info.assume_init() };
        info.pbi_status == SZOMB
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn is_zombie(_pid: i32) -> bool {
        false
    }

    #[cfg(unix)]
    #[test]
    fn a_descendant_whose_start_time_changed_is_not_signalled() {
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};

        let marker = Marker::from_file(&tempfile::tempfile().unwrap()).unwrap();
        let mut root = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 300 & wait")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let root_pid = root.id() as i32;
        let root_start = pid_ppid_uid_start(root_pid)
            .expect("the root must be visible")
            .2;

        let mut victim = None;
        for _ in 0..200 {
            if let Some(pid) = child_pids(root_pid).first().copied() {
                victim = Some(pid);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let victim = victim.expect("the root must spawn a child");
        let victim_start = pid_ppid_uid_start(victim)
            .expect("the victim must be visible")
            .2;

        // The seam makes the victim's start time differ on every read: the
        // scan records one value and the pre-signal re-check always sees a
        // foreign process, exactly like a pid the OS recycled in the gap.
        let reads = AtomicU64::new(0);
        let lookup = move |pid: i32| -> Option<(i32, u32, u64)> {
            if pid == victim {
                let bump = reads.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
                // SAFETY: reads this process's effective uid; no memory is
                // touched and the call cannot fail.
                return Some((
                    root_pid,
                    unsafe { libc::geteuid() },
                    victim_start.wrapping_add(bump),
                ));
            }
            pid_ppid_uid_start(pid)
        };

        kill_process_tree_with(Some(root_pid as u32), Some(root_start), &marker, &lookup);

        std::thread::sleep(Duration::from_millis(300));
        // SAFETY: signal 0 only probes existence; the target is a process this
        // test spawned.
        let alive = unsafe { libc::kill(victim, 0) } == 0;
        let zombie = is_zombie(victim);
        // Clean up before asserting so a failure cannot leak the sleep.
        // SAFETY: best-effort SIGKILL of a process this test spawned.
        unsafe {
            libc::kill(victim, libc::SIGKILL);
        }
        let _ = root.wait();
        assert!(
            alive && !zombie,
            "a descendant whose start time changed must not be signalled"
        );
    }

    #[cfg(unix)]
    #[test]
    fn tracker_prunes_a_child_that_exits() {
        use std::process::{Command, Stdio};

        // Root keeps a child alive; the sampler records the child and must
        // drop it again once it exits, so no stale pid can be signalled later.
        let mut root = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 300 & wait")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let root_pid = root.id() as i32;
        let tracker = TreeTracker::start(root.id());

        let mut child_pid = None;
        for _ in 0..200 {
            if let Some(pid) = child_pids(root_pid).first().copied() {
                if tracker
                    .identities()
                    .iter()
                    .any(|identity| identity.pid == pid)
                {
                    child_pid = Some(pid);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let child_pid = child_pid.expect("the sampler must record the live child");

        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
        }
        let mut pruned = false;
        for _ in 0..200 {
            if !tracker
                .identities()
                .iter()
                .any(|identity| identity.pid == child_pid)
            {
                pruned = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(pruned, "an exited child must be pruned from the tracker");

        let _ = root.kill();
        let _ = root.wait();
    }

    #[cfg(unix)]
    #[test]
    fn kill_marked_processes_kills_only_marked_children() {
        use std::process::{Command, Stdio};

        let marker = new_turn_marker();
        // The marked child must be a non-platform binary: macOS hides the
        // environment of platform (SIP) binaries from KERN_PROCARGS2, so a
        // script interpreter is the mainstream case the sweep can read (the
        // GLM repro uses python3). On Linux any binary works.
        let Ok(mut marked) = Command::new("python3")
            .args(["-c", "import time; time.sleep(300)"])
            .env(TURN_MARKER_ENV, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return; // no python3 on this host: the sweep unit test is skipped
        };
        // Start times are platform-relative (epoch microseconds on macOS,
        // boot jiffies on Linux), so the turn floor must come from the same
        // source, never `SystemTime::now()`.
        let min_start = pid_ppid_uid_start(marked.id() as i32)
            .expect("the marked child must be visible")
            .2;
        let mut unmarked = Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        kill_marked_processes(&marker, min_start);
        let mut gone = false;
        for _ in 0..100 {
            if let Ok(Some(_)) = marked.try_wait() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(gone, "the marked child must be killed");
        assert!(
            matches!(unmarked.try_wait(), Ok(None)),
            "an unmarked process must never be killed"
        );

        // A marker recorded for a previous turn (start < min_start) survives.
        let old_marker = new_turn_marker();
        let mut old = Command::new("sleep")
            .arg("300")
            .env(TURN_MARKER_ENV, &old_marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        kill_marked_processes(&old_marker, u64::MAX);
        assert!(
            matches!(old.try_wait(), Ok(None)),
            "an out-of-turn marker must survive"
        );

        let _ = unmarked.kill();
        let _ = unmarked.wait();
        let _ = old.kill();
        let _ = old.wait();
    }

    #[cfg(unix)]
    #[test]
    fn start_times_distinguish_processes_in_the_same_second() {
        use std::process::Command;

        let mut first = Command::new("sleep").arg("300").spawn().unwrap();
        std::thread::sleep(Duration::from_millis(80));
        let mut second = Command::new("sleep").arg("300").spawn().unwrap();
        let a = pid_ppid_uid_start(first.id() as i32)
            .expect("first is visible")
            .2;
        let b = pid_ppid_uid_start(second.id() as i32)
            .expect("second is visible")
            .2;
        assert_ne!(
            a, b,
            "start times need sub-second precision to disambiguate reuse (K-03)"
        );
        let _ = first.kill();
        let _ = first.wait();
        let _ = second.kill();
        let _ = second.wait();
    }
}
