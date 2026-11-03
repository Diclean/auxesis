//! macOS Seatbelt sandbox for the `shell` tool.
//!
//! The shell tool never runs a command directly while sandboxing is on:
//! [`launch`] builds `sandbox-exec -p <profile> /bin/sh -c <cmd>` with a
//! deny-by-default profile. The profile is deliberately small:
//!
//! - **exec**: `/usr`, `/bin`, `/sbin`, `/System`, the Command Line Tools (or
//!   the full Xcode developer directory when one is selected) and the Python
//!   framework, plus only the *program* directories inside the package
//!   prefixes (`bin`, `sbin`, `opt`, `Cellar`, `lib`, `include`, `share`) —
//!   never the whole prefix. `var`, `etc` and `Caskroom` under
//!   `/opt/homebrew` and `/usr/local` stay unreadable, so a package manager's
//!   logs, datasets, git checkout and config files are not exposed; the only
//!   exceptions are explicit read-backs *after* the deny for the specific
//!   paths common toolchains need to start (Homebrew's OpenSSL config and CA
//!   bundle, Homebrew's own `Library/Homebrew` code so `brew --version`/`list`/
//!   `info` work, system Ruby's gems tree) — never a whole `etc` or `Library`
//!   directory;
//! - **read**: the same system trees, the dyld cache and timezone data under
//!   `/private/var/db`, a handful of `/etc` files common commands need
//!   (`hosts`, `resolv.conf`, `localtime`, `services`, `protocols`, `ssl`),
//!   `/dev`, and the workspace + per-call temp dir. Nothing else — in
//!   particular not `/private/var/db` or `/Library` as a whole, so the unified
//!   log store, `/Library/Logs`, the system keychains and other machine state
//!   stay closed;
//! - **sysctl / process-info**: both are globally denied at the end of the
//!   profile (last-match-wins), so `lsof`, `ps`-equivalents, `launchctl print`
//!   and `sysctl -a` cannot enumerate the user's processes, open files or
//!   kernel state. A small set of non-sensitive sysctl names (CPU count, RAM
//!   size, page size, `uname` identity) is allowed back after the deny, and
//!   `process-info*` is allowed back for **self** only, which Foundation needs
//!   to start (`sw_vers`, `osascript`) but which reveals nothing about other
//!   processes;
//! - **write**: only the workspace and the per-call private temp dir (also
//!   `HOME`/`TMPDIR`), plus the standard `/dev` sinks;
//! - **network**: off by default (all sockets denied, loopback included);
//!   `network = true` allows **all** sockets for v1 — there is no narrower
//!   host/port allowlist, documented on [`ShellSandbox::network`];
//! - **sensitive paths**: the Auxesis home, `.ssh`, `.aws`, `.config`,
//!   `.gnupg`, `.docker`, `.kube`, Keychains, Messages/Mail/Safari/Cookies
//!   and browser profile dirs are denied explicitly, last, so they win over
//!   the broader system reads. A workspace that is equal to, inside, or an
//!   ancestor of any of them is refused up front (a workspace inside
//!   `~/.auxesis` itself stays allowed — that is where agents live).
//!
//! Path filters are matched by the kernel against *canonical* paths, while
//! symlinks are resolved during the check — so the workspace, temp dir and
//! home are canonicalised here, and a symlink inside the workspace that
//! points elsewhere is still denied by the kernel.
//!
//! Fail closed: when `sandbox-exec` is missing (non-macOS, stripped system)
//! the tool refuses to run unless the caller explicitly set
//! [`ShellSandbox::allow_unsandboxed`]. `sandbox = false` on its own is not
//! enough either: it refuses too unless `allow_unsandboxed` is set as well.
//!
//! The child runs with `setsid()` (own session, no terminal), every inherited
//! descriptor >= 3 marked close-on-exec, and best-effort `RLIMIT_CPU` /
//! `RLIMIT_FSIZE` / `RLIMIT_NOFILE` caps. Output is captured to private files
//! in the temp dir, so a background process holding the stdout stream can
//! never turn a finished command into a timeout.

use crate::ToolError;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use thiserror::Error;

/// Where the platform sandbox helper lives on macOS.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Refusal shown to the model when sandboxing is required but unavailable.
pub const UNAVAILABLE_MESSAGE: &str = "shell refused: sandbox-exec is unavailable on this system; \
set `shell.allow_unsandboxed = true` in config.toml to run shell commands without a sandbox (not recommended)";

/// Refusal shown to the model when the config disables sandboxing without
/// also opting in to unsandboxed execution.
pub const DISABLED_MESSAGE: &str = "shell refused: `shell.sandbox = false` only takes effect together with \
`shell.allow_unsandboxed = true`; set both to run shell commands without a sandbox (not recommended)";

/// Highest number of open file descriptors inside a shell command.
pub const MAX_OPEN_FILES: u64 = 4096;

/// Largest file a shell command may create (per file, enforced with
/// `RLIMIT_FSIZE`): 1 GiB. This is a **per-file** cap, not a volume quota;
/// the workspace total is not metered in v1.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// Extra CPU-seconds a command may burn beyond its wall-clock timeout.
pub const CPU_LIMIT_GRACE_SECS: u64 = 30;

/// Memory watchdog budget for a command tree (sum of resident footprints).
/// `RLIMIT_AS`/`RLIMIT_DATA` are set best-effort too, but macOS rejects both,
/// so the watchdog is what actually contains a memory bomb there.
pub const MAX_COMMAND_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The fixed `PATH` every command runs with. Never inherited from the daemon:
/// the owner's `PATH` discloses the account name and private toolchain layout,
/// and every directory a sandboxed command may actually execute from is on
/// this list already.
pub const SANDBOX_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin";

/// Sandbox settings for the shell tool, mirroring the `[shell]` config section.
///
/// The helper path is private and always [`SANDBOX_EXEC`] outside tests: no
/// caller can point the shell at a wrapper that skips the Seatbelt profile.
///
/// ```compile_fail,E0451
/// use kernel_broker::sandbox::ShellSandbox;
/// // The helper is private: a struct literal from outside the crate cannot set it.
/// let _ = ShellSandbox {
///     enabled: true,
///     network: false,
///     allow_unsandboxed: false,
///     sandbox_exec: "/tmp/wrapper".into(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSandbox {
    /// Run commands under `sandbox-exec` (default true). `false` only takes
    /// effect together with [`ShellSandbox::allow_unsandboxed`]; on its own it
    /// makes every call refuse to run.
    pub enabled: bool,
    /// Allow network access inside the sandbox (default false: all sockets are
    /// denied, loopback included). `true` is **all sockets** for v1 — any host
    /// and port; there is no narrower allowlist.
    pub network: bool,
    /// Run unsandboxed when the sandbox is unavailable *and* when
    /// `enabled` is false (default false).
    pub allow_unsandboxed: bool,
    /// Path of the sandbox helper. Always [`SANDBOX_EXEC`] outside tests (see
    /// [`ShellSandbox::with_test_sandbox_exec`]).
    sandbox_exec: PathBuf,
}

impl Default for ShellSandbox {
    fn default() -> Self {
        Self::new(true, false, false)
    }
}

impl ShellSandbox {
    /// The profile for the three `[shell]` config switches, always run through
    /// the fixed [`SANDBOX_EXEC`] helper.
    pub fn new(enabled: bool, network: bool, allow_unsandboxed: bool) -> Self {
        Self {
            enabled,
            network,
            allow_unsandboxed,
            sandbox_exec: PathBuf::from(SANDBOX_EXEC),
        }
    }

    /// Test seam: run this profile through another helper path. A missing path
    /// exercises the fail-closed branch. Compiled out of production builds, so
    /// the helper there is always [`SANDBOX_EXEC`].
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_test_sandbox_exec(mut self, sandbox_exec: impl Into<PathBuf>) -> Self {
        self.sandbox_exec = sandbox_exec.into();
        self
    }

    /// The helper binary this profile runs commands through.
    pub fn sandbox_exec(&self) -> &Path {
        &self.sandbox_exec
    }

    /// True when this platform and this binary can actually sandbox.
    pub fn available(&self) -> bool {
        cfg!(target_os = "macos") && self.sandbox_exec.is_file()
    }

    /// True when a command launched under this profile will run **without**
    /// the sandbox: the explicit `enabled = false` opt-out, or an unavailable
    /// sandbox helper with `allow_unsandboxed` set. Mirrors the decision in
    /// [`launch`] exactly, so the broker can refuse persistent allows for a
    /// call that will escape the sandbox. `enabled = false` without the opt-in
    /// (or an unavailable helper without it) refuses to run and is therefore
    /// *not* unsandboxed.
    pub fn will_run_unsandboxed(&self) -> bool {
        self.allow_unsandboxed && (!self.enabled || !self.available())
    }
}

/// Why a command could not be launched.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// Sandboxing was requested but `sandbox-exec` is missing/unsupported.
    #[error("{UNAVAILABLE_MESSAGE}")]
    Unavailable,
    /// Sandboxing was switched off without opting in to unsandboxed runs.
    #[error("{DISABLED_MESSAGE}")]
    SandboxDisabled,
    /// The workspace cannot be sandboxed safely (root, not a directory, ...).
    #[error("workspace {0} cannot be sandboxed safely")]
    UnsafeWorkspace(String),
    /// The workspace would expose a protected location (keys, keychains, the
    /// Auxesis home root, ...).
    #[error("workspace {0} overlaps a protected location")]
    SensitiveWorkspace(String),
    /// I/O failure while preparing the command.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A launched command plus the per-call resources it needs while it runs.
///
/// Keep this value alive until the child has been waited on: dropping it
/// removes the private temp dir used as `HOME`/`TMPDIR`. `stdout_capture` /
/// `stderr_capture` are unlinked private files in that temp dir; read them
/// after the child exits to get the command's output.
#[derive(Debug)]
pub struct Launched {
    /// The command to spawn (`sandbox-exec` wrapper, or `sh` when
    /// explicitly unsandboxed).
    pub command: tokio::process::Command,
    /// Per-call private temp dir (`HOME`, `TMPDIR`).
    pub temp: TempDir,
    /// Captured standard output (unlinked file, seek to start before reading).
    pub stdout_capture: std::fs::File,
    /// Captured standard error (unlinked file, seek to start before reading).
    pub stderr_capture: std::fs::File,
    /// Per-call marker file. The command inherits it as a **read-only** open
    /// descriptor (every other inherited descriptor is closed on exec); the
    /// process sweep identifies double-fork + `setsid()` orphans that
    /// reparented to launchd by the marker file's `(device, inode)`, which
    /// survives exec of any binary — even platform binaries whose environment
    /// `KERN_PROCARGS2` hides. A hostile command that closes all its
    /// descriptors escapes the sweep; the sandbox still confines whatever
    /// survives.
    pub marker_file: std::fs::File,
}

/// The Auxesis home inside the real home; agent workspaces live inside it, so a
/// workspace *inside* this tree is intended. A workspace equal to it (or an
/// ancestor of it) would expose the daemon's config and every agent.
const AUXESIS_HOME_DIR: &str = ".auxesis";

/// The sensitive directories denied inside the real home. `.auxesis` is
/// denied too (a workspace inside it overrides the deny for its own subtree
/// only, because the workspace allow is emitted after the deny).
const SENSITIVE_DIRS: &[&str] = &[
    ".auxesis",
    ".ssh",
    ".aws",
    ".config",
    ".gnupg",
    ".docker",
    ".kube",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Safari",
    "Library/Messages",
    "Library/Mail",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Chromium",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Firefox",
    "Library/Application Support/Microsoft Edge",
];

/// The sensitive files denied inside the real home.
const SENSITIVE_FILES: &[&str] = &[".netrc", ".git-credentials"];

/// Absolute directories that are always denied (and never a valid workspace):
/// system keychains, logs, the unified log store, the root account.
const SENSITIVE_ABSOLUTE_DIRS: &[&str] = &[
    "/Library/Keychains",
    "/Library/Logs",
    "/private/var/log",
    "/private/var/db/diagnostics",
    "/private/var/db/uuidtext",
    "/var/root",
];

/// Read + execute allowlist: the system trees commands need. Never writable.
const SYSTEM_TREES: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Apple",
    "/Library/Developer/CommandLineTools",
    "/Library/Frameworks/Python.framework",
];

/// The only root a full Xcode developer directory may come from. The bundle
/// must sit directly here, and the selected path must already be canonical.
const APPLICATIONS_ROOT: &str = "/Applications";

/// The only bundle identifier accepted for an `/Applications` developer
/// directory: a full Xcode, not just any app that ships a `Developer` folder.
const XCODE_BUNDLE_ID: &str = "com.apple.dt.Xcode";

/// Upper bound for the `xcode-select` and `plutil` helpers, so a wedged tool
/// can never stall profile construction.
const DEVELOPER_TOOL_TIMEOUT: Duration = Duration::from_secs(2);

/// The Command Line Tools developer directory. It is already in
/// [`SYSTEM_TREES`], so resolving it adds no rule and no duplicate: the
/// existing grant stays byte for byte what it was.
const CLT_DEVELOPER_DIR: &str = "/Library/Developer/CommandLineTools";

/// The only directories inside the package prefixes (`/opt/homebrew`,
/// `/usr/local`) that are read + execute allowed: the program directories the
/// package managers put executables, libraries and headers in. The prefixes
/// themselves are never allowed wholesale — `var`, `etc`, `Library` and
/// `Caskroom` hold service state, datasets, git checkouts and configs.
const PACKAGE_DIRS: &[&str] = &[
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/opt/homebrew/opt",
    "/opt/homebrew/Cellar",
    "/opt/homebrew/lib",
    "/opt/homebrew/include",
    "/opt/homebrew/share",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/opt",
    "/usr/local/Cellar",
    "/usr/local/lib",
    "/usr/local/include",
    "/usr/local/share",
];

/// State/config directories inside the package prefixes that stay explicitly
/// denied even if a future edit widens the allows: live service logs and
/// databases (`var`), package configs (`etc`), cached data (`Library`) and
/// downloaded casks (`Caskroom`).
const PACKAGE_DENIED_DIRS: &[&str] = &[
    "/opt/homebrew/var",
    "/opt/homebrew/etc",
    "/opt/homebrew/Library",
    "/opt/homebrew/Caskroom",
    "/usr/local/var",
    "/usr/local/etc",
    "/usr/local/Library",
    "/usr/local/Caskroom",
];

/// Specific files inside otherwise-denied package `etc` trees that common
/// toolchains read at startup, emitted as read-only allow-backs *after* the
/// package deny. Homebrew's OpenSSL sets `OPENSSLDIR=/opt/homebrew/etc/...`
/// and node/npm/pnpm/tsc abort in `BIO_new_file` when they cannot open the
/// config; the CA bundle is what the config points at. Keep this list literal
/// and path-specific — the surrounding `etc` tree holds service configs and
/// must stay denied.
const PACKAGE_READ_BACK_FILES: &[&str] = &[
    "/opt/homebrew/etc/openssl@3/openssl.cnf",
    "/opt/homebrew/etc/openssl@1.1/openssl.cnf",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/openssl@3/openssl.cnf",
    "/usr/local/etc/openssl@1.1/openssl.cnf",
    "/usr/local/etc/ca-certificates/cert.pem",
];

/// Read-only directory allow-backs *after* the package deny: only
/// package-shipped public certificate stores (never an OpenSSL keg's
/// `private` directory) and the macOS system Ruby gems tree, which rubygems
/// globs at interpreter startup — without it every `ruby`/`gem`/`bundler`
/// call dies with `EPERM`.
///
/// H-07 (calibration): Homebrew's own `Library/Homebrew` tree is here too —
/// that is where the `brew` executable lives and where `brew --version`,
/// `brew list` and `brew info` read their own code and formula metadata from.
/// Without it every `brew` call dies on `EPERM`. The rest of `Library` stays
/// denied; `var`, `etc` and `Caskroom` are untouched.
const READ_BACK_DIRS: &[&str] = &[
    "/opt/homebrew/etc/openssl@3/certs",
    "/opt/homebrew/etc/openssl@1.1/certs",
    "/opt/homebrew/etc/ca-certificates",
    "/opt/homebrew/Library/Homebrew",
    "/usr/local/etc/openssl@3/certs",
    "/usr/local/etc/openssl@1.1/certs",
    "/usr/local/etc/ca-certificates",
    "/usr/local/Library/Homebrew",
    "/Library/Ruby",
];

/// Directories whose programs may be **executed** after the deny, in addition
/// to the read-back above.
///
/// H-07: `brew` is a shell script that re-execs its own vendored Ruby out of
/// `Library/Homebrew` (`vendor/portable-ruby/current/bin/ruby`); read access
/// alone still fails when that binary is run. Both trees are read-only: the
/// profile never grants a write under them, so `brew install`/`brew upgrade`
/// can only touch the workspace and the per-call temp dir.
const EXEC_READ_BACK_DIRS: &[&str] = &[
    "/opt/homebrew/Library/Homebrew",
    "/usr/local/Library/Homebrew",
];

/// Extra read-only trees outside the system ones: dyld cache, timezone data,
/// TLS certificates and the device nodes.
const EXTRA_READ_TREES: &[&str] = &[
    "/private/var/db/dyld",
    "/private/var/db/timezone",
    "/private/etc/ssl",
    "/dev",
];

/// Individual `/etc` files common commands read (name resolution, local time,
/// service/protocol lookups).
const EXTRA_READ_FILES: &[&str] = &[
    "/private/etc/hosts",
    "/private/etc/resolv.conf",
    "/private/etc/localtime",
    "/private/etc/services",
    "/private/etc/protocols",
];

/// The only sysctl names allowed back after the global `(deny sysctl-read)`.
/// Derived empirically from the command matrix: libc's `sysconf`, Python's
/// `os.cpu_count`/`multiprocessing`, `uname`, `hostname` and `perl`/`shasum`
/// need exactly these; everything else (the process table, VM internals,
/// kernel boot/proc state) stays denied.
const ALLOWED_SYSCTL_NAMES: &[&str] = &[
    "hw.machine",
    "hw.memsize",
    "hw.ncpu",
    "kern.hostname",
    "kern.osrelease",
    "kern.ostype",
    "kern.osversion",
    "kern.version",
];

/// Sysctl prefixes allowed back after the global deny.
///
/// - `sysctl.` is the `sysctl(8)` CLI's own metadata namespace: the CLI asks
///   the kernel for an OID's name/format before reading a value, and those
///   lookups carry no value at all. Without it the CLI cannot even print an
///   allowed name.
/// - `hw.pagesize` covers `hw.pagesize` and `hw.pagesize32`; libc's
///   `sysconf(_SC_PAGESIZE)` reads the page size through a path that exact
///   `sysctl-name` filters do not match (empirically verified), and `perl`
///   panics without it.
const ALLOWED_SYSCTL_PREFIXES: &[&str] = &["sysctl.", "hw.pagesize"];

/// True when `workspace` and `other` share any part of their path (equal,
/// one inside the other).
fn overlaps(workspace: &Path, other: &Path) -> bool {
    workspace == other || workspace.starts_with(other) || other.starts_with(workspace)
}

/// The protected home path the workspace overlaps, if any.
fn home_overlap(workspace: &Path, home: &Path) -> Option<String> {
    // Inside the Auxesis home is fine (that is where workspaces live), but
    // the Auxesis home itself or one of its ancestors would cover the whole
    // home: `config.toml`, every agent, every workspace.
    let auxesis = home.join(AUXESIS_HOME_DIR);
    if workspace == auxesis || auxesis.starts_with(workspace) {
        return Some(auxesis.display().to_string());
    }
    for dir in SENSITIVE_DIRS {
        // `.auxesis` is validated above: only the tree itself/ancestors are
        // refused, a workspace inside it is the intended layout.
        if *dir == AUXESIS_HOME_DIR {
            continue;
        }
        let path = home.join(dir);
        if overlaps(workspace, &path) {
            return Some(path.display().to_string());
        }
    }
    for file in SENSITIVE_FILES {
        let path = home.join(file);
        if overlaps(workspace, &path) {
            return Some(path.display().to_string());
        }
    }
    None
}

/// The absolute protected path the workspace overlaps, if any.
///
/// Besides the sensitive directories this includes every tree the profile
/// declares read-only (system trees, package program directories, extra read
/// trees, read-backs) and the package state dirs it denies. The workspace
/// allow is unconditional, so a workspace equal to or inside any of them
/// would turn a read-only tree writable — or override a deny.
fn absolute_overlap(workspace: &Path) -> Option<&'static str> {
    SENSITIVE_ABSOLUTE_DIRS
        .iter()
        .chain(SYSTEM_TREES)
        .chain(PACKAGE_DIRS)
        .chain(PACKAGE_DENIED_DIRS)
        .chain(EXTRA_READ_TREES)
        .chain(READ_BACK_DIRS)
        .copied()
        .find(|dir| overlaps(workspace, Path::new(dir)))
}

/// Filesystem facts the Xcode developer-directory checks need.
struct PathFacts {
    uid: u32,
    mode: u32,
    is_dir: bool,
    is_symlink: bool,
}

/// Real `symlink_metadata` facts for one path.
fn system_facts(path: &Path) -> Option<PathFacts> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path).ok()?;
        Some(PathFacts {
            uid: meta.uid(),
            mode: meta.mode(),
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// `CFBundleIdentifier` read with `plutil` (XML or binary), under a timeout.
fn system_bundle_id(info_plist: &Path) -> Option<String> {
    let mut command = Command::new("/usr/bin/plutil");
    command
        .args(["-extract", "CFBundleIdentifier", "raw", "-o", "-"])
        .arg(info_plist);
    let output = run_with_timeout(&mut command, DEVELOPER_TOOL_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}

/// Run `command` with a wall-clock limit; kill and reap it on timeout.
fn run_with_timeout(command: &mut Command, timeout: Duration) -> Option<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {}
            Err(_) => break,
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// The developer directory `xcrun` shims will use for a sandboxed child.
/// Asked of `xcode-select -p` with `DEVELOPER_DIR` removed: the child's
/// environment is cleared, so that variable must never pick the toolchain.
/// Any failure returns `None` and the caller adds no rule.
fn active_developer_dir() -> Option<PathBuf> {
    let mut command = Command::new("/usr/bin/xcode-select");
    command.arg("-p").env_remove("DEVELOPER_DIR");
    let output = run_with_timeout(&mut command, DEVELOPER_TOOL_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    let selected = PathBuf::from(std::str::from_utf8(&output.stdout).ok()?.trim());
    resolve_developer_dir(
        &selected,
        Path::new(APPLICATIONS_ROOT),
        &system_facts,
        &system_bundle_id,
    )
}

/// The bundle directories of a canonical developer directory.
struct XcodeBundle {
    app: PathBuf,
    contents: PathBuf,
    developer: PathBuf,
}

/// Canonicalise and validate the selected developer directory. The Command
/// Line Tools is accepted (it is already in [`SYSTEM_TREES`], so it adds no
/// rule). A full Xcode is accepted only when the canonical path is exactly
/// `<root>/<bundle>.app/Contents/Developer` with the bundle directly under the
/// root, the selected path is already canonical (no symlink in it), the
/// bundle's `Info.plist` says `CFBundleIdentifier` is [`XCODE_BUNDLE_ID`], and
/// the bundle, `Contents` and `Developer` are each a real directory (checked
/// with `symlink_metadata`), owned by uid 0 with `mode & 0o022 == 0` (not
/// writable by group or others). Every failure returns `None`: no rule.
fn resolve_developer_dir(
    selected: &Path,
    applications_root: &Path,
    facts: &dyn Fn(&Path) -> Option<PathFacts>,
    bundle_id: &dyn Fn(&Path) -> Option<String>,
) -> Option<PathBuf> {
    if !selected.is_absolute() {
        return None;
    }
    let canonical = selected.canonicalize().ok()?;
    if canonical == Path::new(CLT_DEVELOPER_DIR) {
        return Some(canonical);
    }
    // Canonicalisation resolves symlinks, which would hide a symlinked
    // `Developer` (or bundle) behind another otherwise valid path. Only the
    // path the tool named is checked, and it must have no symlink in it.
    if canonical != selected {
        return None;
    }
    let bundle = xcode_bundle_paths(&canonical, applications_root)?;
    if bundle_id(&bundle.contents.join("Info.plist")).as_deref() != Some(XCODE_BUNDLE_ID) {
        return None;
    }
    for dir in [&bundle.app, &bundle.contents, &bundle.developer] {
        let facts = facts(dir)?;
        if facts.is_symlink || !facts.is_dir || facts.uid != 0 || facts.mode & 0o022 != 0 {
            return None;
        }
    }
    Some(canonical)
}

/// Split a canonical developer directory into its bundle paths. Requires the
/// bundle to sit directly under `applications_root`:
/// `<root>/<name>.app/Contents/Developer`, never deeper.
fn xcode_bundle_paths(developer: &Path, applications_root: &Path) -> Option<XcodeBundle> {
    let mut parts = developer.strip_prefix(applications_root).ok()?.components();
    let name = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (
            Some(Component::Normal(name)),
            Some(Component::Normal(contents)),
            Some(Component::Normal(dev)),
            None,
        ) if name.to_string_lossy().ends_with(".app")
            && name.len() > ".app".len()
            && contents == "Contents"
            && dev == "Developer" =>
        {
            name.to_owned()
        }
        _ => return None,
    };
    let app = applications_root.join(&name);
    let contents = app.join("Contents");
    let developer = contents.join("Developer");
    Some(XcodeBundle {
        app,
        contents,
        developer,
    })
}

/// The read + exec grant for a full Xcode developer directory, or `None` when
/// the directory is already covered (the Command Line Tools, in
/// [`SYSTEM_TREES`]).
///
/// The caller passes a directory that already passed [`resolve_developer_dir`].
/// The two lines mirror exactly what the profile already grants the Command
/// Line Tools: `file-read*` and `process-exec*`, never a write, network or
/// `file-map-executable` rule.
fn developer_dir_rules(developer_dir: &Path) -> Option<String> {
    if developer_dir == Path::new(CLT_DEVELOPER_DIR) {
        return None;
    }
    let dir = scheme_string(developer_dir).ok()?;
    Some(format!(
        "; full Xcode selected: the xcrun shims load libxcrun and exec tools from here\n\
         (allow file-read* (subpath \"{dir}\"))\n\
         (allow process-exec* (subpath \"{dir}\"))\n"
    ))
}

/// Build the deny-by-default Seatbelt profile for one call.
///
/// `home` is the *real* home of the daemon user (canonical), used for the
/// explicit sensitive-path denies. Everything not allowed here is denied by
/// the kernel, and rules are ordered last-match-wins, so the sensitive denies
/// come after the system allows and the workspace/temp allows after the
/// denies. Refuses a workspace that would override a protected location.
///
/// The active developer directory is resolved from `xcode-select -p` (with
/// `DEVELOPER_DIR` removed) and accepted only when it passes the
/// authenticity and ownership checks in [`resolve_developer_dir`]. When it is
/// a full Xcode, that directory gets the same read+exec grant as the Command
/// Line Tools; every other value adds no rule.
pub fn seatbelt_profile(
    workspace: &Path,
    temp: &Path,
    home: Option<&Path>,
    network: bool,
) -> Result<String, LaunchError> {
    let developer_dir = active_developer_dir();
    seatbelt_profile_with_developer_dir(workspace, temp, home, network, developer_dir.as_deref())
}

/// [`seatbelt_profile`] with the developer directory passed in: production
/// callers use the resolved value, tests pin it.
fn seatbelt_profile_with_developer_dir(
    workspace: &Path,
    temp: &Path,
    home: Option<&Path>,
    network: bool,
    developer_dir: Option<&Path>,
) -> Result<String, LaunchError> {
    // The grant is read-only. A workspace overlapping it would turn it
    // writable through the unconditional workspace allow, so skip the grant
    // exactly as if no Xcode were selected.
    let developer_dir = developer_dir.filter(|dir| !overlaps(workspace, dir));
    let sensitive = home
        .map(|home| home_overlap(workspace, home).is_some())
        .unwrap_or(false)
        || absolute_overlap(workspace).is_some();
    if sensitive {
        return Err(LaunchError::SensitiveWorkspace(
            workspace.display().to_string(),
        ));
    }

    let workspace = scheme_string(workspace)?;
    let temp = scheme_string(temp)?;

    let mut profile = String::from("(version 1)\n(deny default)\n(allow process-fork)\n");

    profile.push_str("(allow process-exec*");
    for path in SYSTEM_TREES.iter().chain(PACKAGE_DIRS) {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    profile.push_str(")\n");

    profile.push_str(
        "(allow mach-lookup \
         (global-name \"com.apple.system.opendirectoryd.libinfo\") \
         (global-name \"com.apple.cfprefsd.agent\") \
         (global-name \"com.apple.system.logger\") \
         (global-name \"com.apple.logd\"))\n",
    );
    profile.push_str("(allow file-read-metadata)\n");

    profile.push_str("(allow file-read*");
    for path in SYSTEM_TREES
        .iter()
        .chain(PACKAGE_DIRS)
        .chain(EXTRA_READ_TREES)
    {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    for path in EXTRA_READ_FILES {
        profile.push_str(&format!(" (literal \"{path}\")"));
    }
    profile.push_str(
        " (literal \"/\") (literal \"/private/var/select/sh\") \
         (subpath \"/dev\"))\n",
    );

    profile.push_str(
        "(allow file-write* (literal \"/dev/null\") (literal \"/dev/stdout\") \
         (literal \"/dev/stderr\") (literal \"/dev/dtracehelper\"))\n",
    );

    if network {
        // v1 contract: network = true means *all* sockets, any host and port;
        // there is no narrower allowlist.
        profile.push_str("; network = true: all sockets for v1 (loopback included)\n");
        profile.push_str("(allow network*)\n");
    } else {
        profile.push_str("; network = false: all sockets denied (loopback included)\n");
    }

    // Sensitive denies come after the system allows so they always win, and
    // before the workspace/temp allows (a workspace inside `~/.auxesis` is
    // allowed to override its own home's deny for its own subtree only).
    let mut denies: Vec<String> = Vec::new();
    if let Some(home) = home {
        let home = scheme_string(home)?;
        for dir in SENSITIVE_DIRS {
            denies.push(format!("(subpath \"{home}/{dir}\")"));
        }
        for file in SENSITIVE_FILES {
            denies.push(format!("(literal \"{home}/{file}\")"));
        }
    }
    for dir in SENSITIVE_ABSOLUTE_DIRS {
        denies.push(format!("(subpath \"{dir}\")"));
    }
    for dir in PACKAGE_DENIED_DIRS {
        denies.push(format!("(subpath \"{dir}\")"));
    }
    profile.push_str(&format!("(deny file-read* {})\n", denies.join(" ")));

    // Narrow read-backs *after* the deny, so the specific files common
    // toolchains read at startup stay readable without re-opening the broad
    // package `etc` trees: Homebrew's OpenSSL config/CA bundle (node, npm,
    // pnpm, tsc abort without them), Homebrew's own `Library/Homebrew` code
    // (H-07: `brew --version`/`list`/`info`, including exec of its vendored
    // Ruby) and system Ruby's gems tree (rubygems globs it in
    // `gem_prelude`, before any user code runs).
    profile.push_str("(allow file-read*");
    for path in PACKAGE_READ_BACK_FILES {
        profile.push_str(&format!(" (literal \"{path}\")"));
    }
    for path in READ_BACK_DIRS {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    profile.push_str(")\n");
    profile.push_str("(allow process-exec*");
    for path in EXEC_READ_BACK_DIRS {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    profile.push_str(")\n");

    // The workspace and temp allows come after the sensitive denies so they
    // win for their own tree (the workspace lives inside the Auxesis home).
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{workspace}\") (subpath \"{temp}\"))\n\
         (allow file-write* (subpath \"{workspace}\") (subpath \"{temp}\"))\n\
         (allow process-exec* (subpath \"{workspace}\") (subpath \"{temp}\"))\n"
    ));
    // Git may run hooks outside this sandbox later. Never let a shell call
    // plant or alter executable repository metadata in the workspace.
    profile.push_str(&format!(
        "(deny file-write* (subpath \"{workspace}/.git\"))\n"
    ));

    // Deny re-entering the sandbox helper: nested `sandbox-exec` can only add
    // restrictions, but there is no reason to run it from a shell. `osascript`
    // is denied too: every out-of-process AppleScript channel is already
    // unreachable, so the only thing left is in-process Cocoa scripting, which
    // nothing in the command matrix needs.
    profile.push_str(
        "(deny process-exec* (literal \"/usr/bin/sandbox-exec\"))\n\
         (deny process-exec* (literal \"/usr/bin/osascript\"))\n",
    );

    // Global diagnostics tightening, last so it beats anything above. Without
    // these two denies, `lsof` reads the whole process table and open-file map
    // (through process-info, not sysctl), `launchctl print` dumps the GUI
    // launchd job table, and `sysctl -a` exposes kern/vm internals. The
    // allow-backs that follow are deliberately tiny: process-info only for
    // **self** (Foundation aborts on `sw_vers`/`osascript` without it), and
    // the non-sensitive sysctl names common commands actually need.
    profile.push_str("(deny sysctl-read)\n");
    profile.push_str("(deny process-info*)\n");
    profile.push_str("(allow process-info* (target self))\n");
    profile.push_str("(allow sysctl-read");
    for prefix in ALLOWED_SYSCTL_PREFIXES {
        profile.push_str(&format!(" (sysctl-name-prefix \"{prefix}\")"));
    }
    for name in ALLOWED_SYSCTL_NAMES {
        profile.push_str(&format!(" (sysctl-name \"{name}\")"));
    }
    profile.push_str(")\n");

    // A full Xcode moves the xcrun shims' libraries and tools under the
    // selected developer directory; without this grant `/usr/bin/git` (and
    // every other xcrun shim) dies with "unable to load libxcrun". The rule is
    // appended last and only ever adds read + exec: the existing profile above
    // is untouched, and nothing grants a write under the directory.
    if let Some(developer_dir) = developer_dir {
        if let Some(rules) = developer_dir_rules(developer_dir) {
            profile.push_str(&rules);
        }
    }
    Ok(profile)
}

/// Quote a path as a Scheme string in a Seatbelt profile.
///
/// Control characters are refused: they cannot be represented safely and a
/// path containing them must never be able to shape the profile.
fn scheme_string(path: &Path) -> Result<String, LaunchError> {
    let text = path
        .to_str()
        .ok_or_else(|| LaunchError::UnsafeWorkspace(path.display().to_string()))?;
    if text.chars().any(char::is_control) {
        return Err(LaunchError::UnsafeWorkspace(path.display().to_string()));
    }
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The real (canonical) home of the daemon user.
///
/// `HOME` is used when it names a real directory that is not `/`; otherwise
/// the passwd entry for the effective user is the fallback, so an unset or
/// mangled `HOME` cannot silently drop the whole sensitive-path deny list.
/// If even that fails, the drop is logged loudly (the caller sees `None` and
/// the profile simply has no home denies).
fn real_home() -> Option<PathBuf> {
    real_home_from(std::env::var_os("HOME").as_deref())
}

/// Testable core of [`real_home`]: the `HOME` value is passed in.
fn real_home_from(env_home: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    if let Some(home) = env_home {
        if let Ok(home) = PathBuf::from(home).canonicalize() {
            if home.is_dir() && home != Path::new("/") {
                return Some(home);
            }
        }
    }
    match passwd_home() {
        Some(home) => {
            tracing::warn!(
                "shell: HOME is unset or unusable; using the passwd home {} for the \
                 sensitive-path deny list",
                home.display()
            );
            Some(home)
        }
        None => {
            tracing::warn!(
                "shell: HOME is unset or unusable and the passwd home could not be \
                 resolved; sensitive-path denies are NOT applied to this command"
            );
            None
        }
    }
}

/// The home directory from the passwd entry of the effective user, canonical.
#[cfg(unix)]
fn passwd_home() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let uid = unsafe { libc::geteuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    let home = home.canonicalize().ok()?;
    (home.is_dir() && home != Path::new("/")).then_some(home)
}

#[cfg(not(unix))]
fn passwd_home() -> Option<PathBuf> {
    None
}

/// Mark every open descriptor >= 3 close-on-exec, except `keep_fd` (the
/// read-only per-call marker).
///
/// `closefrom(3)` is deliberately not used: it would also close the
/// error-reporting pipe Rust's process spawner holds across `exec`, breaking
/// exec-failure reporting. `PROC_PIDLISTFDS` lists exactly the fds this
/// process has; if that fails, sweep a bounded range instead.
#[cfg(unix)]
fn mark_inherited_fds_close_on_exec(keep_fd: i32) {
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
                if fd == keep_fd {
                    // The marker is created with `O_CLOEXEC` like every Rust
                    // file; clear it so the marker survives exec.
                    set_close_on_exec(fd, false);
                } else {
                    set_close_on_exec(fd, true);
                }
            }
            return;
        }
    }
    // Fallback (non-macOS or a failed proc_pidinfo): sweep the inherited
    // soft limit, capped so a huge limit cannot stall the spawn.
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

#[cfg(unix)]
fn set_close_on_exec(fd: i32, close: bool) {
    let flags = if close { libc::FD_CLOEXEC } else { 0 };
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, flags);
    }
}

/// Best-effort resource caps for the command (and everything it forks).
///
/// `RLIMIT_NPROC` is a per-user total on macOS, so when `max_processes` is
/// non-zero it is set to the current user process count plus that headroom:
/// the command can still spawn its normal toolset, but cannot fork-bomb the
/// whole user session. `0` leaves it unset (the shell tool's own process
/// watchdog covers that path).
#[cfg(unix)]
fn set_child_limits(cpu_seconds: u64, max_file_bytes: u64, max_processes: u64) {
    let limit = |value: u64| libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CPU, &limit(cpu_seconds));
        libc::setrlimit(libc::RLIMIT_FSIZE, &limit(max_file_bytes));
        libc::setrlimit(libc::RLIMIT_NOFILE, &limit(MAX_OPEN_FILES));
        if max_processes > 0 {
            let nproc = user_process_count().saturating_add(max_processes);
            if nproc > 0 {
                libc::setrlimit(libc::RLIMIT_NPROC, &limit(nproc));
            }
        }
        // Best effort: Linux enforces the address-space cap, macOS rejects it
        // (EINVAL) and may accept DATA.
        libc::setrlimit(libc::RLIMIT_AS, &limit(MAX_COMMAND_MEMORY_BYTES));
        libc::setrlimit(libc::RLIMIT_DATA, &limit(MAX_COMMAND_MEMORY_BYTES));
    }
}

/// Extra processes above the current user count an ACP terminal may create
/// (`RLIMIT_NPROC` headroom).
pub const MAX_EXTRA_PROCESSES: u64 = 64;

/// Number of live processes owned by this user (RLIMIT_NPROC headroom).
#[cfg(target_os = "macos")]
fn user_process_count() -> u64 {
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
            return 0;
        }
        let count = n as usize / std::mem::size_of::<i32>();
        if count < capacity {
            buf.truncate(count);
            let euid = unsafe { libc::geteuid() };
            return buf
                .into_iter()
                .filter(|pid| {
                    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
                    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
                    let n = unsafe {
                        libc::proc_pidinfo(
                            *pid,
                            libc::PROC_PIDTBSDINFO,
                            0,
                            info.as_mut_ptr().cast(),
                            size,
                        )
                    };
                    n == size && unsafe { info.assume_init() }.pbi_uid == euid
                })
                .count() as u64;
        }
        capacity = capacity.saturating_mul(2);
    }
    0
}

#[cfg(target_os = "linux")]
fn user_process_count() -> u64 {
    use std::os::unix::fs::MetadataExt;
    let euid = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.chars().all(|ch| ch.is_ascii_digit()))
        })
        .filter(|entry| {
            std::fs::metadata(entry.path())
                .map(|metadata| metadata.uid() == euid)
                .unwrap_or(false)
        })
        .count() as u64
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn user_process_count() -> u64 {
    0
}

/// Build the command for `command_line`, sandboxed when possible.
///
/// Returns [`LaunchError::Unavailable`] (fail closed) when sandboxing is
/// requested but `sandbox-exec` is missing, unless
/// [`ShellSandbox::allow_unsandboxed`] is set — in which case the command
/// runs unsandboxed and the fallback is logged loudly. Likewise,
/// `sandbox.enabled = false` refuses unless `allow_unsandboxed` is set.
pub fn launch(
    command_line: &str,
    workspace: &Path,
    sandbox: &ShellSandbox,
    timeout: Duration,
) -> Result<Launched, LaunchError> {
    launch_with_limits(command_line, workspace, sandbox, timeout, MAX_FILE_BYTES, 0)
}

/// [`launch`] with an explicit `RLIMIT_FSIZE` cap for everything the command
/// tree writes. The ACP terminal broker passes the read cap (256 KiB) so an
/// agent terminal cannot grow its capture files (or any file) without bound.
pub fn launch_with_file_cap(
    command_line: &str,
    workspace: &Path,
    sandbox: &ShellSandbox,
    timeout: Duration,
    max_file_bytes: u64,
) -> Result<Launched, LaunchError> {
    launch_with_limits(command_line, workspace, sandbox, timeout, max_file_bytes, 0)
}

/// [`launch`] with explicit caps: `max_file_bytes` (`RLIMIT_FSIZE`) and, when
/// `max_processes > 0`, an `RLIMIT_NPROC` headroom above the current user
/// process count. The ACP terminal broker uses both.
pub fn launch_with_limits(
    command_line: &str,
    workspace: &Path,
    sandbox: &ShellSandbox,
    timeout: Duration,
    max_file_bytes: u64,
    max_processes: u64,
) -> Result<Launched, LaunchError> {
    let workspace = workspace.canonicalize()?;
    if workspace == Path::new("/") || !workspace.is_dir() {
        return Err(LaunchError::UnsafeWorkspace(
            workspace.display().to_string(),
        ));
    }

    let use_sandbox = if !sandbox.enabled {
        if !sandbox.allow_unsandboxed {
            tracing::error!(
                "shell refused: shell.sandbox = false without shell.allow_unsandboxed = true \
                 (workspace: {})",
                workspace.display()
            );
            return Err(LaunchError::SandboxDisabled);
        }
        tracing::error!(
            "shell: sandbox disabled by configuration and shell.allow_unsandboxed = true; \
             running commands UNSANDBOXED (workspace: {})",
            workspace.display()
        );
        false
    } else if sandbox.available() {
        true
    } else if sandbox.allow_unsandboxed {
        tracing::error!(
            "shell: sandbox-exec unavailable; running commands UNSANDBOXED because \
             shell.allow_unsandboxed = true (workspace: {})",
            workspace.display()
        );
        false
    } else {
        tracing::error!(
            "shell refused: sandbox-exec unavailable and shell.allow_unsandboxed is not set \
             (workspace: {})",
            workspace.display()
        );
        return Err(LaunchError::Unavailable);
    };

    // Per-call private temp dir: `HOME` and `TMPDIR` for the command, and the
    // only writable place besides the workspace. Failing to create it refuses
    // the call: falling back to the system temp root would open the whole
    // world. `tempfile` creates it with plain `create_dir` (0777 & ~umask),
    // so tighten it to 0700 explicitly — the private dir must not depend on
    // the daemon's umask.
    let temp = tempfile::Builder::new().prefix("aux-shell-").tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let temp_path = temp.path().canonicalize()?;

    // Output goes to unlinked private files: a background process holding the
    // stdout stream open can no longer keep the tool waiting for EOF, and the
    // command cannot tamper with (or symlink) a name we later reopen.
    let stdout_capture = tempfile::tempfile_in(&temp_path)?;
    let stderr_capture = tempfile::tempfile_in(&temp_path)?;
    let stdout_child = stdout_capture.try_clone()?;
    let stderr_child = stderr_capture.try_clone()?;
    // The marker file is read-only, empty and unlinked: inheriting it gives
    // the command no data and no write channel, but the sweep can find any
    // process that still holds it.
    let marker_file = tempfile::tempfile_in(&temp_path)?;

    let mut command = if use_sandbox {
        let profile = seatbelt_profile(
            &workspace,
            &temp_path,
            real_home().as_deref(),
            sandbox.network,
        )?;
        let mut command = tokio::process::Command::new(&sandbox.sandbox_exec);
        command.arg("-p").arg(profile);
        command.arg("/bin/sh");
        command
    } else {
        tokio::process::Command::new("/bin/sh")
    };
    command
        .arg("-c")
        .arg(command_line)
        .current_dir(&workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_child))
        .stderr(Stdio::from(stderr_child))
        .kill_on_drop(true);

    // Sanitised environment: never inherit the daemon's (or its parent's)
    // environment, which may hold API keys or tokens. Only a small allowlist
    // crosses into the command; `PATH` is the sandbox's own fixed value (the
    // owner's PATH leaks the account name and private toolchain layout and
    // buys the command nothing), and HOME/TMPDIR point at the private temp dir.
    command.env_clear();
    for key in ["LANG", "LC_ALL", "LC_CTYPE", "TERM"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("PATH", SANDBOX_PATH)
        .env("HOME", &temp_path)
        .env("TMPDIR", &temp_path)
        .env("SHELL", "/bin/sh");

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::process::CommandExt;
        let std_cmd = command.as_std_mut();
        let cpu_seconds = timeout.as_secs().saturating_add(CPU_LIMIT_GRACE_SECS);
        let marker_fd = marker_file.as_raw_fd();
        // New session (and process group): no controlling terminal, and a
        // pgid the timeout can SIGKILL as a group. Also drop every inherited
        // descriptor — except the read-only marker — and set best-effort
        // resource caps: all in the child, before exec, so the daemon itself
        // is untouched.
        unsafe {
            std_cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                mark_inherited_fds_close_on_exec(marker_fd);
                set_child_limits(cpu_seconds, max_file_bytes, max_processes);
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (&marker_file, max_file_bytes, max_processes);

    Ok(Launched {
        command,
        temp,
        stdout_capture,
        stderr_capture,
        marker_file,
    })
}

/// Map a launch failure to the tool-facing error.
///
/// `Unavailable` / `SandboxDisabled` become a [`ToolError::Io`] carrying the
/// refusal message so the model reads exactly why nothing ran.
pub fn launch_error(err: LaunchError) -> ToolError {
    match err {
        LaunchError::Unavailable => ToolError::Io(std::io::Error::other(UNAVAILABLE_MESSAGE)),
        LaunchError::SandboxDisabled => ToolError::Io(std::io::Error::other(DISABLED_MESSAGE)),
        LaunchError::UnsafeWorkspace(path) | LaunchError::SensitiveWorkspace(path) => {
            ToolError::UnsafePath {
                path,
                reason: "shell workspace must be a real directory that does not overlap \
                         sensitive directories"
                    .to_string(),
            }
        }
        LaunchError::Io(err) => ToolError::Io(err),
    }
}

/// A ready macOS Seatbelt wrapper for a long-lived stdio child (an MCP server).
///
/// Unlike the shell tool, the child speaks a protocol on stdin/stdout and is
/// **not** a shell string: the confirmed program is exec'd directly under the
/// same deny-by-default profile. `~/.auxesis` (and the store inside it) is
/// denied read and write as the last rules of the profile, so nothing above
/// can re-open it. Network is denied unless `network` is set.
///
/// The wrapper owns a private temp dir used as the child's `HOME`/`TMPDIR`;
/// keep the value alive for as long as the child runs.
#[derive(Debug)]
pub struct StdioSandbox {
    temp: TempDir,
    profile: String,
    /// Always [`SANDBOX_EXEC`]: set in [`StdioSandbox::build`] and nowhere else.
    sandbox_exec: PathBuf,
}

impl StdioSandbox {
    /// Build the profile for `program` and create the private temp dir.
    ///
    /// `program`'s own directory is made readable and executable (it is the
    /// exact path the owner confirmed) unless it lives inside a protected
    /// tree; the auxesis home stays denied either way.
    ///
    /// The store deny uses the daemon's **actual** Auxesis home
    /// (`$AUXESIS_HOME` when set), not `$HOME/.auxesis` (item 9).
    ///
    /// The `sandbox-exec` executable is always the fixed [`SANDBOX_EXEC`]. No
    /// public constructor takes another path: a caller-chosen wrapper that
    /// ignored the profile would launch the MCP child **unsandboxed**.
    ///
    /// ```compile_fail
    /// # use kernel_broker::sandbox::StdioSandbox;
    /// # use std::path::{Path, PathBuf};
    /// // error[E0599]: no function or associated item named `with_exec` found
    /// let _ = StdioSandbox::with_exec(
    ///     Path::new("/usr/bin/true"),
    ///     false,
    ///     PathBuf::from("/tmp/fake-sandbox-exec"),
    /// );
    /// ```
    pub fn new(program: &Path, network: bool) -> Result<Self, LaunchError> {
        let auxesis_home = kernel_core::auxesis_home();
        Self::build(program, network, Some(&auxesis_home))
    }

    /// The shared body of [`StdioSandbox::new`], with an explicit Auxesis home.
    ///
    /// Tests pass a relocated home so the store deny is exercised without
    /// reading or writing the real one. It takes no `sandbox-exec` path on
    /// purpose: every profile wraps [`SANDBOX_EXEC`].
    fn build(
        program: &Path,
        network: bool,
        auxesis_home: Option<&Path>,
    ) -> Result<Self, LaunchError> {
        let temp = tempfile::Builder::new().prefix("aux-mcp-").tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let temp_path = temp.path().canonicalize()?;
        let home = real_home();
        let mut profile = seatbelt_profile(&temp_path, &temp_path, home.as_deref(), network)?;
        if let Some(dir) = program.parent() {
            let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
            if dir != Path::new("/") && !dir.as_os_str().is_empty() {
                let sensitive = home
                    .as_deref()
                    .is_some_and(|home| home_overlap(&dir, home).is_some())
                    || absolute_overlap(&dir).is_some();
                if !sensitive {
                    if let Ok(dir) = scheme_string(&dir) {
                        profile.push_str(&format!(
                            "(allow file-read* (subpath \"{dir}\"))\n\
                             (allow process-exec* (subpath \"{dir}\"))\n"
                        ));
                    }
                }
            }
        }
        // Last rules win: the daemon's actual Auxesis home **and its store**
        // are denied read and write, wherever `AUXESIS_HOME` points (item 9).
        // The real `$HOME/.auxesis` is still denied by the sensitive-path
        // rules above, so a relocated home never weakens that either.
        if let Some(auxesis) = auxesis_home {
            let root = scheme_string(auxesis)?;
            let store = scheme_string(&kernel_core::store_path(auxesis))?;
            profile.push_str(&format!(
                "(deny file-read* (subpath \"{root}\") (literal \"{store}\"))\n\
                 (deny file-write* (subpath \"{root}\") (literal \"{store}\"))\n"
            ));
        }
        Ok(Self {
            temp,
            profile,
            sandbox_exec: PathBuf::from(SANDBOX_EXEC),
        })
    }

    /// The private temp dir the child uses as `HOME`/`TMPDIR`.
    pub fn temp_path(&self) -> &Path {
        self.temp.path()
    }

    /// Build the sandboxed command that runs `program` with `args`.
    pub fn command(&self, program: &Path, args: &[std::ffi::OsString]) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(&self.sandbox_exec);
        command.arg("-p").arg(&self.profile).arg(program).args(args);
        command
    }
}

#[cfg(test)]
mod stdio_sandbox_tests {
    use super::*;

    #[test]
    fn new_always_wraps_the_child_with_the_fixed_sandbox_exec() {
        // No caller picks the sandbox helper. `new` must record the fixed
        // `SANDBOX_EXEC`, and the command it hands out must execute that binary:
        // a substituted wrapper would skip the profile entirely.
        let program = std::env::current_exe().expect("current exe");
        let sandbox = StdioSandbox::new(&program, false).expect("sandbox");
        assert_eq!(sandbox.sandbox_exec, PathBuf::from(SANDBOX_EXEC));
        let command = sandbox.command(&program, &[]);
        assert_eq!(
            command.as_std().get_program(),
            std::ffi::OsStr::new(SANDBOX_EXEC)
        );
    }

    #[test]
    fn stdio_profile_denies_the_configured_auxesis_home_and_gates_network() {
        let program = std::env::current_exe().expect("current exe");
        // Item 9: the deny follows the daemon's actual AUXESIS_HOME, not
        // `$HOME/.auxesis`. A relocated home is passed explicitly.
        let relocated = Path::new("/tmp/aux-mcp-relocated/.auxesis");
        let denied = StdioSandbox::build(&program, false, Some(relocated)).expect("sandbox");
        assert!(
            denied
                .profile
                .contains("(subpath \"/tmp/aux-mcp-relocated/.auxesis\")"),
            "the configured Auxesis home must be denied: {}",
            denied.profile
        );
        assert!(
            denied
                .profile
                .contains("(literal \"/tmp/aux-mcp-relocated/.auxesis/store.db\")"),
            "the store path must be denied too: {}",
            denied.profile
        );
        assert!(!denied.profile.contains("(allow network*)"));
        let allowed = StdioSandbox::build(&program, true, Some(relocated)).expect("sandbox");
        assert!(allowed.profile.contains("(allow network*)"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_deny_by_default_and_scopes_writes() {
        let profile = seatbelt_profile(
            Path::new("/tmp/ws"),
            Path::new("/tmp/tmp"),
            Some(Path::new("/Users/tester")),
            false,
        )
        .unwrap();

        assert!(profile.starts_with("(version 1)\n(deny default)\n"));
        assert!(
            profile.contains("(allow file-write* (subpath \"/tmp/ws\") (subpath \"/tmp/tmp\"))")
        );
        assert!(profile.contains("(deny file-write* (subpath \"/tmp/ws/.git\"))"));
        assert!(profile.contains("(subpath \"/usr\")"));
        assert!(!profile.contains("(allow network*)"));

        // Sensitive paths are denied after the broad allows, so the deny wins.
        let deny_at = profile.find("(deny file-read*").unwrap();
        let allow_at = profile.find("(allow file-read-metadata)").unwrap();
        assert!(deny_at > allow_at);
        assert!(profile.contains("(subpath \"/Users/tester/.auxesis\")"));
        assert!(profile.contains("(subpath \"/Users/tester/.ssh\")"));
        assert!(profile.contains("(subpath \"/Users/tester/Library/Keychains\")"));
        assert!(profile.contains("(subpath \"/Users/tester/Library/Messages\")"));
        assert!(profile.contains("(subpath \"/Users/tester/Library/Mail\")"));
        assert!(profile.contains("(literal \"/Users/tester/.netrc\")"));
        assert!(profile.contains("(subpath \"/Library/Keychains\")"));

        // The workspace allow comes after the sensitive denies.
        let ws_allow_at = profile
            .rfind("(allow file-read* (subpath \"/tmp/ws\")")
            .unwrap();
        assert!(
            ws_allow_at > deny_at,
            "workspace allow must override the home deny"
        );

        // Network is opt-in only.
        let with_net =
            seatbelt_profile(Path::new("/tmp/ws"), Path::new("/tmp/tmp"), None, true).unwrap();
        assert!(with_net.contains("(allow network*)"));
        assert!(
            with_net.contains("all sockets for v1"),
            "network semantics must stay documented in the profile"
        );
        let no_net =
            seatbelt_profile(Path::new("/tmp/ws"), Path::new("/tmp/tmp"), None, false).unwrap();
        assert!(no_net.contains("all sockets denied"));
    }

    #[test]
    fn read_allowlist_is_minimal() {
        // No blanket `/private/var/db`, `/Library` or `/private/etc` reads:
        // only the explicit paths we can name.
        let profile = seatbelt_profile(
            Path::new("/tmp/ws"),
            Path::new("/tmp/tmp"),
            Some(Path::new("/Users/tester")),
            false,
        )
        .unwrap();

        assert!(!profile.contains("(subpath \"/private/var/db\")"));
        assert!(!profile.contains("(subpath \"/Library\")"));
        assert!(!profile.contains("(subpath \"/private/etc\")"));
        assert!(!profile.contains("(allow file-read* (subpath \"/private/var/log\")"));

        // WSD2-P1-02: the package prefixes must NEVER be allowed wholesale —
        // the top-level trees are owner-owned and hold git checkouts, service
        // state and configs. Only the program directories are allowed.
        assert!(
            !profile.contains("(subpath \"/opt/homebrew\")"),
            "the whole /opt/homebrew prefix must never be allowed"
        );
        assert!(
            !profile.contains("(subpath \"/usr/local\")"),
            "the whole /usr/local prefix must never be allowed"
        );
        for allowed in [
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/opt/homebrew/opt",
            "/opt/homebrew/Cellar",
            "/opt/homebrew/lib",
            "/opt/homebrew/include",
            "/opt/homebrew/share",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/local/opt",
            "/usr/local/Cellar",
            "/usr/local/lib",
            "/usr/local/include",
            "/usr/local/share",
        ] {
            assert!(
                profile.contains(&format!("(subpath \"{allowed}\")")),
                "missing package program dir {allowed}"
            );
        }
        assert!(!profile.contains(".cargo"));
        assert!(!profile.contains(".rustup"));

        // The minimal paths that common commands actually need are present.
        for allowed in [
            "/private/var/db/timezone",
            "/private/var/db/dyld",
            "/private/etc/hosts",
            "/private/etc/resolv.conf",
            "/private/etc/localtime",
            "/private/etc/ssl",
        ] {
            assert!(
                profile.contains(&format!("(subpath \"{allowed}\")"))
                    || profile.contains(&format!("(literal \"{allowed}\")")),
                "missing minimal allow {allowed}"
            );
        }

        // The unprotected machine-state trees are denied in the deny rule,
        // which is emitted after the system allows.
        let deny_line = profile
            .lines()
            .find(|line| line.starts_with("(deny file-read*"))
            .expect("profile must contain a deny rule");
        let deny_at = profile.find(deny_line).unwrap();
        let system_allow_at = profile.find("(allow file-read*").unwrap();
        assert!(
            deny_at > system_allow_at,
            "deny rule must come after the system allows"
        );
        for denied in [
            "/Library/Keychains",
            "/Library/Logs",
            "/private/var/log",
            "/private/var/db/diagnostics",
            "/private/var/db/uuidtext",
            "/var/root",
            // WSD2-P1-02: package state dirs stay explicitly denied.
            "/opt/homebrew/var",
            "/opt/homebrew/etc",
            "/opt/homebrew/Library",
            "/opt/homebrew/Caskroom",
            "/usr/local/var",
            "/usr/local/etc",
            "/usr/local/Library",
            "/usr/local/Caskroom",
        ] {
            assert!(
                deny_line.contains(&format!("(subpath \"{denied}\")")),
                "missing explicit deny {denied}"
            );
        }

        // WSD3-P2-01 / WSD3-P2-02: the specific read-backs after the deny are
        // present, and *no* read-allow rule ever covers a broad package/`etc`
        // prefix — only the named files and public cert/gem/Homebrew-code
        // directories.
        let allow_lines: Vec<&str> = profile
            .lines()
            .filter(|line| line.starts_with("(allow file-read*"))
            .collect();
        for path in [
            "/opt/homebrew/etc/openssl@3/openssl.cnf",
            "/usr/local/etc/openssl@3/openssl.cnf",
        ] {
            assert!(
                allow_lines
                    .iter()
                    .any(|line| line.contains(&format!("(literal \"{path}\")"))),
                "missing OpenSSL config read-back {path}"
            );
        }
        for path in [
            "/opt/homebrew/etc/openssl@3/certs",
            "/opt/homebrew/etc/ca-certificates",
            "/Library/Ruby",
        ] {
            assert!(
                allow_lines
                    .iter()
                    .any(|line| line.contains(&format!("(subpath \"{path}\")"))),
                "missing read-back directory {path}"
            );
        }
        for line in &allow_lines {
            for broad in [
                "(subpath \"/opt/homebrew/etc\")",
                "(subpath \"/opt/homebrew/var\")",
                "(subpath \"/opt/homebrew/Library\")",
                "(subpath \"/usr/local/etc\")",
                "(subpath \"/usr/local/var\")",
                "(subpath \"/usr/local/Library\")",
                "(subpath \"/Library\")",
                "(subpath \"/private/etc\")",
                "(subpath \"/private/var\")",
                "(subpath \"/Users\")",
            ] {
                assert!(
                    !line.contains(broad),
                    "a broad read allow returned: {broad} in {line}"
                );
            }
        }
    }

    #[test]
    fn homebrew_library_homebrew_is_readable_but_the_rest_of_library_is_not() {
        // H-07 (calibration): `brew --version`/`list`/`info` read their own
        // code out of `Library/Homebrew`. The read-back is emitted *after*
        // the package deny (last-match-wins) so it wins for its own subtree;
        // `etc`, `var` and `Caskroom` keep their deny.
        let profile = seatbelt_profile(
            Path::new("/tmp/ws"),
            Path::new("/tmp/tmp"),
            Some(Path::new("/Users/tester")),
            false,
        )
        .unwrap();

        for path in [
            "/opt/homebrew/Library/Homebrew",
            "/usr/local/Library/Homebrew",
        ] {
            let deny_line = profile
                .lines()
                .find(|line| line.starts_with("(deny file-read*"))
                .expect("deny rule");
            assert!(
                deny_line.contains(&format!("(subpath \"{path}\")"))
                    || deny_line.contains("(subpath \"/opt/homebrew/Library\")"),
                "the Library deny must still cover {path}"
            );
            let allow_at = profile
                .find(&format!("(subpath \"{path}\")"))
                .unwrap_or_else(|| panic!("missing read-back {path}"));
            let deny_at = profile.find(deny_line).unwrap();
            assert!(
                allow_at > deny_at,
                "the read-back for {path} must come after the deny (last-match-wins)"
            );
        }
        // The deny itself still names the whole Library tree for both
        // prefixes: only the named subdirectory is read back.
        let deny_line = profile
            .lines()
            .find(|line| line.starts_with("(deny file-read*"))
            .expect("deny rule");
        for denied in [
            "/opt/homebrew/Library",
            "/opt/homebrew/var",
            "/opt/homebrew/etc",
            "/opt/homebrew/Caskroom",
            "/usr/local/Library",
            "/usr/local/var",
            "/usr/local/etc",
            "/usr/local/Caskroom",
        ] {
            assert!(
                deny_line.contains(&format!("(subpath \"{denied}\")")),
                "missing explicit deny {denied}"
            );
        }

        // A read-back alone is not enough for `brew`: its wrapper re-execs
        // the vendored Ruby out of the same tree. The exec allow-back must
        // be narrow (exactly the two Homebrew code dirs) and must never
        // grant write; the rest of the package prefixes stay exec-denied.
        let exec_lines: Vec<&str> = profile
            .lines()
            .filter(|line| line.starts_with("(allow process-exec*"))
            .collect();
        for path in [
            "/opt/homebrew/Library/Homebrew",
            "/usr/local/Library/Homebrew",
        ] {
            assert!(
                exec_lines
                    .iter()
                    .any(|line| line.contains(&format!("(subpath \"{path}\")"))),
                "missing exec read-back {path}"
            );
        }
        for line in &exec_lines {
            for broad in [
                "(subpath \"/opt/homebrew/Library\")",
                "(subpath \"/opt/homebrew\")",
                "(subpath \"/usr/local/Library\")",
                "(subpath \"/opt/homebrew/etc\")",
                "(subpath \"/opt/homebrew/var\")",
                "(subpath \"/opt/homebrew/Caskroom\")",
            ] {
                assert!(
                    !line.contains(broad),
                    "a broad exec allow returned: {broad} in {line}"
                );
            }
        }
        assert!(
            !profile.contains("(allow file-write* (subpath \"/opt/homebrew/Library/Homebrew\")"),
            "the Homebrew read-back must never be writable"
        );
    }

    #[test]
    fn profile_tightens_sysctl_and_process_info() {
        // WSD2-P1-01: no broad sysctl-read; process-info is denied globally
        // and allowed back for self only.
        let profile = seatbelt_profile(
            Path::new("/tmp/ws"),
            Path::new("/tmp/tmp"),
            Some(Path::new("/Users/tester")),
            false,
        )
        .unwrap();

        assert!(
            !profile.contains("(allow sysctl-read)\n"),
            "broad sysctl-read must never come back"
        );
        let deny_at = profile
            .find("(deny sysctl-read)")
            .expect("sysctl-read must be denied");
        let allow_at = profile
            .find("(allow sysctl-read (")
            .expect("the minimal sysctl allow-back must be present");
        assert!(
            allow_at > deny_at,
            "the sysctl allow-back must come after the deny (last-match-wins)"
        );
        let allow_line = profile[allow_at..].lines().next().unwrap();
        for name in [
            "hw.machine",
            "hw.memsize",
            "hw.ncpu",
            "kern.hostname",
            "kern.osrelease",
            "kern.ostype",
            "kern.osversion",
            "kern.version",
        ] {
            assert!(
                allow_line.contains(&format!("(sysctl-name \"{name}\")")),
                "missing allowed sysctl {name}"
            );
        }
        assert!(allow_line.contains("(sysctl-name-prefix \"sysctl.\")"));
        assert!(allow_line.contains("(sysctl-name-prefix \"hw.pagesize\")"));
        // No sensitive families may be allowed by name or prefix.
        for forbidden in ["kern.proc", "vm.", "net.", "machdep.", "kern.boottime"] {
            assert!(
                !allow_line.contains(forbidden),
                "sensitive sysctl family {forbidden} must not be allowed"
            );
        }

        assert!(profile.contains("(deny process-info*)"));
        let proc_deny = profile.find("(deny process-info*)").unwrap();
        let proc_allow = profile
            .find("(allow process-info* (target self))")
            .expect("self process-info must stay allowed");
        assert!(
            proc_allow > proc_deny,
            "the self allow must come after the deny"
        );

        // The helper binary cannot be re-entered from a command either.
        assert!(profile.contains("(deny process-exec* (literal \"/usr/bin/sandbox-exec\"))"));
        assert!(profile.contains("(deny process-exec* (literal \"/usr/bin/osascript\"))"));
    }

    fn profile_with_developer_dir(developer_dir: Option<&Path>) -> String {
        seatbelt_profile_with_developer_dir(
            Path::new("/tmp/ws"),
            Path::new("/tmp/tmp"),
            Some(Path::new("/Users/tester")),
            false,
            developer_dir,
        )
        .unwrap()
    }

    fn fake_facts(uid: u32, mode: u32) -> impl Fn(&Path) -> Option<PathFacts> {
        move |path| {
            let meta = std::fs::symlink_metadata(path).ok()?;
            Some(PathFacts {
                uid,
                mode,
                is_dir: meta.is_dir(),
                is_symlink: meta.file_type().is_symlink(),
            })
        }
    }

    fn resolve(root: &Path, path: &Path, uid: u32, mode: u32, id: &'static str) -> Option<PathBuf> {
        resolve_developer_dir(path, root, &fake_facts(uid, mode), &|_| {
            Some(id.to_string())
        })
    }

    /// A temp directory standing in for `/Applications`, canonicalised so the
    /// selected paths compare equal after canonicalisation.
    fn fake_applications_root(sandbox: &tempfile::TempDir) -> PathBuf {
        let root = sandbox.path().canonicalize().unwrap().join("Applications");
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn fake_xcode_bundle(root: &Path, name: &str) -> PathBuf {
        let developer = root.join(name).join("Contents/Developer");
        std::fs::create_dir_all(&developer).unwrap();
        developer
    }

    #[test]
    fn wrong_bundle_id_adds_no_rule() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = fake_applications_root(&sandbox);
        let developer = fake_xcode_bundle(&root, "Evil.app");
        assert_eq!(
            resolve(&root, &developer, 0, 0o755, "com.example.evil"),
            None
        );
    }

    #[test]
    #[cfg(unix)]
    fn non_root_owned_or_group_writable_bundle_adds_no_rule() {
        use std::os::unix::fs::MetadataExt;
        let sandbox = tempfile::tempdir().unwrap();
        let root = fake_applications_root(&sandbox);
        let developer = fake_xcode_bundle(&root, "Xcode.app");
        let test_uid = std::fs::symlink_metadata(&developer).unwrap().uid();
        if test_uid != 0 {
            assert_eq!(
                resolve(&root, &developer, test_uid, 0o755, XCODE_BUNDLE_ID),
                None
            );
        }
        assert_eq!(resolve(&root, &developer, 0, 0o775, XCODE_BUNDLE_ID), None);
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_developer_directory_adds_no_rule() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = fake_applications_root(&sandbox);
        let real = fake_xcode_bundle(&root, "Real.app");
        let contents = root.join("Evil.app/Contents");
        std::fs::create_dir_all(&contents).unwrap();
        let link = contents.join("Developer");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(resolve(&root, &link, 0, 0o755, XCODE_BUNDLE_ID), None);
    }

    #[test]
    fn developer_dir_environment_variable_has_no_effect() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = fake_applications_root(&sandbox);
        let selected = fake_xcode_bundle(&root, "Selected.app");
        let env_candidate = fake_xcode_bundle(&root, "Evil.app");
        std::env::set_var("DEVELOPER_DIR", &env_candidate);
        let resolved = resolve(&root, &selected, 0, 0o755, XCODE_BUNDLE_ID);
        let with_env = active_developer_dir();
        std::env::remove_var("DEVELOPER_DIR");
        let without_env = active_developer_dir();
        // A valid candidate in DEVELOPER_DIR never wins; only `xcode-select`.
        assert_eq!(resolved.as_deref(), Some(selected.as_path()));
        assert_eq!(with_env, without_env);
    }

    #[test]
    fn resolved_xcode_developer_dir_gets_read_and_exec_but_never_write() {
        let developer_dir = Path::new("/Applications/Xcode_16.4.app/Contents/Developer");
        let base = profile_with_developer_dir(None);
        let profile = profile_with_developer_dir(Some(developer_dir));

        // The profile without the Xcode grant is byte-for-byte a prefix: no
        // existing rule moves, including the Command Line Tools grants.
        assert!(profile.starts_with(&base));
        let added = &profile[base.len()..];
        let added_rules: Vec<&str> = added
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with(';'))
            .collect();
        let expected = format!(
            "(allow file-read* (subpath \"{dir}\"))\n\
             (allow process-exec* (subpath \"{dir}\"))",
            dir = developer_dir.display()
        );
        assert_eq!(added_rules.join("\n"), expected);

        // Read + exec only: no write, network, file-map or broad
        // `/Applications` grant comes with it.
        assert!(!added.contains("file-map-executable"));
        assert!(!profile.contains("(allow network*"));
        assert!(!profile.contains("(subpath \"/Applications\")"));
        assert!(!added.contains("file-write"));
        for line in profile
            .lines()
            .filter(|line| line.starts_with("(allow file-write*"))
        {
            assert!(
                !line.contains(developer_dir.to_str().unwrap()),
                "the Xcode directory must never be writable: {line}"
            );
        }
    }

    #[test]
    fn resolved_xcode_developer_dir_yields_exactly_read_and_exec() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = fake_applications_root(&sandbox);
        let developer = fake_xcode_bundle(&root, "Xcode_16.4.app");
        let resolved = resolve(&root, &developer, 0, 0o755, XCODE_BUNDLE_ID)
            .expect("a root-owned Xcode bundle must resolve");
        let rules = developer_dir_rules(&resolved).expect("a full Xcode must get a grant");
        let rules: Vec<&str> = rules
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with(';'))
            .collect();
        assert_eq!(
            rules.join("\n"),
            format!(
                "(allow file-read* (subpath \"{dir}\"))\n\
                 (allow process-exec* (subpath \"{dir}\"))",
                dir = developer.display()
            )
        );
    }

    #[test]
    fn command_line_tools_rule_is_unchanged_byte_for_byte() {
        let base = profile_with_developer_dir(None);
        let clt = Path::new(CLT_DEVELOPER_DIR);

        // Resolving the Command Line Tools adds no rule: its existing grant is
        // already in the system trees and must not be duplicated or rewritten.
        assert_eq!(profile_with_developer_dir(Some(clt)), base);

        let exec_line = base
            .lines()
            .find(|line| line.starts_with("(allow process-exec*"))
            .expect("exec allow rule");
        assert!(exec_line.contains("(subpath \"/Library/Developer/CommandLineTools\")"));
        let read_line = base
            .lines()
            .find(|line| line.starts_with("(allow file-read*"))
            .expect("read allow rule");
        assert!(read_line.contains("(subpath \"/Library/Developer/CommandLineTools\")"));
        assert_eq!(
            base.matches("(subpath \"/Library/Developer/CommandLineTools\")")
                .count(),
            2,
            "the Command Line Tools grant must stay exactly the two existing rules"
        );
    }

    #[test]
    fn xcode_developer_dir_overlapping_the_workspace_adds_no_rule() {
        // The grant is read-only; a workspace there would turn it writable
        // through the unconditional workspace allow, so it is skipped.
        let developer_dir = Path::new("/Applications/Xcode.app/Contents/Developer");
        let base = seatbelt_profile_with_developer_dir(
            developer_dir,
            Path::new("/tmp/tmp"),
            None,
            false,
            None,
        )
        .unwrap();
        let profile = seatbelt_profile_with_developer_dir(
            developer_dir,
            Path::new("/tmp/tmp"),
            None,
            false,
            Some(developer_dir),
        )
        .unwrap();
        assert_eq!(profile, base);
    }

    #[test]
    fn real_home_falls_back_to_passwd_when_home_is_unusable() {
        // WSD2-P3-09: an unset/mangled HOME must not silently drop the
        // sensitive-path deny list.
        let Some(expected) = passwd_home() else {
            // No passwd entry on this host: nothing to fall back to.
            return;
        };

        assert_eq!(real_home_from(None), Some(expected.clone()));
        assert_eq!(
            real_home_from(Some(std::ffi::OsStr::new("/nonexistent-aux-home"))),
            Some(expected.clone())
        );
        assert_eq!(
            real_home_from(Some(std::ffi::OsStr::new("/"))),
            Some(expected.clone())
        );

        let profile = seatbelt_profile(
            Path::new("/tmp/ws"),
            Path::new("/tmp/tmp"),
            real_home_from(None).as_deref(),
            false,
        )
        .unwrap();
        assert!(
            profile.contains(&format!("(subpath \"{}/.ssh\")", expected.display())),
            "the passwd home must still be denied"
        );
    }

    #[test]
    fn profile_refuses_workspaces_that_overlap_protected_locations() {
        let home = Path::new("/Users/tester");
        let temp = Path::new("/tmp/tmp");

        for workspace in [
            "/Users/tester",
            "/Users/tester/.ssh",
            "/Users/tester/.ssh/sub",
            "/Users/tester/.aws",
            "/Users/tester/.config",
            "/Users/tester/Library/Keychains",
            "/Users/tester/Library/Messages",
            "/Users/tester/Library/Safari",
            "/Users/tester/Library/Application Support/Google/Chrome",
            "/Library/Keychains",
            "/Library/Keychains/System",
            "/private/var/db/diagnostics",
            "/private/var/log",
            "/Users",
            // WSD2-P2-04: a workspace that IS a read-only tree would turn it
            // writable through the unconditional workspace allow.
            "/usr",
            "/usr/local",
            "/usr/local/bin",
            "/opt/homebrew",
            "/opt/homebrew/bin",
            "/opt/homebrew/var/log",
            "/System",
            "/System/Library",
            "/private/etc/ssl",
            "/private/var/db/dyld",
            "/dev",
            // WSD3-P2-02: the read-back trees are read-only in the profile
            // too, so they can never be a workspace.
            "/Library/Ruby",
            "/Library/Ruby/Gems",
            "/opt/homebrew/etc/openssl@3/certs",
            "/opt/homebrew/etc/ca-certificates",
        ] {
            let err = seatbelt_profile(Path::new(workspace), temp, Some(home), false)
                .expect_err(workspace);
            assert!(
                matches!(err, LaunchError::SensitiveWorkspace(_)),
                "{workspace}: {err}"
            );
        }

        // A workspace inside the Auxesis home is the intended production
        // layout and must stay allowed.
        for workspace in [
            "/Users/tester/.auxesis/agents/main/workspace",
            "/Users/tester/.auxesis/agents/axis/workspace/nested",
        ] {
            assert!(
                seatbelt_profile(Path::new(workspace), temp, Some(home), false).is_ok(),
                "{workspace} must be allowed"
            );
        }

        // An unrelated directory stays fine.
        assert!(seatbelt_profile(Path::new("/Users/other/proj"), temp, Some(home), false).is_ok());
    }

    #[test]
    fn profile_escapes_special_characters_in_paths() {
        let profile = seatbelt_profile(
            Path::new("/tmp/we\"ird\\ws"),
            Path::new("/tmp/tmp"),
            None,
            false,
        )
        .unwrap();
        assert!(profile.contains("(subpath \"/tmp/we\\\"ird\\\\ws\")"));

        let err = seatbelt_profile(
            Path::new("/tmp/line\nbreak"),
            Path::new("/tmp"),
            None,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, LaunchError::UnsafeWorkspace(_)));
    }

    #[cfg(unix)]
    #[test]
    fn launch_refuses_a_workspace_symlinked_to_the_root() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/", dir.path().join("root")).unwrap();

        let err = launch(
            "true",
            &dir.path().join("root"),
            &ShellSandbox {
                enabled: false,
                allow_unsandboxed: true,
                ..ShellSandbox::default()
            },
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, LaunchError::UnsafeWorkspace(_)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launch_refuses_a_sensitive_workspace() {
        // `/Library/Keychains` exists on every macOS host and is a protected
        // absolute location, so the launch path refuses it before spawning.
        let err = launch(
            "true",
            Path::new("/Library/Keychains"),
            &ShellSandbox::default(),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, LaunchError::SensitiveWorkspace(_)), "{err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launch_refuses_a_read_only_tree_workspace() {
        // WSD2-P2-04: `/usr` is read+exec only in the profile; as a workspace
        // it would become writable, so the launch path must refuse it.
        let err = launch(
            "true",
            Path::new("/usr"),
            &ShellSandbox::default(),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, LaunchError::SensitiveWorkspace(_)), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn launch_keeps_a_read_only_marker_file() {
        let dir = tempfile::tempdir().unwrap();
        let launched = launch(
            "true",
            dir.path(),
            &ShellSandbox {
                enabled: false,
                allow_unsandboxed: true,
                ..ShellSandbox::default()
            },
            Duration::from_secs(60),
        )
        .unwrap();
        use std::os::unix::fs::MetadataExt;
        let metadata = launched.marker_file.metadata().unwrap();
        assert_eq!(metadata.len(), 0, "the marker file must stay empty");
        assert_eq!(metadata.nlink(), 0, "the marker file must be unlinked");
    }

    #[cfg(unix)]
    #[test]
    fn launch_creates_a_private_temp_dir() {
        // WSD3-P3-05: `tempfile` creates the dir with `create_dir` (0777 &
        // ~umask), so the launcher must tighten it to 0700 explicitly; the
        // documented "private temp dir" must not depend on the umask.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let launched = launch(
            "true",
            dir.path(),
            &ShellSandbox {
                enabled: false,
                allow_unsandboxed: true,
                ..ShellSandbox::default()
            },
            Duration::from_secs(60),
        )
        .unwrap();
        let mode = std::fs::metadata(launched.temp.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "per-call temp dir must be 0700, got {mode:o}");
    }

    #[test]
    fn production_profiles_always_run_the_fixed_helper() {
        // The helper is never configurable outside tests: every profile a
        // production caller can build runs through SANDBOX_EXEC.
        for sandbox in [
            ShellSandbox::default(),
            ShellSandbox::new(true, true, true),
            ShellSandbox::new(false, false, true),
        ] {
            assert_eq!(sandbox.sandbox_exec(), Path::new(SANDBOX_EXEC));
        }
    }

    #[test]
    fn will_run_unsandboxed_mirrors_launch() {
        // The broker's unsandboxed bar must match what `launch` will do:
        // disabled-with-opt-in and unavailable-with-opt-in run unsandboxed;
        // everything else either sandboxes or refuses.
        let default = ShellSandbox::default();
        assert!(!default.will_run_unsandboxed(), "sandboxed by default");

        // Opted in while the sandbox is enabled: unsandboxed exactly when the
        // helper is unavailable (Linux, stripped macOS).
        let opted_in = ShellSandbox {
            allow_unsandboxed: true,
            ..ShellSandbox::default()
        };
        assert_eq!(opted_in.will_run_unsandboxed(), !opted_in.available());

        // Explicitly disabled with the opt-in: always unsandboxed.
        let disabled = ShellSandbox {
            enabled: false,
            allow_unsandboxed: true,
            ..ShellSandbox::default()
        };
        assert!(disabled.will_run_unsandboxed());

        // Disabled without the opt-in refuses to run at all — it must not be
        // reported as an unsandboxed run (the tool never executes).
        let refused = ShellSandbox {
            enabled: false,
            allow_unsandboxed: false,
            ..ShellSandbox::default()
        };
        assert!(!refused.will_run_unsandboxed());
    }
}
