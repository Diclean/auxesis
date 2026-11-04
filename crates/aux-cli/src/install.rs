//! `aux install` / `aux uninstall` / `aux status` — the launchd agent.
//!
//! `aux install` writes `~/Library/LaunchAgents/dev.auxesis.auxd.plist`
//! (`RunAtLoad`, `KeepAlive`, stdout/stderr to `~/.auxesis/logs/auxd.log`)
//! and bootstraps it into the per-user launchd domain (`gui/<uid>`).
//! `aux uninstall` boots it out and removes *exactly* that file. `aux status`
//! reports the plist, the launchctl state and the daemon log heartbeat.
//!
//! Safety properties, by construction:
//! - the only file ever written or removed is
//!   `~/Library/LaunchAgents/dev.auxesis.auxd.plist`; other agents are never
//!   read, rewritten or unloaded (unit + integration tests assert this);
//! - paths are XML-escaped and XML-validated before they reach the plist, so
//!   a home directory with `&`, `<`, `"`… cannot forge plist entries;
//! - re-running `install` is idempotent: identical content is left untouched,
//!   and a loaded agent is only bounced when its plist actually changed;
//! - every launchctl call has a 10-second timeout and bounded output capture;
//! - `HOME` is the single source of the LaunchAgents directory, which lets
//!   tests run fully sandboxed (they also point `AUXESIS_LAUNCHCTL` at a
//!   recording script).
//!
//! # Manual verification (real launchd — never run from tests)
//!
//! ```text
//! cargo build --workspace
//! ./target/debug/aux install
//! launchctl print   gui/$(id -u)/dev.auxesis.auxd     # state = running
//! ./target/debug/aux status
//! ./target/debug/aux uninstall
//! launchctl print   gui/$(id -u)/dev.auxesis.auxd     # fails: not found
//! ```
//!
//! Environment overrides (mostly for tests and sandboxes):
//! `AUXESIS_LAUNCHCTL` replaces `/bin/launchctl`; `AUXESIS_AUXD` pins the
//! daemon binary written into the plist (default: sibling of `aux`, then
//! `$PATH`). Neither is ever set by the tool itself.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// launchd label of the Auxesis daemon.
pub const LABEL: &str = "dev.auxesis.auxd";

/// File name of the agent inside `~/Library/LaunchAgents`.
pub const PLIST_FILE_NAME: &str = "dev.auxesis.auxd.plist";

const LAUNCHCTL_ENV: &str = "AUXESIS_LAUNCHCTL";
const AUXD_ENV: &str = "AUXESIS_AUXD";
const DEFAULT_LAUNCHCTL: &str = "/bin/launchctl";
const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CAPTURE: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Paths touched by install/uninstall/status. Only [`Paths::plist`] is ever
/// written or removed.
struct Paths {
    home: PathBuf,
    plist: PathBuf,
    log: PathBuf,
}

impl Paths {
    fn resolve() -> Result<Self, String> {
        let home = kernel_core::auxesis_home();
        let launch_agents = launch_agents_dir()?;
        Ok(Self {
            plist: launch_agents.join(PLIST_FILE_NAME),
            log: kernel_core::log_dir(&home).join("auxd.log"),
            home,
        })
    }
}

/// `$HOME/Library/LaunchAgents`. `HOME` is deliberately the only input (no
/// passwd lookup): tests sandbox it, and a wrong `HOME` can only ever write
/// a plist under that wrong home.
fn launch_agents_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "HOME is not set; cannot locate ~/Library/LaunchAgents".to_string())?;
    let dir = PathBuf::from(home).join("Library").join("LaunchAgents");
    if !dir.is_absolute() {
        return Err(format!(
            "HOME must be an absolute path to install a launchd agent: {}",
            clean_path(&dir)
        ));
    }
    Ok(dir)
}

/// Locate `auxd`: `$AUXESIS_AUXD`, then the sibling of `aux`, then `$PATH`.
fn resolve_auxd() -> Result<PathBuf, String> {
    if let Some(custom) = std::env::var_os(AUXD_ENV).filter(|value| !value.is_empty()) {
        let path = PathBuf::from(custom);
        validate_auxd(&path)?;
        return Ok(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(candidate) = exe.parent().map(|dir| dir.join("auxd")) {
            if candidate.is_file() {
                validate_auxd(&candidate)?;
                return Ok(candidate);
            }
        }
    }
    if let Some(search) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&search) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let candidate = dir.join("auxd");
            if candidate.is_file() {
                validate_auxd(&candidate)?;
                return Ok(candidate);
            }
        }
    }
    Err(format!(
        "could not find the `auxd` binary next to `aux` or on PATH; \
         run `cargo build --workspace` or set {AUXD_ENV} to its absolute path"
    ))
}

/// `auxd` must exist, be a regular file, be executable and have an absolute
/// path: launchd resolves nothing for us.
fn validate_auxd(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "`auxd` path must be absolute: {}",
            clean_path(path)
        ));
    }
    let meta = std::fs::metadata(path)
        .map_err(|err| format!("cannot use auxd binary {}: {err}", clean_path(path)))?;
    if !meta.is_file() {
        return Err(format!(
            "`auxd` is not a regular file: {}",
            clean_path(path)
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(format!("`auxd` is not executable: {}", clean_path(path)));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plist rendering
// ---------------------------------------------------------------------------

/// XML 1.0 character range (Rust `char` never contains surrogates).
fn is_xml_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{D7FF}').contains(&ch)
        || ('\u{E000}'..='\u{FFFD}').contains(&ch)
        || ch >= '\u{10000}'
}

fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Absolute, UTF-8, XML-representable, escaped path — or a clear error.
fn escaped_path(path: &Path, what: &str) -> Result<String, String> {
    if !path.is_absolute() {
        return Err(format!(
            "{what} path must be absolute for a launchd agent: {}",
            clean_path(path)
        ));
    }
    let text = path
        .to_str()
        .ok_or_else(|| format!("{what} path is not valid UTF-8: {}", clean_path(path)))?;
    for ch in text.chars() {
        if !is_xml_char(ch) {
            return Err(format!(
                "{what} path contains U+{:04X}, which cannot be represented in XML",
                ch as u32
            ));
        }
    }
    Ok(xml_escape(text))
}

/// Render the launchd plist. Deterministic: same inputs, same bytes (the
/// snapshot test pins this). The environment always carries the resolved
/// `AUXESIS_API_PORT`, so a launchd-started `auxd` never silently falls back
/// to 2893.
fn render_plist(auxd: &Path, home: &Path, log: &Path, api_port: u16) -> Result<String, String> {
    let auxd = escaped_path(auxd, "auxd")?;
    let home = escaped_path(home, "home")?;
    let log = escaped_path(log, "log")?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{auxd}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>{log}</string>
	<key>StandardErrorPath</key>
	<string>{log}</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>AUXESIS_HOME</key>
		<string>{home}</string>
		<key>AUXESIS_API_PORT</key>
		<string>{api_port}</string>
	</dict>
</dict>
</plist>
"#
    ))
}

/// Write `contents` to `path` via a unique temporary file + rename.
///
/// The temporary file is created with `O_EXCL` (never through a symlink) and
/// the rename replaces whatever name is at `path` without following it.
fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("no parent directory for {}", clean_path(path)))?;
    // SANDBOX-GATEWAY-EXEMPT: the plist lives outside the Auxesis home and install refuses while the guard is active.
    std::fs::create_dir_all(dir).map_err(|err| format!("creating {}: {err}", clean_path(dir)))?;

    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{PLIST_FILE_NAME}.tmp.{}.{nanos}",
        std::process::id()
    ));

    let write = || -> std::io::Result<()> {
        use std::io::Write as _;
        // SANDBOX-GATEWAY-EXEMPT: the plist lives outside the Auxesis home and install refuses while the guard is active.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()
    };
    if let Err(err) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("writing {}: {err}", clean_path(&tmp)));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("chmod {}: {err}", clean_path(&tmp)));
        }
    }

    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "renaming {} to {}: {err}",
            clean_path(&tmp),
            clean_path(path)
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// launchctl
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LaunchctlOutput {
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl LaunchctlOutput {
    #[cfg(test)]
    fn ok(stdout: impl Into<String>) -> Self {
        Self {
            success: true,
            code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[cfg(test)]
    fn missing(stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            code: Some(113),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[cfg(test)]
    fn failed(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

/// Seam over `launchctl`, so tests never spawn a real one.
trait Launchctl {
    fn run(&self, args: &[String]) -> Result<LaunchctlOutput, String>;
}

struct RealLaunchctl {
    program: PathBuf,
}

impl RealLaunchctl {
    fn from_env() -> Self {
        let program = std::env::var_os(LAUNCHCTL_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LAUNCHCTL));
        Self { program }
    }
}

impl Launchctl for RealLaunchctl {
    fn run(&self, args: &[String]) -> Result<LaunchctlOutput, String> {
        run_program(&self.program, args, LAUNCHCTL_TIMEOUT)
    }
}

/// Run a program with a deadline and bounded, concurrently drained pipes
/// (output larger than the pipe buffer must not deadlock us).
fn run_program(
    program: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<LaunchctlOutput, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("running {}: {err}", clean_path(program)))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "no stdout pipe from launchctl".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "no stderr pipe from launchctl".to_string())?;
    let out_thread = std::thread::spawn(move || read_capped(stdout));
    let err_thread = std::thread::spawn(move || read_capped(stderr));

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{} timed out after {}s",
                        clean_path(program),
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(format!("waiting for {}: {err}", clean_path(program))),
        }
    };

    let stdout = out_thread
        .join()
        .map_err(|_| "launchctl stdout reader panicked".to_string())?;
    let stderr = err_thread
        .join()
        .map_err(|_| "launchctl stderr reader panicked".to_string())?;
    Ok(LaunchctlOutput {
        success: status.success(),
        code: status.code(),
        stdout,
        stderr,
    })
}

fn read_capped(mut reader: impl Read) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while (buf.len() as u64) < MAX_CAPTURE {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = MAX_CAPTURE as usize - buf.len();
                buf.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// `launchctl` reported that the service does not exist (as opposed to a real
/// failure): that is the normal "not installed / not loaded" state.
fn service_missing(out: &LaunchctlOutput) -> bool {
    if out.success {
        return false;
    }
    out.code == Some(113)
        || out.stderr.contains("Could not find service")
        || out.stderr.contains("No such process")
}

#[cfg(unix)]
fn domain_target() -> Result<String, String> {
    Ok(format!("gui/{}", unsafe { libc::getuid() }))
}

#[cfg(not(unix))]
fn domain_target() -> Result<String, String> {
    Err("launchd is macOS-only".to_string())
}

fn service_target() -> Result<String, String> {
    Ok(format!("{}/{}", domain_target()?, LABEL))
}

fn launchctl_error(action: &str, target: &str, out: &LaunchctlOutput) -> String {
    let detail = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let code = out
        .code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".to_string());
    format!(
        "launchctl {action} {target} failed (exit {code}): {}",
        clean(detail)
    )
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// Outcome of `aux install`.
#[derive(Debug)]
pub struct InstallReport {
    plist: PathBuf,
    log: PathBuf,
    target: String,
    wrote_plist: bool,
    was_loaded: bool,
    reloaded: bool,
    bootstrapped: bool,
}

impl InstallReport {
    /// Print the outcome. Write errors (closed stdout) are ignored.
    pub fn print(&self) {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = writeln!(out, "aux install — launchd agent {LABEL}");
        let _ = writeln!(
            out,
            "  plist      {} ({})",
            clean_path(&self.plist),
            if self.wrote_plist {
                "written"
            } else {
                "unchanged"
            }
        );
        let action = if self.reloaded {
            "reloaded (bootout + bootstrap)"
        } else if self.bootstrapped {
            "bootstrapped"
        } else if self.was_loaded {
            "already loaded — nothing to do"
        } else {
            "unchanged"
        };
        let _ = writeln!(out, "  launchctl  {} ({action})", clean(&self.target));
        let _ = writeln!(out, "  log        {}", clean_path(&self.log));
        let _ = writeln!(out, "install ok — auxd will start at login (KeepAlive)");
    }
}

/// Outcome of `aux uninstall`.
#[derive(Debug)]
pub struct UninstallReport {
    plist: PathBuf,
    target: String,
    unloaded: bool,
    removed: bool,
}

impl UninstallReport {
    /// Print the outcome. Write errors (closed stdout) are ignored.
    pub fn print(&self) {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = writeln!(out, "aux uninstall — launchd agent {LABEL}");
        let _ = writeln!(
            out,
            "  launchctl  {} ({})",
            clean(&self.target),
            if self.unloaded {
                "stopped"
            } else {
                "not loaded"
            }
        );
        let _ = writeln!(
            out,
            "  plist      {} ({})",
            clean_path(&self.plist),
            if self.removed {
                "removed"
            } else {
                "not present"
            }
        );
        let _ = writeln!(out, "uninstall ok");
    }
}

#[derive(Debug)]
enum LaunchctlState {
    Loaded {
        state: Option<String>,
        pid: Option<i32>,
    },
    NotLoaded,
    Unavailable(String),
}

struct LogInfo {
    bytes: u64,
    age: Option<Duration>,
}

/// Outcome of `aux status`.
pub struct StatusReport {
    plist: PathBuf,
    plist_installed: bool,
    plist_bytes: Option<u64>,
    launchctl: LaunchctlState,
    log_path: PathBuf,
    log: Option<LogInfo>,
}

impl StatusReport {
    /// Healthy when the plist is installed and launchd knows the service
    /// (an unreachable `launchctl` is reported but not treated as down).
    pub fn success(&self) -> bool {
        self.plist_installed && !matches!(self.launchctl, LaunchctlState::NotLoaded)
    }

    /// Print the report. Write errors (closed stdout) are ignored.
    pub fn print(&self) {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = writeln!(out, "aux status — launchd agent {LABEL}");
        let plist = match (self.plist_installed, self.plist_bytes) {
            (true, Some(bytes)) => format!("installed, {bytes} bytes, {}", clean_path(&self.plist)),
            _ => format!("missing ({})", clean_path(&self.plist)),
        };
        let _ = writeln!(out, "  plist      {plist}");
        let _ = writeln!(out, "  launchctl  {}", self.launchctl_line());
        let log = match &self.log {
            Some(info) => format!(
                "{} ({} bytes, last write {})",
                clean_path(&self.log_path),
                info.bytes,
                humanize_age(info.age)
            ),
            None => format!("no log yet ({})", clean_path(&self.log_path)),
        };
        let _ = writeln!(out, "  log        {log}");
        let _ = writeln!(
            out,
            "status     {}",
            if self.success() { "healthy" } else { "down" }
        );
    }

    fn launchctl_line(&self) -> String {
        match &self.launchctl {
            LaunchctlState::Loaded { state, pid } => {
                let mut parts = Vec::new();
                if let Some(state) = state {
                    parts.push(format!("state={}", clean(state)));
                }
                if let Some(pid) = pid {
                    parts.push(format!("pid={pid}"));
                }
                if parts.is_empty() {
                    "loaded".to_string()
                } else {
                    format!("loaded ({})", parts.join(", "))
                }
            }
            LaunchctlState::NotLoaded => "not loaded".to_string(),
            LaunchctlState::Unavailable(err) => format!("unavailable ({})", clean(err)),
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points (used by main.rs)
// ---------------------------------------------------------------------------

/// Refuse install management while the sandbox guard is active: it would
/// resolve the *real* `~/Library/LaunchAgents` through `$HOME` and bootstrap
/// a real agent (security review J02-2-BI2-04). Tests use a fake `$HOME` and assert this
/// refusal before any write.
fn refuse_when_sandboxed(action: &str) -> Result<(), String> {
    if kernel_core::sandbox_guard_active() {
        return Err(format!(
            "refus de sandbox : `aux {action}` gère le vrai LaunchAgent (~/Library/LaunchAgents) — interdit tant que le garde-fou est actif. \
             / sandbox refused: `aux {action}` manages the real LaunchAgent — refused while the sandbox guard is active."
        ));
    }
    Ok(())
}

/// `aux install`: write the plist and bootstrap it (idempotent).
pub fn install() -> Result<InstallReport, String> {
    if !cfg!(target_os = "macos") {
        return Err("launchd is macOS-only; `aux install` is not available here".to_string());
    }
    refuse_when_sandboxed("install")?;
    let auxd = resolve_auxd()?;
    let paths = Paths::resolve()?;
    install_with(&RealLaunchctl::from_env(), &paths, &auxd)
}

/// `aux uninstall`: boot the agent out, then remove its plist.
pub fn uninstall() -> Result<UninstallReport, String> {
    refuse_when_sandboxed("uninstall")?;
    let paths = Paths::resolve()?;
    uninstall_with(&RealLaunchctl::from_env(), &paths)
}

/// `aux status`: report the plist, launchctl state and log heartbeat.
pub fn status() -> Result<StatusReport, String> {
    refuse_when_sandboxed("status")?;
    let paths = Paths::resolve()?;
    status_with(&RealLaunchctl::from_env(), &paths)
}

/// The port the generated plist must embed: `AUXESIS_API_PORT` when set,
/// else the daemon default.
fn resolved_api_port() -> u16 {
    if let Ok(raw) = std::env::var(kernel_core::API_PORT_ENV) {
        if let Ok(port) = raw.trim().parse::<u16>() {
            return port;
        }
    }
    kernel_core::REAL_DAEMON_PORT
}

// ---------------------------------------------------------------------------
// Core logic (testable with a fake launchctl)
// ---------------------------------------------------------------------------

fn install_with(
    runner: &dyn Launchctl,
    paths: &Paths,
    auxd: &Path,
) -> Result<InstallReport, String> {
    validate_auxd(auxd)?;
    if !paths.home.is_absolute() {
        return Err(format!(
            "AUXESIS_HOME must be absolute for a launchd agent: {}",
            clean_path(&paths.home)
        ));
    }
    let plist_arg = paths
        .plist
        .to_str()
        .ok_or_else(|| {
            format!(
                "plist path is not valid UTF-8: {}",
                clean_path(&paths.plist)
            )
        })?
        .to_string();
    // SANDBOX-GATEWAY-EXEMPT: install refuses while the guard is active; the plist/log paths live outside the sandbox home.
    std::fs::create_dir_all(&paths.home)
        .map_err(|err| format!("creating {}: {err}", clean_path(&paths.home)))?;
    if let Some(log_dir) = paths.log.parent() {
        let created = !log_dir.exists();
        // SANDBOX-GATEWAY-EXEMPT: install refuses while the guard is active; the plist/log paths live outside the sandbox home.
        std::fs::create_dir_all(log_dir)
            .map_err(|err| format!("creating {}: {err}", clean_path(log_dir)))?;
        if created {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(log_dir, std::fs::Permissions::from_mode(0o700));
            }
        }
    }

    let desired = render_plist(auxd, &paths.home, &paths.log, resolved_api_port())?;
    let existing = match std::fs::read_to_string(&paths.plist) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(format!("reading {}: {err}", clean_path(&paths.plist)));
        }
    };
    let wrote_plist = existing.as_deref() != Some(desired.as_str());
    if wrote_plist {
        write_atomic(&paths.plist, &desired)?;
    }

    let target = service_target()?;
    let print = runner.run(&["print".to_string(), target.clone()])?;
    let was_loaded = if print.success {
        true
    } else if service_missing(&print) {
        false
    } else {
        return Err(launchctl_error("print", &target, &print));
    };

    // A loaded agent keeps the old plist in memory: bounce it to pick up a
    // changed daemon path or environment. Unchanged + loaded = no-op.
    let mut reloaded = false;
    if was_loaded && wrote_plist {
        let bootout = runner.run(&["bootout".to_string(), target.clone()])?;
        if !bootout.success && !service_missing(&bootout) {
            return Err(launchctl_error("bootout", &target, &bootout));
        }
        reloaded = true;
    }

    let mut bootstrapped = false;
    if !was_loaded || reloaded {
        let bootstrap =
            runner.run(&["bootstrap".to_string(), domain_target()?, plist_arg.clone()])?;
        if !bootstrap.success {
            return Err(launchctl_error("bootstrap", &target, &bootstrap));
        }
        bootstrapped = true;
    }

    Ok(InstallReport {
        plist: paths.plist.clone(),
        log: paths.log.clone(),
        target,
        wrote_plist,
        was_loaded,
        reloaded,
        bootstrapped,
    })
}

fn uninstall_with(runner: &dyn Launchctl, paths: &Paths) -> Result<UninstallReport, String> {
    let target = service_target()?;
    let bootout = runner.run(&["bootout".to_string(), target.clone()])?;
    let unloaded = if bootout.success {
        true
    } else if service_missing(&bootout) {
        false
    } else {
        // Do not remove the plist: an agent that is still loaded and has no
        // plist on disk is a worse state than a failed uninstall.
        return Err(launchctl_error("bootout", &target, &bootout));
    };

    let removed = match std::fs::symlink_metadata(&paths.plist) {
        Ok(meta) if meta.is_dir() => {
            return Err(format!(
                "refusing to remove a directory at {}",
                clean_path(&paths.plist)
            ));
        }
        Ok(_) => {
            std::fs::remove_file(&paths.plist)
                .map_err(|err| format!("removing {}: {err}", clean_path(&paths.plist)))?;
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => {
            return Err(format!("reading {}: {err}", clean_path(&paths.plist)));
        }
    };

    Ok(UninstallReport {
        plist: paths.plist.clone(),
        target,
        unloaded,
        removed,
    })
}

fn status_with(runner: &dyn Launchctl, paths: &Paths) -> Result<StatusReport, String> {
    let (plist_installed, plist_bytes) = match std::fs::metadata(&paths.plist) {
        Ok(meta) if meta.is_file() => (true, Some(meta.len())),
        _ => (false, None),
    };

    let target = service_target()?;
    let launchctl = match runner.run(&["print".to_string(), target.clone()]) {
        Ok(out) if out.success => {
            let (state, pid) = parse_loaded(&out.stdout);
            LaunchctlState::Loaded { state, pid }
        }
        Ok(out) if service_missing(&out) => LaunchctlState::NotLoaded,
        Ok(out) => LaunchctlState::Unavailable(launchctl_error("print", &target, &out)),
        Err(err) => LaunchctlState::Unavailable(clean(&err)),
    };

    let log = std::fs::metadata(&paths.log)
        .ok()
        .filter(|meta| meta.is_file())
        .map(|meta| LogInfo {
            bytes: meta.len(),
            age: meta
                .modified()
                .ok()
                .and_then(|at| SystemTime::now().duration_since(at).ok()),
        });

    Ok(StatusReport {
        plist: paths.plist.clone(),
        plist_installed,
        plist_bytes,
        launchctl,
        log_path: paths.log.clone(),
        log,
    })
}

/// Pull `state = …` and `pid = …` out of `launchctl print` output.
fn parse_loaded(stdout: &str) -> (Option<String>, Option<i32>) {
    let mut state = None;
    let mut pid = None;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("state = ") {
            state = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("pid = ") {
            pid = value.trim().parse::<i32>().ok();
        }
    }
    (state, pid)
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Replace control characters and cap the length so untrusted text (paths,
/// launchctl stderr) can never forge or flood terminal output.
fn clean(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect();
    if out.chars().count() > 300 {
        out = out.chars().take(300).collect::<String>();
        out.push('…');
    }
    out
}

fn clean_path(path: &Path) -> String {
    clean(&path.display().to_string())
}

fn humanize_age(age: Option<Duration>) -> String {
    match age {
        None => "unknown".to_string(),
        Some(age) if age.as_secs() < 60 => format!("{}s ago", age.as_secs()),
        Some(age) if age.as_secs() < 3600 => format!("{}m ago", age.as_secs() / 60),
        Some(age) if age.as_secs() < 86_400 => format!("{}h ago", age.as_secs() / 3600),
        Some(age) => format!("{}d ago", age.as_secs() / 86_400),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).unwrap();
        }
    }

    /// Sandboxed paths + an executable fake `auxd`.
    fn fixture() -> (tempfile::TempDir, Paths, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("auxesis-home");
        let launch_agents = tmp.path().join("Library/LaunchAgents");
        let paths = Paths {
            plist: launch_agents.join(PLIST_FILE_NAME),
            log: home.join("logs/auxd.log"),
            home,
        };
        let auxd = tmp.path().join("auxd");
        std::fs::write(&auxd, b"#!/bin/sh\n").unwrap();
        make_executable(&auxd);
        (tmp, paths, auxd)
    }

    /// In-memory launchd: tracks "loaded" state exactly like the real one.
    #[derive(Default)]
    struct FakeLaunchctl {
        calls: RefCell<Vec<Vec<String>>>,
        loaded: Cell<bool>,
        print_error: RefCell<Option<LaunchctlOutput>>,
        bootout_error: RefCell<Option<LaunchctlOutput>>,
    }

    impl FakeLaunchctl {
        fn new() -> Self {
            Self::default()
        }

        fn loaded(self) -> Self {
            self.loaded.set(true);
            self
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }

        fn count(&self, verb: &str) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|call| call.first().map(String::as_str) == Some(verb))
                .count()
        }
    }

    impl Launchctl for FakeLaunchctl {
        fn run(&self, args: &[String]) -> Result<LaunchctlOutput, String> {
            self.calls.borrow_mut().push(args.to_vec());
            match args.first().map(String::as_str) {
                Some("print") => {
                    if let Some(err) = self.print_error.borrow().as_ref() {
                        return Ok(err.clone());
                    }
                    if self.loaded.get() {
                        Ok(LaunchctlOutput::ok("state = running\npid = 4242\n"))
                    } else {
                        Ok(LaunchctlOutput::missing("Could not find service"))
                    }
                }
                Some("bootstrap") => {
                    self.loaded.set(true);
                    Ok(LaunchctlOutput::ok(""))
                }
                Some("bootout") => {
                    if let Some(err) = self.bootout_error.borrow().as_ref() {
                        return Ok(err.clone());
                    }
                    if self.loaded.get() {
                        self.loaded.set(false);
                        Ok(LaunchctlOutput::ok(""))
                    } else {
                        Ok(LaunchctlOutput::missing(
                            "Boot-out failed: 3: No such process",
                        ))
                    }
                }
                _ => Ok(LaunchctlOutput::ok("")),
            }
        }
    }

    // ---- plist rendering ----

    #[test]
    fn plist_snapshot() {
        let text = render_plist(
            Path::new("/opt/aux/bin/auxd"),
            Path::new("/Users/tester/.auxesis"),
            Path::new("/Users/tester/.auxesis/logs/auxd.log"),
            2893,
        )
        .unwrap();
        let expected = [
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#,
            r#"<plist version="1.0">"#,
            r#"<dict>"#,
            "\t<key>Label</key>",
            "\t<string>dev.auxesis.auxd</string>",
            "\t<key>ProgramArguments</key>",
            "\t<array>",
            "\t\t<string>/opt/aux/bin/auxd</string>",
            "\t</array>",
            "\t<key>RunAtLoad</key>",
            "\t<true/>",
            "\t<key>KeepAlive</key>",
            "\t<true/>",
            "\t<key>StandardOutPath</key>",
            "\t<string>/Users/tester/.auxesis/logs/auxd.log</string>",
            "\t<key>StandardErrorPath</key>",
            "\t<string>/Users/tester/.auxesis/logs/auxd.log</string>",
            "\t<key>EnvironmentVariables</key>",
            "\t<dict>",
            "\t\t<key>AUXESIS_HOME</key>",
            "\t\t<string>/Users/tester/.auxesis</string>",
            "\t\t<key>AUXESIS_API_PORT</key>",
            "\t\t<string>2893</string>",
            "\t</dict>",
            "</dict>",
            "</plist>",
        ]
        .join("\n")
            + "\n";
        assert_eq!(text, expected);
    }

    #[test]
    fn plist_escapes_xml_metacharacters() {
        let auxd = Path::new("/opt/a&b/auxd");
        let home = Path::new("/Users/a&b <x> \"q\"'s/.auxesis");
        let log = home.join("logs/auxd.log");
        let text = render_plist(auxd, home, &log, 2893).unwrap();

        assert!(text.contains("a&amp;b"));
        assert!(text.contains("&lt;x&gt;"));
        assert!(text.contains("&quot;q&quot;"));
        assert!(text.contains("&apos;s"));
        assert!(!text.contains("a&b "));
        assert!(!text.contains("<x>"));

        // Every `&` must open one of the five XML entities.
        let entities = ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"];
        for (index, _) in text.match_indices('&') {
            let rest = &text[index..];
            assert!(
                entities.iter().any(|entity| rest.starts_with(entity)),
                "raw & at byte {index}: {}",
                &rest[..rest.len().min(16)]
            );
        }
    }

    #[test]
    fn plist_rejects_control_characters() {
        let home = Path::new("/home/bad\u{1}name");
        let err = render_plist(
            Path::new("/opt/auxd"),
            home,
            Path::new("/home/bad/log"),
            2893,
        )
        .unwrap_err();
        assert!(err.contains("U+0001"), "{err}");
    }

    #[test]
    fn plist_rejects_relative_paths() {
        let err = render_plist(
            Path::new("auxd"),
            Path::new("/home/tester/.auxesis"),
            Path::new("/home/tester/.auxesis/logs/auxd.log"),
            2893,
        )
        .unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    // ---- install ----

    #[test]
    fn install_writes_plist_and_bootstraps_once() {
        let (_tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new();

        let report = install_with(&fake, &paths, &auxd).unwrap();
        assert!(report.wrote_plist);
        assert!(report.bootstrapped);
        assert!(!report.was_loaded);
        assert!(!report.reloaded);

        let text = std::fs::read_to_string(&paths.plist).unwrap();
        assert_eq!(
            text,
            render_plist(&auxd, &paths.home, &paths.log, resolved_api_port()).unwrap()
        );

        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0], "print");
        assert_eq!(calls[1][0], "bootstrap");
        assert_eq!(calls[1][1], domain_target().unwrap());
        assert_eq!(calls[1][2], paths.plist.display().to_string());
    }

    #[test]
    fn install_is_idempotent_when_unchanged_and_loaded() {
        let (_tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new();
        install_with(&fake, &paths, &auxd).unwrap();
        let before = std::fs::read(&paths.plist).unwrap();

        let report = install_with(&fake, &paths, &auxd).unwrap();
        assert!(!report.wrote_plist);
        assert!(!report.bootstrapped);
        assert!(report.was_loaded);
        assert!(!report.reloaded);
        assert_eq!(std::fs::read(&paths.plist).unwrap(), before);

        assert_eq!(fake.count("print"), 2);
        assert_eq!(fake.count("bootstrap"), 1);
        assert_eq!(fake.count("bootout"), 0);
    }

    #[test]
    fn install_reloads_when_the_plist_changes() {
        let (tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new().loaded();
        std::fs::create_dir_all(paths.plist.parent().unwrap()).unwrap();
        std::fs::write(
            &paths.plist,
            render_plist(&auxd, &paths.home, &paths.log, resolved_api_port()).unwrap(),
        )
        .unwrap();

        let auxd2 = tmp.path().join("auxd-2");
        std::fs::write(&auxd2, b"#!/bin/sh\n").unwrap();
        make_executable(&auxd2);

        let report = install_with(&fake, &paths, &auxd2).unwrap();
        assert!(report.wrote_plist);
        assert!(report.was_loaded);
        assert!(report.reloaded);
        assert!(report.bootstrapped);

        let text = std::fs::read_to_string(&paths.plist).unwrap();
        assert!(text.contains(&auxd2.display().to_string()));
        let calls = fake.calls();
        assert_eq!(calls[0][0], "print");
        assert_eq!(calls[1][0], "bootout");
        assert_eq!(calls[2][0], "bootstrap");
    }

    #[test]
    fn install_creates_private_log_dir() {
        let (_tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new();
        install_with(&fake, &paths, &auxd).unwrap();
        let log_dir = paths.log.parent().unwrap();
        assert!(log_dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(log_dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn install_rejects_relative_auxd() {
        let (_tmp, paths, _) = fixture();
        let fake = FakeLaunchctl::new();
        let err = install_with(&fake, &paths, Path::new("auxd")).unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        assert!(!paths.plist.exists());
    }

    #[test]
    fn install_rejects_missing_auxd() {
        let (_tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new();
        let missing = auxd.parent().unwrap().join("does-not-exist");
        let err = install_with(&fake, &paths, &missing).unwrap_err();
        assert!(err.contains("cannot use auxd binary"), "{err}");
        assert!(!paths.plist.exists());
        assert!(fake.calls().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_non_utf8_plist_path() {
        use std::os::unix::ffi::OsStrExt;
        let (_tmp, mut paths, auxd) = fixture();
        paths.plist = PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/tmp/\xFF/dev.auxesis.auxd.plist",
        ));
        let fake = FakeLaunchctl::new();
        let err = install_with(&fake, &paths, &auxd).unwrap_err();
        assert!(err.contains("not valid UTF-8"), "{err}");
        assert_eq!(fake.count("bootstrap"), 0);
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_non_executable_auxd() {
        let (tmp, paths, _) = fixture();
        let fake = FakeLaunchctl::new();
        let plain = tmp.path().join("plain");
        std::fs::write(&plain, b"not a binary").unwrap();
        let err = install_with(&fake, &paths, &plain).unwrap_err();
        assert!(err.contains("not executable"), "{err}");
    }

    #[test]
    fn install_never_touches_other_launch_agents() {
        let (_tmp, paths, auxd) = fixture();
        std::fs::create_dir_all(paths.plist.parent().unwrap()).unwrap();
        let decoy = paths
            .plist
            .parent()
            .unwrap()
            .join("com.example.decoy.plist");
        std::fs::write(&decoy, b"<decoy/>").unwrap();

        let fake = FakeLaunchctl::new();
        install_with(&fake, &paths, &auxd).unwrap();
        uninstall_with(&fake, &paths).unwrap();

        assert_eq!(std::fs::read(&decoy).unwrap(), b"<decoy/>");
        assert!(decoy.exists());
        assert!(!paths.plist.exists());
        for call in fake.calls() {
            assert!(
                !call.iter().any(|arg| arg.contains("decoy")),
                "unexpected call: {call:?}"
            );
        }
    }

    // ---- uninstall ----

    #[test]
    fn uninstall_stops_and_removes_plist() {
        let (_tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new();
        install_with(&fake, &paths, &auxd).unwrap();

        let report = uninstall_with(&fake, &paths).unwrap();
        assert!(report.unloaded);
        assert!(report.removed);
        assert!(!paths.plist.exists());
        assert_eq!(fake.count("bootout"), 1);
        let calls = fake.calls();
        let last = calls.last().unwrap();
        assert_eq!(last[0], "bootout");
        assert_eq!(last[1], format!("{}/{}", domain_target().unwrap(), LABEL));
    }

    #[test]
    fn uninstall_when_not_installed_is_a_noop() {
        let (_tmp, paths, _) = fixture();
        let fake = FakeLaunchctl::new();
        let report = uninstall_with(&fake, &paths).unwrap();
        assert!(!report.unloaded);
        assert!(!report.removed);
        assert_eq!(fake.count("bootout"), 1);
    }

    #[test]
    fn uninstall_keeps_the_plist_when_bootout_fails() {
        let (_tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new();
        install_with(&fake, &paths, &auxd).unwrap();
        *fake.bootout_error.borrow_mut() =
            Some(LaunchctlOutput::failed(1, "Operation not permitted"));

        let err = uninstall_with(&fake, &paths).unwrap_err();
        assert!(err.contains("Operation not permitted"), "{err}");
        assert!(
            paths.plist.exists(),
            "a failed bootout must leave the plist in place"
        );
    }

    #[test]
    fn uninstall_refuses_to_remove_a_directory() {
        let (_tmp, paths, _) = fixture();
        std::fs::create_dir_all(&paths.plist).unwrap();
        let fake = FakeLaunchctl::new();
        let err = uninstall_with(&fake, &paths).unwrap_err();
        assert!(err.contains("refusing to remove a directory"), "{err}");
        assert!(paths.plist.is_dir());
    }

    // ---- status ----

    #[test]
    fn status_reports_loaded_state_and_log() {
        let (_tmp, paths, auxd) = fixture();
        let fake = FakeLaunchctl::new();
        install_with(&fake, &paths, &auxd).unwrap();
        std::fs::write(&paths.log, b"auxd ready\n").unwrap();

        let report = status_with(&fake, &paths).unwrap();
        assert!(report.success());
        match &report.launchctl {
            LaunchctlState::Loaded { state, pid } => {
                assert_eq!(state.as_deref(), Some("running"));
                assert_eq!(*pid, Some(4242));
            }
            other => panic!("expected loaded, got {other:?}"),
        }
        let log = report.log.as_ref().unwrap();
        assert_eq!(log.bytes, 11);
        assert!(log.age.is_some());
    }

    #[test]
    fn status_reports_not_loaded() {
        let (_tmp, paths, _) = fixture();
        std::fs::create_dir_all(paths.plist.parent().unwrap()).unwrap();
        std::fs::write(&paths.plist, b"<plist/>").unwrap();
        let fake = FakeLaunchctl::new();

        let report = status_with(&fake, &paths).unwrap();
        assert!(!report.success());
        assert!(matches!(report.launchctl, LaunchctlState::NotLoaded));
        assert!(report.log.is_none());
    }

    #[test]
    fn status_reports_missing_plist() {
        let (_tmp, paths, _) = fixture();
        let fake = FakeLaunchctl::new();
        let report = status_with(&fake, &paths).unwrap();
        assert!(!report.success());
        assert!(!report.plist_installed);
    }

    #[test]
    fn status_reports_launchctl_unavailable() {
        let (_tmp, paths, _) = fixture();
        let fake = FakeLaunchctl::new();
        *fake.print_error.borrow_mut() = Some(LaunchctlOutput::failed(22, "Invalid argument"));
        let report = status_with(&fake, &paths).unwrap();
        match &report.launchctl {
            LaunchctlState::Unavailable(err) => assert!(err.contains("Invalid argument")),
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[test]
    fn parse_loaded_reads_state_and_pid() {
        let (state, pid) = parse_loaded(
            "gui/501/dev.auxesis.auxd = {\n\tstate = waiting\n\tpid = 7\n\tstate = running\n",
        );
        assert_eq!(state.as_deref(), Some("running"));
        assert_eq!(pid, Some(7));
        assert_eq!(parse_loaded("nothing here"), (None, None));
    }

    #[test]
    fn humanize_age_is_readable() {
        assert_eq!(humanize_age(None), "unknown");
        assert_eq!(humanize_age(Some(Duration::from_secs(4))), "4s ago");
        assert_eq!(humanize_age(Some(Duration::from_secs(120))), "2m ago");
        assert_eq!(humanize_age(Some(Duration::from_secs(7200))), "2h ago");
        assert_eq!(humanize_age(Some(Duration::from_secs(172_800))), "2d ago");
    }

    #[test]
    fn launchctl_error_sanitizes_control_characters() {
        let out = LaunchctlOutput::failed(1, "bad\nline\u{7}");
        let err = launchctl_error("print", "gui/501/label", &out);
        assert!(!err.contains('\n'));
        assert!(err.contains("bad?line?"));
    }
}
