//! Filesystem layout of an Auxesis installation.
//!
//! Everything lives under the *Auxesis home*: `$AUXESIS_HOME` when set,
//! otherwise `$HOME/.auxesis`.
//!
//! # The sandbox guard (J-02)
//!
//! [`ensure_sandbox_guard`] is the single entry point every workspace binary
//! calls before it reads or creates anything. It resolves the real home from
//! the OS user database (`getpwuid_r`, never `$HOME`) and refuses an Auxesis
//! home that *is* or is *under* the real `~/.auxesis` — by **directory
//! identity** (`st_dev`, `st_ino`), not by path text, so case, NFD/NFC,
//! symlinks, firmlinks (`/System/Volumes/Data/…`), `/private/var` and
//! hardlinked spellings all resolve to the same inode and are refused. A
//! failed passwd lookup fails closed. `AUXESIS_HOME` equal to the real home
//! root is refused too.
//!
//! [`ensure_home`] then opens/creates the home through verified directory
//! descriptors and returns a [`SandboxHome`] handle. Every later write under
//! the sandbox home goes through that handle (`openat`/`O_NOFOLLOW` relative
//! to the verified fd), never through a path string, so a symlink swapped in
//! after the check cannot redirect a write (breaker round 2, security review P1).
//!
//! # Threat model (maintainer decision, 2026-10-06)
//!
//! In scope: **accidental use of the real `~/.auxesis`** — a binary or test
//! started with a misconfigured `HOME`/`AUXESIS_HOME`/port, or a sandbox home
//! that *resolves into* the real home at start, including via pre-planted
//! symlinks, firmlinks, case or NFD spellings. The guard verifies identity at
//! startup, exports the canonical verified path as the ONLY home consumers
//! use, and refuses a sandbox home containing any symlink (depth ≤ 2).
//!
//! Explicit non-goal: an attacker with same-user write access who **renames or
//! swaps directories while the process runs**. Such an attacker can already
//! edit `~/.auxesis` directly; the guard's job is not to defend against the
//! owner's own uid. Mid-run swap repros are documented, not chased; the
//! handle still re-verifies on every use where it can, which keeps the
//! daemon's state writes fail-closed in practice.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Directory name used under `$HOME` by default.
pub const DEFAULT_DIR_NAME: &str = ".auxesis";

/// Environment variable that marks a sandboxed process (QA harnesses and
/// integration tests). When it is exactly `1`, Auxesis refuses to start
/// against the real `~/.auxesis` and refuses the real daemon port.
pub const SANDBOX_ENV: &str = "AUXESIS_SANDBOX";

/// Port the real daemon listens on by default (the daemon's `DEFAULT_API_PORT`).
///
/// Duplicated here so the sandbox guard can refuse it without `kernel-core`
/// depending on the daemon.
pub const REAL_DAEMON_PORT: u16 = 2893;

/// Home directory the OS user database (`getpwuid_r(getuid())`) reports for
/// this process, never `$HOME`.
///
/// `$HOME` is exactly the variable a sandbox overrides, so it cannot be used
/// to recognise the real `~/.auxesis` (J-02). Returns `None` when the lookup
/// fails; non-unix platforms fall back to `$HOME`.
#[cfg(unix)]
pub fn real_user_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd` and `buf` outlive the call, which only writes into
        // them; `pw_dir` is read after a success return, while it still
        // points into `buf`.
        let rc = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        return Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())));
    }
}

/// Non-unix fallback: there is no user database, so best effort via `$HOME`.
#[cfg(not(unix))]
pub fn real_user_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The one sandbox guard, called first by every workspace binary.
///
/// `api_port` is the port this process would bind (the daemon) or connect to
/// (clients); `None` when the binary never touches the daemon API. On
/// success the verified home to use is returned.
///
/// The guard is **active** when `AUXESIS_SANDBOX=1` is set, when `$HOME` is
/// unset/empty/relative or differs from the OS user database home, or when
/// the passwd lookup fails (fail closed). While active it refuses:
///
/// * any `AUXESIS_HOME` that *is* or is *under* the real `~/.auxesis`, by
///   directory identity (every spelling) and by a folded-path second check;
/// * `AUXESIS_HOME` equal to the real home root;
/// * a relative `AUXESIS_HOME`, or a missing one with no usable `$HOME`
///   (no silent CWD/real home fallback);
/// * the real daemon port [`REAL_DAEMON_PORT`] unless an explicit ephemeral
///   port (`AUXESIS_API_PORT=0`) is passed.
pub fn ensure_sandbox_guard(api_port: Option<u16>) -> Result<PathBuf, String> {
    let ctx = SandboxContext::resolve();
    let home = ctx.resolve_home()?;
    ctx.refuse_home(&home)?;
    if ctx.active && api_port == Some(REAL_DAEMON_PORT) {
        return Err(port_refusal());
    }
    // Export the canonical verified home as the ONE home for this process.
    // A read-only command (`aux activity`) must never create the home, so an
    // existing home is opened/registered/scanned while a missing one is only
    // canonicalised lexically.
    if !home.exists() {
        return Ok(normalize_path(&home));
    }
    let handle = ensure_home(&home).map_err(|err| err.to_string())?;
    // Export the canonical home to the process environment (production
    // binaries only; unit tests must not mutate global env under parallelism
    // — they read the registry instead).
    #[cfg(not(test))]
    if ctx.active {
        std::env::set_var("AUXESIS_HOME", handle.path());
    }
    Ok(handle.path().to_path_buf())
}

/// Whether the sandbox guard is active in this process (flag, `$HOME`
/// override, or a failed passwd lookup). Clients use this to decide whether
/// `--api`/`AUXESIS_API` may be trusted (J-02 round 3).
pub fn sandbox_guard_active() -> bool {
    SandboxContext::resolve().active
}

/// Compatibility wrapper: refuse `home` when it resolves into the real
/// `~/.auxesis` and the guard is active. Prefer [`ensure_sandbox_guard`].
pub fn ensure_sandbox_home(home: &Path) -> Result<(), String> {
    SandboxContext::resolve().refuse_home(home)
}

/// Connect/bind-time port check with the same active condition as
/// [`ensure_sandbox_guard`]: the real daemon port is refused while the guard
/// is active, whatever armed it.
pub fn ensure_sandbox_port(port: u16) -> Result<(), String> {
    if SandboxContext::resolve().active && port == REAL_DAEMON_PORT {
        return Err(port_refusal());
    }
    Ok(())
}

/// Identity of a file or directory: `(st_dev, st_ino)`. Comparing identity
/// defeats every spelling of the same directory — case, NFD/NFC, symlinks,
/// firmlinks (`/System/Volumes/Data/…`), `/private/var` and hardlinked
/// spellings — because the kernel resolves them all to the same inode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileId {
    dev: u64,
    ino: u64,
}

/// The real home captured once per guard decision.
struct RealHome {
    path: PathBuf,
    id: Option<FileId>,
    aux_path: PathBuf,
    aux_id: Option<FileId>,
}

/// Resolved inputs of one guard decision.
struct SandboxContext {
    real: Option<RealHome>,
    env_home: Option<PathBuf>,
    active: bool,
}

impl SandboxContext {
    fn resolve() -> Self {
        let sandbox = std::env::var(SANDBOX_ENV).ok().as_deref() == Some("1");
        let env_home = std::env::var_os("HOME").map(PathBuf::from);
        let lookup = lookup_real_home();
        Self::new(lookup, env_home, sandbox)
    }

    /// Pure constructor (unit tests): invalid/empty/relative `HOME` counts as
    /// overridden, never as a real home to compare against. A failed passwd
    /// lookup arms the guard and fails closed (J02-2-BI2-03).
    fn new(real_home: Option<PathBuf>, env_home: Option<PathBuf>, sandbox: bool) -> Self {
        let env_home = env_home.filter(|home| {
            let text = home.to_string_lossy();
            !text.trim().is_empty() && home.is_absolute()
        });
        let lookup_failed = real_home.is_none();
        let real = real_home.map(|path| {
            let id = file_id(&path);
            let aux_path = path.join(DEFAULT_DIR_NAME);
            let aux_id = file_id(&aux_path);
            RealHome {
                path,
                id,
                aux_path,
                aux_id,
            }
        });
        let active = sandbox
            || env_home.is_none()
            || lookup_failed
            || match (&env_home, &real) {
                (Some(env), Some(real)) => !path_eq(env, &real.path),
                _ => true,
            };
        Self {
            real,
            env_home,
            active,
        }
    }

    /// The home to use: `$AUXESIS_HOME` when set and non-blank, else
    /// `$HOME/.auxesis`. Never falls back to the CWD or the real home.
    fn resolve_home(&self) -> Result<PathBuf, String> {
        self.resolve_home_from(std::env::var("AUXESIS_HOME").ok().as_deref())
    }

    fn resolve_home_from(&self, auxesis_home: Option<&str>) -> Result<PathBuf, String> {
        if let Some(custom) = auxesis_home {
            let custom = custom.trim();
            if !custom.is_empty() {
                let home = PathBuf::from(custom);
                if self.active && !home.is_absolute() {
                    return Err(format!(
                        "refus de sandbox : AUXESIS_HOME doit être un chemin absolu (reçu {}) — pas de repli sur le répertoire courant. \
                         / sandbox refused: AUXESIS_HOME must be an absolute path (got {}) — refusing the CWD fallback.",
                        home.display(),
                        home.display()
                    ));
                }
                return Ok(home);
            }
        }
        if let Some(env_home) = &self.env_home {
            return Ok(env_home.join(DEFAULT_DIR_NAME));
        }
        Err("refus de sandbox : ni AUXESIS_HOME ni HOME absolu — aucun repli silencieux sur le répertoire courant. \
             / sandbox refused: neither AUXESIS_HOME nor an absolute HOME — refusing the silent CWD fallback."
            .to_string())
    }

    /// Refuse `home` when it *is* or is *under* the real `~/.auxesis`, or is
    /// the real home root itself.
    fn refuse_home(&self, home: &Path) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let Some(real) = &self.real else {
            return Err(fail_closed_refusal());
        };
        // Folded-path check first: it also covers a real `.auxesis` that does
        // not exist yet and non-unix platforms.
        if path_under(home, &real.aux_path) {
            return Err(home_refusal(home, &real.aux_path));
        }
        #[cfg(unix)]
        self.refuse_home_by_identity(home, real)?;
        Ok(())
    }

    /// Walk the candidate with `openat` from `/` and compare the identity of
    /// every existing component with the real `~/.auxesis` (and the final
    /// component with the real home). A not-yet-existing tail is checked
    /// against the deepest existing ancestor's resolved path.
    #[cfg(unix)]
    fn refuse_home_by_identity(&self, home: &Path, real: &RealHome) -> Result<(), String> {
        let mut dir = open_base_dir(home).map_err(|err| fail_closed_verify(&err))?;
        let components = path_components(home);
        let last = components.len().saturating_sub(1);
        let mut missing: Vec<OsString> = Vec::new();
        let mut resolved: Option<PathBuf> = None;
        for (index, name) in components.iter().enumerate() {
            let is_last = index == last;
            let fd = match openat_dir(&dir, name, true) {
                Ok(fd) => fd,
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                    missing.push(name.clone());
                    missing.extend(components.iter().skip(index + 1).cloned());
                    break;
                }
                Err(err)
                    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) =>
                {
                    openat_dir(&dir, name, false).map_err(|err| fail_closed_verify(&err))?
                }
                Err(err) => return Err(fail_closed_verify(&err)),
            };
            if let Some(path) = check_fd(real, &fd, is_last, home)? {
                resolved = Some(path);
            }
            dir = fd;
        }
        if !missing.is_empty() {
            let base = resolved.unwrap_or_else(|| normalize_path(home));
            let candidate = missing.iter().fold(base, |acc, name| acc.join(name));
            if path_under(&candidate, &real.aux_path) {
                return Err(home_refusal(home, &real.aux_path));
            }
        }
        Ok(())
    }
}

/// Check one opened directory: refuse when its identity is the real
/// `~/.auxesis` (it is or is under it) or, as the final component, the real
/// home root; re-check the `F_GETPATH` spelling as a second layer.
#[cfg(unix)]
fn check_fd(
    real: &RealHome,
    fd: &std::os::fd::OwnedFd,
    is_last: bool,
    home: &Path,
) -> Result<Option<PathBuf>, String> {
    let id = fd_file_id(fd);
    if id.is_some() && id == real.aux_id {
        return Err(home_refusal(home, &real.aux_path));
    }
    if is_last && id.is_some() && id == real.id {
        return Err(home_refusal_root(home, &real.path));
    }
    let path = fd_real_path(fd);
    if let Some(path) = &path {
        if path_under(path, &real.aux_path) {
            return Err(home_refusal(home, &real.aux_path));
        }
    }
    Ok(path)
}

fn fail_closed_refusal() -> String {
    "refus de sandbox : le foyer réel de l'utilisateur est introuvable (getpwuid) — refus par précaution. \
     / sandbox refused: the OS user database lookup failed — failing closed."
        .to_string()
}

fn fail_closed_verify(err: &std::io::Error) -> String {
    format!(
        "refus de sandbox : impossible de vérifier le chemin ({err}) — refus par précaution. \
         / sandbox refused: cannot verify the path ({err}) — failing closed."
    )
}

/// Message for a home that resolves into the real `~/.auxesis`.
fn home_refusal(home: &Path, real_aux: &Path) -> String {
    let home = normalize_path(home);
    format!(
        "refus de sandbox : {SANDBOX_ENV}=1 ou HOME détourné, mais le foyer Auxesis résolu {} est sous le vrai {} — utilisez des chemins mktemp littéraux : `env -i HOME=<mktemp> AUXESIS_HOME=<mktemp>/{DEFAULT_DIR_NAME} {SANDBOX_ENV}=1 AUXESIS_API_PORT=0`. \
         / sandbox refused: the resolved Auxesis home {} is under the real {} — use literal mktemp paths.",
        home.display(),
        real_aux.display(),
        home.display(),
        real_aux.display()
    )
}

/// Message for `AUXESIS_HOME` equal to the real home root.
fn home_refusal_root(home: &Path, real_home: &Path) -> String {
    format!(
        "refus de sandbox : AUXESIS_HOME {} est le foyer réel lui-même — utilisez un sous-dossier mktemp. \
         / sandbox refused: AUXESIS_HOME is the real home root {} — use a literal mktemp subdirectory.",
        home.display(),
        real_home.display()
    )
}

/// Message for the real daemon port while the guard is active.
pub(crate) fn port_refusal() -> String {
    format!(
        "refus de sandbox : {SANDBOX_ENV}=1 ou HOME détourné, mais le port {REAL_DAEMON_PORT} est celui du vrai auxd — utilisez un port éphémère explicite (`AUXESIS_API_PORT=0`). \
         / sandbox refused: {SANDBOX_ENV}=1 or HOME overridden, but port {REAL_DAEMON_PORT} is the real auxd's — use an explicit ephemeral port (`AUXESIS_API_PORT=0`)."
    )
}

/// Case- and Unicode-normalisation-insensitive path key, used only as the
/// second (textual) check and for not-yet-existing tails. Identity is the
/// primary check.
fn path_key(path: &Path) -> Vec<String> {
    normalize_path(path)
        .components()
        .map(component_key)
        .collect()
}

fn component_key(component: Component<'_>) -> String {
    use unicode_normalization::UnicodeNormalization;
    component
        .as_os_str()
        .to_string_lossy()
        .nfd()
        .collect::<String>()
        .to_lowercase()
}

fn path_eq(a: &Path, b: &Path) -> bool {
    path_key(a) == path_key(b)
}

fn path_under(candidate: &Path, base: &Path) -> bool {
    let candidate = path_key(candidate);
    let base = path_key(base);
    candidate.len() >= base.len() && candidate[..base.len()] == base[..]
}

/// Canonical path for comparison: canonicalise the longest existing ancestor
/// (resolving symlinks even when the leaf does not exist yet), append the
/// remaining components and fold `.`/`..` lexically. Dangling symlinks are
/// followed by hand — a symlink to the real home that does not exist yet must
/// not slip past. Falls back to pure lexical normalisation when nothing can
/// be resolved.
fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|dir| dir.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    resolve_symlinks(&absolute, 0).unwrap_or_else(|| lexical_normalize(&absolute))
}

/// Resolve `path` with `canonicalize`; when it does not exist, follow a
/// symlink component (dangling included) or recurse into the parent. Returns
/// `None` on an unreadable path or a symlink cycle (`depth` bounds the
/// recursion).
fn resolve_symlinks(path: &Path, depth: usize) -> Option<PathBuf> {
    const MAX_SYMLINK_DEPTH: usize = 40;
    if depth > MAX_SYMLINK_DEPTH {
        return None;
    }
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Some(canonical);
    }
    if std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        let target = std::fs::read_link(path).ok()?;
        let target = if target.is_absolute() {
            target
        } else {
            path.parent()?.join(target)
        };
        return resolve_symlinks(&target, depth + 1);
    }
    let name = path.file_name()?;
    let parent = resolve_symlinks(path.parent()?, depth + 1)?;
    Some(parent.join(name))
}

/// Lexical `.`/`..` folding (used once every symlink is already resolved).
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Components of a candidate path for the `openat` walk (`..` is preserved
/// and resolved by the kernel).
fn path_components(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect()
}

// Test hook: force the passwd lookup result (`Some(None)` = simulated
// failure) without touching the real user database.
//
// Thread-local on purpose: tests run in parallel threads within one binary,
// and a process-global override made every concurrently running test observe
// a failed `getpwuid` lookup and fail closed (e.g. the `config_lock` guard
// tests intermittently failing on a Linux build server with "foyer réel
// introuvable (getpwuid)"). Only the thread that installs the override is
// affected, and it is dropped with the thread even if the test panics.
#[cfg(test)]
thread_local! {
    static FORCED_REAL_HOME: std::cell::RefCell<Option<Option<PathBuf>>> =
        const { std::cell::RefCell::new(None) };
}

fn lookup_real_home() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(forced) = FORCED_REAL_HOME.with(|slot| slot.borrow().clone()) {
        return forced;
    }
    real_user_home()
}

/// Resolve the Auxesis home directory.
///
/// `$AUXESIS_HOME` wins when set and non-blank (surrounding whitespace is
/// trimmed); otherwise `$HOME/.auxesis`. Binaries call
/// [`ensure_sandbox_guard`] first and use its return value; this helper stays
/// for library contexts that already run under the guard.
pub fn auxesis_home() -> PathBuf {
    let env_path = if let Ok(custom) = std::env::var("AUXESIS_HOME") {
        let custom = custom.trim();
        if !custom.is_empty() {
            PathBuf::from(custom)
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(DEFAULT_DIR_NAME)
        }
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(DEFAULT_DIR_NAME)
    };
    // One source of truth: when this env spelling belongs to a verified
    // home, return its canonical path (the exported home).
    if let Ok(handle) = verified_home() {
        if path_eq(handle.configured_path(), &env_path) || path_eq(handle.path(), &env_path) {
            return handle.path().to_path_buf();
        }
    }
    env_path
}

// ---------------------------------------------------------------------------
// The write gateway: verified home handle
// ---------------------------------------------------------------------------

/// A verified handle on the Auxesis home.
///
/// [`ensure_home`] opens (creating when needed) the home through `openat`
/// with `O_NOFOLLOW` on every component and re-verifies the opened directory
/// against the real `~/.auxesis` identity. The handle keeps the directory fd
/// alive: every later write under the home goes through [`SandboxHome::write`]
/// and friends, which resolve relative to that fd — a symlink swapped in
/// after the check cannot redirect them.
pub struct SandboxHome {
    /// Canonical path of the verified directory (the ONLY home consumers
    /// use).
    home: PathBuf,
    /// The path as configured at registration (`AUXESIS_HOME`/`$HOME`), kept
    /// so `auxesis_home()` can recognise it.
    raw: PathBuf,
    #[cfg(unix)]
    dir: std::os::fd::OwnedFd,
    #[cfg(unix)]
    id: FileId,
}

impl Clone for SandboxHome {
    fn clone(&self) -> Self {
        #[cfg(unix)]
        {
            Self {
                home: self.home.clone(),
                raw: self.raw.clone(),
                dir: self
                    .dir
                    .try_clone()
                    .expect("duplicating the verified home directory fd"),
                id: self.id,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                home: self.home.clone(),
                raw: self.raw.clone(),
            }
        }
    }
}

impl std::fmt::Debug for SandboxHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxHome")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl SandboxHome {
    /// Open (creating when needed) `home`, verified against the real
    /// `~/.auxesis` while the guard is active.
    pub fn open(home: &Path) -> std::io::Result<Self> {
        let ctx = SandboxContext::resolve();
        Self::open_with(home, &ctx)
    }

    /// Like [`SandboxHome::open`] but never creates the home: a missing
    /// directory is `NotFound`.
    pub fn open_existing(home: &Path) -> std::io::Result<Self> {
        let ctx = SandboxContext::resolve();
        Self::open_existing_with(home, &ctx)
    }

    fn open_existing_with(home: &Path, ctx: &SandboxContext) -> std::io::Result<Self> {
        Self::finish_open(home, ctx, false)
    }

    fn open_with(home: &Path, ctx: &SandboxContext) -> std::io::Result<Self> {
        Self::finish_open(home, ctx, true)
    }

    /// Canonicalise the verified directory once: `home` is the fd's real
    /// path (`F_GETPATH`/`/proc/self/fd`), exported as the ONLY home every
    /// consumer uses; `raw` keeps the configured spelling. While the guard
    /// is active the home is scanned (depth 2) for pre-planted symlinks.
    fn finish_open(home: &Path, ctx: &SandboxContext, create: bool) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let dir = open_home_unix(home, ctx, create)?;
            let id = fd_file_id(&dir)
                .ok_or_else(|| std::io::Error::other("cannot fstat the verified home"))?;
            let canonical = fd_real_path(&dir)
                .ok_or_else(|| std::io::Error::other("cannot resolve the verified home"))?;
            if ctx.active {
                // Depth 4 covers agents/<agent>/workspace (GLM F2). The leaf
                // markers the guard itself manages (STOP, api.token) are
                // skipped: they have dedicated O_NOFOLLOW/identity handlers
                // and a dangling STOP must stay readable and resumable.
                reject_symlinks_at_start(&dir, 4, &["STOP", "api.token"])?;
            }
            Ok(Self {
                home: canonical,
                raw: home.to_path_buf(),
                dir,
                id,
            })
        }
        #[cfg(not(unix))]
        {
            if !home.exists() {
                if !create {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("{} does not exist", home.display()),
                    ));
                }
                std::fs::create_dir_all(home)?;
            }
            Ok(Self {
                home: home.to_path_buf(),
                raw: home.to_path_buf(),
            })
        }
    }

    /// Re-verify the held identity: open the home by path (leaf
    /// `O_NOFOLLOW`, ancestors resolved by the kernel) and compare its
    /// `(st_dev, st_ino)` with the held directory fd. Every mutating method
    /// calls this first, so a home renamed or swapped after the check is
    /// refused rather than followed.
    pub fn reverify(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let fd = open_dir_by_path(&self.home)?;
            let now = fd_file_id(&fd)
                .ok_or_else(|| std::io::Error::other("cannot fstat the re-verified home"))?;
            if now != self.id {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refus de sandbox : l'identité du foyer {} a changé depuis la vérification. \
                         / sandbox refused: the home identity changed since verification.",
                        self.home.display()
                    ),
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    /// The directory's real path, obtained from the held fd (`F_GETPATH` on
    /// macOS, `/proc/self/fd` on Linux) after a re-verification. Consumers
    /// that must open by path (SQLite) build it from here, so it names the
    /// verified inode even when its configured path was renamed or swapped.
    pub fn real_path(&self) -> std::io::Result<PathBuf> {
        self.reverify()?;
        #[cfg(unix)]
        {
            fd_real_path(&self.dir).ok_or_else(|| {
                std::io::Error::other("cannot resolve the verified home's real path")
            })
        }
        #[cfg(not(unix))]
        {
            Ok(self.home.clone())
        }
    }

    /// After opening a file by path, prove the file at `opened` is the same
    /// inode as `rel` reachable through the verified directory fd.
    pub fn verify_file_inode(&self, rel: &Path, opened: &Path) -> std::io::Result<()> {
        self.reverify()?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let components = relative_components(rel)?;
            let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
            let dir = open_rel_dir(self, dirs)?;
            let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let via_fd = FileId {
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
            };
            let via_path = file_id(opened)
                .ok_or_else(|| std::io::Error::other("cannot stat the opened file"))?;
            if via_fd != via_path {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refus de sandbox : {} n'est pas le fichier du foyer vérifié. \
                         / sandbox refused: {} is not the verified home's file.",
                        opened.display(),
                        opened.display()
                    ),
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (rel, opened);
            Ok(())
        }
    }

    /// Open `rel` for append (creating with `mode`), fd-relative and
    /// `O_NOFOLLOW`.
    pub fn open_append(&self, rel: &Path, mode: u32) -> std::io::Result<std::fs::File> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let dir = open_rel_dir(self, dirs)?;
            let flags = libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_APPEND
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW;
            let Some(fd) = openat_with_mode(&dir, name, flags, mode as libc::mode_t)? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "append target exists",
                ));
            };
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            let mut options = std::fs::OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(mode);
            }
            options.open(path)
        }
    }

    /// Open `rel` for reading relative to the verified home descriptor.
    ///
    /// On Unix the leaf is opened with `O_NOFOLLOW | O_NONBLOCK`, then the
    /// returned descriptor is `fstat`ed before it is returned. This refuses
    /// symlinks, FIFOs, devices, directories and oversized files without a
    /// path-based check/read race. Missing parent directories are created
    /// (`0700`); use [`SandboxHome::open_read_existing`] when a read must not
    /// create anything.
    pub fn open_read(&self, rel: &Path, max_bytes: u64) -> std::io::Result<std::fs::File> {
        self.open_read_inner(rel, max_bytes, true)
    }

    /// Like [`SandboxHome::open_read`] but never creates a missing directory:
    /// a path whose parent chain does not exist is `NotFound`.
    pub fn open_read_existing(&self, rel: &Path, max_bytes: u64) -> std::io::Result<std::fs::File> {
        self.open_read_inner(rel, max_bytes, false)
    }

    fn open_read_inner(
        &self,
        rel: &Path,
        max_bytes: u64,
        create_dirs: bool,
    ) -> std::io::Result<std::fs::File> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let dir = if create_dirs {
                open_rel_dir(self, dirs)?
            } else {
                open_rel_dir_existing(self, dirs)?
            };
            let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
            let Some(fd) = openat_with_mode(&dir, name, flags, 0)? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "read target unexpectedly exists",
                ));
            };
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "read target is not a regular file",
                ));
            }
            if metadata.len() > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "read target is too large",
                ));
            }
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            let _ = create_dirs;
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "read target is a symlink",
                ));
            }
            let file = std::fs::OpenOptions::new().read(true).open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "read target is not a bounded regular file",
                ));
            }
            Ok(file)
        }
    }

    /// Remove the directory `rel` (must be empty); `false` when it did not
    /// exist.
    pub fn remove_dir(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let rc =
                unsafe { libc::unlinkat(dir.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(err);
            }
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::remove_dir(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    /// Recursively remove the directory `rel`, fd-checked: a symlinked child
    /// is refused, and the tree is removed through the verified fd's real
    /// path (`F_GETPATH`), never the configured path string.
    pub fn remove_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        self.reverify()?;
        let components = relative_components(rel)?;
        #[cfg(unix)]
        {
            let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
            let parent = open_rel_dir(self, dirs)?;
            match openat_dir(&parent, name, true) {
                Ok(fd) => drop(fd),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err)
                    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) =>
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "refus de sandbox : {} est un lien symbolique. \
                             / sandbox refused: {} is a symlink.",
                            rel.display(),
                            rel.display()
                        ),
                    ));
                }
                Err(err) => return Err(err),
            }
            let real = self.real_path()?;
            let target = components.iter().fold(real, |acc, part| acc.join(part));
            std::fs::remove_dir_all(target)
        }
        #[cfg(not(unix))]
        {
            let target = components
                .iter()
                .fold(self.home.clone(), |acc, part| acc.join(part));
            std::fs::remove_dir_all(target)
        }
    }

    /// The canonical home path: the ONE path every consumer uses (exports,
    /// display, config/store paths).
    pub fn path(&self) -> &Path {
        &self.home
    }

    /// The path as configured at registration (used only to recognise the
    /// env spelling).
    pub fn configured_path(&self) -> &Path {
        &self.raw
    }

    /// Whether `rel` exists in the verified home, without following a leaf
    /// symlink (a dangling symlink counts as present — the kill switch is
    /// fail-safe).
    pub fn exists_no_follow(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc == 0 {
                return Ok(true);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(false);
            }
            Err(err)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            Ok(std::fs::symlink_metadata(path).is_ok())
        }
    }

    /// Create the file `rel` (relative to the home) with `data` and `mode`,
    /// truncating an existing file. Never follows a symlink.
    pub fn write(&self, rel: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
        self.reverify()?;

        self.write_inner(rel, data, mode, false).map(|_| ())
    }

    /// Like [`SandboxHome::write`] but fails with `AlreadyExists` instead of
    /// truncating; returns `false` when the file already exists.
    pub fn write_new(&self, rel: &Path, data: &[u8], mode: u32) -> std::io::Result<bool> {
        self.reverify()?;

        self.write_inner(rel, data, mode, true)
    }

    /// Create the directory `rel` (parents must exist); `false` when it
    /// already exists.
    pub fn create_dir(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;

        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            let dir = open_rel_dir(self, dirs)?;
            match mkdirat(&dir, name, 0o700) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(err) => Err(err),
            }
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::create_dir(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    /// Atomically and durably replace `rel` with `data`: temp file, fsync,
    /// `renameat` in the verified parent, then fsync of that parent. Mode `mode`.
    pub fn write_atomic(&self, rel: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
        self.write_atomic_with_pre_rename_check(rel, data, mode, || Ok(()))
    }

    /// Atomically replace `rel` after syncing a temporary file, running
    /// `before_rename_check` immediately before the final rename. If the check
    /// fails, the temporary file is removed and the existing destination stays
    /// in place.
    pub fn write_atomic_with_pre_rename_check(
        &self,
        rel: &Path,
        data: &[u8],
        mode: u32,
        before_rename_check: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        self.reverify()?;

        use std::io::Write as _;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let temp = OsString::from(format!(
                ".{}.tmp.{}.{stamp}",
                name.to_string_lossy(),
                std::process::id()
            ));
            let flags =
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
            let Some(fd) = openat_with_mode(&dir, &temp, flags, mode as libc::mode_t)? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "atomic temp file already exists",
                ));
            };
            let write_result = (|| -> std::io::Result<()> {
                let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
                let metadata = file.metadata()?;
                if !metadata.is_file() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "atomic target is not a regular file",
                    ));
                }
                let chmod = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
                if chmod != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                file.write_all(data)?;
                file.sync_all()
            })();
            if let Err(err) = write_result {
                let _ = unlinkat(&dir, &temp);
                return Err(err);
            }
            let from = std::ffi::CString::new(temp.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let to = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            if let Err(err) = before_rename_check() {
                let _ = unlinkat(&dir, &temp);
                return Err(err);
            }
            let rc = unsafe {
                libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr())
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                let _ = unlinkat(&dir, &temp);
                return Err(err);
            }
            // The rename is a directory entry change: it survives a crash only
            // once the directory itself is synced.
            if unsafe { libc::fsync(dir.as_raw_fd()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let parent = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name));
            let temp = parent.join(format!(
                ".{}.tmp.{}",
                name.to_string_lossy(),
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options.open(&temp)?;
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            if let Err(err) = before_rename_check() {
                let _ = std::fs::remove_file(&temp);
                return Err(err);
            }
            std::fs::rename(&temp, parent.join(name))
        }
    }

    /// Create `rel` and every missing parent under the home (`0700`).
    pub fn create_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        self.reverify()?;

        let components = relative_components(rel)?;
        #[cfg(unix)]
        {
            let _ = open_rel_dir(self, &components)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let path = components
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name));
            std::fs::create_dir_all(path)
        }
    }

    /// Remove the file `rel`; `false` when it did not exist.
    pub fn remove_file(&self, rel: &Path) -> std::io::Result<bool> {
        self.reverify()?;

        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let dir = open_rel_dir(self, dirs)?;
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid_rel(rel))?;
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(err);
            }
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            match std::fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    fn write_inner(
        &self,
        rel: &Path,
        data: &[u8],
        mode: u32,
        exclusive: bool,
    ) -> std::io::Result<bool> {
        use std::io::Write as _;
        let components = relative_components(rel)?;
        let (name, dirs) = components.split_last().ok_or_else(|| invalid_rel(rel))?;
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let dir = open_rel_dir(self, dirs)?;
            let flags = libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if exclusive {
                    libc::O_EXCL
                } else {
                    libc::O_TRUNC
                };
            // `openat_with_mode` maps EEXIST (exclusive) to `None`: callers
            // using `write_new` want `false`, not an error.
            let Some(fd) = openat_with_mode(&dir, name, flags, mode as libc::mode_t)? else {
                return Ok(false);
            };
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            file.write_all(data)?;
            file.sync_all()?;
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            let path = dirs
                .iter()
                .fold(self.home.clone(), |acc, name| acc.join(name))
                .join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(mode);
            }
            if exclusive {
                options.create_new(true);
            } else {
                options.truncate(true);
            }
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(data)?;
                    Ok(true)
                }
                Err(err) if exclusive && err.kind() == std::io::ErrorKind::AlreadyExists => {
                    Ok(false)
                }
                Err(err) => Err(err),
            }
        }
    }
}

/// `openat` with a mode argument, mapping `EEXIST` (exclusive) to `Ok(None)`.
#[cfg(unix)]
fn openat_with_mode(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<Option<std::os::fd::RawFd>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    // `openat` is variadic: the mode is promoted to `c_uint`.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(None);
        }
        return Err(err);
    }
    Ok(Some(fd))
}

/// `unlinkat` on one verified parent directory.
#[cfg(unix)]
fn unlinkat(dir: &std::os::fd::OwnedFd, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Open the parent directory chain of `components` under the verified home,
/// creating missing directories. Strict `O_NOFOLLOW`: a symlink inside the
/// home is refused rather than followed.
#[cfg(unix)]
fn open_rel_dir(
    home: &SandboxHome,
    components: &[OsString],
) -> std::io::Result<std::os::fd::OwnedFd> {
    open_rel_dir_inner(home, components, true)
}

/// Like [`open_rel_dir`] but never creates anything: a missing directory is
/// `NotFound`, and every component is still opened `O_NOFOLLOW`.
#[cfg(unix)]
fn open_rel_dir_existing(
    home: &SandboxHome,
    components: &[OsString],
) -> std::io::Result<std::os::fd::OwnedFd> {
    open_rel_dir_inner(home, components, false)
}

#[cfg(unix)]
fn open_rel_dir_inner(
    home: &SandboxHome,
    components: &[OsString],
    create: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut dir = home.dir.try_clone()?;
    for name in components {
        dir = match openat_dir(&dir, name, true) {
            Ok(fd) => fd,
            Err(err) if create && err.raw_os_error() == Some(libc::ENOENT) => {
                // Tolerate a concurrent creator winning the mkdir race.
                match mkdirat(&dir, name, 0o700) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err),
                }
                openat_dir(&dir, name, true)?
            }
            Err(err) => return Err(err),
        };
    }
    Ok(dir)
}

/// Validate a sandbox-relative path: no absolute or parent components.
fn relative_components(rel: &Path) -> std::io::Result<Vec<OsString>> {
    let mut out = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => out.push(name.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_rel(rel));
            }
        }
    }
    if out.is_empty() {
        return Err(invalid_rel(rel));
    }
    Ok(out)
}

fn invalid_rel(rel: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "sandbox-relative path must be a non-empty path inside the home: {}",
            rel.display()
        ),
    )
}

/// Create the home directory (and parents) if needed and return the verified
/// write handle.
///
/// Newly created homes are private (`0700`) on unix. On unix the walk opens
/// each component through `openat` with `O_NOFOLLOW` on the leaf, and while
/// the sandbox guard is active it re-verifies every opened directory by
/// identity and `F_GETPATH` (`/proc/self/fd` on Linux) so a symlink swapped
/// in after the check cannot redirect creation into the real `~/.auxesis`.
pub fn ensure_home(home: &Path) -> std::io::Result<SandboxHome> {
    let ctx = SandboxContext::resolve();
    let handle = SandboxHome::open_with(home, &ctx)?;
    register_verified_home(home, &handle);
    Ok(handle)
}

/// Register one verified home for `home` (keyed by its normalised path, so
/// several homes can coexist in one process — e.g. parallel tests).
fn register_verified_home(home: &Path, handle: &SandboxHome) {
    let key = normalize_path(home);
    if let Ok(mut homes) = VERIFIED_HOMES.lock() {
        homes.retain(|(existing, _)| *existing != key);
        homes.push((key, handle.clone()));
    }
}

/// The verified home for `home`, registering it when the process never ran
/// [`ensure_home`] (library/test callers). The home is always verified — a
/// raw path is never used.
pub fn verified_home_or_verify(home: &Path) -> std::io::Result<SandboxHome> {
    match verified_home_for(home) {
        Ok(handle) => Ok(handle),
        Err(_) => ensure_home(home),
    }
}

/// Canonical path of `rel` inside the verified home, for the rare APIs that
/// require a path (e.g. third-party readers). Built from the verified fd's
/// real path, never from the configured spelling.
pub fn verified_child_path(home: &Path, rel: &Path) -> std::io::Result<PathBuf> {
    Ok(verified_home_or_verify(home)?.real_path()?.join(rel))
}

/// The verified home handle registered for exactly this path.
///
/// Returns an error when [`ensure_home`] has not run for it: a consumer must
/// never fall back to a path string.
pub fn verified_home_for(home: &Path) -> std::io::Result<SandboxHome> {
    let key = normalize_path(home);
    let homes = VERIFIED_HOMES
        .lock()
        .map_err(|_| std::io::Error::other("verified home lock poisoned"))?;
    homes
        .iter()
        // The normalised key catches renamed spellings; the raw path catches
        // a path whose symlink target changed *after* registration (the
        // handle's own re-verification then refuses it).
        .find(|(existing, handle)| {
            *existing == key || handle.path() == home || handle.configured_path() == home
        })
        .map(|(_, handle)| handle.clone())
        .ok_or_else(|| std::io::Error::other("no verified home for this path"))
}

/// Verified homes registered by [`ensure_home`], keyed by their normalised
/// path. In a binary there is exactly one; tests may have several in flight
/// and each consumer asks for its own path via [`verified_home_for`].
static VERIFIED_HOMES: std::sync::Mutex<Vec<(PathBuf, SandboxHome)>> =
    std::sync::Mutex::new(Vec::new());

/// The most recently registered verified home (convenience for callers that
/// do not have a path); prefer [`verified_home_for`].
pub fn verified_home() -> std::io::Result<SandboxHome> {
    let homes = VERIFIED_HOMES
        .lock()
        .map_err(|_| std::io::Error::other("verified home lock poisoned"))?;
    homes
        .last()
        .map(|(_, handle)| handle.clone())
        .ok_or_else(|| std::io::Error::other("no verified home: ensure_home has not run"))
}

#[cfg(unix)]
fn open_home_unix(
    home: &Path,
    ctx: &SandboxContext,
    create: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut dir = open_base_dir(home)?;
    let components = path_components(home);
    let last = components.len().saturating_sub(1);
    let mut created = false;
    for (index, name) in components.iter().enumerate() {
        let is_last = index == last;
        dir = match openat_dir(&dir, name, true) {
            Ok(fd) => fd,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                if !create {
                    return Err(err);
                }
                // Tolerate a concurrent creator winning the mkdir race.
                match mkdirat(&dir, name, 0o700) {
                    Ok(()) => {
                        if is_last {
                            created = true;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err),
                }
                openat_dir(&dir, name, true)?
            }
            // A symlink component (`ELOOP`, or `ENOTDIR` on macOS where
            // `O_NOFOLLOW | O_DIRECTORY` reports a symlink that way): follow
            // it once; the verification below rejects a target under the
            // real ~/.auxesis. A regular file fails the retry with ENOTDIR.
            Err(err) if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                openat_dir(&dir, name, false)?
            }
            Err(err) => return Err(err),
        };
        if ctx.active {
            verify_open_home_dir(&dir, ctx, is_last, home)?;
        }
    }
    if created {
        fchmod_0700(&dir)?;
    }
    Ok(dir)
}

/// Verify an opened home directory while the guard is active: fail closed on
/// a failed lookup, refuse the real `~/.auxesis` identity (or an `F_GETPATH`
/// spelling under it) and the real home root as the final component.
#[cfg(unix)]
fn verify_open_home_dir(
    dir: &std::os::fd::OwnedFd,
    ctx: &SandboxContext,
    is_last: bool,
    home: &Path,
) -> std::io::Result<()> {
    let Some(real) = &ctx.real else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            fail_closed_refusal(),
        ));
    };
    match check_fd(real, dir, is_last, home) {
        Ok(_) => Ok(()),
        Err(message) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            message,
        )),
    }
}

#[cfg(unix)]
fn file_id(path: &Path) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|meta| FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(not(unix))]
fn file_id(_path: &Path) -> Option<FileId> {
    None
}

#[cfg(unix)]
fn fd_file_id(dir: &std::os::fd::OwnedFd) -> Option<FileId> {
    use std::os::fd::AsRawFd;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(dir.as_raw_fd(), &mut stat) };
    if rc != 0 {
        return None;
    }
    Some(FileId {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    })
}

/// The two syscalls the startup symlink scan depends on. Kept behind this
/// seam so a unit test can deterministically make one entry vanish between
/// `readdir` and `fstatat` (or fail the stat), without races.
#[cfg(unix)]
trait StartupScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>>;
    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32>;
    /// Open a child directory without following a symlink. Kept behind the
    /// same seam so a test can swap a directory for a symlink in the exact
    /// window between `fstatat` and this open (or fail the open with a chosen
    /// errno) without a real race.
    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd>;
}

/// The real syscalls; every production scan uses this.
#[cfg(unix)]
struct RealStartupScanFs;

#[cfg(unix)]
impl StartupScanFs for RealStartupScanFs {
    fn read_dir_names(
        &self,
        dir: &std::os::fd::OwnedFd,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        read_dir_names(dir)
    }

    fn fstatat_mode(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<u32> {
        fstatat_mode(dir, name)
    }

    fn open_child_dir(
        &self,
        dir: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        nofollow: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        openat_dir(dir, name, nofollow)
    }
}

/// Refuse a sandbox home that contains a symlink at depth ≤ `depth`
/// (J-02 round 5): sandbox homes are fresh temp directories and never need
/// one, and a pre-planted `<home>/whatsapp -> outside` must not redirect
/// session/audit/voice reads or writes.
///
/// FLAKY-03: an entry that disappears between `readdir` and `fstatat`
/// (ENOENT) is skipped, not fatal. Another `aux` process closing the SQLite
/// store unlinks `store.db-wal`/`store.db-shm` exactly while the daemon scans, and
/// a name that no longer exists cannot be the symlink we would follow. Every
/// other stat error stays fatal. The check order remains secure: entries are
/// stat'ed with `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the opened
/// directory fd (never a path-based `lstat` after a join), recursion happens
/// only through `openat(O_NOFOLLOW)`, and nothing is later opened from a path
/// built here — every read/write under the home goes through the same verified
/// handle with `O_NOFOLLOW` and identity re-verification, so an entry swapped
/// for a symlink after this stat is refused, not followed.
#[cfg(unix)]
fn reject_symlinks_at_start(
    dir: &std::os::fd::OwnedFd,
    depth: u32,
    skip: &[&str],
) -> std::io::Result<()> {
    reject_symlinks_at_start_with(dir, depth, skip, &RealStartupScanFs)
}

#[cfg(unix)]
fn reject_symlinks_at_start_with(
    dir: &std::os::fd::OwnedFd,
    depth: u32,
    skip: &[&str],
    fs: &dyn StartupScanFs,
) -> std::io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    for name in fs.read_dir_names(dir)? {
        if skip.iter().any(|managed| name == *managed) {
            continue;
        }
        let mode = match fs.fstatat_mode(dir, &name) {
            Ok(mode) => mode,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                // The entry vanished between readdir and fstatat: skip it. It
                // no longer exists, so it cannot be the symlink we refuse, and
                // no later open is derived from this stat.
                continue;
            }
            Err(err) => return Err(err),
        };
        if mode_is_symlink(mode) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refus de sandbox : le foyer vérifié contient un lien symbolique ({}) — les foyers sandbox sont des dossiers mktemp sans lien. \
                     / sandbox refused: the verified home contains a symlink ({}) — sandbox homes are fresh mktemp directories and never need one.",
                    name.to_string_lossy(),
                    name.to_string_lossy()
                ),
            ));
        }
        if mode_is_dir(mode) {
            match fs.open_child_dir(dir, &name, true) {
                Ok(child) => {
                    reject_symlinks_at_start_with(&child, depth - 1, &[], fs)?;
                }
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                    // The directory disappeared between fstatat and openat
                    // (a concurrent cleanup): skip it, the same rule as the
                    // fstatat ENOENT above. Nothing was opened, so there is
                    // no child to recurse into.
                }
                Err(err) => return Err(scan_open_refusal(&name, &err)),
            }
        }
    }
    Ok(())
}

/// A fatal `openat(O_NOFOLLOW)` failure during the startup symlink scan:
/// same error shape and bilingual style as a found symlink, naming only the
/// entry and never a joined path. The entry was a directory at `fstatat`
/// time but could not be opened without following a link — ELOOP/ENOTDIR
/// means a symlink took its place in that window, exactly the swap this scan
/// refuses; any other errno (EACCES, EMFILE, ...) must fail closed too.
#[cfg(unix)]
fn scan_open_refusal(name: &std::ffi::OsStr, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "refus de sandbox : l'entrée vérifiée d'un dossier n'a pas pu être ouverte sans suivre de lien ({0} — {1}) — un dossier a pu être remplacé par un lien symbolique après la vérification. \
             / sandbox refused: the verified entry of a directory could not be opened without following a link ({0}) — a directory may have been swapped for a symlink after the check.",
            name.to_string_lossy(),
            err
        ),
    )
}

/// This thread's errno storage, per platform.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__error` returns this thread's errno storage.
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__errno_location` returns this thread's errno storage.
    unsafe { libc::__errno_location() }
}

/// Other unix libcs (BSD) expose the same accessor as macOS.
#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    ))
))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: BSD libc exposes `__error` for this thread's errno.
    unsafe { libc::__error() }
}

/// Set this thread's errno to 0 before a `readdir` call, so a following NULL
/// can be disambiguated: NULL means end-of-directory only when errno is 0.
#[cfg(unix)]
fn clear_process_errno() {
    // SAFETY: the pointer is this thread's errno storage.
    unsafe { *errno_location() = 0 };
}

/// This thread's errno after the most recent syscall.
#[cfg(unix)]
fn process_errno() -> libc::c_int {
    // SAFETY: the pointer is this thread's errno storage.
    unsafe { *errno_location() }
}

/// The directory-listing syscalls behind one open stream. Kept behind this
/// seam so a unit test can deterministically make a mid-listing `readdir` fail
/// with a chosen errno (EIO) and can count fd opens/closes, without any
/// production-reachable injection switch. Every production scan uses
/// [`RealDirReadFs`].
#[cfg(unix)]
trait DirReadFs {
    /// Cursor over one open listing; owns the fd `fdopendir` took over.
    type Cursor;

    /// Open a fresh file description for "." under `dir` and `fdopendir` it.
    /// On failure the opened fd is closed exactly once and the *original* OS
    /// error is returned, never one clobbered by the close.
    fn open(&self, dir: &std::os::fd::OwnedFd) -> std::io::Result<Self::Cursor>;

    /// Clear this thread's errno before the next `readdir`.
    fn clear_errno(&self);

    /// One `readdir`: `Some(name)` when the pointer is non-NULL, `None` when
    /// it is NULL (end-of-directory or error — the caller checks `errno`).
    fn readdir(&self, cursor: &Self::Cursor) -> Option<std::ffi::OsString>;

    /// The errno left by the last `readdir`.
    fn errno(&self) -> libc::c_int;

    /// Close the listing exactly once.
    fn close(&self, cursor: Self::Cursor);
}

/// One open `DIR*` stream; owns the fd `fdopendir` took over.
#[cfg(unix)]
struct RealDirCursor {
    stream: *mut libc::DIR,
}

/// The real syscalls; every production scan uses this.
#[cfg(unix)]
struct RealDirReadFs;

#[cfg(unix)]
impl DirReadFs for RealDirReadFs {
    type Cursor = RealDirCursor;

    fn open(&self, dir: &std::os::fd::OwnedFd) -> std::io::Result<RealDirCursor> {
        use std::os::fd::AsRawFd;
        // Open a fresh file description for "." instead of `dup`-ing the
        // caller's fd: `dup` shares the directory offset, so a second scan on
        // the same fd would silently read nothing. `openat` gives an
        // independent offset and a relative "." can never be a symlink out of
        // this directory.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            // Capture the fdopendir error BEFORE `close`: `close` sets its own
            // errno and would otherwise clobber this diagnostic.
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(RealDirCursor { stream })
    }

    fn clear_errno(&self) {
        clear_process_errno();
    }

    fn readdir(&self, cursor: &RealDirCursor) -> Option<std::ffi::OsString> {
        use std::ffi::{CStr, OsStr};
        use std::os::unix::ffi::OsStrExt;
        let entry = unsafe { libc::readdir(cursor.stream) };
        if entry.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        Some(OsStr::from_bytes(name.to_bytes()).to_os_string())
    }

    fn errno(&self) -> libc::c_int {
        process_errno()
    }

    fn close(&self, cursor: RealDirCursor) {
        unsafe { libc::closedir(cursor.stream) };
    }
}

/// Collect the entries of one open cursor, excluding `.`/`..`.
///
/// Security review P2: errno is cleared before EVERY `readdir`, so a stale value from an
/// earlier syscall can never turn a clean end-of-directory into a false
/// truncation; conversely a NULL result with a non-zero errno is a fatal OS
/// error, never a silently truncated listing.
#[cfg(unix)]
fn collect_dir_names<F: DirReadFs>(
    fs: &F,
    cursor: &F::Cursor,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStrExt;
    let mut names = Vec::new();
    loop {
        fs.clear_errno();
        let Some(name) = fs.readdir(cursor) else {
            let errno = fs.errno();
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            return Ok(names);
        };
        let bytes = name.as_os_str().as_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(name);
    }
}

/// Open a fresh listing of `dir` and collect its entry names (excluding
/// `.`/`..`). The stream is closed exactly once, on the success and error
/// paths alike; a failed `open` owns its own fd cleanup.
#[cfg(unix)]
fn read_dir_names_with<F: DirReadFs>(
    fs: &F,
    dir: &std::os::fd::OwnedFd,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    let cursor = fs.open(dir)?;
    let result = collect_dir_names(fs, &cursor);
    fs.close(cursor);
    result
}

/// Entry names of one directory fd (excluding `.`/`..`).
#[cfg(unix)]
fn read_dir_names(dir: &std::os::fd::OwnedFd) -> std::io::Result<Vec<std::ffi::OsString>> {
    read_dir_names_with(&RealDirReadFs, dir)
}

/// `S_IFMT`/`S_IFLNK` are `u16` on macOS and `u32` on Linux; the casts are
/// necessary on one platform and redundant on the other.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn mode_is_symlink(mode: u32) -> bool {
    mode & (libc::S_IFMT as u32) == libc::S_IFLNK as u32
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn mode_is_dir(mode: u32) -> bool {
    mode & (libc::S_IFMT as u32) == libc::S_IFDIR as u32
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` mode of one entry.
#[cfg(unix)]
fn fstatat_mode(dir: &std::os::fd::OwnedFd, name: &std::ffi::OsStr) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name_c.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat.st_mode as u32)
}

/// Open the home directory by path for re-verification: walk from `/`,
/// following ancestors (a legitimate symlink ancestor like `/var` is fine)
/// and refusing to follow a symlink at the leaf (`ELOOP`/`ENOTDIR` retry
/// resolves it, then the caller compares identity).
#[cfg(unix)]
fn open_dir_by_path(home: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut dir = open_base_dir(home)?;
    for name in path_components(home) {
        dir = match openat_dir(&dir, &name, true) {
            Ok(fd) => fd,
            Err(err) if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                openat_dir(&dir, &name, false)?
            }
            Err(err) => return Err(err),
        };
    }
    Ok(dir)
}

#[cfg(unix)]
fn open_base_dir(home: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let path = if home.is_absolute() { c"/" } else { c"." };
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
fn openat_dir(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    nofollow: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
fn mkdirat(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    mode: libc::mode_t,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })?;
    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn fchmod_0700(dir: &std::os::fd::OwnedFd) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let rc = unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn fd_real_path(dir: &std::os::fd::OwnedFd) -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buf: Vec<libc::c_char> = vec![0; libc::PATH_MAX as usize];
    let rc = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
    Some(PathBuf::from(OsStr::from_bytes(cstr.to_bytes())))
}

#[cfg(target_os = "linux")]
fn fd_real_path(dir: &std::os::fd::OwnedFd) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd())).ok()
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn fd_real_path(_dir: &std::os::fd::OwnedFd) -> Option<PathBuf> {
    None
}

/// Route a write at `path` through the verified home gateway when the path
/// lives under the current Auxesis home; `None` when it does not (the caller
/// falls back to its legacy path-based behaviour). J-02 round 4: this lets
/// legacy private-file helpers (voice, WhatsApp) keep their API while the
/// home-derived path is resolved by the verified fd.
pub fn sandbox_write_path(path: &Path, data: &[u8], mode: u32) -> Option<std::io::Result<()>> {
    let home = auxesis_home();
    let rel = path.strip_prefix(&home).ok()?;
    let handle = match SandboxHome::open(&home) {
        Ok(handle) => handle,
        Err(err) => return Some(Err(err)),
    };
    Some(handle.write_atomic(rel, data, mode))
}

/// Like [`sandbox_write_path`] but `create_new` semantics (`Ok(false)` when
/// the target exists).
pub fn sandbox_write_new_path(
    path: &Path,
    data: &[u8],
    mode: u32,
) -> Option<std::io::Result<bool>> {
    let home = auxesis_home();
    let rel = path.strip_prefix(&home).ok()?;
    let handle = match SandboxHome::open(&home) {
        Ok(handle) => handle,
        Err(err) => return Some(Err(err)),
    };
    Some(handle.write_new(rel, data, mode))
}

/// Route a delete at `path` through the verified home gateway when the path
/// lives under the current Auxesis home; `Ok(false)` when it does not exist.
pub fn sandbox_remove_path(path: &Path) -> Option<std::io::Result<bool>> {
    let home = auxesis_home();
    let rel = path.strip_prefix(&home).ok()?;
    let handle = match SandboxHome::open_existing(&home) {
        Ok(handle) => handle,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Some(Ok(false)),
        Err(err) => return Some(Err(err)),
    };
    Some(handle.remove_file(rel))
}

/// Path of the main configuration file.
pub fn config_path(home: &Path) -> PathBuf {
    home.join("config.toml")
}

/// Path of the SQLite store.
pub fn store_path(home: &Path) -> PathBuf {
    home.join("store.db")
}

/// Path of the log directory.
pub fn log_dir(home: &Path) -> PathBuf {
    home.join("logs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Environment variables are process-global: serialize the tests that touch them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn env_override_wins() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom-auxesis");
        std::env::set_var("AUXESIS_HOME", &custom);
        assert_eq!(auxesis_home(), custom);
        std::env::remove_var("AUXESIS_HOME");
    }

    #[test]
    fn env_override_is_trimmed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let trimmed = dir.path().join("trimmed-auxesis");
        std::env::set_var("AUXESIS_HOME", format!("  {}  ", trimmed.display()));
        assert_eq!(auxesis_home(), trimmed);
        std::env::remove_var("AUXESIS_HOME");
    }

    #[test]
    fn blank_override_falls_back_to_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous = std::env::var("HOME").ok();
        std::env::set_var("AUXESIS_HOME", "   ");
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(auxesis_home(), PathBuf::from("/home/tester/.auxesis"));
        std::env::remove_var("AUXESIS_HOME");
        restore_home(previous);
    }

    #[test]
    fn paths_live_under_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        assert_eq!(config_path(&home), home.join("config.toml"));
        assert_eq!(store_path(&home), home.join("store.db"));
        assert_eq!(log_dir(&home), home.join("logs"));
    }

    // --- H-03/J-02: the sandbox guard -------------------------------------

    /// Back to `$HOME` after an env-mutating test.
    fn restore_home(previous: Option<String>) {
        match previous {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
    }

    /// The pure half of the guard for one explicit context.
    fn check_sandbox_home(
        home: &Path,
        real_home: &Path,
        env_home: Option<&Path>,
        sandbox: bool,
    ) -> Result<(), String> {
        let ctx = SandboxContext::new(
            Some(real_home.to_path_buf()),
            env_home.map(Path::to_path_buf),
            sandbox,
        );
        ctx.refuse_home(home)
    }

    /// A context for the `ensure_home` tests: active unless explicitly
    /// inactive with `HOME == real home`.
    fn home_ctx(real_home: &Path, active: bool) -> SandboxContext {
        let env = if active {
            None
        } else {
            Some(real_home.to_path_buf())
        };
        SandboxContext::new(Some(real_home.to_path_buf()), env, active)
    }

    /// The combinations of (sandbox flag, real vs overridden `$HOME`) crossed
    /// with (real vs sandbox Auxesis home), plus the incident mode.
    #[test]
    fn sandbox_guard_covers_the_combinations() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let real_aux = real_home.join(DEFAULT_DIR_NAME);
        std::fs::create_dir_all(real_aux.join("nested")).unwrap();
        let sandbox_home = dir.path().join("sandbox-home");
        let sandbox_aux = sandbox_home.join(DEFAULT_DIR_NAME);
        std::fs::create_dir_all(&sandbox_aux).unwrap();

        let cases: &[(bool, Option<&Path>, &Path, bool, &str)] = &[
            (
                true,
                Some(&real_home),
                &real_aux,
                true,
                "sandbox flag + real HOME",
            ),
            (
                true,
                Some(&sandbox_home),
                &sandbox_aux,
                false,
                "recommended command",
            ),
            (
                true,
                Some(&sandbox_home),
                &real_aux,
                true,
                "incident: HOME overridden, home real",
            ),
            (false, Some(&real_home), &real_aux, false, "production"),
            (
                false,
                Some(&sandbox_home),
                &real_aux,
                true,
                "HOME override alone",
            ),
            (
                false,
                Some(&sandbox_home),
                &sandbox_aux,
                false,
                "sandbox home, no flag",
            ),
            // Item 2: empty and relative `$HOME` are violations too.
            (false, Some(Path::new("")), &real_aux, true, "empty HOME"),
            (
                false,
                Some(Path::new("relative/home")),
                &real_aux,
                true,
                "relative HOME",
            ),
            (false, None, &real_aux, true, "unset HOME"),
        ];
        for (sandbox, env_home, home, refused, label) in cases {
            let outcome = check_sandbox_home(home, &real_home, *env_home, *sandbox);
            assert_eq!(outcome.is_err(), *refused, "case {label}: {outcome:?}");
            if *refused {
                assert!(outcome.unwrap_err().contains("refus de sandbox"));
            }
        }

        // "Or under" the real home, not just equal to it.
        assert!(check_sandbox_home(
            &real_aux.join("nested"),
            &real_home,
            Some(&sandbox_home),
            true
        )
        .is_err());
    }

    /// Item (e): `AUXESIS_HOME` equal to the real home root is refused.
    #[test]
    fn sandbox_guard_refuses_the_real_home_root() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let sandbox_home = dir.path().join("sandbox-home");
        let err =
            check_sandbox_home(&real_home, &real_home, Some(&sandbox_home), true).unwrap_err();
        assert!(err.contains("foyer réel"), "{err}");
    }

    /// Item (a): identity defeats a firmlink spelling of the real `.auxesis`
    /// (`/System/Volumes/Data/…` on macOS) even though no symlink is
    /// involved and the textual path is different.
    #[test]
    #[cfg(target_os = "macos")]
    fn sandbox_guard_refuses_a_firmlink_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let real_aux = real_home.join(DEFAULT_DIR_NAME);
        std::fs::create_dir_all(&real_aux).unwrap();
        let sandbox_home = dir.path().join("sandbox-home");
        let canonical = std::fs::canonicalize(&real_aux).unwrap();
        let firmlink = PathBuf::from("/System/Volumes/Data").join(
            canonical
                .strip_prefix("/")
                .expect("canonical path is absolute"),
        );
        assert!(
            std::fs::metadata(&firmlink).is_ok(),
            "the firmlink spelling must resolve: {}",
            firmlink.display()
        );
        assert!(
            check_sandbox_home(&firmlink, &real_home, Some(&sandbox_home), true).is_err(),
            "the firmlink spelling must be refused"
        );
        // …and the same spelling must not be usable as AUXESIS_HOME.
        assert!(check_sandbox_home(
            &firmlink.join("future"),
            &real_home,
            Some(&sandbox_home),
            true
        )
        .is_err());
    }

    /// Item (a): case- and normalisation-insensitive variants of the real
    /// `.auxesis` (APFS/HFS+) must be refused.
    #[test]
    fn sandbox_guard_refuses_case_and_normalisation_variants() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox_home = dir.path().join("sandbox-home");

        // The real `.auxesis` may not exist yet (e.g. on CI): the tail must
        // still compare case-insensitively.
        let absent_real = dir.path().join("absent-real");
        std::fs::create_dir_all(&absent_real).unwrap();
        assert!(
            check_sandbox_home(
                &absent_real.join(".AUXESIS"),
                &absent_real,
                Some(&sandbox_home),
                true
            )
            .is_err(),
            ".AUXESIS must be refused even when the real home does not exist"
        );

        // An NFD/NFC pair must compare equal. Rust source strings are NFC
        // ("é" = U+00E9); the decomposed spelling is "e" + U+0301. The home
        // does not exist, so the comparison itself has to normalise.
        let composed = dir.path().join("Caf\u{00e9}");
        let decomposed = dir.path().join("Cafe\u{0301}");
        assert!(
            check_sandbox_home(
                &decomposed.join(DEFAULT_DIR_NAME),
                &composed,
                Some(&sandbox_home),
                true
            )
            .is_err(),
            "NFC/NFD variants must compare equal"
        );
        assert!(
            check_sandbox_home(
                &composed.join(DEFAULT_DIR_NAME),
                &decomposed,
                Some(&sandbox_home),
                true
            )
            .is_err(),
            "NFC/NFD variants must compare equal (other direction)"
        );

        // When it exists, identity resolves the spelling as well.
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(real_home.join(DEFAULT_DIR_NAME)).unwrap();
        assert!(
            check_sandbox_home(
                &real_home.join(".AUXESIS"),
                &real_home,
                Some(&sandbox_home),
                true
            )
            .is_err(),
            ".AUXESIS must be refused when the real home exists"
        );
    }

    /// Item 2: a missing `AUXESIS_HOME` with an unusable `$HOME` must never
    /// fall back to the CWD or the real home.
    #[test]
    fn sandbox_guard_refuses_a_missing_home_without_a_usable_home_env() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        for env_home in [None, Some(Path::new("")), Some(Path::new("relative"))] {
            let ctx = SandboxContext::new(
                Some(real_home.clone()),
                env_home.map(Path::to_path_buf),
                false,
            );
            assert!(ctx.active, "invalid HOME must arm the guard: {env_home:?}");
            let err = ctx.resolve_home_from(None).unwrap_err();
            assert!(err.contains("refus de sandbox"), "{err}");
        }
        // A valid HOME still resolves the documented fallback.
        let ctx = SandboxContext::new(Some(real_home.clone()), Some(real_home.clone()), false);
        assert_eq!(
            ctx.resolve_home_from(None).unwrap(),
            real_home.join(DEFAULT_DIR_NAME)
        );
    }

    /// A relative `AUXESIS_HOME` is refused while the guard is active.
    #[test]
    fn sandbox_guard_refuses_a_relative_auxesis_home() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let sandbox_home = dir.path().join("sandbox-home");
        let ctx = SandboxContext::new(Some(real_home.clone()), Some(sandbox_home.clone()), true);
        assert!(ctx.resolve_home_from(Some("./.auxesis")).is_err());
        // Production (HOME == real home, no flag) keeps the historical
        // tolerance.
        let ctx = SandboxContext::new(Some(real_home.clone()), Some(real_home), false);
        assert!(ctx.resolve_home_from(Some("./.auxesis")).is_ok());
    }

    /// Symlinked spellings, including ancestors of a home not created yet.
    #[test]
    #[cfg(unix)]
    fn sandbox_guard_refuses_symlinked_spellings() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let real_aux = real_home.join(DEFAULT_DIR_NAME);
        std::fs::create_dir_all(real_aux.join("nested")).unwrap();
        let sandbox_home = dir.path().join("sandbox-home");
        std::fs::create_dir_all(&sandbox_home).unwrap();

        // A symlink straight to the real Auxesis home.
        let alias = sandbox_home.join("alias");
        std::os::unix::fs::symlink(&real_aux, &alias).unwrap();
        assert!(check_sandbox_home(&alias, &real_home, Some(&sandbox_home), true).is_err());
        // … even when the leaf does not exist yet (the ancestor is resolved).
        assert!(check_sandbox_home(
            &alias.join("nested").join("future"),
            &real_home,
            Some(&sandbox_home),
            true
        )
        .is_err());
        // A symlinked spelling of the real home itself.
        let home_alias = sandbox_home.join("home-alias");
        std::os::unix::fs::symlink(&real_home, &home_alias).unwrap();
        assert!(check_sandbox_home(
            &home_alias.join(DEFAULT_DIR_NAME),
            &real_home,
            Some(&sandbox_home),
            true
        )
        .is_err());
        // A shared *string* prefix is not a shared path prefix.
        assert!(check_sandbox_home(
            &real_home.join(".auxesis-evil"),
            &real_home,
            Some(&sandbox_home),
            true
        )
        .is_ok());
        // A symlink that leaves the real tree stays allowed.
        let away = sandbox_home.join("away");
        std::os::unix::fs::symlink(&sandbox_home, &away).unwrap();
        assert!(check_sandbox_home(
            &away.join(DEFAULT_DIR_NAME),
            &real_home,
            Some(&sandbox_home),
            true
        )
        .is_ok());

        // A *dangling* symlink to the real home (the real `.auxesis` may not
        // exist yet, e.g. on CI) is still refused, leaf included.
        let absent_real = dir.path().join("absent-real");
        std::fs::create_dir_all(&absent_real).unwrap();
        let dangling = sandbox_home.join("dangling");
        std::os::unix::fs::symlink(absent_real.join(DEFAULT_DIR_NAME), &dangling).unwrap();
        assert!(check_sandbox_home(&dangling, &absent_real, Some(&sandbox_home), true).is_err());
        assert!(check_sandbox_home(
            &dangling.join("future"),
            &absent_real,
            Some(&sandbox_home),
            true
        )
        .is_err());
    }

    /// The OS user database, not `$HOME`, decides what "real" means.
    #[test]
    #[cfg(unix)]
    fn real_user_home_ignores_a_sandboxed_home_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let Some(from_db) = real_user_home() else {
            return;
        };
        let previous_home = std::env::var("HOME").ok();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        assert_eq!(real_user_home(), Some(from_db));
        restore_home(previous_home);
    }

    /// J02-2-BI2-03: a failed passwd lookup fails closed while the guard is
    /// active, whatever `$HOME` says.
    #[test]
    fn guard_fails_closed_when_the_passwd_lookup_fails() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sandbox_home = dir.path().join("sandbox-home");
        let previous_home = std::env::var("HOME").ok();
        let previous_aux = std::env::var("AUXESIS_HOME").ok();
        let previous_forced = FORCED_REAL_HOME.with(|slot| slot.borrow().clone());

        FORCED_REAL_HOME.with(|slot| *slot.borrow_mut() = Some(None));
        std::env::set_var(SANDBOX_ENV, "1");
        std::env::set_var("HOME", dir.path());
        std::env::set_var("AUXESIS_HOME", &sandbox_home);
        let err = ensure_sandbox_guard(Some(0)).unwrap_err();
        assert!(
            err.contains("introuvable") || err.contains("lookup"),
            "{err}"
        );

        // Restore everything before asserting the happy path.
        std::env::remove_var(SANDBOX_ENV);
        FORCED_REAL_HOME.with(|slot| *slot.borrow_mut() = previous_forced);
        match previous_aux {
            Some(value) => std::env::set_var("AUXESIS_HOME", value),
            None => std::env::remove_var("AUXESIS_HOME"),
        }
        restore_home(previous_home);
    }

    /// End-to-end guard: the incident's own spelling is refused, the
    /// recommended literal invocation is accepted.
    #[test]
    fn guard_refuses_the_incident_and_allows_the_recommended() {
        let _guard = ENV_LOCK.lock().unwrap();
        let Some(os_home) =
            real_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let previous_home = std::env::var("HOME").ok();
        let previous_aux = std::env::var("AUXESIS_HOME").ok();
        std::env::set_var("HOME", dir.path());
        std::env::set_var(SANDBOX_ENV, "1");

        // The incident: HOME=<tmp> but AUXESIS_HOME expanded to the real home.
        std::env::set_var("AUXESIS_HOME", os_home.join(DEFAULT_DIR_NAME));
        let refused = ensure_sandbox_guard(Some(0)).unwrap_err();
        assert!(refused.contains("refus de sandbox"), "{refused}");
        // Its own recommendation must work now.
        let sandbox = dir.path().join(DEFAULT_DIR_NAME);
        std::fs::create_dir_all(&sandbox).unwrap();
        std::env::set_var("AUXESIS_HOME", &sandbox);
        // The guard exports the canonical path (macOS temp dirs are behind
        // /private/var).
        let exported = ensure_sandbox_guard(Some(0)).unwrap();
        assert_eq!(exported, std::fs::canonicalize(&sandbox).unwrap());
        // …but the real daemon port stays refused while the guard is active.
        let port_refused = ensure_sandbox_guard(Some(REAL_DAEMON_PORT)).unwrap_err();
        assert!(port_refused.contains("2893"), "{port_refused}");

        std::env::remove_var(SANDBOX_ENV);
        match previous_aux {
            Some(value) => std::env::set_var("AUXESIS_HOME", value),
            None => std::env::remove_var("AUXESIS_HOME"),
        }
        restore_home(previous_home);
    }

    /// An overridden `HOME` alone activates the guard; `AUXESIS_SANDBOX`
    /// values other than `1` do not.
    #[test]
    fn guard_activates_on_home_override_and_only_literal_one() {
        let _guard = ENV_LOCK.lock().unwrap();
        let Some(os_home) =
            real_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let previous_home = std::env::var("HOME").ok();
        let real_aux = os_home.join(DEFAULT_DIR_NAME);

        std::env::remove_var(SANDBOX_ENV);
        std::env::set_var("HOME", dir.path());
        assert!(ensure_sandbox_home(&real_aux).is_err());
        std::env::set_var(SANDBOX_ENV, "0");
        assert!(ensure_sandbox_home(&real_aux).is_err());

        // Inert only when neither signal is present.
        restore_home(Some(os_home.to_string_lossy().into_owned()));
        assert!(ensure_sandbox_home(&real_aux).is_ok());

        std::env::remove_var(SANDBOX_ENV);
        restore_home(previous_home);
    }

    /// Item 5: the port guard follows the guard's active condition, not just
    /// the flag, and only refuses the real daemon port.
    #[test]
    fn sandbox_port_guard_refuses_2893() {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous_flag = std::env::var(SANDBOX_ENV).ok();
        let previous_home = std::env::var("HOME").ok();
        let Some(os_home) =
            real_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();

        std::env::set_var(SANDBOX_ENV, "1");
        let refused = ensure_sandbox_port(REAL_DAEMON_PORT).unwrap_err();
        assert!(refused.contains("refus de sandbox"), "{refused}");
        assert!(refused.contains("2893"), "{refused}");
        assert!(ensure_sandbox_port(0).is_ok());
        assert!(ensure_sandbox_port(2894).is_ok());

        // A HOME override alone arms the port guard too (no flag).
        std::env::remove_var(SANDBOX_ENV);
        std::env::set_var("HOME", dir.path());
        assert!(ensure_sandbox_port(REAL_DAEMON_PORT).is_err());
        assert!(ensure_sandbox_port(0).is_ok());

        // Inert in production.
        restore_home(Some(os_home.to_string_lossy().into_owned()));
        assert!(ensure_sandbox_port(REAL_DAEMON_PORT).is_ok());
        std::env::set_var(SANDBOX_ENV, "0");
        assert!(ensure_sandbox_port(REAL_DAEMON_PORT).is_ok());

        match previous_flag {
            Some(value) => std::env::set_var(SANDBOX_ENV, value),
            None => std::env::remove_var(SANDBOX_ENV),
        }
        restore_home(previous_home);
    }

    // --- Item 4: ensure_home / the write gateway --------------------------

    #[test]
    #[cfg(unix)]
    fn ensure_home_refuses_a_symlink_into_the_real_auxesis() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let real_aux = real_home.join(DEFAULT_DIR_NAME);
        std::fs::create_dir_all(&real_aux).unwrap();
        let sandbox_home = dir.path().join("sandbox-home");
        std::fs::create_dir_all(&sandbox_home).unwrap();
        let link = sandbox_home.join("home-link");
        std::os::unix::fs::symlink(&real_aux, &link).unwrap();

        let active = home_ctx(&real_home, true);
        let err = SandboxHome::open_with(&link, &active).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("refus de sandbox"), "{err}");

        // The same link is fine when the guard is not active.
        let inactive = home_ctx(&real_home, false);
        SandboxHome::open_with(&link, &inactive).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn ensure_home_refuses_a_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("absent"), &link).unwrap();
        let ctx = home_ctx(dir.path(), true);
        let err = SandboxHome::open_with(&link, &ctx).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(
            !dir.path().join("absent").exists(),
            "no target may be created"
        );
    }

    #[test]
    #[cfg(unix)]
    fn ensure_home_allows_a_symlink_outside_the_real_home() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let real_aux = real_home.join(DEFAULT_DIR_NAME);
        std::fs::create_dir_all(&real_aux).unwrap();
        let target = dir.path().join("sandbox-target");
        std::fs::create_dir_all(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        SandboxHome::open_with(&link, &home_ctx(&real_home, true)).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn ensure_home_creates_the_directory_with_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("nested").join("home");
        SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        let mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "new homes are private");
        // Idempotent.
        SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
    }

    // --- FLAKY-03: the startup scan must tolerate a racing ENOENT ----------

    /// Simulates SQLite unlinking `store.db-wal` between the scan's `readdir`
    /// and its `fstatat`: the hook unlinks the real entry through the same
    /// directory fd, so the following `fstatat` observes a genuine ENOENT.
    #[cfg(unix)]
    struct VanishingScanFs {
        victim: std::ffi::OsString,
    }

    #[cfg(unix)]
    impl StartupScanFs for VanishingScanFs {
        fn read_dir_names(
            &self,
            dir: &std::os::fd::OwnedFd,
        ) -> std::io::Result<Vec<std::ffi::OsString>> {
            RealStartupScanFs.read_dir_names(dir)
        }

        fn fstatat_mode(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
        ) -> std::io::Result<u32> {
            if name == self.victim {
                use std::os::fd::AsRawFd;
                use std::os::unix::ffi::OsStrExt;
                let c = std::ffi::CString::new(name.as_bytes()).unwrap();
                let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) };
                assert_eq!(rc, 0, "hook could not unlink {}", name.to_string_lossy());
            }
            fstatat_mode(dir, name)
        }

        fn open_child_dir(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
            nofollow: bool,
        ) -> std::io::Result<std::os::fd::OwnedFd> {
            openat_dir(dir, name, nofollow)
        }
    }

    /// Test scanner that fails every `fstatat` with a chosen errno.
    #[cfg(unix)]
    struct FailingScanFs {
        errno: i32,
    }

    #[cfg(unix)]
    impl StartupScanFs for FailingScanFs {
        fn read_dir_names(
            &self,
            dir: &std::os::fd::OwnedFd,
        ) -> std::io::Result<Vec<std::ffi::OsString>> {
            RealStartupScanFs.read_dir_names(dir)
        }

        fn fstatat_mode(
            &self,
            _dir: &std::os::fd::OwnedFd,
            _name: &std::ffi::OsStr,
        ) -> std::io::Result<u32> {
            Err(std::io::Error::from_raw_os_error(self.errno))
        }

        fn open_child_dir(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
            nofollow: bool,
        ) -> std::io::Result<std::os::fd::OwnedFd> {
            openat_dir(dir, name, nofollow)
        }
    }

    /// Injected `openat` seam: at the child open, the victim directory is
    /// removed and replaced with a symlink to `target` — the exact swap
    /// window between `fstatat` and `openat(O_NOFOLLOW)`. The hook then calls
    /// the real open and proves it returns ELOOP (Linux) or ENOTDIR (macOS).
    #[cfg(unix)]
    struct SwappedForSymlinkScanFs {
        victim: std::ffi::OsString,
        target: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl StartupScanFs for SwappedForSymlinkScanFs {
        fn read_dir_names(
            &self,
            dir: &std::os::fd::OwnedFd,
        ) -> std::io::Result<Vec<std::ffi::OsString>> {
            RealStartupScanFs.read_dir_names(dir)
        }

        fn fstatat_mode(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
        ) -> std::io::Result<u32> {
            fstatat_mode(dir, name)
        }

        fn open_child_dir(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
            nofollow: bool,
        ) -> std::io::Result<std::os::fd::OwnedFd> {
            if name == self.victim {
                use std::os::fd::AsRawFd;
                use std::os::unix::ffi::OsStrExt;
                let c = std::ffi::CString::new(name.as_bytes()).unwrap();
                let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
                assert_eq!(rc, 0, "hook could not rmdir {}", name.to_string_lossy());
                let target = std::ffi::CString::new(self.target.as_os_str().as_bytes()).unwrap();
                let rc = unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), c.as_ptr()) };
                assert_eq!(rc, 0, "hook could not symlinkat {}", name.to_string_lossy());
            }
            let result = openat_dir(dir, name, nofollow);
            if name == self.victim {
                let errno = result.as_ref().err().and_then(|e| e.raw_os_error());
                assert!(
                    matches!(errno, Some(libc::ELOOP) | Some(libc::ENOTDIR)),
                    "the swap must make the nofollow open fail with ELOOP/ENOTDIR, got {errno:?}"
                );
            }
            result
        }
    }

    /// Injected `openat` seam: at the child open, the victim directory is
    /// removed so the real `openat` observes a genuine ENOENT.
    #[cfg(unix)]
    struct VanishingDirScanFs {
        victim: std::ffi::OsString,
    }

    #[cfg(unix)]
    impl StartupScanFs for VanishingDirScanFs {
        fn read_dir_names(
            &self,
            dir: &std::os::fd::OwnedFd,
        ) -> std::io::Result<Vec<std::ffi::OsString>> {
            RealStartupScanFs.read_dir_names(dir)
        }

        fn fstatat_mode(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
        ) -> std::io::Result<u32> {
            fstatat_mode(dir, name)
        }

        fn open_child_dir(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
            nofollow: bool,
        ) -> std::io::Result<std::os::fd::OwnedFd> {
            if name == self.victim {
                use std::os::fd::AsRawFd;
                use std::os::unix::ffi::OsStrExt;
                let c = std::ffi::CString::new(name.as_bytes()).unwrap();
                let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
                assert_eq!(rc, 0, "hook could not rmdir {}", name.to_string_lossy());
            }
            openat_dir(dir, name, nofollow)
        }
    }

    /// Injected `openat` seam: the victim child open fails with a chosen errno.
    #[cfg(unix)]
    struct DeniedOpenScanFs {
        victim: std::ffi::OsString,
        errno: i32,
    }

    #[cfg(unix)]
    impl StartupScanFs for DeniedOpenScanFs {
        fn read_dir_names(
            &self,
            dir: &std::os::fd::OwnedFd,
        ) -> std::io::Result<Vec<std::ffi::OsString>> {
            RealStartupScanFs.read_dir_names(dir)
        }

        fn fstatat_mode(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
        ) -> std::io::Result<u32> {
            fstatat_mode(dir, name)
        }

        fn open_child_dir(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
            nofollow: bool,
        ) -> std::io::Result<std::os::fd::OwnedFd> {
            if name == self.victim {
                return Err(std::io::Error::from_raw_os_error(self.errno));
            }
            openat_dir(dir, name, nofollow)
        }
    }

    /// Records the entry names returned by every `read_dir_names` call so a
    /// test can prove two consecutive scans of the same directory fd see the
    /// same full entry set (the fresh-`.`-open vs `dup` offset guard).
    #[cfg(unix)]
    struct RecordingScanFs {
        seen: Mutex<Vec<Vec<std::ffi::OsString>>>,
    }

    #[cfg(unix)]
    impl StartupScanFs for RecordingScanFs {
        fn read_dir_names(
            &self,
            dir: &std::os::fd::OwnedFd,
        ) -> std::io::Result<Vec<std::ffi::OsString>> {
            let names = RealStartupScanFs.read_dir_names(dir)?;
            self.seen.lock().unwrap().push(names.clone());
            Ok(names)
        }

        fn fstatat_mode(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
        ) -> std::io::Result<u32> {
            fstatat_mode(dir, name)
        }

        fn open_child_dir(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
            nofollow: bool,
        ) -> std::io::Result<std::os::fd::OwnedFd> {
            openat_dir(dir, name, nofollow)
        }
    }

    /// Scripted `readdir` step for [`ScriptedDirFs`].
    #[cfg(unix)]
    #[derive(Clone, Copy)]
    enum ScriptStep {
        /// A successful `readdir`; it leaves the configured stale errno behind
        /// (POSIX allows a successful call to change errno).
        Entry(&'static str),
        /// A NULL `readdir` that leaves errno as-is: a clean end-of-directory.
        End,
        /// A NULL `readdir` that sets errno: a mid-listing I/O error.
        Error(libc::c_int),
    }

    /// Injected `readdir` seam: yields a scripted sequence of entries and then
    /// either a clean end or a chosen OS error, and models a sticky errno so a
    /// loop that fails to clear it per call observes a false error. Also counts
    /// open/close so a double close (or a missed close) is visible.
    #[cfg(unix)]
    struct ScriptedDirFs {
        script: Vec<ScriptStep>,
        index: std::sync::atomic::AtomicUsize,
        stale_errno: libc::c_int,
        errno: std::sync::atomic::AtomicI32,
        opens: std::sync::atomic::AtomicUsize,
        closes: std::sync::atomic::AtomicUsize,
        live: std::sync::atomic::AtomicI32,
        double_close: std::sync::atomic::AtomicBool,
        fail_open_with: Option<libc::c_int>,
    }

    #[cfg(unix)]
    impl ScriptedDirFs {
        fn new(script: Vec<ScriptStep>, stale_errno: libc::c_int) -> Self {
            Self {
                script,
                index: std::sync::atomic::AtomicUsize::new(0),
                stale_errno,
                errno: std::sync::atomic::AtomicI32::new(0),
                opens: std::sync::atomic::AtomicUsize::new(0),
                closes: std::sync::atomic::AtomicUsize::new(0),
                live: std::sync::atomic::AtomicI32::new(0),
                double_close: std::sync::atomic::AtomicBool::new(false),
                fail_open_with: None,
            }
        }

        fn fail_open_with(cursor_errno: libc::c_int) -> Self {
            let mut fs = Self::new(vec![ScriptStep::End], 0);
            fs.fail_open_with = Some(cursor_errno);
            fs
        }
    }

    #[cfg(unix)]
    impl DirReadFs for ScriptedDirFs {
        type Cursor = ();

        fn open(&self, _dir: &std::os::fd::OwnedFd) -> std::io::Result<()> {
            use std::sync::atomic::Ordering;
            self.opens.fetch_add(1, Ordering::SeqCst);
            if let Some(errno) = self.fail_open_with {
                // Like `RealDirReadFs::open`: a failed open cleans up its own
                // fd, so the caller must not close anything.
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            self.index.store(0, Ordering::SeqCst);
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn clear_errno(&self) {
            self.errno.store(0, std::sync::atomic::Ordering::SeqCst);
        }

        fn readdir(&self, _cursor: &()) -> Option<std::ffi::OsString> {
            use std::sync::atomic::Ordering;
            let step = *self.script.get(self.index.fetch_add(1, Ordering::SeqCst))?;
            match step {
                ScriptStep::Entry(name) => {
                    self.errno.store(self.stale_errno, Ordering::SeqCst);
                    Some(std::ffi::OsString::from(name))
                }
                ScriptStep::End => None,
                ScriptStep::Error(errno) => {
                    self.errno.store(errno, Ordering::SeqCst);
                    None
                }
            }
        }

        fn errno(&self) -> libc::c_int {
            self.errno.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn close(&self, _cursor: ()) {
            use std::sync::atomic::Ordering;
            self.closes.fetch_add(1, Ordering::SeqCst);
            if self.live.fetch_sub(1, Ordering::SeqCst) <= 0 {
                self.double_close.store(true, Ordering::SeqCst);
            }
        }
    }

    /// A `StartupScanFs` whose `read_dir_names` runs the real collection loop
    /// over a scripted `DirReadFs`, so the whole scan path sees the injected
    /// `readdir` fault. `fstatat`/`open_child_dir` stay real and are never
    /// reached before the listing error.
    #[cfg(unix)]
    struct ScriptedScanFs {
        dir_fs: ScriptedDirFs,
    }

    #[cfg(unix)]
    impl StartupScanFs for ScriptedScanFs {
        fn read_dir_names(
            &self,
            dir: &std::os::fd::OwnedFd,
        ) -> std::io::Result<Vec<std::ffi::OsString>> {
            read_dir_names_with(&self.dir_fs, dir)
        }

        fn fstatat_mode(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
        ) -> std::io::Result<u32> {
            fstatat_mode(dir, name)
        }

        fn open_child_dir(
            &self,
            dir: &std::os::fd::OwnedFd,
            name: &std::ffi::OsStr,
            nofollow: bool,
        ) -> std::io::Result<std::os::fd::OwnedFd> {
            openat_dir(dir, name, nofollow)
        }
    }

    /// (a) An entry that vanished between `readdir` and `fstatat` (ENOENT) is
    /// skipped, not fatal: the FLAKY-03 SQLite WAL/SHM race.
    #[test]
    #[cfg(unix)]
    fn startup_scan_skips_an_entry_that_vanishes_between_readdir_and_fstatat() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let sidecar = home.join("store.db-wal");
        std::fs::write(&sidecar, b"wal").unwrap();

        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        let fs = VanishingScanFs {
            victim: std::ffi::OsString::from("store.db-wal"),
        };
        reject_symlinks_at_start_with(&handle.dir, 4, &["STOP", "api.token"], &fs).unwrap();
        assert!(!sidecar.exists(), "the hook removed the racing entry");
    }

    /// (b) A symlink in the home (at the root or nested inside the scanned
    /// depth) still rejects startup exactly as before.
    #[test]
    #[cfg(unix)]
    fn startup_scan_still_refuses_a_symlink_inside_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink(&outside, home.join("whatsapp")).unwrap();
        let err = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("refus de sandbox"), "{err}");

        // Depth 4 covers agents/<agent>/workspace; recursion must still refuse.
        let nested_home = dir.path().join("nested-home");
        let deep = nested_home.join("agents").join("agent").join("workspace");
        std::fs::create_dir_all(&deep).unwrap();
        std::os::unix::fs::symlink(&outside, deep.join("leak")).unwrap();
        let err = SandboxHome::open_with(&nested_home, &home_ctx(&real_home, true)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("refus de sandbox"), "{err}");
    }

    /// (c) Only ENOENT is tolerated: permission-denied or any other stat
    /// failure stays fatal.
    #[test]
    #[cfg(unix)]
    fn startup_scan_keeps_non_enoent_errors_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("store.db"), b"db").unwrap();
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

        let denied = FailingScanFs {
            errno: libc::EACCES,
        };
        let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &denied).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));

        let io = FailingScanFs { errno: libc::EIO };
        let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &io).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
    }

    /// (d) Real churn: one thread repeatedly creates/removes the SQLite
    /// sidecars while the scan runs 2000 times; zero failures.
    #[test]
    #[cfg(unix)]
    fn startup_scan_survives_store_sidecar_churn() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let churn = {
            let wal = home.join("store.db-wal");
            let shm = home.join("store.db-shm");
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::fs::write(&wal, b"wal");
                    let _ = std::fs::write(&shm, b"shm");
                    let _ = std::fs::remove_file(&wal);
                    let _ = std::fs::remove_file(&shm);
                }
            })
        };

        for _ in 0..2000 {
            reject_symlinks_at_start(&handle.dir, 4, &["STOP", "api.token"]).unwrap();
        }

        stop.store(true, Ordering::Relaxed);
        churn.join().unwrap();
    }

    /// (e) security review P2: a child directory that `fstatat` saw as a directory but
    /// that was replaced by a symlink before `openat(O_NOFOLLOW)` must make
    /// the scan fail (ELOOP on Linux / ENOTDIR on macOS), never be swallowed.
    #[test]
    #[cfg(unix)]
    fn startup_scan_fails_when_a_child_directory_becomes_a_symlink_before_open() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("agents")).unwrap();
        std::fs::write(home.join("store.db"), b"db").unwrap();

        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        let fs = SwappedForSymlinkScanFs {
            victim: std::ffi::OsString::from("agents"),
            target: outside.clone(),
        };
        let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("refus de sandbox"), "{err}");
        assert!(err.to_string().contains("agents"), "{err}");
    }

    /// (f) A directory that vanishes between `fstatat` and `openat` (ENOENT)
    /// is skipped exactly like a vanished file: it cannot be the symlink we
    /// refuse, and nothing was opened.
    #[test]
    #[cfg(unix)]
    fn startup_scan_skips_a_directory_that_vanishes_between_fstatat_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        let victim = home.join("agents");
        std::fs::create_dir_all(&victim).unwrap();

        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        let fs = VanishingDirScanFs {
            victim: std::ffi::OsString::from("agents"),
        };
        reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();
        assert!(!victim.exists(), "the hook removed the racing directory");
    }

    /// (g) Any non-ENOENT child-open failure (EACCES here) is fatal, with the
    /// entry named in the refusal.
    #[test]
    #[cfg(unix)]
    fn startup_scan_keeps_a_denied_child_open_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("agents")).unwrap();

        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        let denied = DeniedOpenScanFs {
            victim: std::ffi::OsString::from("agents"),
            errno: libc::EACCES,
        };
        let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &denied).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("refus de sandbox"), "{err}");
        assert!(err.to_string().contains("agents"), "{err}");
    }

    /// (h) Deterministic guard for the fresh-`.`-open: two consecutive scans of
    /// the same directory fd must both see every entry. If the scan `dup`-ed
    /// the caller's fd, the second scan would inherit the drained offset and
    /// read nothing.
    #[test]
    #[cfg(unix)]
    fn startup_scan_sees_the_same_entries_on_two_consecutive_scans() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        for name in ["alpha", "beta", "gamma"] {
            std::fs::write(home.join(name), b"x").unwrap();
        }

        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        let fs = RecordingScanFs {
            seen: Mutex::new(Vec::new()),
        };
        reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();
        reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();

        let seen = fs.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "one read per scan on a leaf-only home");
        for names in seen.iter() {
            let mut got: Vec<String> = names
                .iter()
                .map(|n| n.to_string_lossy().into_owned())
                .collect();
            got.sort();
            assert_eq!(
                got,
                vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()],
                "every scan must see the full entry set"
            );
        }
    }

    /// (i) The FLAKY-03 rule holds deeper in the tree too: an entry at depth 2
    /// removed between `readdir` and `fstatat` is skipped, not fatal.
    #[test]
    #[cfg(unix)]
    fn startup_scan_tolerates_a_vanishing_entry_at_depth_two() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        let agent = home.join("agents").join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        let deep = agent.join("deep-wal");
        std::fs::write(&deep, b"wal").unwrap();

        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        let fs = VanishingScanFs {
            victim: std::ffi::OsString::from("deep-wal"),
        };
        reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap();
        assert!(!deep.exists(), "the depth-2 entry was removed mid-scan");
    }

    /// (j) security review P2: a `readdir` I/O error *after* an ordinary entry must NOT
    /// be reported as a clean (truncated) listing — the scan returns Err. On
    /// the unfixed head, NULL is treated as end-of-directory and the scan
    /// returns Ok with `["store.db"]`, never inspecting a later symlink.
    #[test]
    #[cfg(unix)]
    fn startup_scan_returns_err_when_readdir_fails_after_an_entry() {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("agents")).unwrap();
        std::fs::write(home.join("store.db"), b"db").unwrap();
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

        let fs = ScriptedScanFs {
            dir_fs: ScriptedDirFs::new(
                vec![ScriptStep::Entry("store.db"), ScriptStep::Error(libc::EIO)],
                0,
            ),
        };
        let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EIO),
            "the mid-listing I/O error must be fatal, not a truncated Ok: {err}"
        );
        assert_eq!(fs.dir_fs.opens.load(Ordering::SeqCst), 1);
        assert_eq!(fs.dir_fs.closes.load(Ordering::SeqCst), 1);
        assert_eq!(fs.dir_fs.live.load(Ordering::SeqCst), 0);
    }

    /// (k) security review P2: a `readdir` I/O error *before* the first entry is fatal
    /// too (Err, not an empty Ok listing).
    #[test]
    #[cfg(unix)]
    fn startup_scan_returns_err_when_readdir_fails_before_the_first_entry() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

        let fs = ScriptedScanFs {
            dir_fs: ScriptedDirFs::new(vec![ScriptStep::Error(libc::EIO)], 0),
        };
        let err = reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO), "{err}");
    }

    /// (l) Stale errno must never be a false error: errno is cleared before
    /// every `readdir`. A successful `readdir` leaves errno dirty and the
    /// clean end-of-directory does not touch it, so only per-call clearing
    /// keeps this listing Ok.
    #[test]
    #[cfg(unix)]
    fn startup_scan_clears_errno_before_every_readdir() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

        // The scripted entry poisons errno with EIO; the clean NULL after it
        // must still be recognised as end-of-directory.
        let fs = ScriptedScanFs {
            dir_fs: ScriptedDirFs::new(
                vec![ScriptStep::Entry("store.db"), ScriptStep::End],
                libc::EIO,
            ),
        };
        reject_symlinks_at_start_with(&handle.dir, 4, &[], &fs)
            .expect("a stale errno must not truncate or fail a clean listing");
    }

    /// (m) The real accessor path: errno set to EIO just before a genuine
    /// listing of a real directory must not make the clean end a false error.
    #[test]
    #[cfg(unix)]
    fn real_read_dir_names_ignores_a_stale_errno() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        for name in ["alpha", "beta", "gamma"] {
            std::fs::write(home.join(name), b"x").unwrap();
        }
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

        // SAFETY: the pointer is this thread's errno storage.
        unsafe { *errno_location() = libc::EIO };
        let mut names = read_dir_names(&handle.dir).expect("stale errno is not a listing error");
        names.sort();
        assert_eq!(
            names,
            vec![
                std::ffi::OsString::from("alpha"),
                std::ffi::OsString::from("beta"),
                std::ffi::OsString::from("gamma"),
            ]
        );
    }

    /// (n) fd ownership: `fdopendir`/`closedir` close the stream exactly once
    /// on the success and error paths, and an open failure never leaves a
    /// close to the caller (no double close, no leak).
    #[test]
    #[cfg(unix)]
    fn startup_scan_read_dir_closes_its_stream_exactly_once() {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();

        let assert_balanced = |fs: &ScriptedDirFs, opens: usize, closes: usize| {
            assert_eq!(fs.opens.load(Ordering::SeqCst), opens);
            assert_eq!(fs.closes.load(Ordering::SeqCst), closes);
            assert_eq!(fs.live.load(Ordering::SeqCst), 0, "no leaked/extra fd");
            assert!(
                !fs.double_close.load(Ordering::SeqCst),
                "the stream must never be closed twice"
            );
        };

        let clean = ScriptedDirFs::new(vec![ScriptStep::End], 0);
        read_dir_names_with(&clean, &handle.dir).unwrap();
        assert_balanced(&clean, 1, 1);

        let failing = ScriptedDirFs::new(vec![ScriptStep::Error(libc::EIO)], 0);
        assert!(read_dir_names_with(&failing, &handle.dir).is_err());
        assert_balanced(&failing, 1, 1);

        let denied = ScriptedDirFs::fail_open_with(libc::EACCES);
        let err = read_dir_names_with(&denied, &handle.dir).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
        assert_balanced(&denied, 1, 0);
    }

    /// J02-2-BI2-01 (security review P1): a symlink swapped *after* `ensure_home` must
    /// not redirect later writes — the handle holds the verified fd.
    #[test]
    #[cfg(unix)]
    fn write_gateway_survives_a_home_symlink_swap() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let first = dir.path().join("first-target");
        let second = dir.path().join("second-target");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let link = dir.path().join("home-link");
        std::os::unix::fs::symlink(&first, &link).unwrap();

        let handle = SandboxHome::open_with(&link, &home_ctx(&real_home, true)).unwrap();

        // The verified real path is the first target.
        let real = handle.real_path().unwrap();
        assert_eq!(
            std::fs::canonicalize(&real).unwrap(),
            std::fs::canonicalize(&first).unwrap()
        );

        // Swap the configured symlink to a second target after the check.
        // The handle's home is the CANONICAL path of the verified target, so
        // writes continue to land in the verified directory and the swapped
        // spelling is ignored (mid-run swaps are an explicit non-goal).
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&second, &link).unwrap();

        handle
            .write(Path::new("canary"), b"post-check", 0o600)
            .unwrap();
        assert!(handle.write_new(Path::new("new"), b"n", 0o600).unwrap());
        assert!(handle.real_path().is_ok());

        assert!(
            first.join("canary").is_file(),
            "the verified target keeps receiving writes"
        );
        assert!(first.join("new").is_file());
        assert!(
            !second.join("canary").exists(),
            "the swapped target must stay untouched"
        );
    }

    /// J-02 round 5 (security review P1): a pre-planted symlink in the sandbox home
    /// (`whatsapp -> outside`, `voice -> outside`, any depth ≤ 2) is refused
    /// at startup; production homes keep the historical tolerance.
    #[test]
    #[cfg(unix)]
    fn guard_refuses_preplanted_symlinks_in_the_sandbox_home() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let home = dir.path().join("sandbox");
        std::fs::create_dir_all(&home).unwrap();

        let active = home_ctx(&real_home, true);
        for child in ["whatsapp", "voice"] {
            let link = home.join(child);
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            let err = SandboxHome::open_with(&home, &active).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{child}");
            assert!(
                err.to_string().contains("lien symbolique"),
                "{child}: {err}"
            );
            std::fs::remove_file(&link).unwrap();
        }

        // Depth 2 (`agents/<name> -> outside`) is refused too.
        let agents = home.join("agents");
        std::fs::create_dir_all(&agents).unwrap();
        std::os::unix::fs::symlink(&outside, agents.join("main")).unwrap();
        assert!(SandboxHome::open_with(&home, &active).is_err());
        std::fs::remove_file(agents.join("main")).unwrap();

        // Depth 3 (`agents/<name>/workspace -> outside`, the engine agent
        // workspace) is refused as well (GLM F2).
        let agent_dir = agents.join("main");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::os::unix::fs::symlink(&outside, agent_dir.join("workspace")).unwrap();
        assert!(SandboxHome::open_with(&home, &active).is_err());

        // Production (inactive) keeps the historical tolerance: a symlink in
        // the real home is the owner's business.
        let inactive = home_ctx(&real_home, false);
        SandboxHome::open_with(&home, &inactive).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn write_gateway_refuses_parent_components() {
        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        std::fs::create_dir_all(&real_home).unwrap();
        let home = dir.path().join("home");
        let handle = SandboxHome::open_with(&home, &home_ctx(&real_home, true)).unwrap();
        assert!(
            handle.write(Path::new("../escape"), b"x", 0o600).is_err(),
            "a parent component must never escape the home"
        );
        assert!(handle.write(Path::new("/abs"), b"x", 0o600).is_err());
    }
}
