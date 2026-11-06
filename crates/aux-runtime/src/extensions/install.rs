//! Install, verify and remove.
//!
//! An install is explicit and per extension. The pinned artefact is fetched
//! through the one HTTP client, its sha256 is verified **before** anything is
//! unpacked, and it lands in `~/.auxesis/extensions/<name>@<version>/` (0700)
//! with its own `work/` subdirectory. No npm/uv lifecycle script ever runs:
//! the tarball is unpacked by this module, which is the `--ignore-scripts`
//! guarantee for slice 1.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::catalog::{Entry, SourceType, Transport};
use super::{extensions_dir, hex, valid_name};

/// The secrets file, relative to the sandboxed home. Same name the provider writer uses.
const ENV_FILE: &str = ".env";
/// Upper bound on a `.env` read: one line per key, never bulk data.
const MAX_ENV_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 256 * 1024;

/// How an install runs.
#[derive(Debug, Clone, Copy)]
pub struct InstallOptions {
    /// Allow a loopback HTTP target (tests only; production is public-only).
    pub allow_loopback: bool,
    /// Discover the server and pin its tool identities after unpacking.
    pub pin: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            allow_loopback: false,
            pin: true,
        }
    }
}

/// Everything that can refuse an install.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// A feature the contract marks Phase 1.
    #[error("not available in slice 1 (Phase 1): {0}")]
    Phase1(String),
    /// The entry has no pinned version or sha256.
    #[error("entry is not pinned: {0}")]
    Unpinned(String),
    /// The downloaded bytes did not hash to `source.sha256`.
    #[error("sha256 mismatch for `{name}`: expected {expected}, got {actual}")]
    HashMismatch {
        /// Extension name.
        name: String,
        /// `source.sha256`.
        expected: String,
        /// The hash of the bytes actually downloaded.
        actual: String,
    },
    /// The artefact could not be fetched.
    #[error("download failed: {0}")]
    Download(String),
    /// The artefact could not be unpacked.
    #[error("unpack failed: {0}")]
    Unpack(String),
    /// The source type or package spelling is not supported.
    #[error("unsupported source: {0}")]
    UnsupportedSource(String),
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The extension is not installed.
    #[error("extension `{0}` is not installed")]
    NotInstalled(String),
    /// The approval row (or, as `<name>.last`, the last approval a remove
    /// kept) cannot be read back: an install never overwrites it.
    #[error(
        "the approval row extensions/state/{0}.json is unreadable or corrupt; \
         nothing installed, the row is kept"
    )]
    StateUnreadable(String),
}

/// One installed extension on disk.
#[derive(Debug, Clone)]
pub struct InstalledExtension {
    /// `[a-z0-9-]{1,40}`.
    pub name: String,
    /// Pinned version.
    pub version: String,
    /// `~/.auxesis/extensions/<name>@<version>/`.
    pub dir: PathBuf,
    /// The entry copied in at install time.
    pub entry: Entry,
}

impl InstalledExtension {
    /// The writable workspace of this install.
    pub fn work_dir(&self) -> PathBuf {
        self.dir.join("work")
    }

    /// The executable this install runs: an in-tree path when the entry names
    /// one, otherwise the bare runtime name to resolve on `PATH`.
    pub fn program(&self) -> PathBuf {
        let candidate = self.dir.join(&self.entry.run.command);
        if candidate.is_file() {
            candidate
        } else {
            PathBuf::from(&self.entry.run.command)
        }
    }
}

/// Set a unix mode, ignoring the call on non-unix targets.
pub(crate) fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Whether the directory `rel` exists below the verified home, every component
/// a real directory. A symlink or file on the way is an error, never followed.
fn anchored_dir_exists(handle: &kernel_core::SandboxHome, rel: &Path) -> std::io::Result<bool> {
    match handle.open_dir(rel).map(drop) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// The entry names of the open directory `dir`, read from its own fd.
#[cfg(unix)]
fn list_fd(dir: &std::fs::File) -> std::io::Result<Vec<std::ffi::OsString>> {
    let names = {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        // `fdopendir` owns the fd it is given and `closedir` closes it: hand it a duplicate.
        // SAFETY: `dir` is an open directory fd owned by this frame; fcntl only duplicates it.
        let dup = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `dup` is a fresh directory fd that nothing else owns.
        let stream = unsafe { libc::fdopendir(dup) };
        if stream.is_null() {
            let err = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed, so `dup` is still ours to close.
            unsafe { libc::close(dup) };
            return Err(err);
        }
        // The duplicate shares the offset of a listing done before: start over.
        // SAFETY: `stream` is the open stream above.
        unsafe { libc::rewinddir(stream) };
        let mut names = Vec::new();
        let failure = loop {
            clear_errno();
            // SAFETY: `stream` is the open stream above; the entry is read before the next call.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let err = std::io::Error::last_os_error();
                break err.raw_os_error().filter(|code| *code != 0).map(|_| err);
            }
            // SAFETY: `d_name` is a NUL-terminated name inside the entry just returned.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(std::ffi::OsStr::from_bytes(name).to_owned());
            }
        };
        // SAFETY: `stream` is open and not used again; this closes `dup`.
        unsafe { libc::closedir(stream) };
        match failure {
            Some(err) => return Err(err),
            None => names,
        }
    };
    Ok(names)
}

/// The entry names of the directory `rel` below the verified home, listed from
/// the fd the kernel's `open_dir` opened, never from a path: a link on the way is
/// an error, and `None` means the directory is absent.
fn list_dir_anchored(
    handle: &kernel_core::SandboxHome,
    rel: &Path,
) -> std::io::Result<Option<Vec<std::ffi::OsString>>> {
    #[cfg(unix)]
    let names = {
        let dir = match handle.open_dir(rel) {
            Ok(dir) => dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        list_fd(&dir)?
    };
    #[cfg(not(unix))]
    let names = match std::fs::read_dir(handle.real_path()?.join(rel)) {
        Ok(entries) => entries
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    Ok(Some(names))
}

/// Reset errno so a null `readdir` can tell the end of the listing from a failure.
#[cfg(unix)]
fn clear_errno() {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    // SAFETY: `__error` returns this thread's errno storage.
    unsafe {
        *libc::__error() = 0;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: `__errno_location` returns this thread's errno storage.
    unsafe {
        *libc::__errno_location() = 0;
    }
}

pub(crate) fn force_private_dir(
    handle: &kernel_core::SandboxHome,
    rel: &Path,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let file = handle.open_dir(rel)?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(not(unix))]
    let _ = (handle, rel);
    Ok(())
}

/// Download or copy the artefact bytes for `entry`.
pub async fn fetch_artifact(entry: &Entry, allow_loopback: bool) -> Result<Vec<u8>, InstallError> {
    let package = entry.source.package.trim();
    if package.is_empty() {
        return Err(InstallError::Unpinned("source.package is empty".to_owned()));
    }
    let target = if let Some(path) = package.strip_prefix("file://") {
        return std::fs::read(path).map_err(InstallError::Io);
    } else if package.starts_with("http://") || package.starts_with("https://") {
        package.to_owned()
    } else if Path::new(package).is_file() {
        return std::fs::read(package).map_err(InstallError::Io);
    } else {
        match entry.source.kind {
            SourceType::Npm => npm_tarball_url(package, &entry.version)?,
            SourceType::Uv => {
                return Err(InstallError::UnsupportedSource(
                    "a bare uv package has no pinned URL yet".to_owned(),
                ))
            }
            SourceType::Binary => {
                return Err(InstallError::UnsupportedSource(format!(
                    "binary package `{package}` is neither a URL nor a path"
                )))
            }
        }
    };
    download_bytes(&target, allow_loopback).await
}

/// The registry tarball URL for an npm package and pinned version.
fn npm_tarball_url(package: &str, version: &str) -> Result<String, InstallError> {
    if version.trim().is_empty() {
        return Err(InstallError::Unpinned("version is empty".to_owned()));
    }
    let basename = package.rsplit('/').next().unwrap_or(package);
    Ok(format!(
        "https://registry.npmjs.org/{package}/-/{basename}-{version}.tgz"
    ))
}

/// The wall-clock budget of one artefact download, connect to last byte.
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The largest artefact a download keeps. A larger one is refused, never truncated.
const MAX_ARTEFACT_BYTES: usize = 50 * 1024 * 1024;

/// The most bytes an artefact may unpack to, across every entry. A gzip bomb is
/// refused, not expanded.
const MAX_UNPACKED_BYTES: u64 = 200 * 1024 * 1024;

/// The most entries an artefact may hold.
const MAX_ENTRIES: usize = 10_000;

/// A reader that fails, rather than truncating, once `remaining` bytes have been
/// read: an archive over its size limit is an error, never a partial unpack.
struct Capped<R> {
    inner: R,
    remaining: u64,
}

impl<R: std::io::Read> std::io::Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        let read = read as u64;
        if read > self.remaining {
            return Err(std::io::Error::other(format!(
                "the artefact unpacks past its {} MB size limit",
                MAX_UNPACKED_BYTES / (1024 * 1024)
            )));
        }
        self.remaining -= read;
        Ok(buf.len().min(read as usize))
    }
}

fn artefact_too_large() -> InstallError {
    InstallError::Download(format!(
        "the artefact is over the {} MB size limit",
        MAX_ARTEFACT_BYTES / (1024 * 1024)
    ))
}

/// The address policy of a download. Production is public addresses only. The
/// loopback policy is a test seam: outside `cfg(test)` a loopback download is
/// refused, not silently made public.
fn download_policy(allow_loopback: bool) -> Result<kernel_net::AddressPolicy, InstallError> {
    if !allow_loopback {
        return Ok(kernel_net::AddressPolicy::PublicOnly);
    }
    #[cfg(test)]
    {
        Ok(kernel_net::AddressPolicy::AllowLoopback)
    }
    #[cfg(not(test))]
    {
        Err(InstallError::Download(
            "loopback downloads are a test seam".to_owned(),
        ))
    }
}

/// Fetch one URL into memory through kernel-net's pinned client: the host is
/// resolved and every answer checked, then the request goes to that one validated
/// address. Redirects are not followed, so a hop cannot reach a private address.
async fn download_bytes(url: &str, allow_loopback: bool) -> Result<Vec<u8>, InstallError> {
    let parsed = reqwest::Url::parse(url).map_err(|err| InstallError::Download(err.to_string()))?;
    let policy = download_policy(allow_loopback)?;
    let client = crate::net::pinned_client(policy, &parsed)
        .await
        .map_err(|err| InstallError::Download(err.to_string()))?;
    let fetch = async {
        let mut response = client
            .get(parsed)
            .map_err(|err| InstallError::Download(err.to_string()))?
            .send()
            .await
            .map_err(|err| InstallError::Download(err.to_string()))?;
        if !response.status().is_success() {
            return Err(InstallError::Download(format!(
                "HTTP {} for {url}",
                response.status()
            )));
        }
        // Refuse a declared size first, then count the streamed bytes: the cap holds
        // even when the server declares nothing.
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ARTEFACT_BYTES as u64)
        {
            return Err(artefact_too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| InstallError::Download(err.to_string()))?
        {
            if body.len() + chunk.len() > MAX_ARTEFACT_BYTES {
                return Err(artefact_too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };
    tokio::time::timeout(DOWNLOAD_TIMEOUT, fetch)
        .await
        .map_err(|_| InstallError::Download(format!("timed out after {DOWNLOAD_TIMEOUT:?}")))?
}

/// Install one entry into `~/.auxesis/extensions/<name>@<version>/`.
///
/// The sha256 is checked before the bytes are unpacked; a mismatch leaves
/// nothing on disk.
pub async fn install(
    home: &Path,
    entry: &Entry,
    options: &InstallOptions,
) -> Result<InstalledExtension, InstallError> {
    if !valid_name(&entry.name) {
        return Err(InstallError::Phase1(format!(
            "invalid name `{}`",
            entry.name
        )));
    }
    entry
        .installable()
        .map_err(|err| InstallError::Phase1(err.to_string()))?;
    if entry.source.sha256.trim().is_empty() || entry.version.trim().is_empty() {
        return Err(InstallError::Unpinned(entry.name.clone()));
    }
    if entry.run.transport != Transport::Stdio {
        return Err(InstallError::Phase1("http transport".to_owned()));
    }
    // EXT-ANCHOR-9 r2: an approval row that cannot be read is refused before
    // anything is fetched or written; `pin_extension` never overwrites a row.
    if options.pin && super::mount::read_state(home, &entry.name).is_err() {
        return Err(InstallError::StateUnreadable(entry.name.clone()));
    }
    // EXT-ANCHOR-10: so is a kept last approval (named `<name>.last`).
    if options.pin && super::mount::read_last(home, &entry.name).is_err() {
        return Err(InstallError::StateUnreadable(format!(
            "{}.last",
            entry.name
        )));
    }

    let bytes = fetch_artifact(entry, options.allow_loopback).await?;
    let actual = hex(&Sha256::digest(&bytes));
    if actual != entry.source.sha256.to_ascii_lowercase() {
        // Nothing has been written yet: the mismatch is refused in memory.
        return Err(InstallError::HashMismatch {
            name: entry.name.clone(),
            expected: entry.source.sha256.clone(),
            actual,
        });
    }

    let rel_dir = Path::new("extensions").join(format!("{}@{}", entry.name, entry.version));
    // Defence in depth: the install path must stay under the extensions root
    // before anything is created or removed.
    ensure_within(Path::new("extensions"), &rel_dir)?;
    let handle = kernel_core::SandboxHome::open(home)?;
    handle.create_dir_all(Path::new("extensions"))?;
    force_private_dir(&handle, Path::new("extensions"))?;
    // Every path below is built from the verified home's real path, the same
    // directory `handle` creates in: the created and unpacked trees are one.
    let dir = handle.real_path()?.join(&rel_dir);
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(InstallError::Unpack(format!(
                "{} is a symbolic link",
                dir.display()
            )));
        }
        Ok(_) => {
            remove_tree_at(&handle, &rel_dir)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    if !handle.create_dir(&rel_dir)? {
        return Err(InstallError::Unpack(format!(
            "{} already exists",
            dir.display()
        )));
    }
    if !std::fs::symlink_metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
        return Err(InstallError::Unpack(format!(
            "{} is not a directory",
            dir.display()
        )));
    }

    // Everything after the tree exists is one fallible step: on any failure the
    // partial install is cleaned up and a cleanup failure is reported, never
    // swallowed.
    let setup = (|| -> Result<(), InstallError> {
        unpack(entry, &handle, &rel_dir, &dir, &bytes)?;
        let work = dir.join("work");
        if !handle.create_dir(&rel_dir.join("work"))? {
            return Err(InstallError::Unpack(format!(
                "{} already exists",
                work.display()
            )));
        }
        if !std::fs::symlink_metadata(&work).is_ok_and(|meta| meta.is_dir()) {
            return Err(InstallError::Unpack(format!(
                "{} is not a directory",
                work.display()
            )));
        }
        force_private_dir(&handle, &rel_dir.join("work"))?;
        // Copy the verified entry in, so `verify` and `remove` can read it back
        // without the catalog.
        let text = toml::to_string(entry).map_err(|err| InstallError::Unpack(err.to_string()))?;
        handle.write_atomic(&rel_dir.join("entry.toml"), text.as_bytes(), 0o600)?;
        Ok(())
    })();
    if let Err(err) = setup {
        return Err(discard_partial_install(&handle, &rel_dir, err));
    }

    let installed = InstalledExtension {
        name: entry.name.clone(),
        version: entry.version.clone(),
        dir,
        entry: entry.clone(),
    };

    if options.pin {
        // Over an approval row this pins and starts nothing: the upgrade keeps
        // the owner's old yes until `aux ext verify --accept` names its changes.
        // A server that cannot be pinned is not installed: its tree goes too.
        if let Err(err) =
            super::session::pin_extension(home, &installed, options.allow_loopback).await
        {
            return Err(discard_partial_install(
                &handle,
                &rel_dir,
                InstallError::Unpack(err.to_string()),
            ));
        }
    }
    Ok(installed)
}

/// Delete a failed install's tree; a cleanup failure is reported beside the cause.
fn discard_partial_install(
    handle: &kernel_core::SandboxHome,
    rel_dir: &Path,
    err: InstallError,
) -> InstallError {
    match remove_tree_at(handle, rel_dir) {
        Ok(()) => err,
        Err(cleanup_err) => InstallError::Unpack(format!(
            "{err}; partial-install cleanup failed: {cleanup_err}"
        )),
    }
}

fn unpack(
    entry: &Entry,
    handle: &kernel_core::SandboxHome,
    rel_dir: &Path,
    dir: &Path,
    bytes: &[u8],
) -> Result<(), InstallError> {
    match entry.source.kind {
        SourceType::Binary => {
            let relative = Path::new(&entry.run.command);
            let target = if relative.components().count() == 1
                && relative
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
            {
                rel_dir.join(relative)
            } else {
                rel_dir.join("server")
            };
            handle.write_atomic(&target, bytes, 0o755)?;
            Ok(())
        }
        SourceType::Npm | SourceType::Uv => unpack_tarball(dir, bytes),
    }
}

/// Unpack a `.tar.gz`/`.tgz`, stripping one leading directory (`package/`).
///
/// Only `Regular` and `Directory` entries are accepted: a symlink, hard link,
/// device or FIFO is refused, as is any GNU long-name/long-link trick that
/// resolves to one. The stripped path is validated (no absolute, no `..`) and
/// the bytes are written with [`tar::Entry::unpack_in`], which refuses to
/// follow a symlink already planted in the destination.
fn unpack_tarball(dir: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    // Pass 1: validate every entry and rewrite the archive with stripped,
    // traversal-free paths. Reading the data here also proves the entry is
    // well formed before anything reaches the filesystem.
    let mut clean = tar::Builder::new(Vec::new());
    {
        let decoder = Capped {
            inner: flate2::read::GzDecoder::new(bytes),
            remaining: MAX_UNPACKED_BYTES,
        };
        let mut archive = tar::Archive::new(decoder);
        let entries = archive
            .entries()
            .map_err(|err| InstallError::Unpack(err.to_string()))?;
        for (count, entry) in entries.enumerate() {
            if count >= MAX_ENTRIES {
                return Err(InstallError::Unpack(format!(
                    "the artefact holds more than {MAX_ENTRIES} entries"
                )));
            }
            let mut entry = entry.map_err(|err| InstallError::Unpack(err.to_string()))?;
            let kind = entry.header().entry_type();
            if !matches!(kind, tar::EntryType::Regular | tar::EntryType::Directory) {
                return Err(InstallError::Unpack(format!(
                    "refused tar entry type {kind:?}"
                )));
            }
            let path = entry
                .path()
                .map_err(|err| InstallError::Unpack(err.to_string()))?
                .into_owned();
            let relative = safe_relative(&path)?;
            if relative.as_os_str().is_empty() {
                continue;
            }
            if relative.components().count() > WINDOW {
                return Err(InstallError::Unpack(format!(
                    "the artefact nests deeper than {WINDOW} levels"
                )));
            }
            let mut header = entry.header().clone();
            header
                .set_path(&relative)
                .map_err(|err| InstallError::Unpack(err.to_string()))?;
            header.set_size(entry.size());
            header.set_cksum();
            clean
                .append(&header, &mut entry)
                .map_err(|err| InstallError::Unpack(err.to_string()))?;
        }
    }
    let clean = clean
        .into_inner()
        .map_err(|err| InstallError::Unpack(err.to_string()))?;

    // Pass 2: write with `unpack_in`, which trims leading `/`, skips `..` and
    // refuses a parent outside `dir` (a planted symlink).
    let mut archive = tar::Archive::new(clean.as_slice());
    let entries = archive
        .entries()
        .map_err(|err| InstallError::Unpack(err.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| InstallError::Unpack(err.to_string()))?;
        let kind = entry.header().entry_type();
        if !matches!(kind, tar::EntryType::Regular | tar::EntryType::Directory) {
            return Err(InstallError::Unpack(format!(
                "refused tar entry type {kind:?}"
            )));
        }
        if !entry
            .unpack_in(dir)
            .map_err(|err| InstallError::Unpack(format!("{err:?}")))?
        {
            return Err(InstallError::Unpack("path traversal in tarball".to_owned()));
        }
    }
    Ok(())
}

/// Lexically normalise a path (no filesystem access), collapsing `.`/`..`.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// Refuse a path that does not stay under `root` (lexical containment).
fn ensure_within(root: &Path, path: &Path) -> Result<(), InstallError> {
    let root = lexical_normalize(root);
    let path = lexical_normalize(path);
    if path.starts_with(&root) && path != root {
        Ok(())
    } else {
        Err(InstallError::Unpack(
            "install path escapes the extensions root".to_owned(),
        ))
    }
}

/// Most parent fds a removal walk keeps open, as the kernel's `remove_dir_all`:
/// above them the walk re-opens levels from the tree root by checked identity,
/// so any depth is removed without exhausting fds. Unpack refuses a deeper
/// artefact.
const WINDOW: usize = 64;

const MOUNT_POINT: (&str, &str) = ("est un point de montage", "is a mount point");
const HAS_MOUNT: (&str, &str) = ("contient un point de montage", "contains a mount point");
const CHANGED: (&str, &str) = (
    "a un dossier qui a changé pendant la suppression",
    "has a directory that changed during removal",
);

// The test seam: the name whose directory reports itself a mount root.
#[cfg(test)]
thread_local! {
    static MOUNT_SEAM: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// What the mount checks see of one directory: its device, its mount (the
/// Linux mount id, the macOS `f_mntonname`; empty elsewhere) and whether it is
/// a mount root (Linux `STATX_ATTR_MOUNT_ROOT`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct MountFacts {
    dev: u64,
    mount: Vec<u8>,
    root: bool,
}

/// Whether a directory showing `facts` is not plainly on the home's mount
/// `home`: another device, another mount on the same device (a bind or nullfs
/// mount), or a mount root.
fn is_mount(facts: &MountFacts, home: &MountFacts) -> bool {
    facts.root || facts.dev != home.dev || facts.mount != home.mount
}

/// The [`MountFacts`] of the open directory `dir` (named `name` for the seam).
/// A mount that cannot be read is an error: the removal fails closed.
fn mount_facts(dir: &std::fs::File, name: &std::ffi::CStr) -> std::io::Result<MountFacts> {
    use std::os::fd::AsRawFd;
    let (dev, mount, root) = (file_id(dir)?.0, Vec::new(), false);
    let mut facts = MountFacts { dev, mount, root };
    os_mount(dir.as_raw_fd(), &mut facts)?;
    #[cfg(test)]
    if MOUNT_SEAM.with(|at| at.borrow().as_deref() == Some(name.to_bytes())) {
        facts.root = true;
    }
    let _ = name;
    Ok(facts)
}

/// The [`MountFacts`] of the entry `name` in `dir` (any type), never
/// following a link: a file bind mount shows another mount id or device.
/// Outside Linux only the device is compared (`mount` is the parent's).
fn entry_facts(dir: &std::fs::File, name: &std::ffi::CStr) -> std::io::Result<MountFacts> {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    let facts = statx_facts(dir.as_raw_fd(), name, 0)?;
    #[cfg(not(target_os = "linux"))]
    let facts = {
        // SAFETY: zeroed `stat` is a valid out-parameter for `fstatat`.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let at = dir.as_raw_fd();
        // SAFETY: valid fd, NUL-terminated name, valid out-pointer; never follows a link.
        if unsafe { libc::fstatat(at, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut facts = mount_facts(dir, c".")?;
        #[allow(clippy::unnecessary_cast)]
        let dev = st.st_dev as u64;
        facts.dev = dev;
        facts
    };
    #[cfg(test)]
    let mut facts = facts;
    #[cfg(test)]
    if MOUNT_SEAM.with(|at| at.borrow().as_deref() == Some(name.to_bytes())) {
        facts.root = true;
    }
    Ok(facts)
}

/// Linux: the device, mount id and mount-root flag from `statx`. A kernel
/// without `STATX_MNT_ID` (before 5.8) fails closed: every removal is refused.
#[cfg(target_os = "linux")]
fn statx_facts(
    at: std::os::fd::RawFd,
    path: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<MountFacts> {
    // SAFETY: zeroed `statx` is a valid out-parameter.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let flags = flags | libc::AT_SYMLINK_NOFOLLOW;
    // SAFETY: valid fd, a NUL-terminated path (empty only with `AT_EMPTY_PATH`), valid out-pointer.
    if unsafe { libc::statx(at, path.as_ptr(), flags, libc::STATX_MNT_ID, &mut stx) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if stx.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(std::io::Error::other("no mount id: removal refused"));
    }
    let root = libc::STATX_ATTR_MOUNT_ROOT as u64;
    Ok(MountFacts {
        dev: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
        mount: stx.stx_mnt_id.to_le_bytes().to_vec(),
        root: stx.stx_attributes_mask & root != 0 && stx.stx_attributes & root != 0,
    })
}

#[cfg(target_os = "linux")]
fn os_mount(fd: std::os::fd::RawFd, facts: &mut MountFacts) -> std::io::Result<()> {
    let found = statx_facts(fd, c"", libc::AT_EMPTY_PATH)?;
    (facts.mount, facts.root) = (found.mount, found.root);
    Ok(())
}

#[cfg(target_os = "macos")]
fn os_mount(fd: std::os::fd::RawFd, facts: &mut MountFacts) -> std::io::Result<()> {
    // SAFETY: zeroed `statfs` is a valid out-parameter for `fstatfs` on an open fd.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut fs) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let name = fs.f_mntonname.iter().take_while(|&&byte| byte != 0);
    facts.mount = name.map(|&byte| byte as u8).collect();
    Ok(())
}

// Elsewhere only the device is compared.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn os_mount(_fd: std::os::fd::RawFd, _facts: &mut MountFacts) -> std::io::Result<()> {
    Ok(())
}

type FileId = (u64, u64);

fn file_id(dir: &std::fs::File) -> std::io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = dir.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

/// Delete the directory `rel` below the verified home and everything in it,
/// through fds only (see [`remove_tree_in`]).
/// `rel` is `extensions/<tree>`: like the removal scan, a mount at
/// `extensions/` itself is refused, and the tree is checked against the home's
/// mount (not the mount of `extensions/`).
fn remove_tree_at(handle: &kernel_core::SandboxHome, rel: &Path) -> std::io::Result<()> {
    let parent = handle.open_dir(rel.parent().unwrap_or(Path::new("")))?;
    let name = rel
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let home = home_facts(&parent)?;
    remove_tree_in(&parent, name, rel, &home, &mut |_| {})
}

/// Delete `name` in the open `parent` and everything below it, through fds
/// only: the tree is opened `O_NOFOLLOW` from `parent` (a link or a file is
/// refused, a root on another device is a mount point), emptied by
/// [`empty_tree`], then unlinked if `name` still names it. `rel` names it in
/// errors; `after_open` is the test seam once the tree is open.
fn remove_tree_in(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    rel: &Path,
    home: &MountFacts,
    after_open: &mut dyn FnMut(&str),
) -> std::io::Result<()> {
    let Some(tree) = open_child_dir(parent, name, home, rel, MOUNT_POINT, None)? else {
        return Err(refusal(
            rel,
            "est un lien ou un fichier",
            "is a link or a file",
        ));
    };
    after_open("opened");
    let id = file_id(&tree)?;
    empty_tree(rel, &tree, home, None)?;
    unlink_dir_checked(parent, name, id, rel)
}

fn c_name(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

/// Open the directory `name` in `parent` `O_NOFOLLOW`; `None` for a file or a
/// link. One that [`is_mount`] against `home` is refused with `other_dev`
/// before anything changes. A `000` directory is first given `u+rwx` by
/// [`unlock_locked`] (`u+rx` in a `scan`, recorded there with its old mode
/// before any later check can refuse it), and the open after it must show the
/// same identity, so a locked tree stays removable. The removal itself
/// (no `scan`) puts no mode back: the tree is being deleted, and a removal
/// refused midway leaves its unlocked directories `u+rwx` (owner-only).
fn open_child_dir(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    home: &MountFacts,
    rel: &Path,
    other_dev: (&str, &str),
    mut scan: Option<&mut Unlocked>,
) -> std::io::Result<Option<std::fs::File>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let at = parent.as_raw_fd();
    let mounted = || refusal(rel, other_dev.0, other_dev.1);
    let grant = if scan.is_some() { 0o500 } else { 0o700 };
    // The unlocked identity, old mode, and whether the scan recorded it.
    let mut unlocked: Option<(FileId, u32, bool)> = None;
    loop {
        // SAFETY: `at` is an open directory fd and `name` a NUL-terminated CString.
        let fd = unsafe { libc::openat(at, name.as_ptr(), flags) };
        if fd >= 0 {
            // SAFETY: `fd` is a fresh, valid descriptor nothing else owns.
            let dir = unsafe { std::fs::File::from_raw_fd(fd) };
            if let Some((id, old, recorded)) = unlocked {
                if file_id(&dir)? != id {
                    return Err(refusal(rel, CHANGED.0, CHANGED.1));
                }
                // Recorded before the mount check below can refuse it (Linux
                // recorded it already, through the unlock's own fd).
                if let (Some(list), false) = (scan.as_deref_mut(), recorded) {
                    list.push((dir.try_clone()?, id, old));
                }
            }
            if is_mount(&mount_facts(&dir, &name)?, home) {
                return Err(mounted());
            }
            return Ok(Some(dir));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // A file or a link: it is unlinked as itself.
            Some(libc::ENOTDIR | libc::ELOOP) => return Ok(None),
            Some(libc::EACCES) if unlocked.is_none() => {}
            _ => return Err(err),
        }
        // `None`: not a directory, the open's own error stands.
        let (id, old, held) = unlock_locked(at, &name, home, &mounted, grant)?.ok_or(err)?;
        let recorded = held.is_some() && scan.is_some();
        if let (Some(list), Some(held)) = (scan.as_deref_mut(), held) {
            list.push((held, id, old));
        }
        unlocked = Some((id, old, recorded));
    }
}

/// Add `grant` to the unreadable directory `name` in `at` through an `O_PATH`
/// fd (no permission needed to open it): it is checked against `home` on that
/// fd, then changed through `/proc/self/fd`, never by its name. `O_DIRECTORY`
/// is load-bearing: `O_PATH | O_NOFOLLOW` alone opens a link itself, and the
/// `/proc` chmod would then follow it, so a non-directory fd is never changed.
/// Returns its identity, its old mode and the `O_PATH` fd ([`set_fd_mode`]
/// puts the mode back through it).
#[cfg(target_os = "linux")]
fn unlock_locked(
    at: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    home: &MountFacts,
    mounted: &dyn Fn() -> std::io::Error,
    grant: u32,
) -> std::io::Result<Option<(FileId, u32, Option<std::fs::File>)>> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: `at` is an open directory fd and `name` a NUL-terminated CString.
    let fd = unsafe { libc::openat(at, name.as_ptr(), flags) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOTDIR | libc::ELOOP) => Ok(None),
            _ => Err(err),
        };
    }
    // SAFETY: `fd` is a fresh, valid descriptor nothing else owns.
    let locked = unsafe { std::fs::File::from_raw_fd(fd) };
    if is_mount(&mount_facts(&locked, name)?, home) {
        return Err(mounted());
    }
    let meta = locked.metadata()?;
    if !meta.is_dir() {
        return Ok(None);
    }
    let old = meta.mode() & 0o7777;
    proc_chmod(&locked, old | grant)?;
    Ok(Some(((meta.dev(), meta.ino()), old, Some(locked))))
}

/// `chmod` the directory the (`O_PATH`) fd `dir` holds, through
/// `/proc/self/fd`: the magic link names that fd's object, never a path.
#[cfg(target_os = "linux")]
fn proc_chmod(dir: &std::fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let path = std::ffi::CString::new(format!("/proc/self/fd/{}", dir.as_raw_fd()))?;
    // SAFETY: NUL-terminated path; it resolves to the directory `dir` holds.
    match unsafe { libc::chmod(path.as_ptr(), mode as libc::mode_t) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// Add `grant` to the unreadable directory `name` in `at`; returns its
/// identity and old mode. With no `O_PATH` here, by name
/// (`AT_SYMLINK_NOFOLLOW`) once `fstatat` shows a directory on the home's
/// device; the caller's open must then show that identity and the home's
/// mount. Residual (documented, not closed): the chmod comes before the full
/// mount check (only the device is compared first, so a nullfs mount on the
/// same device is refused only after its root gained `grant`), and a same-uid
/// swap between the two calls can add `grant` to the swapped-in directory.
#[cfg(not(target_os = "linux"))]
fn unlock_locked(
    at: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    home: &MountFacts,
    mounted: &dyn Fn() -> std::io::Error,
    grant: u32,
) -> std::io::Result<Option<(FileId, u32, Option<std::fs::File>)>> {
    // SAFETY: zeroed `stat` is a valid out-parameter for `fstatat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, NUL-terminated name, valid out-pointer.
    let found = unsafe { libc::fstatat(at, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if found != 0 || st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Ok(None);
    }
    #[allow(clippy::unnecessary_cast)]
    let id = (st.st_dev as u64, st.st_ino as u64);
    if id.0 != home.dev {
        return Err(mounted());
    }
    let old = st.st_mode & 0o7777;
    let mode = old | grant as libc::mode_t;
    // SAFETY: as above; `AT_SYMLINK_NOFOLLOW` never follows a link.
    let changed = unsafe { libc::fchmodat(at, name.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW) };
    if changed != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    let old = old as u32;
    Ok(Some((id, old, None)))
}

/// The directories a scan unlocked, each with its identity and old mode: put
/// back through the held fd as the scan leaves each one, and all of them when
/// the scan stops on a refusal, so a refused removal changes no mode.
type Unlocked = Vec<(std::fs::File, FileId, u32)>;

/// Add `u+rwx` to the open directory `dir` (`fchmod`), so a `555` level can be
/// emptied. A `scan` only adds what it needs to look inside (`u+rx`) and
/// records the old mode.
fn unlock(dir: &std::fs::File, scan: Option<&mut Unlocked>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = dir.metadata()?.permissions().mode() & 0o7777;
    let Some(list) = scan else {
        return set_fd_mode(dir, mode | 0o700);
    };
    if mode & 0o500 != 0o500 {
        // The record is ready before the mode widens.
        let record = (dir.try_clone()?, file_id(dir)?, mode);
        set_fd_mode(dir, mode | 0o500)?;
        list.push(record);
    }
    Ok(())
}

/// `fchmod` the open directory `dir`; an `O_PATH` fd (Linux, `EBADF`) goes
/// through [`proc_chmod`].
fn set_fd_mode(dir: &std::fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `dir` is an open fd owned by the caller.
    if unsafe { libc::fchmod(dir.as_raw_fd(), mode as libc::mode_t) } == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    #[cfg(target_os = "linux")]
    if err.raw_os_error() == Some(libc::EBADF) {
        return proc_chmod(dir, mode);
    }
    Err(err)
}

/// Put back every mode in `list`, deepest first; the first failure is returned.
fn restore_modes(list: &mut Unlocked) -> std::io::Result<()> {
    let mut first = Ok(());
    while let Some((dir, _, mode)) = list.pop() {
        if let Err(err) = set_fd_mode(&dir, mode) {
            first = first.and(Err(err));
        }
    }
    first
}

fn unlink_at(
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let name = c_name(name)?;
    // SAFETY: `dir` is an open directory fd and `name` a NUL-terminated CString.
    match unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// Unlink the emptied directory `name` in `parent` if `name` still shows its
/// identity `id`; another identity is refused. This narrows the swap window but
/// does not close it: a same-uid process can still swap in another empty
/// directory between the `fstatat` and the `unlinkat`, and that one is removed.
fn unlink_dir_checked(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    id: FileId,
    rel: &Path,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let c = c_name(name)?;
    // SAFETY: zeroed `stat` is a valid out-parameter for `fstatat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, NUL-terminated name, valid out-pointer; never follows a link.
    let found = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if found != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    if (st.st_dev as u64, st.st_ino as u64) != id {
        return Err(refusal(rel, CHANGED.0, CHANGED.1));
    }
    unlink_at(parent, name, libc::AT_REMOVEDIR)
}

/// One entered directory: its name and identity, its parent's fd while in the
/// window, and its parent's names still to do.
struct Level {
    name: std::ffi::OsString,
    id: FileId,
    parent: Option<std::fs::File>,
    rest: Vec<std::ffi::OsString>,
}

/// Empty the open tree `root` with an explicit stack, fd-relative, as the
/// kernel's walk: each directory is entered via [`open_child_dir`] on the
/// home's mount (a mount point is refused before any chmod or unlink), then
/// made `u+rwx`; anything else, a link included, is checked against the
/// home's mount too (a file bind mount is refused) and unlinked as itself. The
/// parent fds of the deepest [`WINDOW`] levels stay open; above them the
/// up-walk re-opens the names from `root`, refusing a changed identity. A
/// `scan` walks the same way, unlinks nothing, adds only `u+rx` and puts each
/// directory's old mode back as it leaves it (the caller restores the rest).
fn empty_tree(
    rel: &Path,
    root: &std::fs::File,
    home: &MountFacts,
    mut scan: Option<&mut Unlocked>,
) -> std::io::Result<()> {
    let mut stack: Vec<Level> = Vec::new();
    // Levels from `low` up hold their parent's fd.
    let mut low = 0;
    let mut dir = root.try_clone()?;
    unlock(&dir, scan.as_deref_mut())?;
    let mut todo = list_fd(&dir)?;
    loop {
        if let Some(name) = todo.pop() {
            match open_child_dir(&dir, &name, home, rel, HAS_MOUNT, scan.as_deref_mut())? {
                None => {
                    // A file bind mount is refused like a directory one.
                    if is_mount(&entry_facts(&dir, &c_name(&name)?)?, home) {
                        return Err(refusal(rel, HAS_MOUNT.0, HAS_MOUNT.1));
                    }
                    if scan.is_none() {
                        unlink_at(&dir, &name, 0)?;
                    }
                }
                Some(child) => {
                    unlock(&child, scan.as_deref_mut())?;
                    let id = file_id(&child)?;
                    let rest = std::mem::replace(&mut todo, list_fd(&child)?);
                    let parent = Some(std::mem::replace(&mut dir, child));
                    stack.push(Level {
                        name,
                        id,
                        parent,
                        rest,
                    });
                    if stack.len() - low > WINDOW {
                        stack[low].parent = None;
                        low += 1;
                    }
                }
            }
            continue;
        }
        // `dir` is empty: go back to its parent and remove it there.
        let Some(level) = stack.pop() else {
            return Ok(());
        };
        dir = match level.parent {
            Some(parent) => parent,
            None => {
                let (parent, start) = reopen(rel, root, home, &mut stack, scan.as_deref_mut())?;
                low = start;
                parent
            }
        };
        todo = level.rest;
        match scan.as_deref_mut() {
            None => unlink_dir_checked(&dir, &level.name, level.id, rel)?,
            // The scan is done with this directory: its old mode goes back,
            // and the record goes only once that worked (else the caller retries).
            Some(list) if list.last().is_some_and(|last| last.1 == level.id) => {
                let (left, _, mode) = list.last().expect("checked above");
                set_fd_mode(left, *mode)?;
                list.pop();
            }
            Some(_) => {}
        }
    }
}

/// Re-open the names of `stack` from `root`, refusing a changed identity, and
/// keep the parent fds of its deepest [`WINDOW`] levels; returns the top
/// directory and the new window start.
fn reopen(
    rel: &Path,
    root: &std::fs::File,
    home: &MountFacts,
    stack: &mut [Level],
    mut scan: Option<&mut Unlocked>,
) -> std::io::Result<(std::fs::File, usize)> {
    let low = stack.len().saturating_sub(WINDOW);
    let mut dir = root.try_clone()?;
    for (at, level) in stack.iter_mut().enumerate() {
        let next = open_child_dir(&dir, &level.name, home, rel, HAS_MOUNT, scan.as_deref_mut())?;
        let next = next.ok_or_else(|| refusal(rel, CHANGED.0, CHANGED.1))?;
        if file_id(&next)? != level.id {
            return Err(refusal(rel, CHANGED.0, CHANGED.1));
        }
        if at >= low {
            level.parent = Some(dir);
        }
        dir = next;
    }
    Ok((dir, low))
}

/// Strip one leading directory and refuse any traversal component.
fn safe_relative(path: &Path) -> Result<PathBuf, InstallError> {
    let mut parts = path.components();
    match parts.next() {
        Some(Component::Normal(_)) => {}
        _ => return Err(InstallError::Unpack("path traversal in tarball".to_owned())),
    }
    let mut relative = PathBuf::new();
    for part in parts {
        match part {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(InstallError::Unpack("path traversal in tarball".to_owned()));
            }
        }
    }
    Ok(relative)
}

/// Load one installed extension by name, preferring the highest version.
/// A refusal reads as `None` here; [`try_load_installed`] tells them apart.
pub fn load_installed(home: &Path, name: &str) -> Option<InstalledExtension> {
    try_load_installed(home, name).ok().flatten()
}

/// The names of every installed extension, listed through the verified home:
/// a link in place of `extensions/` is refused, never followed.
pub fn installed_names(home: &Path) -> std::io::Result<Vec<String>> {
    let Some(handle) = open_home(home)? else {
        return Ok(Vec::new());
    };
    let names = list_dir_anchored(&handle, Path::new("extensions"))?.unwrap_or_default();
    let mut found: Vec<String> = (names.iter())
        .filter_map(|name| Some(name.to_str()?.rsplit_once('@')?.0.to_owned()))
        .collect();
    found.sort();
    found.dedup();
    Ok(found)
}

/// The verified home, `None` when it does not exist.
fn open_home(home: &Path) -> std::io::Result<Option<kernel_core::SandboxHome>> {
    match kernel_core::SandboxHome::open_existing(home) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        opened => opened.map(Some),
    }
}

/// `load_installed`, where `Ok(None)` is "not installed" and a link, an
/// unreadable listing or an unreadable entry is an error. An entry that reads
/// but does not parse is skipped with a warning.
pub fn try_load_installed(home: &Path, name: &str) -> std::io::Result<Option<InstalledExtension>> {
    Ok(scan_installed(home, name)?.0)
}

/// `try_load_installed`, plus the versions whose entry was skipped as corrupt.
type Scan = (Option<InstalledExtension>, Vec<String>);
fn scan_installed(home: &Path, name: &str) -> std::io::Result<Scan> {
    let root = extensions_dir(home);
    let Some(handle) = open_home(home)? else {
        return Ok((None, Vec::new()));
    };
    let (mut best, mut corrupt): Scan = (None, Vec::new());
    // Listed through the verified home: a link in place of `extensions/` is refused.
    let Some(names) = list_dir_anchored(&handle, Path::new("extensions"))? else {
        return Ok((None, corrupt));
    };
    for name_on_disk in names {
        let file_name = name_on_disk.to_string_lossy().to_string();
        let dir = root.join(&file_name);
        let Some((dir_name, version)) = file_name.rsplit_once('@') else {
            continue;
        };
        if dir_name != name {
            continue;
        }
        let rel = Path::new("extensions").join(&file_name).join("entry.toml");
        let refused = || refusal(&rel, "est illisible", "cannot be read");
        let text = match super::read_text_at_checked(&handle, &rel, MAX_ENTRY_BYTES) {
            super::ReadAt::Absent => continue,
            super::ReadAt::Unreadable => return Err(refused()),
            super::ReadAt::Text(text) => text,
        };
        let Ok(parsed) = toml::from_str::<Entry>(&text) else {
            // A corrupt entry is skipped, never fatal: a valid version beside it
            // still loads, mounts and removes.
            tracing::warn!(extension = %name, entry = %rel.display(), "corrupt extension entry skipped");
            corrupt.push(version.to_owned());
            continue;
        };
        let candidate = InstalledExtension {
            name: name.to_owned(),
            version: version.to_owned(),
            dir,
            entry: parsed,
        };
        let replace = best
            .as_ref()
            .map(|current| {
                super::catalog::compare_versions(&candidate.version, &current.version)
                    == std::cmp::Ordering::Greater
            })
            .unwrap_or(true);
        if replace {
            best = Some(candidate);
        }
    }
    Ok((best, corrupt))
}

/// A verified install, with the versions above it whose `entry.toml` is
/// corrupt: they never run, and the caller shows them to the owner.
#[derive(Debug)]
pub struct VerifiedInstall {
    /// The build that runs (the highest valid entry), re-hashed.
    pub installed: InstalledExtension,
    /// Versions newer than `installed` skipped as corrupt, lowest first.
    pub corrupt_newer: Vec<String>,
}

/// Re-hash the installed artefact and confirm it still matches the entry.
pub fn verify_installed(home: &Path, name: &str) -> Result<InstalledExtension, InstallError> {
    Ok(verify_installed_report(home, name)?.installed)
}

/// [`verify_installed`], plus the corrupt newer entries beside the running build.
///
/// A binary is re-hashed against its entry. An npm/uv tree is not: its
/// tarball is not kept and the unpacked tree has no stable hash (an
/// interpreter may write caches such as `__pycache__` in it where no sandbox
/// stops it), so its approval binds the tarball sha256 checked at install
/// (`mount::artefact_pin`). TODO(EXT-ANCHOR-8): a tree manifest pinned at install.
pub fn verify_installed_report(home: &Path, name: &str) -> Result<VerifiedInstall, InstallError> {
    let (installed, corrupt) = scan_installed(home, name)?;
    let installed = installed.ok_or_else(|| InstallError::NotInstalled(name.to_owned()))?;
    // A corrupt newer entry never runs (`load_installed` skips it), so the valid
    // build that does run is verified; the corrupt one goes back to the caller
    // (`aux ext verify` prints it, `--accept` refuses a silent downgrade).
    let newer = |version: &String| {
        super::catalog::compare_versions(version, &installed.version) == std::cmp::Ordering::Greater
    };
    let mut corrupt_newer: Vec<String> = corrupt.into_iter().filter(newer).collect();
    corrupt_newer.sort_by(|a, b| super::catalog::compare_versions(a, b));
    if installed.entry.source.kind == SourceType::Binary {
        // Read through the verified home: a link planted for the artefact is
        // refused, never followed, so an outside file is never hashed.
        let handle = kernel_core::SandboxHome::open_existing(home)?;
        let rel = Path::new("extensions")
            .join(format!("{name}@{}", installed.version))
            .join(&installed.entry.run.command);
        let mut bytes = Vec::new();
        let mut file = handle.open_read_existing(&rel, MAX_ARTEFACT_BYTES as u64)?;
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        let actual = hex(&Sha256::digest(&bytes));
        if actual != installed.entry.source.sha256.to_ascii_lowercase() {
            return Err(InstallError::HashMismatch {
                name: name.to_owned(),
                expected: installed.entry.source.sha256.clone(),
                actual,
            });
        }
    }
    Ok(VerifiedInstall {
        installed,
        corrupt_newer,
    })
}

/// Remove every `<name>@*` tree, its state, its mounts and its secrets.
///
/// Returns the number of install trees deleted. The Ledger keeps its history.
/// The approval row is kept as `state/<name>.last.json` (EXT-ANCHOR-10): a
/// later install diffs over it like an upgrade, never a fresh yes.
pub fn remove(home: &Path, name: &str) -> Result<usize, InstallError> {
    remove_after_open(home, name, false, || {})
}

/// [`remove`] that also drops the last approval (`aux ext remove --forget`):
/// the next install is a true first install.
pub fn remove_and_forget(home: &Path, name: &str) -> Result<usize, InstallError> {
    remove_after_open(home, name, true, || {})
}

/// `remove`, running `after_open` once the home handle is open: the seam the
/// tests plant a swapped link through, as a swap after the check would.
fn remove_after_open(
    home: &Path,
    name: &str,
    forget: bool,
    after_open: impl FnOnce(),
) -> Result<usize, InstallError> {
    if !valid_name(name) {
        return Err(InstallError::NotInstalled(name.to_owned()));
    }
    // An installed entry that cannot be read stops the removal before anything
    // changes (no row and a corrupt entry is not refused: it is swept below).
    if super::mount::load_state(home, name).is_none()
        && !super::mount::state_row_is_corrupt(home, name)
    {
        scan_installed(home, name)?;
    }
    // One rule: the trees go, then the mounts and secrets, and the state row
    // last, so a failure anywhere leaves the row (and its secret names) for a
    // retry. A refusal stops there and returns the error.
    // One handle for the whole removal: the home is verified once, before any
    // change, and the state row is unlinked through that same handle.
    let home_handle = open_home(home)?;
    let mut removed = 0;
    if let Some(handle) = home_handle.as_ref() {
        after_open();
        let mut first_error = None;
        removed = remove_trees(handle, name, &mut |err| {
            first_error.get_or_insert(err);
        });
        if let Some(err) = first_error {
            return Err(err);
        }
        // A linked `state/` is refused here, before mounts or `.env` change.
        anchored_dir_exists(handle, &Path::new("extensions").join("state"))?;
    }
    super::mount::remove_from_all_mounts(home, name)?;
    // Every key under this extension's own `EXT_<NAME>__` prefix goes, not only
    // the names a record lists: every valid secret name carries the prefix, so an
    // OAuth token (never in the record), an unreadable row and a retry after a
    // half-done removal all leave nothing in `.env`. The row goes last.
    remove_secret_namespace(home, &super::catalog::secret_prefix(name))?;
    if let Some(handle) = home_handle.as_ref() {
        keep_last_row(handle, name, forget)?;
        remove_state_row(handle, name)?;
    }
    Ok(removed)
}

/// Delete every `extensions/<name>@*` tree through the verified home, after it
/// is verified: a link anywhere on the way is refused, never followed. Returns
/// how many trees went; each failure is passed to `record`.
fn remove_trees(
    handle: &kernel_core::SandboxHome,
    name: &str,
    record: &mut impl FnMut(InstallError),
) -> usize {
    remove_trees_after_check(handle, name, record, &mut |_| {})
}

fn remove_trees_after_check(
    handle: &kernel_core::SandboxHome,
    name: &str,
    record: &mut impl FnMut(InstallError),
    after_check: &mut dyn FnMut(&str),
) -> usize {
    use std::os::unix::fs::MetadataExt;
    let extensions = Path::new("extensions");
    let id = |dir: &std::fs::File| dir.metadata().map(|meta| (meta.dev(), meta.ino()));
    // Listed from the fd the kernel opened, never by path. A root that exists
    // but cannot be read is an error, never "nothing to remove".
    let listed = match handle.open_dir(extensions) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return 0,
        opened => opened.and_then(|dir| Ok((id(&dir)?, list_fd(&dir)?, dir))),
    };
    let (root, names, root_dir) = match listed {
        Ok(listed) => listed,
        Err(err) => {
            record(err.into());
            return 0;
        }
    };
    let names: Vec<_> = (names.into_iter())
        .filter(|file_name| file_name.to_string_lossy().starts_with(&format!("{name}@")))
        .collect();
    // Before any unlink, `extensions/` and every directory of every tree are
    // checked against the home's mount: a mount anywhere refuses the whole
    // removal and every tree stays, every mode the scan widened put back.
    let home = match scan_for_mounts(&root_dir, &names) {
        Ok(home) => home,
        Err(err) => {
            record(err.into());
            return 0;
        }
    };
    after_check("listed");
    let mut removed = 0;
    for file_name in names {
        // `extensions/` must still be the listed directory (a link is refused).
        // The tree is opened `O_NOFOLLOW` from the listed fd and removed only
        // through the fds opened from it, never by re-resolving a path.
        let rel = extensions.join(&file_name);
        let result = handle.open_dir(extensions).and_then(|dir| {
            if id(&dir)? != root {
                return Err(refusal(extensions, "a changé", "changed"));
            }
            remove_tree_in(&root_dir, &file_name, &rel, &home, &mut *after_check)
        });
        match result {
            Ok(()) => removed += 1,
            Err(err) => record(err.into()),
        }
    }
    removed
}

/// The home's [`MountFacts`] (`..` of the open `extensions/` dir `root`); a
/// mount at `extensions/` itself is refused.
fn home_facts(root: &std::fs::File) -> std::io::Result<MountFacts> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: `root` is an open directory fd and `..` a NUL-terminated string.
    let fd = unsafe { libc::openat(root.as_raw_fd(), c"..".as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, valid descriptor nothing else owns.
    let home = mount_facts(&unsafe { std::fs::File::from_raw_fd(fd) }, c"..")?;
    if is_mount(&mount_facts(root, c"extensions")?, &home) {
        let extensions = Path::new("extensions");
        return Err(refusal(extensions, MOUNT_POINT.0, MOUNT_POINT.1));
    }
    Ok(home)
}

/// The home's [`MountFacts`], once `extensions/` and every entry of the trees
/// `names` show them. A link tree is left to the removal. Every mode the scan
/// changed is put back, whether it passes or refuses.
fn scan_for_mounts(
    root: &std::fs::File,
    names: &[std::ffi::OsString],
) -> std::io::Result<MountFacts> {
    let home = home_facts(root)?;
    let mut unlocked = Unlocked::new();
    let mut scan = || -> std::io::Result<()> {
        for name in names {
            let rel = Path::new("extensions").join(name);
            let found = open_child_dir(root, name, &home, &rel, MOUNT_POINT, Some(&mut unlocked));
            if let Some(tree) = found? {
                empty_tree(&rel, &tree, &home, Some(&mut unlocked))?;
            }
        }
        Ok(())
    };
    let scanned = scan();
    match (scanned, restore_modes(&mut unlocked)) {
        (Ok(()), Ok(())) => Ok(home),
        (Err(err), Ok(())) | (Ok(()), Err(err)) => Err(err),
        // A refusal whose modes could not all go back says both.
        (Err(err), Err(restore)) => Err(std::io::Error::new(
            err.kind(),
            format!("{err}; mode restore failed: {restore}"),
        )),
    }
}

/// A `PermissionDenied` sandbox refusal at `rel`, in French and English.
fn refusal(rel: &Path, fr: &str, en: &str) -> std::io::Error {
    let at = rel.display();
    let msg = format!("refus de sandbox : {at} {fr}. / sandbox refused: {at} {en}.");
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
}

/// Copy a valid `state/<name>.json` to `state/<name>.last.json` (0600, through
/// the verified home), or drop the last row with `forget`. A missing or
/// corrupt row leaves any older last row as it is.
fn keep_last_row(
    handle: &kernel_core::SandboxHome,
    name: &str,
    forget: bool,
) -> std::io::Result<()> {
    let state_dir = Path::new("extensions").join("state");
    if !anchored_dir_exists(handle, &state_dir)? {
        return Ok(());
    }
    let last = super::mount::last_rel(name);
    if forget {
        return handle.remove_file(&last).map(|_| ());
    }
    let row = state_dir.join(format!("{name}.json"));
    if let super::ReadAt::Text(text) = super::read_text_at_checked(handle, &row, MAX_ENTRY_BYTES) {
        let parsed = serde_json::from_str::<super::mount::ExtensionState>(&text);
        if parsed.is_ok_and(|state| state.name == name) {
            handle.write_atomic(&last, text.as_bytes(), 0o600)?;
        }
    }
    Ok(())
}

/// Unlink `extensions/state/<name>.json` through the verified home. The row is
/// unlinked itself (a FIFO, link or dangling link included), never its target,
/// and a linked `state/` directory is refused.
fn remove_state_row(handle: &kernel_core::SandboxHome, name: &str) -> std::io::Result<()> {
    let state_dir = Path::new("extensions").join("state");
    if anchored_dir_exists(handle, &state_dir)? {
        handle.remove_file(&state_dir.join(format!("{name}.json")))?;
    }
    Ok(())
}

/// Drop the named keys from `~/.auxesis/.env`, keeping every other line.
///
/// A line is dropped exactly when the kernel reader would read it as one of
/// `names` (`export`, whitespace, quote and CRLF rules included), so removal
/// and reading cannot disagree.
pub fn remove_secrets(home: &Path, names: &[String]) -> std::io::Result<()> {
    // No home means no `.env` to edit.
    if !home.is_dir() {
        return Ok(());
    }
    let names: BTreeSet<String> = names.iter().cloned().collect();
    // Serialized with every other `.env` writer (provider key saves, `aux secret
    // set`) by the shared config lock. Without it, a save that lands between this
    // read and the write is erased by the stale text written here.
    kernel_core::with_config_lock(home, || rewrite_env(home, &names))
        .map_err(std::io::Error::other)?
}

/// Drop every `.env` key that starts with `prefix` (one extension's own
/// `EXT_<NAME>__` namespace), under the config lock like `remove_secrets`.
fn remove_secret_namespace(home: &Path, prefix: &str) -> std::io::Result<()> {
    if !home.is_dir() {
        return Ok(());
    }
    // The key as `kernel_core::env_file::parse` reads it.
    let key = |line: &str| -> Option<String> {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        Some(line.split_once('=')?.0.trim().to_owned())
    };
    kernel_core::with_config_lock(home, || {
        let handle = kernel_core::SandboxHome::open_existing(home)?;
        let text = read_env(&handle)?.unwrap_or_default();
        let names: BTreeSet<String> = (text.lines().filter_map(key))
            .filter(|name| name.starts_with(prefix))
            .collect();
        match names.is_empty() {
            true => Ok(()),
            false => rewrite_env(home, &names),
        }
    })
    .map_err(std::io::Error::other)?
}

/// Upsert one named secret in `<home>/.env` (mode 0600), keeping every other
/// line. The extension OAuth token store uses this (E5); the value is never
/// logged and never appears in an error.
pub fn set_secret(home: &Path, name: &str, value: &str) -> std::io::Result<()> {
    if !home.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "auxesis home is missing",
        ));
    }
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid secret entry",
        ));
    }
    // Serialized with every other `.env` writer by the shared config lock (the
    // same guard `remove_secrets` and the provider key save take).
    kernel_core::with_config_lock(home, || rewrite_one_env(home, name, value))
        .map_err(std::io::Error::other)?
}

/// Read `.env`, drop the named line, append the new one and write through the
/// gateway. The caller holds the config lock. A kept line keeps its ending
/// (LF, CRLF); an unterminated last line is ended before the new one, and the
/// new line takes the file's first ending.
fn rewrite_one_env(home: &Path, name: &str, value: &str) -> std::io::Result<()> {
    let handle = kernel_core::SandboxHome::open_existing(home)?;
    let existing = read_env(&handle)?.unwrap_or_default();
    let names: BTreeSet<String> = std::iter::once(name.to_owned()).collect();
    let eol = match existing.split_once('\n') {
        Some((first, _)) if first.ends_with('\r') => "\r\n",
        _ => "\n",
    };
    let mut kept = String::with_capacity(existing.len() + name.len() + value.len() + 2);
    for line in existing.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        if kernel_core::env_file::parse(bare.strip_suffix('\r').unwrap_or(bare), &names).is_empty()
        {
            kept.push_str(line);
        }
    }
    if !kept.is_empty() && !kept.ends_with('\n') {
        kept.push_str(eol);
    }
    kept.push_str(&format!("{name}={value}{eol}"));
    handle.write_atomic(Path::new(ENV_FILE), kept.as_bytes(), 0o600)
}

/// Read `.env` and write back every line except the named keys, through the
/// gateway. The caller holds the config lock.
fn rewrite_env(home: &Path, names: &BTreeSet<String>) -> std::io::Result<()> {
    let handle = kernel_core::SandboxHome::open_existing(home)?;
    // No file means no secrets to drop. Any other read failure is reported: a
    // silent Ok would leave the key in place with nothing said.
    let Some(text) = read_env(&handle)? else {
        return Ok(());
    };
    // A kept line keeps its ending (LF, CRLF, none); its key is read without it.
    let mut kept = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let bare = match line.strip_suffix('\n') {
            Some(bare) => bare.strip_suffix('\r').unwrap_or(bare),
            None => line,
        };
        if kernel_core::env_file::parse(bare, names).is_empty() {
            kept.push_str(line);
        }
    }
    // The gateway stages a private temp file, fsyncs it and renames it over `.env`.
    handle.write_atomic(Path::new(ENV_FILE), kept.as_bytes(), 0o600)
}

/// The text of `.env`, or `None` when there is no file. The gateway refuses a
/// symlink, a FIFO, a device and any other non-regular file without following it.
fn read_env(handle: &kernel_core::SandboxHome) -> std::io::Result<Option<String>> {
    let mut file = match handle.open_read_existing(Path::new(ENV_FILE), MAX_ENV_BYTES) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut text = String::new();
    std::io::Read::read_to_string(&mut file, &mut text)?;
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::catalog::{EntryKind, Run, Sensitivity, Source};

    #[test]
    fn a_locked_directory_is_opened_and_made_writable_without_following_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir_all(locked.join("inner")).unwrap();
        set_mode(&locked.join("inner"), 0o000).unwrap();
        set_mode(&locked, 0o000).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("link")).unwrap();
        let parent = std::fs::File::open(dir.path()).unwrap();
        let home = mount_facts(&parent, c".").unwrap();
        let open = |at: &std::fs::File, name: &str| {
            let name = std::ffi::OsStr::new(name);
            open_child_dir(at, name, &home, &locked, HAS_MOUNT, None).unwrap()
        };
        assert!(open(&parent, "link").is_none(), "a link is never opened");
        let opened = open(&parent, "locked");
        let mode = |path: &Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        // Root opens a 000 directory without the chmod; anyone else gets u+rwx added.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(mode(&locked), 0o700, "the target gets u+rwx, nothing more");
        }
        let inner = open(&opened.expect("a 000 directory opens"), "inner");
        assert!(inner.is_some() && std::fs::read_dir(locked.join("inner")).is_ok());
    }

    fn binary_entry(name: &str, bytes: &[u8], version: &str) -> Entry {
        Entry {
            name: name.to_owned(),
            kind: EntryKind::Mcp,
            version: version.to_owned(),
            licence: "MIT".to_owned(),
            reviewed: true,
            sensitivity: Sensitivity::Public,
            summary_en: String::new(),
            summary_fr: String::new(),
            source: Source {
                kind: SourceType::Binary,
                package: "server".to_owned(),
                sha256: hex(&Sha256::digest(bytes)),
            },
            run: Run {
                transport: Transport::Stdio,
                command: "server".to_owned(),
                args: Vec::new(),
            },
            tools: Vec::new(),
            oauth: None,
            meta: None,
        }
    }

    #[tokio::test]
    async fn an_artefact_over_the_size_cap_is_refused_before_it_is_kept() {
        // 50 MB plus one byte, from a loopback server the test policy allows.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![
                0u8;
                50 * 1024 * 1024
                    + 1
            ]))
            .mount(&server)
            .await;
        let url = format!("{}/artefact.tgz", server.uri());
        // Match the result without printing it: a refused body must not be dumped.
        let Err(err) = download_bytes(&url, true).await else {
            panic!("an oversized artefact must be refused");
        };
        assert!(
            matches!(&err, InstallError::Download(message) if message.contains("size limit")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn sha256_mismatch_leaves_nothing_on_disk() {
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server");
        std::fs::write(&path, b"real").unwrap();
        let mut entry = binary_entry("demo", b"expected", "1.0.0");
        entry.source.package = path.to_string_lossy().into_owned();
        // sha256 is of b"expected", the file holds b"real".
        let err = install(
            home.path(),
            &entry,
            &InstallOptions {
                allow_loopback: true,
                pin: false,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, InstallError::HashMismatch { .. }));
        assert!(!extensions_dir(home.path()).join("demo@1.0.0").exists());
    }

    #[tokio::test]
    async fn a_binary_installs_and_removes_cleanly() {
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        let mut entry = binary_entry("demo", b"#!/bin/sh\n", "1.0.0");
        entry.source.package = path.to_string_lossy().into_owned();
        let installed = install(
            home.path(),
            &entry,
            &InstallOptions {
                allow_loopback: true,
                pin: false,
            },
        )
        .await
        .unwrap();
        assert!(installed.dir.join("server").is_file());
        assert!(installed.work_dir().is_dir());
        assert!(installed.dir.join("entry.toml").is_file());

        let removed = remove(home.path(), "demo").unwrap();
        assert_eq!(removed, 1);
        assert!(!extensions_dir(home.path()).join("demo@1.0.0").exists());
        assert!(load_installed(home.path(), "demo").is_none());
    }

    #[test]
    fn remove_drops_only_the_named_secrets() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".env"), "KEEP=1\nDROP=2\nOTHER=3\n").unwrap();
        remove_secrets(home.path(), &["DROP".to_owned()]).unwrap();
        let text = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert!(text.contains("KEEP=1"));
        assert!(text.contains("OTHER=3"));
        assert!(!text.contains("DROP=2"));
    }

    #[test]
    fn tarball_path_traversal_is_refused() {
        assert!(safe_relative(Path::new("package/../../evil")).is_err());
        assert!(safe_relative(Path::new("/etc/passwd")).is_err());
        assert_eq!(
            safe_relative(Path::new("package/dist/index.js")).unwrap(),
            PathBuf::from("dist/index.js")
        );
    }

    // ---- The tar unpack refuses every non-Regular/Directory entry -------

    #[test]
    fn a_gzip_bomb_is_refused_before_it_is_expanded() {
        // 201 MB of zeros: a few hundred kilobytes compressed, over the 200 MB cap.
        const BOMB: u64 = 201 * 1024 * 1024;
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(BOMB);
        builder
            .append_data(
                &mut header,
                "bomb.bin",
                std::io::Read::take(std::io::repeat(0), BOMB),
            )
            .unwrap();
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        assert!(bytes.len() < 1024 * 1024, "the bomb is small on the wire");

        let dir = tempfile::tempdir().unwrap();
        let Err(err) = unpack_tarball(dir.path(), &bytes) else {
            panic!("a gzip bomb must be refused");
        };
        assert!(err.to_string().contains("size limit"), "{err}");
        assert!(
            !dir.path().join("bomb.bin").exists(),
            "nothing of the bomb is kept"
        );
    }

    #[test]
    fn an_archive_with_too_many_entries_is_refused() {
        let mut builder = tar::Builder::new(Vec::new());
        for index in 0..=10_000 {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(0);
            builder
                .append_data(&mut header, format!("f{index}"), std::io::empty())
                .unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &bytes).unwrap();
        let gz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let Err(err) = unpack_tarball(dir.path(), &gz) else {
            panic!("an archive with 10001 entries must be refused");
        };
        assert!(err.to_string().contains("entries"), "{err}");
    }

    fn gz_tar(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        build(&mut builder);
        let tar_bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn header(path: &str, kind: tar::EntryType, link: Option<&str>) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        // Write the raw name/link bytes: `set_path`/`set_link_name` refuse the
        // absolute and `..` shapes the tests must plant.
        {
            let gnu = header.as_gnu_mut().unwrap();
            let name = path.as_bytes();
            assert!(name.len() <= gnu.name.len());
            gnu.name[..name.len()].copy_from_slice(name);
            if let Some(link) = link {
                let link = link.as_bytes();
                assert!(link.len() <= gnu.linkname.len());
                gnu.linkname[..link.len()].copy_from_slice(link);
            }
        }
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(kind);
        header.set_cksum();
        header
    }

    fn regular(path: &str, data: &[u8]) -> (tar::Header, Vec<u8>) {
        let mut header = header(path, tar::EntryType::Regular, None);
        header.set_size(data.len() as u64);
        header.set_cksum();
        (header, data.to_vec())
    }

    #[test]
    fn symlink_entries_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(|builder| {
            let header = header("package/link", tar::EntryType::Symlink, Some("/etc/passwd"));
            builder.append(&header, &[][..]).unwrap();
        });
        let err = unpack_tarball(dir.path(), &gz).unwrap_err();
        assert!(matches!(err, InstallError::Unpack(_)));
        assert!(!dir.path().join("link").exists());
    }

    #[test]
    fn hardlink_entries_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(|builder| {
            let header = header("package/link", tar::EntryType::Link, Some("package/server"));
            builder.append(&header, &[][..]).unwrap();
        });
        let err = unpack_tarball(dir.path(), &gz).unwrap_err();
        assert!(matches!(err, InstallError::Unpack(_)));
        assert!(!dir.path().join("link").exists());
    }

    #[test]
    fn device_and_fifo_entries_are_refused() {
        for kind in [
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let gz = gz_tar(|builder| {
                let header = header("package/node", kind, None);
                builder.append(&header, &[][..]).unwrap();
            });
            let err = unpack_tarball(dir.path(), &gz).unwrap_err();
            assert!(matches!(err, InstallError::Unpack(_)));
            assert!(!dir.path().join("node").exists());
        }
    }

    #[test]
    fn write_through_a_planted_symlink_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("evil")).unwrap();
        let gz = gz_tar(|builder| {
            let (header, data) = regular("package/evil/pwned", b"owned");
            builder.append(&header, &data[..]).unwrap();
        });
        let result = unpack_tarball(dir.path(), &gz);
        assert!(result.is_err(), "unpack must refuse the planted symlink");
        assert!(!outside.path().join("pwned").exists());
    }

    #[test]
    fn absolute_and_parent_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = gz_tar(|builder| {
            let (header, data) = regular("/etc/passwd", b"x");
            builder.append(&header, &data[..]).unwrap();
        });
        assert!(unpack_tarball(dir.path(), &absolute).is_err());
        let parent = gz_tar(|builder| {
            let (header, data) = regular("package/../../evil", b"x");
            builder.append(&header, &data[..]).unwrap();
        });
        assert!(unpack_tarball(dir.path(), &parent).is_err());
        assert!(!dir.path().join("evil").exists());
    }

    #[test]
    fn a_clean_tarball_unpacks_stripping_one_component() {
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(|builder| {
            let mut dir_header = header("package/dist", tar::EntryType::Directory, None);
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_cksum();
            builder.append(&dir_header, &[][..]).unwrap();
            let (header, data) = regular("package/dist/index.js", b"ok");
            builder.append(&header, &data[..]).unwrap();
        });
        unpack_tarball(dir.path(), &gz).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("dist/index.js")).unwrap(),
            "ok"
        );
    }

    // ---- Version and secret-name validation ---------------------------

    #[test]
    fn invalid_versions_are_refused_by_installable() {
        let mut entry = binary_entry("demo", b"x", "1.0.0");
        for version in ["../evil", ".hidden", "-1", "a b", &"x".repeat(65)] {
            entry.version = version.to_owned();
            assert!(
                entry.installable().is_err(),
                "version `{version}` must be refused"
            );
        }
        for version in ["1.4.2", "2026.10.09-1", "1.0.0-rc.1+build"] {
            entry.version = version.to_owned();
            assert!(
                entry.installable().is_ok(),
                "version `{version}` must be accepted"
            );
        }
    }

    #[test]
    fn ensure_within_refuses_an_escape() {
        let root = Path::new("/tmp/ext");
        assert!(ensure_within(root, Path::new("/tmp/ext/demo@1.0.0")).is_ok());
        assert!(ensure_within(root, Path::new("/tmp/ext/../escape")).is_err());
        assert!(ensure_within(root, Path::new("/tmp/other")).is_err());
        assert!(ensure_within(root, root).is_err());
    }

    #[tokio::test]
    async fn a_traversal_version_is_refused_and_creates_nothing() {
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        let mut entry = binary_entry("demo", b"#!/bin/sh\n", "../../escape");
        entry.source.package = path.to_string_lossy().into_owned();
        assert!(install(
            home.path(),
            &entry,
            &InstallOptions {
                allow_loopback: true,
                pin: false,
            },
        )
        .await
        .is_err());
        // Nothing was created under the extensions root.
        let root = extensions_dir(home.path());
        assert!(!root.join("escape").exists());
        assert_eq!(std::fs::read_dir(&root).map(|r| r.count()).unwrap_or(0), 0);
    }

    #[tokio::test]
    async fn install_refuses_a_secret_name_outside_the_extension_namespace() {
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        let mut entry = binary_entry("demo", b"#!/bin/sh\n", "1.0.0");
        entry.source.package = path.to_string_lossy().into_owned();
        entry.tools = vec![crate::extensions::catalog::EntryTool {
            name: "ping".to_owned(),
            description: String::new(),
            network: Vec::new(),
            secrets: vec!["AUX_KEY_DEEPSEEK".to_owned()],
            auth: "none".to_owned(),
            fs: Vec::new(),
        }];
        std::fs::write(home.path().join(".env"), "AUX_KEY_DEEPSEEK=keep\n").unwrap();
        let err = install(
            home.path(),
            &entry,
            &InstallOptions {
                allow_loopback: true,
                pin: false,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, InstallError::Phase1(_)));
        assert!(!extensions_dir(home.path()).join("demo@1.0.0").exists());
        let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert!(env.contains("AUX_KEY_DEEPSEEK=keep"));
    }

    // ---- N3: install/remove robustness ------------------------------------

    fn tarball_entry(name: &str, bytes: &[u8], version: &str) -> Entry {
        let mut entry = binary_entry(name, b"unused", version);
        entry.source.kind = SourceType::Npm;
        entry.source.sha256 = hex(&Sha256::digest(bytes));
        entry
    }

    #[tokio::test]
    async fn a_regular_file_at_work_is_refused_with_full_cleanup() {
        let home = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let gz = gz_tar(|builder| {
            let (header, data) = regular("package/work", b"not a directory");
            builder.append(&header, &data[..]).unwrap();
        });
        let path = scratch.path().join("pkg.tgz");
        std::fs::write(&path, &gz).unwrap();
        let mut entry = tarball_entry("demo", &gz, "1.0.0");
        entry.source.package = path.to_string_lossy().into_owned();
        let err = install(
            home.path(),
            &entry,
            &InstallOptions {
                allow_loopback: true,
                pin: false,
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, InstallError::Unpack(_) | InstallError::Io(_)),
            "{err:?}"
        );
        assert!(
            !extensions_dir(home.path()).join("demo@1.0.0").exists(),
            "a failed install must leave nothing behind"
        );
    }

    #[test]
    fn a_read_only_install_tree_can_still_be_removed() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/file"), b"x").unwrap();
        // 0500, not 0000: the guarded home scan must still be able to read it.
        set_mode(&dir.join("sub"), 0o500).unwrap();
        set_mode(&dir, 0o555).unwrap();
        let removed = remove(home.path(), "demo").unwrap();
        assert_eq!(removed, 1);
        assert!(!dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn remove_touches_nothing_in_a_home_it_cannot_verify() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o500).unwrap();
        // The guard (on in CI) refuses a home holding a link; off, this home verifies.
        std::os::unix::fs::symlink("gone", home.path().join("planted")).unwrap();
        let result = remove(home.path(), "demo");
        if kernel_core::sandbox_guard_active() {
            assert!(result.is_err());
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o500, "no mode changes before verification");
        }
        let traversal = remove(home.path(), "../x");
        assert!(matches!(traversal, Err(InstallError::NotInstalled(_))));
    }

    #[cfg(unix)]
    #[test]
    fn force_private_dir_never_follows_a_swapped_parent() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("state");
        std::fs::create_dir(&target).unwrap();
        set_mode(&target, 0o755).unwrap();
        let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
        // `extensions/` is swapped for a link after the handle was opened.
        std::os::unix::fs::symlink(outside.path(), home.path().join("extensions")).unwrap();
        assert!(force_private_dir(&handle, Path::new("extensions/state")).is_err());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "the target's mode is kept");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_install_through_a_linked_home_lands_in_the_real_home() {
        let scratch = tempfile::tempdir().unwrap();
        let real = scratch.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let gz = gz_tar(|builder| {
            let (header, data) = regular("package/index.js", b"x");
            builder.append(&header, &data[..]).unwrap();
        });
        let path = scratch.path().join("pkg.tgz");
        std::fs::write(&path, &gz).unwrap();
        let mut entry = tarball_entry("demo", &gz, "1.0.0");
        entry.source.package = path.to_string_lossy().into_owned();
        let options = InstallOptions {
            allow_loopback: true,
            pin: false,
        };
        let installed = install(&link, &entry, &options).await.unwrap();
        let real = real.canonicalize().unwrap();
        assert!(installed.dir.starts_with(&real), "{:?}", installed.dir);
        assert!(installed.dir.join("index.js").is_file());
        assert!(installed.work_dir().is_dir());
        assert!(real.join("extensions/demo@1.0.0/index.js").is_file());
    }

    // Links are planted after the handle opens, as a swap would be: the guard
    // (on in CI) refuses a home that already holds one before any of this runs.
    #[cfg(unix)]
    #[test]
    fn a_state_dir_swapped_for_a_link_is_refused_at_the_link() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("demo.json"), b"{}").unwrap();
        std::fs::create_dir(home.path().join("extensions")).unwrap();
        let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
        let state = home.path().join("extensions/state");
        std::os::unix::fs::symlink(outside.path(), &state).unwrap();
        let err = remove_state_row(&handle, "demo").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("refus de sandbox"), "{err}");
        assert!(outside.path().join("demo.json").is_file());
        assert!(std::fs::symlink_metadata(&state).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_tree_swapped_for_a_link_is_refused_and_its_target_survives() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("kept"), b"x").unwrap();
        std::fs::create_dir(home.path().join("extensions")).unwrap();
        let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
        let tree = extensions_dir(home.path()).join("demo@1.0.0");
        std::os::unix::fs::symlink(outside.path(), &tree).unwrap();
        let mut errors = Vec::new();
        let removed = remove_trees(&handle, "demo", &mut |err| errors.push(err.to_string()));
        assert_eq!(removed, 0);
        assert!(
            errors.len() == 1 && errors[0].contains("refus de sandbox"),
            "{errors:?}"
        );
        assert!(outside.path().join("kept").is_file());
    }

    fn demo_state() -> crate::extensions::mount::ExtensionState {
        crate::extensions::mount::ExtensionState {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            kind: "mcp".to_owned(),
            frozen: false,
            tools: Default::default(),
            network: Vec::new(),
            secrets: Vec::new(),
            oauth: None,
            artefact: None,
            launch: None,
        }
    }

    // A swapped link, planted once `remove` holds its home handle, through the
    // public path. `extensions/` exists first, so the link is the only change.
    #[cfg(unix)]
    fn remove_through_a_swapped_link(link: &str, outside: &Path) -> InstallError {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("extensions")).unwrap();
        let planted = home.path().join(link);
        let err = remove_after_open(home.path(), "demo", false, || {
            std::os::unix::fs::symlink(outside, &planted).unwrap();
        })
        .unwrap_err();
        assert!(
            std::fs::symlink_metadata(&planted).is_ok(),
            "link not followed or unlinked"
        );
        err
    }

    #[cfg(unix)]
    #[test]
    fn remove_refuses_a_state_dir_swapped_for_a_link_and_keeps_its_target() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("demo.json"), b"{}").unwrap();
        let err = remove_through_a_swapped_link("extensions/state", outside.path());
        let InstallError::Io(io) = &err else {
            panic!("{err:?}")
        };
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("extensions/state"), "{err}");
        assert!(outside.path().join("demo.json").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn remove_refuses_a_tree_swapped_for_a_link_and_keeps_its_target() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("kept"), b"x").unwrap();
        let err = remove_through_a_swapped_link("extensions/demo@1.0.0", outside.path());
        let InstallError::Io(io) = &err else {
            panic!("{err:?}")
        };
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("demo@1.0.0"), "{err}");
        assert!(outside.path().join("kept").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn remove_refuses_a_home_holding_an_unreadable_tree_and_changes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let tree = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&tree).unwrap();
        crate::extensions::mount::store_state(home.path(), &demo_state()).unwrap();
        let row = home.path().join("extensions/state/demo.json");
        set_mode(&tree, 0o000).unwrap();
        // Decided before remove() runs: root reads a 000 tree.
        if std::fs::read_dir(&tree).is_ok() {
            set_mode(&tree, 0o700).unwrap();
            eprintln!("skipped: a 000 tree is readable here (root)");
            return;
        }
        let result = remove(home.path(), "demo");
        if !kernel_core::sandbox_guard_active() {
            // No home scan refuses it: remove unlocks the 000 tree and deletes it.
            assert_eq!(result.unwrap(), 1);
            assert!(!tree.exists() && !row.exists(), "tree and row gone");
            return;
        }
        let mode = std::fs::metadata(&tree).map(|meta| meta.permissions().mode() & 0o777);
        set_mode(&tree, 0o700).unwrap();
        let err = result.unwrap_err();
        assert!(err.to_string().contains("refus de sandbox"), "{err}");
        assert!(err.to_string().contains("demo@1.0.0"), "{err}");
        assert_eq!(mode.unwrap(), 0o000, "no mode change before verification");
        assert!(tree.is_dir(), "the tree stays");
        assert!(row.is_file(), "the state row stays");
    }

    #[cfg(unix)]
    #[test]
    fn the_extensions_listing_follows_the_verified_home_never_a_link() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("leaked@1.0.0")).unwrap();
        let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
        let root = Path::new("extensions");
        assert!(
            list_dir_anchored(&handle, root).unwrap().is_none(),
            "absent"
        );
        std::fs::create_dir_all(home.path().join("extensions/demo@1.0.0")).unwrap();
        std::fs::write(home.path().join("extensions/mounts.json"), b"{}").unwrap();
        let mut names = list_dir_anchored(&handle, root).unwrap().unwrap();
        names.sort();
        assert_eq!(names, ["demo@1.0.0", "mounts.json"]);
        // `extensions/` is swapped for a link after the handle opened.
        std::fs::remove_dir_all(home.path().join("extensions")).unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("extensions")).unwrap();
        let err = list_dir_anchored(&handle, root).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn remove_unlinks_a_fifo_state_row() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("extensions/state");
        std::fs::create_dir_all(&dir).unwrap();
        let row = dir.join("demo.json");
        let mkfifo = std::process::Command::new("mkfifo").arg(&row).status();
        assert!(mkfifo.unwrap().success());
        remove(home.path(), "demo").unwrap();
        assert!(std::fs::symlink_metadata(&row).is_err(), "FIFO row gone");
    }

    #[cfg(unix)]
    #[test]
    fn a_link_or_dangling_state_row_is_unlinked_never_its_target() {
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("kept.json");
        std::fs::write(&target, b"{}").unwrap();
        for link_to in [target.clone(), outside.path().join("gone")] {
            let home = tempfile::tempdir().unwrap();
            let dir = home.path().join("extensions/state");
            std::fs::create_dir_all(&dir).unwrap();
            let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
            let row = dir.join("demo.json");
            std::os::unix::fs::symlink(&link_to, &row).unwrap();
            remove_state_row(&handle, "demo").unwrap();
            assert!(std::fs::symlink_metadata(&row).is_err(), "link row gone");
        }
        assert!(target.is_file(), "a link row's target survives");
    }

    #[test]
    fn remove_changes_nothing_else_when_the_tree_cannot_be_deleted() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("entry.toml"),
            toml::to_string(&binary_entry("demo", b"x", "1.0.0")).unwrap(),
        )
        .unwrap();
        // A mount re-hashes the binary, so the tree carries it.
        std::fs::write(dir.join("server"), b"x").unwrap();
        let mut state = crate::extensions::mount::ExtensionState {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            kind: "mcp".to_owned(),
            frozen: false,
            tools: Default::default(),
            network: Vec::new(),
            secrets: vec!["EXT_DEMO__TOKEN".to_owned()],
            oauth: None,
            artefact: Some(hex(&Sha256::digest(b"x"))),
            launch: Some(crate::extensions::mount::launch_pin(&binary_entry(
                "demo", b"x", "1.0.0",
            ))),
        };
        state.tools.insert("ping".to_owned(), "00".to_owned());
        crate::extensions::mount::store_state(home.path(), &state).unwrap();
        crate::extensions::mount::mount(home.path(), "demo", "alice").unwrap();
        std::fs::write(home.path().join(".env"), "EXT_DEMO__TOKEN=drop\nKEEP=1\n").unwrap();
        // Replace the tree with a regular file: `remove_dir_all` refuses it.
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, b"not a directory").unwrap();
        let result = remove(home.path(), "demo");
        assert!(result.is_err(), "a tree that cannot be deleted is reported");
        // The state, mount and secret stay for a retry: nothing is half-removed.
        assert!(crate::extensions::mount::load_state(home.path(), "demo").is_some());
        assert!(crate::extensions::mount::is_mounted(
            home.path(),
            "demo",
            "alice"
        ));
        let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert!(env.contains("EXT_DEMO__TOKEN=drop") && env.contains("KEEP=1"));
    }

    // The artefact is swapped for a link to an outside file: verify refuses it
    // and the outside file's hash is never computed into the error.
    #[cfg(unix)]
    #[test]
    fn verify_refuses_an_artefact_swapped_for_a_link() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"outside bytes").unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        let entry = binary_entry("demo", b"x", "1.0.0");
        std::fs::write(dir.join("entry.toml"), toml::to_string(&entry).unwrap()).unwrap();
        std::os::unix::fs::symlink(&secret, dir.join(&entry.run.command)).unwrap();
        let err = verify_installed(home.path(), "demo").unwrap_err();
        let leaked = hex(&Sha256::digest(b"outside bytes"));
        assert!(!matches!(err, InstallError::HashMismatch { .. }), "{err}");
        assert!(!err.to_string().contains(&leaked), "{err}");
    }

    #[test]
    fn remove_drops_every_spelling_the_kernel_reads() {
        let home = tempfile::tempdir().unwrap();
        let names: std::collections::BTreeSet<String> =
            ["EXT_FOO__TOKEN".to_owned()].into_iter().collect();
        let spellings = [
            "export EXT_FOO__TOKEN=v",
            "export    EXT_FOO__TOKEN = v",
            "  EXT_FOO__TOKEN=v",
            "EXT_FOO__TOKEN=\"quoted\"",
            "export EXT_FOO__TOKEN='single'",
            "EXT_FOO__TOKEN=v",
        ];
        for spelling in spellings {
            std::fs::write(
                home.path().join(".env"),
                format!("KEEP=1\r\n{spelling}\r\nEXT_FOO_BAR__TOKEN=keep\r\n"),
            )
            .unwrap();
            let mut state = crate::extensions::mount::ExtensionState {
                name: "foo".to_owned(),
                version: "1.0.0".to_owned(),
                kind: "mcp".to_owned(),
                frozen: false,
                tools: Default::default(),
                network: Vec::new(),
                secrets: vec!["EXT_FOO__TOKEN".to_owned()],
                oauth: None,
                artefact: None,
                launch: None,
            };
            state.tools.insert("ping".to_owned(), "00".to_owned());
            crate::extensions::mount::store_state(home.path(), &state).unwrap();
            remove(home.path(), "foo").unwrap();
            let text = std::fs::read_to_string(home.path().join(".env")).unwrap();
            assert!(
                kernel_core::env_file::parse(&text, &names).is_empty(),
                "`{spelling}` survived remove: {text}"
            );
            assert!(text.contains("KEEP=1"), "{text}");
            let foo_bar: std::collections::BTreeSet<String> =
                ["EXT_FOO_BAR__TOKEN".to_owned()].into_iter().collect();
            assert_eq!(
                kernel_core::env_file::parse(&text, &foo_bar)
                    .get("EXT_FOO_BAR__TOKEN")
                    .map(String::as_str),
                Some("keep"),
                "a hyphenated extension's key must be untouched: {text}"
            );
        }
    }

    #[test]
    fn remove_fails_when_the_extensions_root_cannot_be_read() {
        let home = tempfile::tempdir().unwrap();
        let root = extensions_dir(home.path());
        std::fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o000).unwrap();
        let readable = std::fs::read_dir(&root).is_ok();
        let result = remove(home.path(), "demo");
        set_mode(&root, 0o700).unwrap();
        if readable {
            // Root ignores the mode bits, so there is no unreadable root to test.
            eprintln!("skipped: the extensions root is readable despite mode 000");
            return;
        }
        assert!(
            result.is_err(),
            "an unreadable extensions root must fail remove, not report Ok(0)"
        );
    }

    #[test]
    fn remove_refuses_an_env_it_cannot_read_and_leaves_it_alone() {
        let home = tempfile::tempdir().unwrap();
        let env = home.path().join(".env");
        // Not UTF-8: the read fails, so nothing may be reported as removed.
        let bytes = b"KEEP=1\n\xff\xfe EXT_DEMO__TOKEN=drop\n".to_vec();
        std::fs::write(&env, &bytes).unwrap();
        let result = remove_secrets(home.path(), &["EXT_DEMO__TOKEN".to_owned()]);
        assert!(result.is_err(), "an unreadable .env must fail the removal");
        assert_eq!(std::fs::read(&env).unwrap(), bytes, ".env was rewritten");
    }

    #[cfg(unix)]
    #[test]
    fn remove_refuses_an_env_with_no_read_permission() {
        let home = tempfile::tempdir().unwrap();
        let env = home.path().join(".env");
        std::fs::write(&env, "EXT_DEMO__TOKEN=drop\n").unwrap();
        set_mode(&env, 0o000).unwrap();
        let readable = std::fs::read(&env).is_ok();
        let result = remove_secrets(home.path(), &["EXT_DEMO__TOKEN".to_owned()]);
        set_mode(&env, 0o600).unwrap();
        if readable {
            // Root ignores the mode bits, so there is no unreadable file to test.
            eprintln!("skipped: .env is readable despite mode 000");
            return;
        }
        assert!(result.is_err(), "a .env that cannot be read must fail");
    }

    #[cfg(unix)]
    #[test]
    fn remove_secrets_never_follows_a_symlinked_env() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().unwrap();
        let decoy = home.path().join("decoy.env");
        std::fs::write(&decoy, "EXT_DEMO__TOKEN=decoy\n").unwrap();
        let env = home.path().join(".env");
        symlink(&decoy, &env).unwrap();
        assert!(remove_secrets(home.path(), &["EXT_DEMO__TOKEN".to_owned()]).is_err());
        assert_eq!(
            std::fs::read_to_string(&decoy).unwrap(),
            "EXT_DEMO__TOKEN=decoy\n",
            "the symlink target was rewritten"
        );
        assert!(std::fs::symlink_metadata(&env).unwrap().is_symlink());
    }

    /// The provider writer's read-modify-write (`aux-providers` `set_named_in_env_file`):
    /// the config lock, a gateway read, a line replace, a gateway atomic write. It is
    /// repeated here because aux-runtime does not depend on aux-providers.
    fn upsert_env_key(home: &Path, name: &str, value: &str) {
        kernel_core::with_config_lock(home, || {
            let handle = kernel_core::SandboxHome::open(home).unwrap();
            let mut lines: Vec<String> = match read_env(&handle).unwrap() {
                Some(text) => text.lines().map(str::to_string).collect(),
                None => Vec::new(),
            };
            lines.retain(|line| !line.starts_with(&format!("{name}=")));
            lines.push(format!("{name}={value}"));
            let mut text = lines.join("\n");
            text.push('\n');
            handle
                .write_atomic(Path::new(ENV_FILE), text.as_bytes(), 0o600)
                .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn a_concurrent_secret_removal_never_erases_a_key_saved_meanwhile() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".env"), "KEEP=1\n").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let remover = {
            let home = home.path().to_path_buf();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    remove_secrets(&home, &["EXT_DEMO__TOKEN".to_owned()]).unwrap();
                }
            })
        };
        for index in 0..300 {
            upsert_env_key(
                home.path(),
                &format!("AUX_KEY_P{index}"),
                &format!("v{index}"),
            );
        }
        stop.store(true, Ordering::Relaxed);
        remover.join().unwrap();
        let text = std::fs::read_to_string(home.path().join(".env")).unwrap();
        let lost: Vec<usize> = (0..300)
            .filter(|index| !text.contains(&format!("AUX_KEY_P{index}=v{index}\n")))
            .collect();
        assert!(lost.is_empty(), "{} provider keys were lost", lost.len());
        assert!(text.contains("KEEP=1"));
    }

    #[test]
    fn remove_secrets_with_no_env_file_is_a_no_op() {
        let home = tempfile::tempdir().unwrap();
        remove_secrets(home.path(), &["EXT_DEMO__TOKEN".to_owned()]).unwrap();
        assert!(!home.path().join(".env").exists());
    }

    #[test]
    fn remove_drops_the_secrets_the_entry_declares_when_the_state_is_missing() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        let mut entry = binary_entry("demo", b"x", "1.0.0");
        entry.tools = vec![crate::extensions::catalog::EntryTool {
            name: "ping".to_owned(),
            description: String::new(),
            network: Vec::new(),
            secrets: vec!["EXT_DEMO__TOKEN".to_owned()],
            auth: "none".to_owned(),
            fs: Vec::new(),
        }];
        std::fs::write(dir.join("entry.toml"), toml::to_string(&entry).unwrap()).unwrap();
        std::fs::write(home.path().join(".env"), "EXT_DEMO__TOKEN=drop\nKEEP=1\n").unwrap();
        assert!(crate::extensions::mount::load_state(home.path(), "demo").is_none());
        assert_eq!(remove(home.path(), "demo").unwrap(), 1);
        let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert!(!env.contains("EXT_DEMO__TOKEN"), "{env}");
        assert!(env.contains("KEEP=1"), "{env}");
    }

    // DeepSeek #169 r2: a key no record names (the OAuth token store's) goes too;
    // a neighbour extension's namespace and other keys stay.
    #[test]
    fn remove_drops_an_oauth_token_no_record_names() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        let entry = binary_entry("demo", b"x", "1.0.0");
        std::fs::write(dir.join("entry.toml"), toml::to_string(&entry).unwrap()).unwrap();
        let env = "EXT_DEMO__OAUTH_TOKENS=refresh\nEXT_DEMO_X__K=1\nKEEP=1\n";
        std::fs::write(home.path().join(".env"), env).unwrap();
        assert_eq!(remove(home.path(), "demo").unwrap(), 1);
        let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert!(!env.contains("EXT_DEMO__OAUTH_TOKENS"), "{env}");
        assert!(
            env.contains("EXT_DEMO_X__K=1") && env.contains("KEEP=1"),
            "{env}"
        );
    }

    #[tokio::test]
    async fn a_failed_pin_removes_the_install_tree() {
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server");
        let script = b"#!/bin/sh\nexit 1\n";
        std::fs::write(&path, script).unwrap();
        let mut entry = binary_entry("demo", script, "1.0.0");
        entry.source.package = path.to_string_lossy().into_owned();
        let result = install(
            home.path(),
            &entry,
            &InstallOptions {
                allow_loopback: true,
                pin: true,
            },
        )
        .await;
        assert!(result.is_err(), "a server that exits at once cannot pin");
        assert!(
            !extensions_dir(home.path()).join("demo@1.0.0").exists(),
            "a failed pin must leave nothing behind"
        );
    }

    // `extensions/` is swapped once listed, for a link to an outside canary or
    // for a real replacement holding it: the canary is never touched.
    #[cfg(unix)]
    #[test]
    fn an_extensions_root_swapped_after_the_check_is_refused_and_the_canary_survives() {
        use std::os::unix::fs::PermissionsExt;
        for linked in [true, false] {
            let (home, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let (root, out) = (home.path().join("extensions"), outside.path().join("e"));
            std::fs::create_dir_all(out.join("demo@1.0.0/kept")).unwrap();
            std::fs::create_dir_all(root.join("demo@1.0.0")).unwrap();
            set_mode(&out.join("demo@1.0.0"), 0o500).unwrap();
            let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
            let mut errors = Vec::new();
            let removed =
                remove_trees_after_check(&handle, "demo", &mut |e| errors.push(e), &mut |at| {
                    if at != "listed" {
                        return;
                    }
                    std::fs::rename(&root, home.path().join("moved")).unwrap();
                    match linked {
                        true => std::os::unix::fs::symlink(&out, &root).unwrap(),
                        false => std::fs::rename(&out, &root).unwrap(),
                    }
                });
            let canary = root.join("demo@1.0.0");
            let mode = std::fs::metadata(&canary).unwrap().permissions().mode() & 0o777;
            set_mode(&canary, 0o700).unwrap();
            assert!(removed == 0 && errors.len() == 1, "{errors:?}");
            assert!(
                errors[0].to_string().contains("refus de sandbox"),
                "{errors:?}"
            );
            assert!(canary.join("kept").is_dir() && mode == 0o500, "canary kept");
        }
    }

    // An entry naming the secrets that cannot be read is a refusal, never "not
    // installed": remove (no state row) changes nothing while the key stays.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_entry_is_a_refusal_not_not_installed() {
        let home = tempfile::tempdir().unwrap();
        let toml_path = extensions_dir(home.path()).join("demo@1.0.0/entry.toml");
        std::fs::create_dir_all(toml_path.parent().unwrap()).unwrap();
        let mut entry = binary_entry("demo", b"x", "1.0.0");
        entry.tools = vec![crate::extensions::catalog::EntryTool {
            name: "ping".to_owned(),
            description: String::new(),
            network: Vec::new(),
            secrets: vec!["EXT_DEMO__TOKEN".to_owned()],
            auth: "none".to_owned(),
            fs: Vec::new(),
        }];
        std::fs::write(&toml_path, toml::to_string(&entry).unwrap()).unwrap();
        std::fs::write(home.path().join(".env"), "EXT_DEMO__TOKEN=keep\n").unwrap();
        set_mode(&toml_path, 0o000).unwrap();
        if std::fs::read(&toml_path).is_ok() {
            return eprintln!("skipped: a 000 entry is readable here (root)");
        }
        let verified = verify_installed(home.path(), "demo");
        let removed = remove(home.path(), "demo");
        let _ = set_mode(&toml_path, 0o600);
        assert!(!matches!(
            verified,
            Ok(_) | Err(InstallError::NotInstalled(_))
        ));
        assert!(removed.is_err() && toml_path.is_file(), "{removed:?}");
        let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert!(env.contains("EXT_DEMO__TOKEN"), "{env}");
    }

    // The tree is swapped, once opened and checked, for another directory of the
    // home: removal acts through the fd it opened, so the swapped-in one survives.
    #[cfg(unix)]
    #[test]
    fn a_tree_swapped_inside_the_home_after_its_check_leaves_the_swapped_in_dir() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("extensions");
        std::fs::create_dir_all(root.join("demo@1.0.0/sub")).unwrap();
        std::fs::create_dir_all(home.path().join("keep/inner")).unwrap();
        std::fs::write(home.path().join("keep/inner/file"), b"x").unwrap();
        let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
        let mut errors = Vec::new();
        let removed =
            remove_trees_after_check(&handle, "demo", &mut |e| errors.push(e), &mut |at| {
                if at == "opened" {
                    std::fs::rename(root.join("demo@1.0.0"), home.path().join("moved")).unwrap();
                    std::fs::rename(home.path().join("keep"), root.join("demo@1.0.0")).unwrap();
                }
            });
        let swapped = root.join("demo@1.0.0/inner/file");
        assert!(swapped.is_file(), "the swapped-in directory is untouched");
        assert!(removed == 0 && errors.len() == 1, "{errors:?}");
        assert!(
            errors[0].to_string().contains("refus de sandbox"),
            "{errors:?}"
        );
    }

    #[test]
    fn a_corrupt_old_entry_is_skipped_and_the_valid_newer_one_loads_and_removes() {
        let home = tempfile::tempdir().unwrap();
        let root = extensions_dir(home.path());
        std::fs::create_dir_all(root.join("demo@1.0.0")).unwrap();
        std::fs::write(root.join("demo@1.0.0/entry.toml"), b"not = [toml").unwrap();
        std::fs::create_dir_all(root.join("demo@2.0.0")).unwrap();
        let entry = toml::to_string(&binary_entry("demo", b"x", "2.0.0")).unwrap();
        std::fs::write(root.join("demo@2.0.0/entry.toml"), entry).unwrap();
        let loaded = try_load_installed(home.path(), "demo").unwrap();
        assert_eq!(loaded.expect("the newer one loads").version, "2.0.0");
        assert_eq!(remove(home.path(), "demo").unwrap(), 2);
        assert!(!root.join("demo@1.0.0").exists() && !root.join("demo@2.0.0").exists());
    }

    // With no record of the secret names (a corrupt state row, or no row and a
    // corrupt entry), remove sweeps this extension's own `EXT_DEMO__` keys only,
    // and the row goes last, once the keys are gone.
    #[test]
    fn an_unknown_secret_list_sweeps_only_this_extensions_namespace() {
        let env = "EXT_DEMO__TOKEN=x\nexport EXT_DEMO__OTHER = 'y'\nEXT_DEMO_X__K=1\nKEEP=1\n";
        for (row, entry_text) in [(true, None), (false, Some("not = [toml")), (true, Some(""))] {
            let home = tempfile::tempdir().unwrap();
            let row_path = home.path().join("extensions/state/demo.json");
            std::fs::create_dir_all(row_path.parent().unwrap()).unwrap();
            if row {
                std::fs::write(&row_path, b"{not json").unwrap();
            }
            if let Some(text) = entry_text {
                let dir = extensions_dir(home.path()).join("demo@1.0.0");
                std::fs::create_dir_all(&dir).unwrap();
                let valid = toml::to_string(&binary_entry("demo", b"x", "1.0.0")).unwrap();
                let text = if text.is_empty() {
                    valid
                } else {
                    text.to_owned()
                };
                std::fs::write(dir.join("entry.toml"), text).unwrap();
            }
            std::fs::write(home.path().join(".env"), env).unwrap();
            remove(home.path(), "demo").unwrap();
            let left = std::fs::read_to_string(home.path().join(".env")).unwrap();
            assert_eq!(left, "EXT_DEMO_X__K=1\nKEEP=1\n", "{row} {entry_text:?}");
            assert!(!row_path.exists(), "the row goes once the keys are gone");
        }
    }

    // EXT-ANCHOR-5: a valid row that names only TOKEN still sweeps the OAuth
    // token store's key, which no record ever lists.
    #[test]
    fn a_valid_row_naming_only_token_also_drops_the_oauth_tokens() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        let entry = toml::to_string(&binary_entry("demo", b"x", "1.0.0")).unwrap();
        std::fs::write(dir.join("entry.toml"), entry).unwrap();
        let mut state = demo_state();
        state.secrets = vec!["EXT_DEMO__TOKEN".to_owned()];
        crate::extensions::mount::store_state(home.path(), &state).unwrap();
        let env = "EXT_DEMO__TOKEN=t\nEXT_DEMO__OAUTH_TOKENS=r\nKEEP=1\n";
        std::fs::write(home.path().join(".env"), env).unwrap();
        assert_eq!(remove(home.path(), "demo").unwrap(), 1);
        let left = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert_eq!(left, "KEEP=1\n");
        assert!(crate::extensions::mount::load_state(home.path(), "demo").is_none());
    }

    // EXT-ANCHOR-5: line endings and a missing final newline stay as found.
    #[test]
    fn remove_secrets_keeps_crlf_and_a_missing_final_newline() {
        let home = tempfile::tempdir().unwrap();
        let env = home.path().join(".env");
        let drop = ["EXT_DEMO__T".to_owned()];
        for (before, after) in [
            ("A=1\r\nEXT_DEMO__T=x\r\nKEEP=2", "A=1\r\nKEEP=2"),
            ("A=1\nEXT_DEMO__T=x\r\nB=2\r\n", "A=1\nB=2\r\n"),
            ("A=1\nEXT_DEMO__T=x", "A=1\n"),
        ] {
            std::fs::write(&env, before).unwrap();
            remove_secrets(home.path(), &drop).unwrap();
            assert_eq!(std::fs::read_to_string(&env).unwrap(), after, "{before:?}");
        }
    }

    // EXT-ANCHOR-5: the decision behind every mount refusal, on fake facts for
    // the mounts an unprivileged test cannot create.
    #[test]
    fn a_mount_is_another_device_another_mount_or_a_mount_root() {
        let facts = |dev, mount: &[u8], root| MountFacts {
            dev,
            mount: mount.to_vec(),
            root,
        };
        let home = facts(7, b"/", false);
        assert!(!is_mount(&home.clone(), &home), "same device and mount");
        // A bind mount (same device), another device, a mount root.
        let bind = facts(7, b"/h/ext", false);
        for other in [bind, facts(8, b"/", false), facts(7, b"/", true)] {
            assert!(is_mount(&other, &home), "{other:?}");
        }
    }

    // A corrupt entry above the running version: the valid build that runs
    // (the one `load_installed` picks) is still verified, so `--accept` can
    // re-pin it; the corrupt one is only warned about.
    #[test]
    fn verify_passes_the_running_build_beside_a_corrupt_higher_entry() {
        let home = tempfile::tempdir().unwrap();
        let root = extensions_dir(home.path());
        std::fs::create_dir_all(root.join("demo@1.0.0")).unwrap();
        let entry = toml::to_string(&binary_entry("demo", b"x", "1.0.0")).unwrap();
        std::fs::write(root.join("demo@1.0.0/entry.toml"), entry).unwrap();
        std::fs::write(root.join("demo@1.0.0/server"), b"x").unwrap();
        assert!(verify_installed(home.path(), "demo").is_ok());
        std::fs::create_dir_all(root.join("demo@2.0.0")).unwrap();
        std::fs::write(root.join("demo@2.0.0/entry.toml"), b"not = [toml").unwrap();
        let loaded = load_installed(home.path(), "demo").expect("the running build");
        let verified = verify_installed_report(home.path(), "demo").unwrap();
        let versions = [loaded.version, verified.installed.version];
        assert_eq!(versions, ["1.0.0", "1.0.0"]);
        // EXT-ANCHOR-6: the corrupt newer entry goes back to the caller.
        assert_eq!(verified.corrupt_newer, ["2.0.0"]);
    }

    // A volume mounted in the tree, at its root or at `extensions/` is refused,
    // through the cfg(test) seam that reports a mount root, before any chmod or
    // unlink: the pre-scan leaves a sibling tree whole too (EXT-ANCHOR-5).
    #[cfg(unix)]
    #[test]
    fn a_mount_point_in_the_tree_is_refused_before_any_chmod_or_unlink() {
        use std::os::unix::fs::PermissionsExt;
        for (seam, want) in [
            ("mnt", "demo@1.0.0 contains a mount point"),
            ("demo@1.0.0", "demo@1.0.0 is a mount point"),
            ("extensions", "extensions is a mount point"),
            // EXT-ANCHOR-7: a file bind mount is an entry on another mount too.
            ("file", "demo@1.0.0 contains a mount point"),
        ] {
            let home = tempfile::tempdir().unwrap();
            let sibling = extensions_dir(home.path()).join("demo@0.1.0/sub");
            std::fs::create_dir_all(&sibling).unwrap();
            let mnt = extensions_dir(home.path()).join("demo@1.0.0/work/mnt");
            std::fs::create_dir_all(&mnt).unwrap();
            std::fs::write(mnt.join("file"), b"x").unwrap();
            set_mode(&mnt, 0o555).unwrap();
            MOUNT_SEAM.with(|at| *at.borrow_mut() = Some(seam.as_bytes().to_vec()));
            let result = remove(home.path(), "demo");
            MOUNT_SEAM.with(|at| *at.borrow_mut() = None);
            let mode = std::fs::metadata(&mnt).unwrap().permissions().mode() & 0o777;
            set_mode(&mnt, 0o700).unwrap();
            let err = result.unwrap_err().to_string();
            assert!(err.contains(want), "{err}");
            assert!(
                mnt.join("file").is_file() && mode == 0o555 && sibling.is_dir(),
                "nothing under it changed"
            );
        }
    }

    // EXT-ANCHOR-6: the scan adds only u+rx and puts every mode back, so a
    // refused removal leaves 000/0400/0100 ancestors exactly as they were at
    // any depth (a passing scan too); the removal after it still deletes them.
    // On the scan itself: the guarded home refuses a 000 dir before `remove`.
    #[cfg(unix)]
    #[test]
    fn a_refused_scan_puts_back_every_locked_ancestors_mode() {
        use std::os::unix::fs::PermissionsExt;
        let modes = [0o000, 0o400, 0o100];
        for turn in 0..modes.len() {
            let home = tempfile::tempdir().unwrap();
            let work = extensions_dir(home.path()).join("demo@1.0.0/work");
            let chain = [work.join("a"), work.join("a/b"), work.join("a/b/c")];
            std::fs::create_dir_all(chain[2].join("mnt")).unwrap();
            let want: Vec<u32> = (0..3).map(|at| modes[(at + turn) % 3]).collect();
            for (dir, mode) in chain.iter().zip(&want).rev() {
                set_mode(dir, *mode).unwrap();
            }
            // Read top-down (each level briefly u+x to reach the next), then put back.
            let modes_now = || -> Vec<u32> {
                let mut got = Vec::new();
                for dir in &chain {
                    got.push(std::fs::metadata(dir).unwrap().permissions().mode() & 0o777);
                    set_mode(dir, got[got.len() - 1] | 0o100).unwrap();
                }
                for (dir, mode) in chain.iter().zip(&got).rev() {
                    set_mode(dir, *mode).unwrap();
                }
                got
            };
            let root = std::fs::File::open(extensions_dir(home.path())).unwrap();
            let names = [std::ffi::OsString::from("demo@1.0.0")];
            MOUNT_SEAM.with(|at| *at.borrow_mut() = Some(b"mnt".to_vec()));
            let err = scan_for_mounts(&root, &names).unwrap_err().to_string();
            MOUNT_SEAM.with(|at| *at.borrow_mut() = None);
            assert!(err.contains("contains a mount point"), "{err}");
            assert_eq!(modes_now(), want, "turn {turn}: every mode put back");
            let facts = scan_for_mounts(&root, &names).unwrap();
            assert_eq!(modes_now(), want, "turn {turn}: a passing scan too");
            let rel = Path::new("extensions/demo@1.0.0");
            remove_tree_in(&root, &names[0], rel, &facts, &mut |_| {}).unwrap();
            assert!(!work.exists(), "then removed");
        }
    }

    // EXT-ANCHOR-6: the install-path removal agrees with the scan on a mount
    // at `extensions/` itself.
    #[cfg(unix)]
    #[test]
    fn remove_tree_at_refuses_a_mount_at_the_extensions_root() {
        let home = tempfile::tempdir().unwrap();
        let tree = extensions_dir(home.path()).join("demo@1.0.0/work");
        std::fs::create_dir_all(&tree).unwrap();
        let handle = kernel_core::SandboxHome::open_existing(home.path()).unwrap();
        let rel = Path::new("extensions/demo@1.0.0");
        MOUNT_SEAM.with(|at| *at.borrow_mut() = Some(b"extensions".to_vec()));
        let result = remove_tree_at(&handle, rel);
        MOUNT_SEAM.with(|at| *at.borrow_mut() = None);
        let err = result.unwrap_err().to_string();
        assert!(err.contains("extensions is a mount point"), "{err}");
        assert!(tree.is_dir(), "nothing removed");
        remove_tree_at(&handle, rel).unwrap();
        assert!(!tree.exists());
    }

    // EXT-ANCHOR-6: the Linux O_PATH unlock opens directories only: a link to
    // a locked directory is never chmodded through `/proc/self/fd`.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_o_path_unlock_never_opens_a_link() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        set_mode(&locked, 0o000).unwrap();
        std::os::unix::fs::symlink(&locked, dir.path().join("link")).unwrap();
        let parent = std::fs::File::open(dir.path()).unwrap();
        let home = mount_facts(&parent, c".").unwrap();
        let mounted = || std::io::Error::other("mounted");
        let at = parent.as_raw_fd();
        let found = unlock_locked(at, c"link", &home, &mounted, 0o700).unwrap();
        let mode = std::fs::metadata(&locked).unwrap().permissions().mode() & 0o777;
        assert!(found.is_none() && mode == 0, "a link is refused");
        let unlocked = unlock_locked(at, c"locked", &home, &mounted, 0o500).unwrap();
        let (_, old, held) = unlocked.unwrap();
        assert!(held.is_some(), "the O_PATH fd is kept to restore through");
        let mode = std::fs::metadata(&locked).unwrap().permissions().mode() & 0o777;
        assert_eq!((old, mode), (0o000, 0o500), "u+rx only, old mode returned");
    }

    // EXT-ANCHOR-7: a locked (000) mount point the scan unlocked is recorded
    // before the check refuses it, so its mode goes back.
    #[cfg(unix)]
    #[test]
    fn a_refused_locked_mount_point_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let mnt = extensions_dir(home.path()).join("demo@1.0.0/mnt");
        std::fs::create_dir_all(&mnt).unwrap();
        set_mode(&mnt, 0o000).unwrap();
        let root = std::fs::File::open(extensions_dir(home.path())).unwrap();
        let names = [std::ffi::OsString::from("demo@1.0.0")];
        MOUNT_SEAM.with(|at| *at.borrow_mut() = Some(b"mnt".to_vec()));
        let err = scan_for_mounts(&root, &names).unwrap_err().to_string();
        MOUNT_SEAM.with(|at| *at.borrow_mut() = None);
        let mode = std::fs::metadata(&mnt).unwrap().permissions().mode() & 0o777;
        set_mode(&mnt, 0o700).unwrap();
        assert!(err.contains("contains a mount point"), "{err}");
        assert_eq!(mode, 0o000, "the unlock was put back");
    }

    // EXT-ANCHOR-7: `set_secret` keeps CRLF and ends an unterminated last line.
    #[test]
    fn set_secret_keeps_crlf_and_a_missing_final_newline() {
        let home = tempfile::tempdir().unwrap();
        let env = home.path().join(".env");
        for (before, after) in [
            (
                "A=1\r\nEXT_DEMO__T=x\r\nKEEP=2",
                "A=1\r\nKEEP=2\r\nEXT_DEMO__T=y\r\n",
            ),
            ("A=1\nB=2", "A=1\nB=2\nEXT_DEMO__T=y\n"),
            ("A=1\r\nB=2\n", "A=1\r\nB=2\nEXT_DEMO__T=y\r\n"),
            ("", "EXT_DEMO__T=y\n"),
        ] {
            std::fs::write(&env, before).unwrap();
            set_secret(home.path(), "EXT_DEMO__T", "y").unwrap();
            assert_eq!(std::fs::read_to_string(&env).unwrap(), after, "{before:?}");
        }
    }

    #[test]
    fn an_artefact_nested_deeper_than_the_window_is_refused_at_unpack() {
        let dir = tempfile::tempdir().unwrap();
        let deep = format!("package/{}f", "d/".repeat(WINDOW));
        let gz = gz_tar(|builder| {
            // `append_data` writes the GNU long name this path needs.
            let (mut header, data) = regular("x", b"x");
            builder
                .append_data(&mut header, &deep, data.as_slice())
                .unwrap();
        });
        let err = unpack_tarball(dir.path(), &gz).unwrap_err();
        assert!(err.to_string().contains("64"), "{err}");
        assert!(!dir.path().join("d").exists());
    }

    // Every descriptor still open whose path lies below `dir`.
    #[cfg(unix)]
    fn fds_below(dir: &Path) -> Vec<PathBuf> {
        let dir = std::fs::canonicalize(dir).unwrap();
        let path_of = |fd: i32| -> Option<PathBuf> {
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::ffi::OsStringExt;
                let mut buf = vec![0u8; libc::PATH_MAX as usize];
                // SAFETY: F_GETPATH writes at most PATH_MAX bytes into `buf`.
                if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } != 0 {
                    return None;
                }
                buf.truncate(buf.iter().position(|b| *b == 0)?);
                Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
            }
            #[cfg(not(target_os = "macos"))]
            std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
        };
        (0..4096)
            .filter_map(path_of)
            .filter(|p| p.starts_with(&dir))
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn a_tree_deeper_than_the_window_is_removed_with_no_fd_left_open() {
        let home = tempfile::tempdir().unwrap();
        let tree = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&tree).unwrap();
        let mut deepest = tree.clone();
        for level in 0..80 {
            deepest.push("d");
            std::fs::create_dir(&deepest).unwrap();
            std::fs::write(deepest.join(format!("f{level}")), b"x").unwrap();
        }
        set_mode(&deepest, 0o555).unwrap();
        assert_eq!(remove(home.path(), "demo").unwrap(), 1);
        assert!(!tree.exists(), "the whole tree is gone");
        assert_eq!(
            fds_below(home.path()),
            Vec::<PathBuf>::new(),
            "no fd left open"
        );
    }
}
