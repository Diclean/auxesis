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

/// Open the directory `rel` below the verified home, one component at a time
/// with `openat(O_NOFOLLOW | O_DIRECTORY)`: a symlink at ANY level is refused,
/// never followed. The root fd is checked to be the verified home's inode.
#[cfg(unix)]
fn open_dir_anchored(
    handle: &kernel_core::SandboxHome,
    rel: &Path,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let flags = libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let mut dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(handle.real_path()?)?;
    handle.reverify()?;
    let (opened, held) = (dir.metadata()?, std::fs::symlink_metadata(handle.path())?);
    if (opened.dev(), opened.ino()) != (held.dev(), held.ino()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the home changed while it was being opened",
        ));
    }
    for part in rel.components() {
        let Component::Normal(part) = part else {
            return Err(std::io::ErrorKind::InvalidInput.into());
        };
        let name = std::ffi::CString::new(part.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        dir = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    Ok(dir)
}

/// Whether the directory `rel` exists below the verified home, every component
/// a real directory. A symlink or file on the way is an error, never followed.
fn anchored_dir_exists(handle: &kernel_core::SandboxHome, rel: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    let opened = open_dir_anchored(handle, rel).map(drop);
    #[cfg(not(unix))]
    let opened = std::fs::read_dir(handle.real_path()?.join(rel)).map(drop);
    match opened {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

pub(crate) fn force_private_dir(
    handle: &kernel_core::SandboxHome,
    rel: &Path,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let file = open_dir_anchored(handle, rel)?;
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
            make_writable_tree(&dir)?;
            handle.remove_dir_all(&rel_dir)?;
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
        return Err(discard_partial_install(&handle, &rel_dir, &dir, err));
    }

    let installed = InstalledExtension {
        name: entry.name.clone(),
        version: entry.version.clone(),
        dir,
        entry: entry.clone(),
    };

    if options.pin {
        // A server that cannot be pinned is not installed: its tree goes too.
        if let Err(err) =
            super::session::pin_extension(home, &installed, options.allow_loopback).await
        {
            return Err(discard_partial_install(
                &handle,
                &rel_dir,
                &installed.dir,
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
    dir: &Path,
    err: InstallError,
) -> InstallError {
    let cleanup = make_writable_tree(dir).and_then(|()| handle.remove_dir_all(rel_dir));
    match cleanup {
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

/// Add the owner read/write/execute bits to a tree, never following a symlink.
///
/// A `000`/`555` install tree otherwise wedges `remove_dir_all`. Directories
/// get `u+rwx`, files `u+rw`; a symlink is left untouched (its target is never
/// chmodded).
fn make_writable_tree(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = meta.permissions();
        let mode = permissions.mode();
        permissions.set_mode(if meta.is_dir() {
            mode | 0o700
        } else {
            mode | 0o600
        });
        std::fs::set_permissions(path, permissions)?;
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            make_writable_tree(&entry?.path())?;
        }
    }
    Ok(())
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
pub fn load_installed(home: &Path, name: &str) -> Option<InstalledExtension> {
    let root = extensions_dir(home);
    let handle = kernel_core::SandboxHome::open_existing(home).ok()?;
    let mut best: Option<InstalledExtension> = None;
    let entries = std::fs::read_dir(&root).ok()?;
    for entry in entries.flatten() {
        let dir = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        let Some((dir_name, version)) = file_name.rsplit_once('@') else {
            continue;
        };
        if dir_name != name {
            continue;
        }
        let rel = Path::new("extensions").join(&file_name).join("entry.toml");
        let super::ReadAt::Text(text) = super::read_text_at_checked(&handle, &rel, MAX_ENTRY_BYTES)
        else {
            continue;
        };
        let Ok(parsed) = toml::from_str::<Entry>(&text) else {
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
    best
}

/// Re-hash the installed artefact and confirm it still matches the entry.
pub fn verify_installed(home: &Path, name: &str) -> Result<InstalledExtension, InstallError> {
    let installed =
        load_installed(home, name).ok_or_else(|| InstallError::NotInstalled(name.to_owned()))?;
    if installed.entry.source.kind == SourceType::Binary {
        let target = installed.dir.join(&installed.entry.run.command);
        let bytes = std::fs::read(&target)?;
        let actual = hex(&Sha256::digest(&bytes));
        if actual != installed.entry.source.sha256.to_ascii_lowercase() {
            return Err(InstallError::HashMismatch {
                name: name.to_owned(),
                expected: installed.entry.source.sha256.clone(),
                actual,
            });
        }
    }
    Ok(installed)
}

/// Remove every `<name>@*` tree, its state, its mounts and its secrets.
///
/// Returns the number of install trees deleted. The Ledger keeps its history.
pub fn remove(home: &Path, name: &str) -> Result<usize, InstallError> {
    if !valid_name(name) {
        return Err(InstallError::NotInstalled(name.to_owned()));
    }
    let state = super::mount::load_state(home, name);
    // The state is the record of this extension's secrets. Without it, the installed
    // entry names the same secrets, and it is read before the trees are deleted.
    // Only this extension's own `EXT_<NAME>_...` names are ever deleted.
    let declared: Vec<String> = match state.as_ref() {
        Some(state) => state.secrets.clone(),
        None => load_installed(home, name)
            .map(|installed| installed.entry.secret_names())
            .unwrap_or_default(),
    };
    let secret_names: Vec<String> = declared
        .into_iter()
        .filter(|secret| super::catalog::valid_secret_name(name, secret))
        .collect();
    let mut removed = 0usize;
    let mut first_error: Option<InstallError> = None;
    let mut record = |err: InstallError| {
        first_error.get_or_insert(err);
    };
    // A `000` subdirectory makes the guarded home scan refuse the whole home, so
    // owner bits are restored first; `make_writable_tree` never follows a link,
    // and a real `extensions/` dir is required. Failures surface below.
    let raw_root = extensions_dir(home);
    if std::fs::symlink_metadata(&raw_root).is_ok_and(|meta| meta.is_dir()) {
        for entry in std::fs::read_dir(&raw_root).into_iter().flatten().flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{name}@"))
            {
                let _ = make_writable_tree(&entry.path());
            }
        }
    }
    let handle = match kernel_core::SandboxHome::open_existing(home) {
        Ok(handle) => Some(handle),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            record(err.into());
            None
        }
    };
    if let Some(handle) = handle.as_ref() {
        // Trees and the state row are removed by name through the verified
        // home: a link anywhere on the way is refused, and a planted link,
        // FIFO or dangling state row is unlinked itself, never its target.
        let extensions = Path::new("extensions");
        // A root that exists but cannot be read is an error, never "nothing to remove".
        let entries = anchored_dir_exists(handle, extensions).and_then(|exists| {
            if !exists {
                return Ok(None);
            }
            std::fs::read_dir(handle.real_path()?.join(extensions)).map(Some)
        });
        let entries = entries.unwrap_or_else(|err| {
            record(err.into());
            None
        });
        for entry in entries.into_iter().flatten().flatten() {
            let file_name = entry.file_name();
            if !file_name.to_string_lossy().starts_with(&format!("{name}@")) {
                continue;
            }
            let rel = extensions.join(&file_name);
            let result = (|| -> Result<(), InstallError> {
                // `file_type` is the listing's own entry type: a link is never followed.
                if !entry.file_type()?.is_dir() {
                    let msg = format!("{} is not a directory", rel.display());
                    return Err(std::io::Error::other(msg).into());
                }
                make_writable_tree(&handle.real_path()?.join(&rel))?;
                handle.remove_dir_all(&rel)?;
                Ok(())
            })();
            match result {
                Ok(()) => removed += 1,
                Err(err) => record(err),
            }
        }
        // State, mounts and secrets are cleaned up even when a tree could not be
        // deleted, and the first failure is reported at the end.
        if let Err(err) = remove_state_row(handle, name) {
            record(err.into());
        }
    }
    if let Err(err) = super::mount::remove_from_all_mounts(home, name) {
        if first_error.is_none() {
            first_error = Some(err.into());
        }
    }
    if !secret_names.is_empty() {
        if let Err(err) = remove_secrets(home, &secret_names) {
            if first_error.is_none() {
                first_error = Some(err.into());
            }
        }
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(removed),
    }
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
/// gateway. The caller holds the config lock.
fn rewrite_one_env(home: &Path, name: &str, value: &str) -> std::io::Result<()> {
    let handle = kernel_core::SandboxHome::open_existing(home)?;
    let existing = read_env(&handle)?.unwrap_or_default();
    let names: BTreeSet<String> = std::iter::once(name.to_owned()).collect();
    let mut kept = String::with_capacity(existing.len() + name.len() + value.len() + 2);
    for line in existing.lines() {
        if !kernel_core::env_file::parse(line, &names).is_empty() {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    kept.push_str(name);
    kept.push('=');
    kept.push_str(value);
    kept.push('\n');
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
    let mut kept = String::with_capacity(text.len());
    for line in text.lines() {
        if !kernel_core::env_file::parse(line, names).is_empty() {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
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
        set_mode(&dir.join("sub"), 0o000).unwrap();
        set_mode(&dir, 0o555).unwrap();
        let removed = remove(home.path(), "demo").unwrap();
        assert_eq!(removed, 1);
        assert!(!dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn force_private_dir_never_follows_a_swapped_parent() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("state")).unwrap();
        set_mode(&outside.path().join("state"), 0o755).unwrap();
        let handle = kernel_core::SandboxHome::open(home.path()).unwrap();
        // `extensions/` is swapped for a link after the handle was opened.
        std::os::unix::fs::symlink(outside.path(), home.path().join("extensions")).unwrap();
        assert!(force_private_dir(&handle, Path::new("extensions/state")).is_err());
        let mode = std::fs::metadata(outside.path().join("state"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o755,
            "the link target's mode must not change"
        );
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

    #[cfg(unix)]
    #[test]
    fn remove_never_follows_a_linked_state_dir() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("demo.json"), b"{}").unwrap();
        std::fs::create_dir(home.path().join("extensions")).unwrap();
        let state = home.path().join("extensions/state");
        std::os::unix::fs::symlink(outside.path(), &state).unwrap();
        assert!(
            remove(home.path(), "demo").is_err(),
            "a linked state dir is reported"
        );
        assert!(outside.path().join("demo.json").is_file());
        assert!(std::fs::symlink_metadata(&state).is_ok());
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
        assert!(
            std::fs::symlink_metadata(&row).is_err(),
            "the FIFO row is gone"
        );
    }

    // A home holding a link is refused whole while the sandbox guard is on (CI),
    // so the link rows are planted after the handle is opened, as a swap would be.
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
            assert!(
                std::fs::symlink_metadata(&row).is_err(),
                "the link row is gone"
            );
        }
        assert!(target.is_file(), "a link row's target survives");
    }

    #[test]
    fn remove_still_cleans_state_when_the_tree_cannot_be_deleted() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions_dir(home.path()).join("demo@1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("entry.toml"),
            toml::to_string(&binary_entry("demo", b"x", "1.0.0")).unwrap(),
        )
        .unwrap();
        let mut state = crate::extensions::mount::ExtensionState {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            kind: "mcp".to_owned(),
            frozen: false,
            tools: Default::default(),
            network: Vec::new(),
            secrets: vec!["EXT_DEMO__TOKEN".to_owned()],
            oauth: None,
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
        // The state, mount and secret are still cleaned up.
        assert!(crate::extensions::mount::load_state(home.path(), "demo").is_none());
        assert!(!crate::extensions::mount::is_mounted(
            home.path(),
            "demo",
            "alice"
        ));
        let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
        assert!(!env.contains("EXT_DEMO__TOKEN"));
        assert!(env.contains("KEEP=1"));
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
}
