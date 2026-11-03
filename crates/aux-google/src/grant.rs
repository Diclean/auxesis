//! Private on-disk refresh grant handling.

use crate::{AuthError, Scope, SecretString};
use kernel_core::paths::SandboxHome;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const GRANT_VERSION: u32 = 1;
const MAX_GRANT_BYTES: u64 = 16 * 1024;
const GRANT_MODE: u32 = 0o600;
const HOME_MODE: u32 = 0o700;

#[derive(Debug)]
pub(crate) struct StoredGrant {
    pub(crate) refresh: SecretString,
    pub(crate) scopes: Vec<Scope>,
}

pub(crate) struct GrantStore {
    home: PathBuf,
    account_hash: String,
}

#[derive(Serialize)]
struct GrantWrite<'a> {
    version: u32,
    account_hash: &'a str,
    refresh_token: &'a str,
    scopes: &'a [Scope],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRead {
    version: u32,
    account_hash: String,
    refresh_token: SecretString,
    scopes: Vec<Scope>,
}

impl GrantStore {
    pub(crate) fn new(home: PathBuf, account_hash: String) -> Self {
        Self { home, account_hash }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> PathBuf {
        self.home.join(self.file_name())
    }

    fn file_name(&self) -> String {
        format!("google-auth-{}.json", self.account_hash)
    }

    fn home_handle(&self) -> Result<SandboxHome, AuthError> {
        let handle = kernel_core::paths::ensure_home(&self.home).map_err(|_| AuthError::Storage)?;
        handle.reverify().map_err(|_| AuthError::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(handle.path())
                .map_err(|_| AuthError::Storage)?
                .permissions()
                .mode()
                & 0o777;
            if mode != HOME_MODE {
                return Err(AuthError::Storage);
            }
        }
        Ok(handle)
    }

    pub(crate) fn load(&self) -> Result<Option<StoredGrant>, AuthError> {
        self.load_inner(|| {}, || {}, || {})
    }

    #[cfg(test)]
    pub(crate) fn load_with_pre_read_hook(
        &self,
        before_read: impl FnOnce(),
    ) -> Result<Option<StoredGrant>, AuthError> {
        self.load_inner(before_read, || {}, || {})
    }

    #[cfg(test)]
    pub(crate) fn load_with_read_hooks(
        &self,
        before_read: impl FnOnce(),
        after_read: impl FnOnce(),
    ) -> Result<Option<StoredGrant>, AuthError> {
        self.load_inner(before_read, after_read, || {})
    }

    #[cfg(test)]
    pub(crate) fn load_with_path_entry_hook(
        &self,
        after_descriptor_check: impl FnOnce(),
    ) -> Result<Option<StoredGrant>, AuthError> {
        self.load_inner(|| {}, || {}, after_descriptor_check)
    }

    fn load_inner(
        &self,
        before_read: impl FnOnce(),
        after_read: impl FnOnce(),
        after_descriptor_check: impl FnOnce(),
    ) -> Result<Option<StoredGrant>, AuthError> {
        let handle = self.home_handle()?;
        let mut file = match handle.open_read(Path::new(&self.file_name()), MAX_GRANT_BYTES) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AuthError::Storage),
        };

        // Metadata comes from the same O_NOFOLLOW file descriptor used below.
        let metadata = file.metadata().map_err(|_| AuthError::Storage)?;
        validate_grant_metadata(&metadata)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        before_read();
        std::io::Read::take(&mut file, MAX_GRANT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthError::Storage)?;
        after_read();
        // The hard-link count can change after the initial fstat. Check the
        // same descriptor again after reading so a link created in that window
        // cannot make a private grant visible outside the protected home.
        let metadata = file.metadata().map_err(|_| AuthError::Storage)?;
        validate_grant_metadata(&metadata)?;
        after_descriptor_check();

        // Check the name again through the held home directory after the read.
        // This catches a path replacement with a linked inode even when the
        // descriptor above still points to a single-link file.
        let path_file = handle
            .open_read(Path::new(&self.file_name()), MAX_GRANT_BYTES)
            .map_err(|_| AuthError::Storage)?;
        let path_metadata = path_file.metadata().map_err(|_| AuthError::Storage)?;
        validate_grant_metadata(&path_metadata)?;
        if !same_file(&metadata, &path_metadata) {
            return Err(AuthError::Storage);
        }
        // A same-user process can still create and remove a hard link entirely
        // between these checks. The private 0600 file already permits that user
        // to read the grant, so this remaining window is not an isolation boundary.
        if bytes.len() as u64 > MAX_GRANT_BYTES {
            return Err(AuthError::Storage);
        }
        let parsed: GrantRead =
            serde_json::from_slice(&bytes[..]).map_err(|_| AuthError::Storage)?;
        if parsed.version != GRANT_VERSION
            || parsed.account_hash != self.account_hash
            || parsed.refresh_token.expose().is_empty()
            || parsed.refresh_token.expose().len() > 8 * 1024
            || parsed.scopes.is_empty()
            || has_duplicates(&parsed.scopes)
        {
            return Err(AuthError::Storage);
        }
        Ok(Some(StoredGrant {
            refresh: parsed.refresh_token,
            scopes: parsed.scopes,
        }))
    }

    pub(crate) fn save(&self, refresh: &SecretString, scopes: &[Scope]) -> Result<(), AuthError> {
        self.save_inner(refresh, scopes, || {})
    }

    #[cfg(test)]
    pub(crate) fn save_with_pre_rename_hook(
        &self,
        refresh: &SecretString,
        scopes: &[Scope],
        before_destination_check: impl FnOnce(),
    ) -> Result<(), AuthError> {
        self.save_inner(refresh, scopes, before_destination_check)
    }

    fn save_inner(
        &self,
        refresh: &SecretString,
        scopes: &[Scope],
        before_destination_check: impl FnOnce(),
    ) -> Result<(), AuthError> {
        // Refuse an existing symlink, special file, malformed document, or
        // unexpected mode instead of silently replacing it.
        let _ = self.load()?;
        let handle = self.home_handle()?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&GrantWrite {
                version: GRANT_VERSION,
                account_hash: &self.account_hash,
                refresh_token: refresh.expose(),
                scopes,
            })
            .map_err(|_| AuthError::Storage)?,
        );
        if bytes.len() as u64 > MAX_GRANT_BYTES {
            return Err(AuthError::Storage);
        }
        let check_handle = handle.clone();
        let file_name = self.file_name();
        handle
            .write_atomic_with_pre_rename_check(
                Path::new(&file_name),
                &bytes[..],
                GRANT_MODE,
                || {
                    before_destination_check();
                    match check_handle.open_read(Path::new(&file_name), MAX_GRANT_BYTES) {
                        Ok(destination) => {
                            let metadata = destination.metadata()?;
                            validate_grant_metadata(&metadata).map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "invalid grant destination metadata",
                                )
                            })?;
                            Ok(())
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(err) => Err(err),
                    }
                },
            )
            .map_err(|_| AuthError::Storage)?;
        self.check_written_file(&handle)
    }

    fn check_written_file(&self, handle: &SandboxHome) -> Result<(), AuthError> {
        let file = handle
            .open_read(Path::new(&self.file_name()), MAX_GRANT_BYTES)
            .map_err(|_| AuthError::Storage)?;
        let metadata = file.metadata().map_err(|_| AuthError::Storage)?;
        validate_grant_metadata(&metadata)
    }

    pub(crate) fn remove(&self) -> Result<(), AuthError> {
        let handle = self.home_handle()?;
        handle
            .remove_file(Path::new(&self.file_name()))
            .map(|_| ())
            .map_err(|_| AuthError::Storage)
    }
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        true
    }
}

fn validate_grant_metadata(metadata: &std::fs::Metadata) -> Result<(), AuthError> {
    if !metadata.is_file() || metadata.len() > MAX_GRANT_BYTES {
        return Err(AuthError::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != GRANT_MODE || metadata.nlink() != 1 {
            return Err(AuthError::Storage);
        }
    }
    Ok(())
}

fn has_duplicates(scopes: &[Scope]) -> bool {
    let mut unique = scopes.to_vec();
    unique.sort_unstable();
    unique.dedup();
    unique.len() != scopes.len()
}
