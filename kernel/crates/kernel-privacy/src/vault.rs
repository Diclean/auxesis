//! Encrypted per-session vault for token ↔ value mappings (slice 3).
//!
//! The vault keeps one sealed record per session: the [`TokenMap`] that
//! [`Anonymizer::anonymize`](crate::Anonymizer::anonymize) produced for that
//! session. Records are sealed with AES-256-GCM under a random 256-bit key in
//! `vault.key` (mode 0600). The caller picks the directory, usually one derived
//! from `AUXESIS_HOME`; nothing here reads the Keychain. A missing, unreadable
//! or corrupt key, and a record that fails authentication, are errors. They are
//! never read as an empty map.
//!
//! Layout under the vault directory (mode 0700):
//!
//! * `vault.key`: 32 random bytes, mode 0600;
//! * `vault.lock`: the advisory lock file, mode 0600 (see *Concurrency*);
//! * `manifest.bin`: the sealed manifest, mode 0600, mapping each session slot
//!   to its current generation;
//! * `sessions/<slot>.bin`: `MAGIC ‖ nonce ‖ ciphertext ‖ tag`, one file per
//!   session. `slot` is the hex SHA-256 of a domain tag and the session id, so
//!   file names reveal neither the id nor any value.
//!
//! The AEAD additional data is `MAGIC ‖ slot` for a record and `MAGIC ‖
//! "manifest"` for the manifest, so a file copied or renamed into another place
//! fails authentication. The sealed record also carries its session id and its
//! generation, and every read checks both.
//!
//! **Rollback and crashes.** A record carries the generation it was written
//! under; the manifest carries each slot's current generation. A record older
//! than its slot's generation is a copy from before a write or an erasure, and it
//! is refused with [`VaultError::Rollback`].
//!
//! * **A write replaces the record first, then raises the manifest** to the new
//!   generation. A crash in between leaves the record one generation ahead of the
//!   manifest. The record is then the newer write, so the next read commits it by
//!   raising the manifest, under the lock. Until that read, a pre-write copy of
//!   the record restored by someone with write access to the vault directory
//!   would pass. That is the whole-directory case excluded below, limited to the
//!   crash window.
//! * **A removal raises the manifest first, then unlinks the record.** A crash
//!   after the raise leaves the record on disk but refused, so an erased record
//!   can never read again. The session answers [`VaultError::Rollback`] until a
//!   retry of [`Vault::forget_session`] or [`Vault::forget_value`] unlinks the
//!   leftover file. The session is refused, not empty, in that window.
//! * **A rewrite that keeps some entries is a write**, so it takes the write
//!   order above. A crash there commits the erasure.
//! * **A crash before a rename leaves a temp file** holding the ciphertext of
//!   that write. No record names it, and every erasure removes such files.
//!
//! **Exhaustion.** Generations are `u64` and never wrap. A write or an erasure
//! that would pass `u64::MAX` fails with [`VaultError::GenerationExhausted`]
//! before it writes anything. At `u64::MAX` every operation on the session is
//! refused, reads included, so a wrapped generation can never let an older copy
//! pass as current.
//!
//! The raise past any record on disk is also what keeps a copy of a deleted
//! record refused. Rolling back the whole vault directory, manifest included, is
//! out of scope: the FileVault and backup policy covers it.
//!
//! **Concurrency.** Every public operation holds one vault-wide `flock` on
//! `vault.lock` from its first read to its last write. It is vault-wide rather
//! than per session because the manifest is shared by every session.
//!
//! Every write goes through [`kernel_core::SandboxHome`], the verified home handle
//! that anchors writes to a directory descriptor, so a symlink swapped into the
//! tree cannot redirect them (the write-gateway rule). Records and the manifest
//! are replaced by write-then-rename, fsynced before and after the rename, so a
//! torn write never leaves a partial file and a finished write survives a crash.
//!
//! Unix only (macOS is the target): the modes above use `std::os::unix` APIs.

#[cfg(test)]
use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use kernel_core::SandboxHome;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::anonymize::{casefold, kind_of_token, normalize_value, TokenMap};
use crate::span::EntityKind;

const KEY_FILE: &str = "vault.key";
const LOCK_FILE: &str = "vault.lock";
const MANIFEST_FILE: &str = "manifest.bin";
const MANIFEST_LABEL: &str = "manifest";
const SESSIONS_DIR: &str = "sessions";
const RECORD_EXT: &str = "bin";
const MAGIC: &[u8; 8] = b"AXVAULT1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SLOT_DOMAIN: &[u8] = b"auxesis.vault.session.v1\0";
const RECORD_VERSION: u8 = 2;
const MANIFEST_VERSION: u8 = 1;

/// Why a vault operation failed. No message carries a value or the key.
#[derive(Debug)]
pub enum VaultError {
    /// The key file is missing, unreadable, the wrong size or readable by
    /// someone other than its owner, or it is gone while records exist. Private
    /// stores stay locked.
    KeyUnavailable(&'static str),
    /// A record or the manifest is truncated, not a vault file, fails
    /// authentication (wrong key, tampered, or moved to another place) or does
    /// not parse. It is never read as an empty map.
    Corrupt(&'static str),
    /// A record is older than its session's generation: a copy from before a
    /// write or an erasure. It is refused, never restored.
    Rollback,
    /// The session's generation is at `u64::MAX`, so the next write or erasure
    /// has no larger generation to name. Nothing is written: a generation never
    /// wraps to zero, which would let an older copy pass the rollback check.
    GenerationExhausted,
    /// A token is already mapped to a different value in this session. Nothing
    /// was written. The caller must re-tokenise the message.
    TokenConflict,
    /// A file-system operation failed.
    Io(io::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyUnavailable(why) => write!(f, "vault key unavailable: {why}"),
            Self::Corrupt(why) => write!(f, "vault record rejected: {why}"),
            Self::Rollback => write!(
                f,
                "vault record rejected: older than the session's last write or erasure"
            ),
            Self::GenerationExhausted => write!(f, "vault session generation is exhausted"),
            Self::TokenConflict => write!(
                f,
                "vault token conflict: a token already maps to another value"
            ),
            Self::Io(err) => write!(f, "vault I/O failed: {err}"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for VaultError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// The encrypted session vault rooted at one directory.
pub struct Vault {
    home: SandboxHome,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl Vault {
    /// Opens the vault in `dir`, creating it on first use.
    ///
    /// `dir` is opened as a [`SandboxHome`], which creates it 0700 when missing.
    /// A missing key file gets a fresh 0600 key, but only when no record exists
    /// yet. A missing key beside records is an error, because a new key would
    /// orphan them silently.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, VaultError> {
        let home = SandboxHome::open(dir.as_ref())?;
        // Held across the key and manifest creation below, so two first opens
        // cannot both create state, and one cannot clobber the other's manifest.
        let _lock = lock_file(&home)?;
        let key = if home.exists_no_follow(Path::new(KEY_FILE))? {
            read_key(&home.path().join(KEY_FILE))?
        } else if !record_slots(home.path())?.is_empty() {
            return Err(VaultError::KeyUnavailable(
                "key file is missing but records exist",
            ));
        } else {
            create_key(&home)?
        };
        let vault = Self { home, key };
        // The manifest exists before the first record: a crash in the first write
        // must not leave a record with no manifest beside it, which reads refuse.
        if !vault.home.exists_no_follow(Path::new(MANIFEST_FILE))?
            && record_slots(vault.home.path())?.is_empty()
        {
            vault.store_manifest(&Manifest::default())?;
        }
        Ok(vault)
    }

    /// Adds `map` to the session's record. Tokens already recorded keep their
    /// first surface form, and every occurrence is appended, so a replayed
    /// message does not change the entries.
    ///
    /// Fails with [`VaultError::TokenConflict`] and writes nothing when a token
    /// of `map` is already mapped to a different value in this session. The
    /// caller must re-tokenise the message in that case. Fails with
    /// [`VaultError::Rollback`] when the session's record is stale.
    pub fn record(&self, session_id: &str, map: &TokenMap) -> Result<(), VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        let mut merged = self
            .checked_session(&mut manifest, session_id)?
            .unwrap_or_default();
        merge(&mut merged, map)?;
        if merged.is_empty() {
            return Ok(());
        }
        self.write_session(&mut manifest, session_id, &merged, 0)
    }

    /// The session's token map. A session with no record yields an empty map;
    /// a record that fails to open, or is stale, is an error.
    pub fn lookup(&self, session_id: &str) -> Result<TokenMap, VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        Ok(self
            .checked_session(&mut manifest, session_id)?
            .unwrap_or_default())
    }

    /// Deletes one session's record and raises its generation, so an older copy
    /// of the record is refused from now on. Returns `false` if the record did
    /// not exist.
    pub fn forget_session(&self, session_id: &str) -> Result<bool, VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        self.sweep_temp_files()?;
        self.remove_session(&mut manifest, session_id)
    }

    /// Erases one person from every session. A token is removed when any value
    /// kept under it equals `value` once both are folded under the token's own
    /// kind and casefolded. Every surface kept under a removed token goes too,
    /// so `0612345678` also removes `06 12 34 56 78` when they share a token.
    /// Returns the number of token mappings removed across all sessions.
    ///
    /// Any record that cannot be opened is an error. The erasure never skips a
    /// record silently. Stale records and records ahead of the manifest are
    /// erased too, because their values are still on disk: the erased copy is
    /// written past the record's generation, so the original never reads again.
    /// Leftover temp files from interrupted writes are removed as well, since
    /// they hold ciphertext of values that may be erased here.
    ///
    /// A record whose session is at `u64::MAX` cannot be rewritten, so the call
    /// fails with [`VaultError::GenerationExhausted`]. Records the walk erased
    /// before that stay erased, and the caller must treat the erasure as incomplete.
    pub fn forget_value(&self, value: &str) -> Result<usize, VaultError> {
        let _lock = self.lock()?;
        let mut manifest = self.load_manifest()?;
        self.sweep_temp_files()?;
        let mut removed = 0;
        for slot in record_slots(self.home.path())? {
            let Some(record) = self.open_record(&slot)? else {
                continue;
            };
            let doomed: HashSet<&str> = record
                .map
                .iter()
                .chain(record.map.occurrences())
                .filter(|(token, original)| erases(token, original, value))
                .map(|(token, _)| token.as_str())
                .collect();
            if doomed.is_empty() {
                continue;
            }
            removed += record
                .map
                .iter()
                .filter(|(token, _)| doomed.contains(token.as_str()))
                .count();
            let mut kept = TokenMap::default();
            for (token, original) in record.map.iter() {
                if !doomed.contains(token.as_str()) {
                    kept.push_entry(token.clone(), original.clone());
                }
            }
            for (token, original) in record.map.occurrences() {
                if !doomed.contains(token.as_str()) {
                    kept.push_occurrence(token.clone(), original.clone());
                }
            }
            if kept.is_empty() {
                self.remove_session(&mut manifest, &record.session_id)?;
            } else {
                self.write_session(&mut manifest, &record.session_id, &kept, record.generation)?;
            }
        }
        Ok(removed)
    }

    fn record_path(&self, slot: &str) -> PathBuf {
        self.home.path().join(record_rel(slot))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key[..]))
    }

    /// The advisory lock every public operation holds across its reads and
    /// writes. It is released when the returned file is dropped, on the error
    /// paths too.
    fn lock(&self) -> Result<fs::File, VaultError> {
        lock_file(&self.home)
    }

    /// The manifest, or an empty one while the vault has no records. A missing
    /// manifest beside records is an error: deleting it must not reset every
    /// generation to zero.
    fn load_manifest(&self) -> Result<Manifest, VaultError> {
        let sealed = match fs::read(self.home.path().join(MANIFEST_FILE)) {
            Ok(sealed) => sealed,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if record_slots(self.home.path())?.is_empty() {
                    return Ok(Manifest::default());
                }
                return Err(VaultError::Corrupt("manifest is missing but records exist"));
            }
            Err(err) => return Err(err.into()),
        };
        let plaintext = self.unseal(&additional_data(MANIFEST_LABEL), &sealed)?;
        decode_manifest(&plaintext)
    }

    fn store_manifest(&self, manifest: &Manifest) -> Result<(), VaultError> {
        let plaintext = encode_manifest(manifest)?;
        let sealed = self.seal(&additional_data(MANIFEST_LABEL), &plaintext)?;
        self.home
            .write_atomic(Path::new(MANIFEST_FILE), &sealed, 0o600)?;
        Ok(())
    }

    /// Seals the manifest with `slot` at `generation`.
    fn set_generation(
        &self,
        manifest: &mut Manifest,
        slot: &str,
        generation: u64,
    ) -> Result<(), VaultError> {
        manifest.generations.insert(slot.to_owned(), generation);
        self.store_manifest(manifest)
    }

    /// The session's map, or `None` when it has no record.
    ///
    /// A record at the manifest's generation is current. One ahead of it is the
    /// newer half of a write that crashed before its manifest step: it is
    /// committed here, under the lock, and returned. A record below the
    /// generation is refused with [`VaultError::Rollback`]. Anything further
    /// ahead is an error.
    fn checked_session(
        &self,
        manifest: &mut Manifest,
        session_id: &str,
    ) -> Result<Option<TokenMap>, VaultError> {
        let slot = slot_for(session_id);
        let Some(record) = self.open_record(&slot)? else {
            return Ok(None);
        };
        if record.session_id != session_id {
            return Err(VaultError::Corrupt("session id does not match its record"));
        }
        let current = manifest.generation(&slot);
        // Checked before any comparison: at `u64::MAX` there is no next generation
        // for the commit below, so the session is refused whatever its record holds.
        let ahead = next_generation(current)?;
        if record.generation == current {
            return Ok(Some(record.map));
        }
        if record.generation == ahead {
            self.set_generation(manifest, &slot, record.generation)?;
            return Ok(Some(record.map));
        }
        if record.generation < current {
            return Err(VaultError::Rollback);
        }
        Err(VaultError::Corrupt("record is ahead of the manifest"))
    }

    /// Reads and authenticates one record without checking its generation.
    /// `None` when the file does not exist.
    fn open_record(&self, slot: &str) -> Result<Option<Record>, VaultError> {
        let sealed = match fs::read(self.record_path(slot)) {
            Ok(sealed) => sealed,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let plaintext = self.unseal(&additional_data(slot), &sealed)?;
        let record = decode(&plaintext)?;
        if slot_for(&record.session_id) != slot {
            return Err(VaultError::Corrupt("session id does not match its record"));
        }
        Ok(Some(record))
    }

    /// Replaces the session's record with `map`, under a generation past both the
    /// manifest and `replaces`, the generation of the record being replaced (0
    /// when there is none). The record goes first: a crash before the manifest
    /// step leaves it one generation ahead, and [`Vault::checked_session`] commits
    /// it on the next read. Nothing is lost, and the write is never half-visible.
    /// Fails with [`VaultError::GenerationExhausted`] before writing anything when
    /// that generation would pass `u64::MAX`.
    fn write_session(
        &self,
        manifest: &mut Manifest,
        session_id: &str,
        map: &TokenMap,
        replaces: u64,
    ) -> Result<(), VaultError> {
        let slot = slot_for(session_id);
        let generation = next_generation(manifest.generation(&slot).max(replaces))?;
        let plaintext = encode(session_id, generation, map)?;
        let sealed = self.seal(&additional_data(&slot), &plaintext)?;
        self.home.create_dir_all(Path::new(SESSIONS_DIR))?;
        self.home.write_atomic(&record_rel(&slot), &sealed, 0o600)?;
        crash_point(CrashPoint::AfterRecordWrite)?;
        self.set_generation(manifest, &slot, generation)
    }

    /// Removes the session's record and returns whether one existed. The manifest
    /// goes first, past any record on disk, so a crash before the unlink leaves a
    /// record that is refused and never one that reads again. A retry removes it.
    /// Fails with [`VaultError::GenerationExhausted`] before anything is removed
    /// when that generation would pass `u64::MAX`.
    fn remove_session(
        &self,
        manifest: &mut Manifest,
        session_id: &str,
    ) -> Result<bool, VaultError> {
        let slot = slot_for(session_id);
        let generation = next_generation(
            manifest
                .generation(&slot)
                .max(self.on_disk_generation(&slot)?),
        )?;
        self.set_generation(manifest, &slot, generation)?;
        crash_point(CrashPoint::AfterGenerationBump)?;
        Ok(self.home.remove_file(&record_rel(&slot))?)
    }

    /// The generation of the record on disk, or 0 when there is none. A record
    /// that cannot be authenticated is never served, so its generation is moot.
    fn on_disk_generation(&self, slot: &str) -> Result<u64, VaultError> {
        match self.open_record(slot) {
            Ok(record) => Ok(record.map_or(0, |record| record.generation)),
            Err(VaultError::Corrupt(_)) => Ok(0),
            Err(err) => Err(err),
        }
    }

    /// Removes the temp files that an interrupted write left in the vault and in
    /// `sessions/`. [`write_atomic`](kernel_core::SandboxHome::write_atomic) names
    /// its temp file `.<name>.tmp.<pid>.<stamp>`. Such a file was never renamed
    /// into place, so no record names it, but it holds ciphertext of the values
    /// that write carried. Erasure must reach it too. Called under the lock, so
    /// no write is in flight.
    fn sweep_temp_files(&self) -> Result<(), VaultError> {
        for dir in [PathBuf::new(), PathBuf::from(SESSIONS_DIR)] {
            let entries = match fs::read_dir(self.home.path().join(&dir)) {
                Ok(entries) => entries,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            for entry in entries {
                let name = entry?.file_name();
                let is_temp = name
                    .to_str()
                    .is_some_and(|name| name.starts_with('.') && name.contains(".tmp."));
                if is_temp {
                    self.home.remove_file(&dir.join(&name))?;
                }
            }
        }
        Ok(())
    }

    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        random(&mut nonce)?;
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultError::Corrupt("seal failed"))?;
        let mut sealed = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn unseal(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if sealed.len() < MAGIC.len() + NONCE_LEN + TAG_LEN || !sealed.starts_with(MAGIC) {
            return Err(VaultError::Corrupt("not a complete vault record"));
        }
        let (nonce, ciphertext) = sealed[MAGIC.len()..].split_at(NONCE_LEN);
        let plaintext = self
            .cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| {
                VaultError::Corrupt("authentication failed: wrong key, tampered, or moved")
            })?;
        Ok(Zeroizing::new(plaintext))
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("dir", &self.home.path())
            .field("key", &"<redacted>")
            .finish()
    }
}

/// The generation each session slot is at. A record below its slot's
/// generation is stale.
#[derive(Default)]
struct Manifest {
    generations: BTreeMap<String, u64>,
}

impl Manifest {
    fn generation(&self, slot: &str) -> u64 {
        self.generations.get(slot).copied().unwrap_or(0)
    }
}

/// The generation after `current`. Fails at `u64::MAX` rather than panicking or
/// wrapping to zero, since a wrapped generation would pass the rollback check.
fn next_generation(current: u64) -> Result<u64, VaultError> {
    current
        .checked_add(1)
        .ok_or(VaultError::GenerationExhausted)
}

/// A decrypted record: its session, its generation and its map.
struct Record {
    session_id: String,
    generation: u64,
    map: TokenMap,
}

/// Opens `vault.lock` and takes the vault-wide `flock` on it.
fn lock_file(home: &SandboxHome) -> Result<fs::File, VaultError> {
    let file = home.open_append(Path::new(LOCK_FILE), 0o600)?;
    file.lock()?;
    Ok(file)
}

/// The points a test can make an operation fail at, as if the process had died
/// there. Each sits between two durable steps of a write or an erasure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashPoint {
    /// After a record is replaced, before the manifest names its generation.
    AfterRecordWrite,
    /// After an erasure raised the manifest, before the record is unlinked.
    AfterGenerationBump,
}

#[cfg(test)]
thread_local! {
    /// The crash point this thread will hit next, if a test armed one.
    static CRASH_AT: Cell<Option<CrashPoint>> = const { Cell::new(None) };
}

/// Fails with an injected error when a test armed `point` on this thread, and
/// disarms it. Otherwise does nothing.
#[cfg(test)]
fn crash_point(point: CrashPoint) -> Result<(), VaultError> {
    if CRASH_AT.with(|armed| armed.get() == Some(point)) {
        CRASH_AT.with(|armed| armed.set(None));
        return Err(VaultError::Io(io::Error::other("injected crash")));
    }
    Ok(())
}

#[cfg(not(test))]
fn crash_point(_point: CrashPoint) -> Result<(), VaultError> {
    Ok(())
}

fn read_key(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|_| VaultError::KeyUnavailable("key file is unreadable"))?;
    if !meta.is_file() {
        return Err(VaultError::KeyUnavailable("key path is not a regular file"));
    }
    if (meta.permissions().mode() & 0o077) != 0 {
        return Err(VaultError::KeyUnavailable(
            "key file is readable by group or others",
        ));
    }
    let bytes = Zeroizing::new(
        fs::read(path).map_err(|_| VaultError::KeyUnavailable("key file is unreadable"))?,
    );
    if bytes.len() != KEY_LEN {
        return Err(VaultError::KeyUnavailable("key file has the wrong length"));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn create_key(home: &SandboxHome) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    random(&mut key[..])?;
    if !home.write_new(Path::new(KEY_FILE), &key[..], 0o600)? {
        return Err(VaultError::KeyUnavailable(
            "key file appeared during creation",
        ));
    }
    Ok(key)
}

fn random(buf: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(buf).map_err(|_| io::Error::other("no operating-system randomness"))
}

/// The slots of every record file under `dir/sessions`, by file stem.
fn record_slots(dir: &Path) -> Result<Vec<String>, VaultError> {
    let entries = match fs::read_dir(dir.join(SESSIONS_DIR)) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut slots = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension() == Some(OsStr::new(RECORD_EXT)) {
            if let Some(slot) = path.file_stem().and_then(OsStr::to_str) {
                slots.push(slot.to_owned());
            }
        }
    }
    Ok(slots)
}

/// A record's path relative to the vault root.
fn record_rel(slot: &str) -> PathBuf {
    Path::new(SESSIONS_DIR).join(format!("{slot}.{RECORD_EXT}"))
}

/// The record file name for a session: hex SHA-256 over a domain tag and the id.
fn slot_for(session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(session_id.as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The AEAD additional data for one file: the magic, then the file's label (a
/// session slot, or `manifest`).
fn additional_data(label: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + label.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(label.as_bytes());
    aad
}

/// Whether two surfaces kept under one token are the same value: equal once
/// folded the way the token was minted. A token with no known kind matches on
/// folded text.
fn same_value(token: &str, first: &str, second: &str) -> bool {
    match kind_of_token(token) {
        Some(kind) => normalize_value(kind, first) == normalize_value(kind, second),
        None => fold_text(first) == fold_text(second),
    }
}

/// Whether `stored`, kept under `token`, is the value an erasure names. Both
/// sides are folded under the token's kind, the same fold the token was minted
/// with, so `06 12 34 56 78` and `0612345678` match, and an e-mail matches in
/// any case. A textual kind (a name, a place) keys its token on the exact
/// spelling, but an erasure compares it with [`fold_text`], so `Camille
/// Exemple` and `CAMILLE EXEMPLE` are one person. A token with no known kind
/// compares folded text.
fn erases(token: &str, stored: &str, value: &str) -> bool {
    match kind_of_token(token) {
        Some(kind) if is_textual(kind) => fold_text(stored) == fold_text(value),
        Some(kind) => normalize_value(kind, stored) == normalize_value(kind, value),
        None => fold_text(stored) == fold_text(value),
    }
}

/// Whether `kind` is a textual kind: neither an identifier nor an e-mail.
fn is_textual(kind: EntityKind) -> bool {
    !(kind.is_identifier() || kind == EntityKind::Email)
}

/// NFKC, trim, then full case folding: the comparison for text with no known
/// kind.
fn fold_text(text: &str) -> String {
    let folded: String = text.nfkc().collect();
    casefold(folded.trim())
}

/// Adds the entries and occurrences of `from` to `into`. A token already mapped
/// to the same value keeps its entry. A token mapped to a different value fails
/// the whole merge, and `into` is left untouched.
fn merge(into: &mut TokenMap, from: &TokenMap) -> Result<(), VaultError> {
    let mut known: HashMap<&str, &str> = into
        .iter()
        .map(|(token, original)| (token.as_str(), original.as_str()))
        .collect();
    let mut fresh: Vec<(String, String)> = Vec::new();
    for (token, original) in from.iter() {
        match known.entry(token.as_str()) {
            Entry::Occupied(first) => {
                if !same_value(token, first.get(), original) {
                    return Err(VaultError::TokenConflict);
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(original.as_str());
                fresh.push((token.clone(), original.clone()));
            }
        }
    }
    for (token, original) in from.occurrences() {
        match known.get(token.as_str()) {
            Some(first) if same_value(token, first, original) => {}
            Some(_) => return Err(VaultError::TokenConflict),
            None => return Err(VaultError::Corrupt("occurrence without a mapping")),
        }
    }
    for (token, original) in fresh {
        into.push_entry(token, original);
    }
    for (token, original) in from.occurrences() {
        into.push_occurrence(token.clone(), original.clone());
    }
    Ok(())
}

/// Record plaintext layout: version byte, session id, generation, entries,
/// occurrences. Every string is a big-endian `u32` length then UTF-8 bytes; a
/// pair list is a `u32` count then pairs; the generation is a big-endian `u64`.
fn encode(
    session_id: &str,
    generation: u64,
    map: &TokenMap,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut out = Zeroizing::new(vec![RECORD_VERSION]);
    put_bytes(&mut out, session_id.as_bytes())?;
    out.extend_from_slice(&generation.to_be_bytes());
    put_pairs(&mut out, map)?;
    put_pairs(&mut out, map.occurrences())?;
    Ok(out)
}

/// Manifest plaintext layout: version byte, a `u32` count, then one
/// `(slot, generation)` pair per session.
fn encode_manifest(manifest: &Manifest) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut out = Zeroizing::new(vec![MANIFEST_VERSION]);
    let count = u32::try_from(manifest.generations.len())
        .map_err(|_| VaultError::Io(io::Error::other("too many sessions")))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (slot, generation) in &manifest.generations {
        put_bytes(&mut out, slot.as_bytes())?;
        out.extend_from_slice(&generation.to_be_bytes());
    }
    Ok(out)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VaultError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| VaultError::Io(io::Error::other("record field too long")))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_pairs(out: &mut Vec<u8>, pairs: &[(String, String)]) -> Result<(), VaultError> {
    let count = u32::try_from(pairs.len())
        .map_err(|_| VaultError::Io(io::Error::other("too many record entries")))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (token, original) in pairs {
        put_bytes(out, token.as_bytes())?;
        put_bytes(out, original.as_bytes())?;
    }
    Ok(())
}

/// Parses a plaintext record. A decode error drops the partly built map, which
/// zeroes what it had read.
fn decode(plaintext: &[u8]) -> Result<Record, VaultError> {
    let mut reader = Reader(plaintext);
    if reader.take(1)?[0] != RECORD_VERSION {
        return Err(VaultError::Corrupt("unknown record version"));
    }
    let session_id = reader.string()?;
    let generation = reader.u64()?;
    let mut map = TokenMap::default();
    reader.pairs(|token, original| map.push_entry(token, original))?;
    reader.pairs(|token, original| map.push_occurrence(token, original))?;
    if !reader.0.is_empty() {
        return Err(VaultError::Corrupt("trailing bytes in record"));
    }
    Ok(Record {
        session_id,
        generation,
        map,
    })
}

fn decode_manifest(plaintext: &[u8]) -> Result<Manifest, VaultError> {
    let mut reader = Reader(plaintext);
    if reader.take(1)?[0] != MANIFEST_VERSION {
        return Err(VaultError::Corrupt("unknown manifest version"));
    }
    let mut generations = BTreeMap::new();
    for _ in 0..reader.u32()? {
        let slot = reader.string()?;
        let generation = reader.u64()?;
        if generations.insert(slot, generation).is_some() {
            return Err(VaultError::Corrupt("duplicate session in manifest"));
        }
    }
    if !reader.0.is_empty() {
        return Err(VaultError::Corrupt("trailing bytes in manifest"));
    }
    Ok(Manifest { generations })
}

/// Bounds-checked cursor over a decrypted record.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], VaultError> {
        if self.0.len() < len {
            return Err(VaultError::Corrupt("truncated record"));
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, VaultError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, VaultError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, VaultError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| VaultError::Corrupt("record field too long"))?;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| VaultError::Corrupt("record text is not UTF-8"))
    }

    fn pairs(&mut self, mut sink: impl FnMut(String, String)) -> Result<(), VaultError> {
        for _ in 0..self.u32()? {
            let token = self.string()?;
            let original = self.string()?;
            sink(token, original);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::anonymize::{Anonymizer, UnknownPolicy};
    use crate::span::{EntityKind, Span};

    const KEY: [u8; 32] = [7; 32];
    const EMAIL: &str = "jean.dupont@example.test";
    const PHONE: &str = "06 12 34 56 78";
    const TEXT: &str = "Écrivez à jean.dupont@example.test ou au 06 12 34 56 78.";
    const OTHER: &str = "Écrivez à marie@example.test.";

    fn span_of(text: &str, needle: &str, kind: EntityKind) -> Span {
        let start = text.find(needle).expect("needle is in the text");
        Span {
            kind,
            start,
            end: start + needle.len(),
            score: 1.0,
            recognizer: "test",
            person_id: None,
        }
    }

    /// Masks `text`, marking each `(needle, kind)` pair, with the given key.
    fn mask(key: [u8; 32], text: &str, needles: &[(&str, EntityKind)]) -> (String, TokenMap) {
        let spans: Vec<Span> = needles
            .iter()
            .map(|(needle, kind)| span_of(text, needle, *kind))
            .collect();
        Anonymizer::new(key).anonymize(text, &spans)
    }

    fn mask_text(key: [u8; 32]) -> (String, TokenMap) {
        mask(
            key,
            TEXT,
            &[(EMAIL, EntityKind::Email), (PHONE, EntityKind::Phone)],
        )
    }

    /// A map with one token, shown once as `original`.
    fn single(token: &str, original: &str) -> TokenMap {
        let mut map = TokenMap::default();
        map.push_entry(token.to_owned(), original.to_owned());
        map.push_occurrence(token.to_owned(), original.to_owned());
        map
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn round_trip_restores_the_exact_text() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let (masked, map) = mask_text(KEY);
        vault.record("session-a", &map).unwrap();

        let loaded = vault.lookup("session-a").unwrap();
        assert_eq!(loaded, map);
        let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
        assert!(report.is_clean());
        assert_eq!(report.text, TEXT);
    }

    #[test]
    fn wrong_key_is_rejected_not_read_as_empty() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();

        fs::write(dir.path().join(KEY_FILE), [9u8; KEY_LEN]).unwrap();
        let reopened = Vault::open(dir.path()).unwrap();
        assert!(matches!(
            reopened.lookup("session-a"),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        let path = vault.record_path(&slot_for("session-a"));
        let original = fs::read(&path).unwrap();

        for index in [
            MAGIC.len() + NONCE_LEN,
            MAGIC.len() + NONCE_LEN + 1,
            original.len() - 1,
        ] {
            let mut bytes = original.clone();
            bytes[index] ^= 0x01;
            fs::write(&path, &bytes).unwrap();
            assert!(
                matches!(vault.lookup("session-a"), Err(VaultError::Corrupt(_))),
                "a flipped byte at {index} was accepted"
            );
        }
        fs::write(&path, &original).unwrap();
        assert!(!vault.lookup("session-a").unwrap().is_empty());
    }

    #[test]
    fn key_and_directories_are_private() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("privacy");
        let vault = Vault::open(&root).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();

        assert_eq!(mode(&root.join(KEY_FILE)), 0o600);
        assert_eq!(mode(&root.join(MANIFEST_FILE)), 0o600);
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join(SESSIONS_DIR)), 0o700);
        assert_eq!(mode(&vault.record_path(&slot_for("session-a"))), 0o600);
    }

    #[test]
    fn key_readable_by_others_is_refused() {
        let dir = TempDir::new().unwrap();
        Vault::open(dir.path()).unwrap();
        fs::set_permissions(dir.path().join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Vault::open(dir.path()),
            Err(VaultError::KeyUnavailable(_))
        ));
    }

    #[test]
    fn missing_key_beside_records_fails_closed() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        fs::remove_file(dir.path().join(KEY_FILE)).unwrap();
        assert!(matches!(
            Vault::open(dir.path()),
            Err(VaultError::KeyUnavailable(_))
        ));
    }

    #[test]
    fn one_sessions_tokens_do_not_resolve_in_another_session() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let (masked, map) = mask_text(KEY);
        vault.record("session-a", &map).unwrap();

        let other = vault.lookup("session-b").unwrap();
        assert!(other.is_empty());
        let report = Anonymizer::restore(&masked, &other, UnknownPolicy::Redact);
        assert_eq!(report.unknown.len(), 2);
        assert!(!report.text.contains(EMAIL));
        assert!(!report.text.contains(PHONE));
    }

    #[test]
    fn record_moved_to_another_session_slot_is_rejected() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        fs::copy(
            vault.record_path(&slot_for("session-a")),
            vault.record_path(&slot_for("session-b")),
        )
        .unwrap();

        assert!(matches!(
            vault.lookup("session-b"),
            Err(VaultError::Corrupt(_))
        ));
        assert!(!vault.lookup("session-a").unwrap().is_empty());
    }

    #[test]
    fn forget_session_removes_only_that_session() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        vault.record("session-b", &mask_text([8; 32]).1).unwrap();

        assert!(vault.forget_session("session-a").unwrap());
        assert!(vault.lookup("session-a").unwrap().is_empty());
        assert!(!vault.lookup("session-b").unwrap().is_empty());
        assert!(!vault.forget_session("session-a").unwrap());
    }

    #[test]
    fn forget_value_erases_one_person_across_sessions() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        vault.record("session-a", &marie.1).unwrap();
        vault.record("session-b", &mask_text([8; 32]).1).unwrap();

        assert_eq!(vault.forget_value(EMAIL).unwrap(), 2);

        let a = vault.lookup("session-a").unwrap();
        assert_eq!(a.len(), 2, "phone and the other person remain");
        assert!(a.iter().all(|(_, original)| original != EMAIL));
        assert!(a
            .occurrences()
            .iter()
            .all(|(_, original)| original != EMAIL));
        assert_eq!(vault.lookup("session-b").unwrap().len(), 1);
        assert_eq!(vault.forget_value(EMAIL).unwrap(), 0);
    }

    #[test]
    fn forget_value_matches_after_nfkc_folding() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
        vault.record("session-a", &marie.1).unwrap();

        // Fullwidth Latin folds to ASCII under NFKC.
        assert_eq!(vault.forget_value("ｍａｒｉｅ@example.test").unwrap(), 1);
        assert!(vault.lookup("session-a").unwrap().is_empty());
    }

    #[test]
    fn forget_value_erases_a_person_in_any_case_and_padding() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        // The token keys on the exact spelling, so each surface is its own token.
        let lower = mask(
            KEY,
            "Bonjour Camille Exemple.",
            &[("Camille Exemple", EntityKind::Person)],
        );
        let upper = mask(
            KEY,
            "Bonjour CAMILLE EXEMPLE.",
            &[("CAMILLE EXEMPLE", EntityKind::Person)],
        );
        vault.record("session-a", &lower.1).unwrap();
        vault.record("session-a", &upper.1).unwrap();

        assert_eq!(vault.forget_value("camille exemple").unwrap(), 2);
        assert!(vault.lookup("session-a").unwrap().is_empty());

        vault.record("session-a", &lower.1).unwrap();
        vault.record("session-a", &upper.1).unwrap();
        assert_eq!(vault.forget_value(" CAMILLE EXEMPLE ").unwrap(), 2);
        assert!(vault.lookup("session-a").unwrap().is_empty());
    }

    #[test]
    fn forget_value_matches_an_email_in_any_case() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
        vault.record("session-a", &marie.1).unwrap();

        assert_eq!(vault.forget_value("MARIE@Example.TEST").unwrap(), 1);
        assert!(vault.lookup("session-a").unwrap().is_empty());
    }

    #[test]
    fn forget_value_erases_every_surface_of_a_shared_token() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        // Spaced surface first, compact surface second: one token, two surfaces.
        let text = "Appelez 06 12 34 56 78 ou 0612345678.";
        let (_, map) = mask(
            KEY,
            text,
            &[
                ("06 12 34 56 78", EntityKind::Phone),
                ("0612345678", EntityKind::Phone),
            ],
        );
        assert_eq!(map.len(), 1, "both surfaces share one token");
        vault.record("session-a", &map).unwrap();

        assert_eq!(vault.forget_value("0612345678").unwrap(), 1);
        let left = vault.lookup("session-a").unwrap();
        assert!(left.is_empty());
        assert!(left.occurrences().is_empty());
    }

    #[test]
    fn a_token_mapped_to_another_value_is_refused() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let token = "PHONE_0A1B2C3D4E5F";
        vault
            .record("session-a", &single(token, "0612345678"))
            .unwrap();
        let before = vault.lookup("session-a").unwrap();

        // A second value that minted the same token, as two anonymizers can.
        let clash = single(token, "0712345678");
        assert!(matches!(
            vault.record("session-a", &clash),
            Err(VaultError::TokenConflict)
        ));
        assert_eq!(vault.lookup("session-a").unwrap(), before);
    }

    #[test]
    fn the_same_value_under_another_surface_is_not_a_conflict() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let token = "PHONE_0A1B2C3D4E5F";
        vault
            .record("session-a", &single(token, "06 12 34 56 78"))
            .unwrap();
        vault
            .record("session-a", &single(token, "0612345678"))
            .unwrap();

        let loaded = vault.lookup("session-a").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.occurrences().len(), 2);
    }

    #[test]
    fn two_handles_recording_in_parallel_keep_every_update() {
        let dir = TempDir::new().unwrap();
        Vault::open(dir.path()).unwrap();
        std::thread::scope(|scope| {
            for worker in 0..2 {
                let root = dir.path();
                scope.spawn(move || {
                    let vault = Vault::open(root).unwrap();
                    for index in 0..25 {
                        let needle = format!("worker{worker}-{index}@example.test");
                        let text = format!("Écrivez à {needle}.");
                        let (_, map) = mask(KEY, &text, &[(needle.as_str(), EntityKind::Email)]);
                        vault.record("session-shared", &map).unwrap();
                    }
                });
            }
        });

        let vault = Vault::open(dir.path()).unwrap();
        assert_eq!(vault.lookup("session-shared").unwrap().len(), 50);
    }

    #[test]
    fn a_copy_of_a_record_from_before_an_erasure_is_refused() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        let path = vault.record_path(&slot_for("session-a"));
        let before = fs::read(&path).unwrap();

        assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);
        fs::write(&path, &before).unwrap();

        assert!(matches!(
            vault.lookup("session-a"),
            Err(VaultError::Rollback)
        ));
        assert!(matches!(
            vault.record("session-a", &mask_text(KEY).1),
            Err(VaultError::Rollback)
        ));
    }

    #[test]
    fn a_forgotten_session_cannot_be_restored_from_a_copy() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        let path = vault.record_path(&slot_for("session-a"));
        let before = fs::read(&path).unwrap();

        assert!(vault.forget_session("session-a").unwrap());
        fs::write(&path, &before).unwrap();

        assert!(matches!(
            vault.lookup("session-a"),
            Err(VaultError::Rollback)
        ));
    }

    #[test]
    fn a_stale_record_is_still_erased_by_forget_value() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        let path = vault.record_path(&slot_for("session-a"));
        let before = fs::read(&path).unwrap();
        assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);

        // The old copy is back, as after a write interrupted before its record.
        fs::write(&path, &before).unwrap();
        assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);

        let left = vault.lookup("session-a").unwrap();
        assert_eq!(left.len(), 1, "the phone remains");
        assert!(left.iter().all(|(_, original)| original != EMAIL));
    }

    #[test]
    fn a_missing_or_tampered_manifest_fails_closed() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        let manifest = dir.path().join(MANIFEST_FILE);
        let sealed = fs::read(&manifest).unwrap();

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        fs::write(&manifest, &tampered).unwrap();
        assert!(matches!(
            vault.lookup("session-a"),
            Err(VaultError::Corrupt(_))
        ));

        fs::remove_file(&manifest).unwrap();
        assert!(matches!(
            vault.lookup("session-a"),
            Err(VaultError::Corrupt(_))
        ));

        fs::write(&manifest, &sealed).unwrap();
        assert!(!vault.lookup("session-a").unwrap().is_empty());
    }

    #[test]
    fn no_value_appears_in_the_bytes_on_disk() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-canary", &mask_text(KEY).1).unwrap();
        let bytes = fs::read(vault.record_path(&slot_for("session-canary"))).unwrap();

        for needle in [EMAIL, PHONE, "session-canary"] {
            assert!(
                !contains(&bytes, needle.as_bytes()),
                "a plaintext value or session id appears in the record file"
            );
        }
    }

    #[test]
    fn debug_output_shows_neither_the_key_nor_a_value() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let key_hex = hex(&fs::read(dir.path().join(KEY_FILE)).unwrap());
        let shown = format!("{vault:?} {:?}", mask_text(KEY).1);
        assert!(!shown.contains(EMAIL));
        assert!(!shown.contains(&key_hex));
    }

    #[test]
    fn recording_the_same_map_twice_keeps_one_entry_per_token() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let (masked, map) = mask_text(KEY);
        vault.record("session-a", &map).unwrap();
        vault.record("session-a", &map).unwrap();

        let loaded = vault.lookup("session-a").unwrap();
        assert_eq!(loaded.len(), 2);
        let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
        assert_eq!(report.text, TEXT);
    }

    /// Arms `point` on this thread: the next operation that reaches it fails.
    fn arm_crash(point: CrashPoint) {
        CRASH_AT.with(|armed| armed.set(Some(point)));
    }

    /// The generation of the session's record on disk, and of its manifest entry.
    fn generations(vault: &Vault, session_id: &str) -> (Option<u64>, u64) {
        let slot = slot_for(session_id);
        let record = vault
            .open_record(&slot)
            .unwrap()
            .map(|record| record.generation);
        (record, vault.load_manifest().unwrap().generation(&slot))
    }

    #[test]
    fn crash_between_a_record_and_its_manifest_commits_the_record() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
        vault.record("session-a", &marie.1).unwrap();
        let path = vault.record_path(&slot_for("session-a"));
        let before = fs::read(&path).unwrap();

        let (masked, map) = mask_text(KEY);
        arm_crash(CrashPoint::AfterRecordWrite);
        assert!(matches!(
            vault.record("session-a", &map),
            Err(VaultError::Io(_))
        ));
        drop(vault);

        let reopened = Vault::open(dir.path()).unwrap();
        assert_eq!(generations(&reopened, "session-a"), (Some(2), 1));
        // The record was replaced first, so the write is committed. The read
        // raises the manifest to match it.
        let loaded = reopened.lookup("session-a").unwrap();
        assert_eq!(loaded.len(), 3, "marie plus the two masked values");
        let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
        assert_eq!(report.text, TEXT);
        assert_eq!(generations(&reopened, "session-a"), (Some(2), 2));

        // Once repaired, a copy from before the crashed write is refused.
        fs::write(&path, &before).unwrap();
        assert!(matches!(
            reopened.lookup("session-a"),
            Err(VaultError::Rollback)
        ));
    }

    #[test]
    fn crash_in_the_first_write_leaves_a_usable_vault() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let (masked, map) = mask_text(KEY);
        arm_crash(CrashPoint::AfterRecordWrite);
        assert!(matches!(
            vault.record("session-a", &map),
            Err(VaultError::Io(_))
        ));
        drop(vault);

        // The manifest already existed, so the lone record is not a corrupt vault.
        let reopened = Vault::open(dir.path()).unwrap();
        let loaded = reopened.lookup("session-a").unwrap();
        let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
        assert_eq!(report.text, TEXT);
        reopened.record("session-b", &mask_text([8; 32]).1).unwrap();
        assert_eq!(generations(&reopened, "session-a"), (Some(1), 1));
    }

    #[test]
    fn crash_before_an_erasure_unlinks_refuses_the_record_until_a_retry() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        let path = vault.record_path(&slot_for("session-a"));
        let before = fs::read(&path).unwrap();

        arm_crash(CrashPoint::AfterGenerationBump);
        assert!(matches!(
            vault.forget_session("session-a"),
            Err(VaultError::Io(_))
        ));
        drop(vault);

        // The erasure is never undone: the leftover record is refused, not read.
        let reopened = Vault::open(dir.path()).unwrap();
        assert!(matches!(
            reopened.lookup("session-a"),
            Err(VaultError::Rollback)
        ));
        // A retry clears the leftover file and leaves the session empty.
        assert!(reopened.forget_session("session-a").unwrap());
        assert!(reopened.lookup("session-a").unwrap().is_empty());
        // A copy of the pre-erasure record stays refused.
        fs::write(&path, &before).unwrap();
        assert!(matches!(
            reopened.lookup("session-a"),
            Err(VaultError::Rollback)
        ));
    }

    #[test]
    fn crash_in_an_erasure_that_empties_a_session_is_finished_by_a_retry() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
        vault.record("session-a", &marie.1).unwrap();

        arm_crash(CrashPoint::AfterGenerationBump);
        assert!(matches!(
            vault.forget_value("marie@example.test"),
            Err(VaultError::Io(_))
        ));
        drop(vault);

        let reopened = Vault::open(dir.path()).unwrap();
        assert!(matches!(
            reopened.lookup("session-a"),
            Err(VaultError::Rollback)
        ));
        assert_eq!(reopened.forget_value("marie@example.test").unwrap(), 1);
        assert!(reopened.lookup("session-a").unwrap().is_empty());
    }

    #[test]
    fn crash_after_an_erasure_rewrite_keeps_the_erasure() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();

        arm_crash(CrashPoint::AfterRecordWrite);
        assert!(matches!(vault.forget_value(EMAIL), Err(VaultError::Io(_))));
        drop(vault);

        let reopened = Vault::open(dir.path()).unwrap();
        let left = reopened.lookup("session-a").unwrap();
        assert_eq!(left.len(), 1, "the phone remains");
        assert!(left.iter().all(|(_, original)| original != EMAIL));
        assert!(left
            .occurrences()
            .iter()
            .all(|(_, original)| original != EMAIL));
    }

    #[test]
    fn forgetting_one_address_keeps_the_one_that_differs_by_an_accent() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let text = "Écrivez à José@example.test et à Jos@example.test.";
        let (_, map) = mask(
            KEY,
            text,
            &[
                ("José@example.test", EntityKind::Email),
                ("Jos@example.test", EntityKind::Email),
            ],
        );
        assert_eq!(map.len(), 2, "two addresses, two tokens");
        vault.record("session-a", &map).unwrap();

        assert_eq!(vault.forget_value("José@example.test").unwrap(), 1);
        let left = vault.lookup("session-a").unwrap();
        assert_eq!(left.len(), 1);
        assert!(left
            .iter()
            .all(|(_, original)| original == "Jos@example.test"));
    }

    #[test]
    fn erasure_reaches_a_record_the_manifest_has_fallen_behind() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
        vault.record("session-a", &marie.1).unwrap();
        // A manifest restored from an older copy names generation 0.
        let mut manifest = vault.load_manifest().unwrap();
        vault
            .set_generation(&mut manifest, &slot_for("session-a"), 0)
            .unwrap();
        assert!(matches!(
            vault.lookup("session-a"),
            Err(VaultError::Corrupt(_))
        ));

        // The erasure still reaches the record, and the erased copy is newer.
        assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);
        let left = vault.lookup("session-a").unwrap();
        assert_eq!(left.len(), 2, "phone and the other person remain");
        assert!(left.iter().all(|(_, original)| original != EMAIL));
    }

    #[test]
    fn erasure_removes_a_leftover_temp_file_of_an_interrupted_write() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.record("session-a", &mask_text(KEY).1).unwrap();
        // The temp file `write_atomic` names for this record, left by a crash
        // before the rename. It holds the ciphertext of the email.
        let slot = slot_for("session-a");
        let leftover = dir
            .path()
            .join(SESSIONS_DIR)
            .join(format!(".{slot}.{RECORD_EXT}.tmp.4242.1"));
        fs::copy(vault.record_path(&slot), &leftover).unwrap();

        assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);
        assert!(
            !leftover.exists(),
            "the erased value must not survive in a temp file"
        );
    }

    /// Sets the session's manifest generation, as a restored manifest would.
    fn set_manifest(vault: &Vault, session_id: &str, generation: u64) {
        let mut manifest = vault.load_manifest().unwrap();
        vault
            .set_generation(&mut manifest, &slot_for(session_id), generation)
            .unwrap();
    }

    /// Writes `map` as the session's record at `generation`, through the vault's
    /// own write path: the manifest is set one below, then the record is written.
    fn record_at(vault: &Vault, session_id: &str, map: &TokenMap, generation: u64) {
        set_manifest(vault, session_id, generation - 1);
        vault.record(session_id, map).unwrap();
    }

    /// One call to each public operation on `session-a`, with its result.
    fn run_each(vault: &Vault, map: &TokenMap) -> Vec<(&'static str, Result<(), VaultError>)> {
        vec![
            ("lookup", vault.lookup("session-a").map(|_| ())),
            ("record", vault.record("session-a", map)),
            (
                "forget_session",
                vault.forget_session("session-a").map(|_| ()),
            ),
            ("forget_value", vault.forget_value(EMAIL).map(|_| ())),
        ]
    }

    #[test]
    fn generation_at_max_refuses_every_operation_and_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let (_, map) = mask_text(KEY);
        record_at(&vault, "session-a", &map, u64::MAX);
        let path = vault.record_path(&slot_for("session-a"));
        let before = fs::read(&path).unwrap();

        for (name, result) in run_each(&vault, &map) {
            assert!(
                matches!(result, Err(VaultError::GenerationExhausted)),
                "{name} at u64::MAX: {result:?}"
            );
        }
        assert_eq!(fs::read(&path).unwrap(), before, "the record is untouched");
        assert_eq!(
            generations(&vault, "session-a"),
            (Some(u64::MAX), u64::MAX),
            "the generation does not wrap"
        );

        // A session with no record but a generation at the limit: a write is refused
        // before its record is created.
        set_manifest(&vault, "session-c", u64::MAX);
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]).1;
        assert!(matches!(
            vault.record("session-c", &marie),
            Err(VaultError::GenerationExhausted)
        ));
        assert!(!vault.record_path(&slot_for("session-c")).exists());

        // Another session is unaffected.
        vault.record("session-b", &marie).unwrap();
        assert_eq!(generations(&vault, "session-b"), (Some(1), 1));
    }

    #[test]
    fn crash_one_below_max_commits_the_last_generation_on_read() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let (_, map) = mask_text(KEY);
        set_manifest(&vault, "session-a", u64::MAX - 1);
        arm_crash(CrashPoint::AfterRecordWrite);
        assert!(matches!(
            vault.record("session-a", &map),
            Err(VaultError::Io(_))
        ));
        drop(vault);

        // The record sits at `u64::MAX`, one ahead of the manifest: the read commits it.
        let reopened = Vault::open(dir.path()).unwrap();
        assert_eq!(
            generations(&reopened, "session-a"),
            (Some(u64::MAX), u64::MAX - 1)
        );
        assert_eq!(reopened.lookup("session-a").unwrap(), map);
        assert_eq!(
            generations(&reopened, "session-a"),
            (Some(u64::MAX), u64::MAX)
        );
        assert!(matches!(
            reopened.lookup("session-a"),
            Err(VaultError::GenerationExhausted)
        ));
    }

    #[test]
    fn generation_one_below_max_takes_one_last_step_then_refuses() {
        let (_, map) = mask_text(KEY);
        let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]).1;
        for step in ["record", "forget_session", "forget_value"] {
            let dir = TempDir::new().unwrap();
            let vault = Vault::open(dir.path()).unwrap();
            record_at(&vault, "session-a", &map, u64::MAX - 1);
            assert_eq!(
                vault.lookup("session-a").unwrap(),
                map,
                "{step}: a read below u64::MAX is unchanged"
            );

            let result = match step {
                "record" => vault.record("session-a", &marie),
                "forget_session" => vault.forget_session("session-a").map(|_| ()),
                _ => vault.forget_value(EMAIL).map(|_| ()),
            };
            assert!(result.is_ok(), "{step} at u64::MAX - 1: {result:?}");
            assert_eq!(
                generations(&vault, "session-a").1,
                u64::MAX,
                "{step} takes the last generation"
            );
            assert!(
                matches!(
                    vault.record("session-a", &marie),
                    Err(VaultError::GenerationExhausted)
                ),
                "{step}: a write past u64::MAX is refused"
            );
            assert!(
                matches!(
                    vault.forget_session("session-a"),
                    Err(VaultError::GenerationExhausted)
                ),
                "{step}: an erasure past u64::MAX is refused"
            );
        }
    }
}
