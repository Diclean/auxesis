//! Encryption at rest for the local store.
//!
//! One `master.key` roots every key. It is 32 random bytes from the operating
//! system CSPRNG, created atomically (`O_CREAT|O_EXCL`, mode `0600`, fsynced)
//! in the store's directory, and refused if it is a symlink, not a regular
//! file, owned by another user, or readable by group or others. It is never
//! logged and never tightened: the owner fixes a loose mode.
//!
//! Two keys are derived from it with HKDF-SHA256 over a fixed application salt
//! (no key-encryption-key file, no wrapped data key):
//!
//! ```text
//! <home>/master.key   32 random bytes, 0600
//! <home>/store.db     SQLCipher, key = HKDF(master, "auxesis/store/v1")
//! vault key           HKDF(master, "auxesis/vault/v1")   (see [`vault_key`])
//! evidence key        HKDF(master, "auxesis/evidence/v1") (see [`evidence_key`])
//! ```
//!
//! The derived store key is handed to SQLCipher as a raw key, so no passphrase
//! KDF runs on each open. A wrong or missing master key refuses the open and
//! leaves the store bytes alone.
//!
//! # Migration from the pre-WO-06c layout
//!
//! The old layout kept a random KEK (`keys/store.kek`) wrapping a random DEK
//! (`keys/store.dek`) that keyed the database. When those files are present the
//! store is re-keyed once, in place, with SQLCipher's `PRAGMA rekey`: a copy of
//! the database is written first (`store.db.legacy-bak`, `0600`), the rekey
//! runs, the derived key is verified against the live file, and only then are
//! the old key files and the backup removed. A crash at any point leaves either
//! the old-keyed store (and the backup) or the new-keyed store (and the old key
//! files), and the next open finishes the job. The old DEK is never used as the
//! final key: the derived store key is.
//!
//! The session vault (kernel-privacy `Vault`) is process-memory only in this
//! build (`auxd::api::display::MemorySessionTokens`); no `Vault::open` call
//! site exists in the app, so there is no on-disk vault sealed under an old
//! `vault.key` to re-seal. [`vault_key`] exposes the derived key for the
//! future on-disk vault, and its derivation is tested here.
//!
//! # Hardening
//!
//! All fail-closed: the store directory must be a real directory owned by this
//! user that no other user can write into; a key file must be a regular file
//! that only its owner can read. A symlink, another owner or a loose mode is
//! refused, never followed or silently tightened. Every keyed connection wipes
//! freed SQLCipher memory and keeps temporary data in memory. No key is logged
//! or put in an error, and the in-memory copies are zeroized (aes-gcm 0.10
//! keeps its expanded key schedule un-wiped; the window is one wrap or unwrap
//! call).
//!
//! The plaintext backup of a plaintext→SQLCipher migration exists only until
//! the first keyed open after the swap. It is zeroed before it is unlinked.

use super::StoreError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce};
use hkdf::Hkdf;
use rusqlite::{params, Connection, ErrorCode, OpenFlags};
use sha2::Sha256;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// The one root key file, beside the store.
const MASTER_FILE: &str = "master.key";
/// Where a new root key is written before it is linked to `MASTER_FILE`.
const MASTER_STAGING_FILE: &str = "master.key.new";
/// Room for `PRAGMA rekey = "x'<64 hex digits>'";`, so building the key statement
/// never reallocates and leaves a stale copy of the key text behind.
const PRAGMA_KEY_CAPACITY: usize =
    "PRAGMA rekey = \"".len() + "x''".len() + 2 * KEY_LEN + "\";".len();
/// Refusal text for a damaged `master.key` beside store data (EN, then FR).
const DAMAGED_MASTER_REASON: &str = "master.key is empty or the wrong length beside existing store data; refusing to replace it (master.key est vide ou de mauvaise taille à côté des données du store ; remplacement refusé)";
/// Refusal text for a legacy backup beside an empty store (EN, then FR).
const LEGACY_BACKUP_REASON: &str = "a legacy store backup is present beside an empty store; refusing to continue (une sauvegarde héritée est présente à côté d'un store vide ; arrêt)";
/// The advisory lock that serializes a first open and the one-time migrations.
const LOCK_FILE: &str = ".store.lock";
/// The pre-WO-06c key layout, read only to migrate it.
const LEGACY_KEYS_DIR: &str = "keys";
const LEGACY_KEK_FILE: &str = "store.kek";
const LEGACY_DEK_FILE: &str = "store.dek";
const DEK_MAGIC: &[u8] = b"AUXDEK01";
const DEK_AAD: &[u8] = b"auxesis.store.dek.v1";
/// Fixed HKDF salt for every Auxesis key derivation.
const HKDF_SALT: &[u8] = b"auxesis.master.v1";
/// HKDF `info` for the SQLCipher store key.
const STORE_INFO: &[u8] = b"auxesis/store/v1";
/// HKDF `info` for the session-vault key.
const VAULT_INFO: &[u8] = b"auxesis/vault/v1";
/// HKDF `info` for the evidence-blob key, and the sealed blob's magic.
const EVIDENCE_INFO: &[u8] = b"auxesis/evidence/v1";
const EVIDENCE_MAGIC: &[u8] = b"AUXEVD01";
/// Suffixes of the files a migration may leave beside the store.
const MIGRATION_SCRATCH_SUFFIX: &str = ".encrypting";
const PLAINTEXT_BACKUP_SUFFIX: &str = ".plaintext-bak";
const LEGACY_BACKUP_SUFFIX: &str = ".legacy-bak";
/// How long a migration waits for a reader that holds the journal.
const MIGRATION_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Permission bits a directory must not grant to anyone but its owner. The store
/// directory only has to keep other users from writing into it, so group and other write
/// are denied. The legacy `keys/` directory is created `0700` and must grant group and
/// other nothing at all.
const STORE_DIR_DENIED_BITS: u32 = 0o022;
const LEGACY_KEYS_DIR_DENIED_BITS: u32 = 0o077;

/// A 256-bit key. Wiped from memory on drop, and its `Debug` never shows bytes.
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    fn zeroed() -> Self {
        Self(Zeroizing::new([0u8; KEY_LEN]))
    }

    /// The raw bytes. Callers must not log, print or persist them in the clear.
    pub fn expose(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// Open an existing encrypted store read-write, without running migrations.
///
/// For callers that read or seed rows outside [`super::Store`] (tests, tools).
/// A plaintext store is refused: only [`super::Store::open`] migrates one.
pub fn open_keyed(path: &Path) -> Result<Connection, StoreError> {
    open_existing(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
}

/// Open an existing encrypted store read-only (CLI and daemon read paths).
pub fn open_keyed_readonly(path: &Path) -> Result<Connection, StoreError> {
    open_existing(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
}

thread_local! {
    /// Set only by `open_keyed_snapshot`: live daemon readers never open immutable.
    static SNAPSHOT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Open an existing encrypted store read-only for a one-shot preview (`--dry-run`):
/// when no writer holds it (no shared memory beside it) it is opened immutable, so
/// SQLite creates neither a WAL nor a shared memory.
pub fn open_keyed_snapshot(path: &Path) -> Result<Connection, StoreError> {
    SNAPSHOT.with(|snapshot| snapshot.set(true));
    let opened = open_existing(path, OpenFlags::SQLITE_OPEN_READ_ONLY);
    SNAPSHOT.with(|snapshot| snapshot.set(false));
    opened
}

/// The derived key that keys the SQLCipher store at `home/store.db`.
pub fn store_key(home: &Path) -> Result<Key, StoreError> {
    Ok(derive(&read_master(home)?, STORE_INFO))
}

/// The derived key for the session vault (`auxesis/vault/v1`).
///
/// The vault is process-memory only in this build, so nothing is sealed under
/// this key yet; it is exposed for the on-disk vault that replaces
/// `MemorySessionTokens`.
pub fn vault_key(home: &Path) -> Result<Key, StoreError> {
    Ok(derive(&read_master(home)?, VAULT_INFO))
}

/// The derived key for evidence blobs at rest (`auxesis/evidence/v1`, DOC-SAFE-1).
pub fn evidence_key(home: &Path) -> Result<Key, StoreError> {
    Ok(derive(&read_master(home)?, EVIDENCE_INFO))
}

/// Seal one evidence blob as `magic || nonce || ciphertext+tag`. `name` (the
/// blob's content address) is the associated data, so a blob moved to another
/// name no longer opens.
pub fn seal_evidence(key: &Key, name: &str, plain: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    random(&mut nonce)?;
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key.expose()));
    let payload = Payload {
        msg: plain,
        aad: name.as_bytes(),
    };
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| StoreError::KeyRejected)?;
    let mut out = Vec::with_capacity(EVIDENCE_MAGIC.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(EVIDENCE_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a blob [`seal_evidence`] wrote. `None` when `sealed` is not one (no
/// magic, wrong key, wrong name or tampered bytes).
pub fn open_evidence(key: &Key, name: &str, sealed: &[u8]) -> Option<Vec<u8>> {
    let body = sealed.strip_prefix(EVIDENCE_MAGIC)?;
    if body.len() < NONCE_LEN {
        return None;
    }
    let (nonce, msg) = body.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key.expose()));
    let payload = Payload {
        msg,
        aad: name.as_bytes(),
    };
    cipher.decrypt(Nonce::from_slice(nonce), payload).ok()
}

fn open_existing(path: &Path, flags: OpenFlags) -> Result<Connection, StoreError> {
    if is_empty_or_missing(path)? {
        // A zero-byte file holds no pages, so there is nothing to decrypt: a
        // read-only caller sees an empty store, as it always has. A writer
        // never gets an unkeyed database out of it.
        if path.exists() && flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY) {
            return Ok(Connection::open_with_flags(path, flags)?);
        }
        return Err(io::Error::new(io::ErrorKind::NotFound, "store does not exist").into());
    }
    check_store_dir(path)?;
    let store_key = match store_key(parent_of(path)) {
        Ok(store_key) => store_key,
        // No root key: a plaintext store says so (only `Store::open` migrates);
        // an encrypted one is missing the key that would open it.
        Err(StoreError::KeyMissing) => {
            if is_plaintext(path, flags)? {
                return Err(StoreError::NotEncrypted);
            }
            return Err(StoreError::KeyMissing);
        }
        Err(err) => return Err(err),
    };
    match keyed_open(path, flags, &store_key) {
        Ok(conn) => {
            // A keyed open proves the store is encrypted, so a plaintext copy
            // left by an interrupted migration is stale. Best effort: a reader
            // must not fail because it could not clean up.
            let _ = remove_migration_leftovers(path);
            return Ok(conn);
        }
        Err(StoreError::KeyRejected) => {}
        Err(err) => return Err(err),
    }
    if is_plaintext(path, flags)? {
        return Err(StoreError::NotEncrypted);
    }
    Err(StoreError::KeyRejected)
}

/// Exclusive lock on `<home>/.store.lock`, held by one `Store::open` until the
/// schema is current. The master key, the keyed open and any migration all run
/// under it, so a concurrent first open can never mint a second root over the
/// one a first opener is already using.
pub(super) struct OpenLock {
    _file: File,
}

pub(super) fn lock_for_open(path: &Path) -> Result<OpenLock, StoreError> {
    let lock = parent_of(path).join(LOCK_FILE);
    let prior = prior_key_slot(&lock)?;
    let file = open_verified(
        &lock,
        private_options().read(true).write(true).create(true),
        prior.as_ref(),
        true,
    )?;
    file.lock()?;
    Ok(OpenLock { _file: file })
}

/// Open the store at `path` as a keyed connection, creating or migrating it.
/// The caller holds the [`OpenLock`] for `path`. Creates `master.key` on first
/// use. A plaintext store or the pre-WO-06c key layout is migrated once.
pub(super) fn open_encrypted(path: &Path) -> Result<Connection, StoreError> {
    let home = parent_of(path);
    // A legacy backup beside an empty store means an earlier migration never finished.
    // Refused before any key is touched or minted, and nothing is deleted.
    if is_empty_or_missing(path)? && legacy_backup_exists(path) {
        return Err(migration_error(LEGACY_BACKUP_REASON));
    }
    // Legacy key files only matter for a store that is still encrypted. A plaintext
    // store was never under them, so they are ignored and the plaintext is migrated.
    let legacy = legacy_keys_present(path) && !is_plaintext_store(path)?;
    let master = match read_master(home) {
        Ok(master) => master,
        Err(StoreError::KeyMissing) if may_mint_master(path, legacy)? => {
            // The legacy DEK must open the store before a new root is minted over it.
            if legacy && !is_empty_or_missing(path)? {
                legacy_dek_opens(path)?;
            }
            create_master(home, false)?
        }
        // A damaged master is replaced only when no store data depends on it.
        Err(StoreError::KeyRejected) if is_empty_or_missing(path)? => create_master(home, true)?,
        Err(StoreError::KeyRejected) => return Err(migration_error(DAMAGED_MASTER_REASON)),
        Err(err) => return Err(err),
    };
    let store_key = derive(&master, STORE_INFO);

    if is_empty_or_missing(path)? {
        // Nothing to migrate. Legacy key files are left in place: only a finished
        // migration (backup present) may remove them.
        remove_if_exists(&sibling(path, MIGRATION_SCRATCH_SUFFIX))?;
        let conn = Connection::open(path)?;
        apply_key(&conn, &store_key)?;
        return Ok(conn);
    }

    // The derived key is tried first, so an ordinary start never probes the
    // file for plaintext and a finished-but-uncleaned rekey is completed here.
    match keyed_open(path, OpenFlags::SQLITE_OPEN_READ_WRITE, &store_key) {
        Ok(conn) => {
            if legacy && legacy_backup_exists(path) {
                cleanup_legacy_migration(path)?;
            }
            remove_migration_leftovers(path)?;
            return Ok(conn);
        }
        Err(StoreError::KeyRejected) => {}
        Err(err) => return Err(err),
    }

    if legacy {
        migrate_legacy(path, &store_key)?;
        let conn = keyed_open(path, OpenFlags::SQLITE_OPEN_READ_WRITE, &store_key)?;
        cleanup_legacy_migration(path)?;
        remove_migration_leftovers(path)?;
        return Ok(conn);
    }

    // Not openable with the derived key and no legacy key files: either a
    // plaintext store to migrate, or an encrypted one whose key is gone.
    if !is_plaintext(path, OpenFlags::SQLITE_OPEN_READ_WRITE)? {
        return Err(StoreError::KeyRejected);
    }
    migrate_plaintext(path, &store_key)?;
    let conn = keyed_open(path, OpenFlags::SQLITE_OPEN_READ_WRITE, &store_key)?;
    crash_point("before-leftover-removal")?;
    remove_migration_leftovers(path)?;
    Ok(conn)
}

/// Whether a missing `master.key` may be minted. It may when there is nothing
/// encrypted to orphan: no store yet, a legacy-keyed store to migrate, or a
/// plaintext store to migrate. A non-empty encrypted store with no master key
/// refuses, so the key is never silently replaced.
fn may_mint_master(path: &Path, legacy: bool) -> Result<bool, StoreError> {
    if legacy || is_empty_or_missing(path)? {
        return Ok(true);
    }
    is_plaintext(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
}

/// Open `path` with `key`. A missing or wrong key fails here, before any page
/// is read.
fn keyed_open(path: &Path, flags: OpenFlags, key: &Key) -> Result<Connection, StoreError> {
    check_store_dir(path)?;
    // A read-only reader writes nothing: with the shared memory beside the
    // store it locks it as it is; without it, it opens the file as it is, and
    // SQLite creates neither a WAL nor a shared memory beside it.
    let text = path.to_str().unwrap_or_default();
    let shm = PathBuf::from(format!("{text}-shm"));
    let conn = if SNAPSHOT.with(std::cell::Cell::get)
        && flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY)
        && !shm.exists()
        && !text.contains(['%', '?', '#'])
    {
        let uri = format!("file:{text}?mode=ro&immutable=1");
        Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)?
    } else {
        Connection::open_with_flags(path, flags)?
    };
    // A daemon may be mid-write: wait out a transient lock on the key check.
    let _ = conn.busy_timeout(Duration::from_secs(2));
    apply_key(&conn, key)?;
    Ok(conn)
}

/// True when the file holds a plaintext database. Probed through a SQLite
/// connection, not by reading the file's bytes: closing any descriptor on the
/// file releases the POSIX locks SQLite holds for the other connections of this
/// process.
fn is_plaintext(path: &Path, flags: OpenFlags) -> Result<bool, StoreError> {
    let conn = Connection::open_with_flags(path, flags)?;
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(true),
        Err(err) if not_a_database(&err) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn is_empty_or_missing(path: &Path) -> Result<bool, StoreError> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.len() == 0),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err.into()),
    }
}

/// SQLite's "file is not a database": the key does not decrypt the pages, or
/// the file is not a database at all.
fn not_a_database(err: &rusqlite::Error) -> bool {
    matches!(err, rusqlite::Error::SqliteFailure(code, _) if code.code == ErrorCode::NotADatabase)
}

// ---------------------------------------------------------------------------
// The root key and its derived keys
// ---------------------------------------------------------------------------

/// The master key, read through a verified descriptor. Missing, a symlink, a
/// loose mode or another owner fails closed.
fn read_master(home: &Path) -> Result<Key, StoreError> {
    let raw = read_key_file(&home.join(MASTER_FILE))?;
    if raw.len() != KEY_LEN {
        return Err(StoreError::KeyRejected);
    }
    let mut key = Key::zeroed();
    key.0.copy_from_slice(&raw[..]);
    Ok(key)
}

/// Mint `master.key`. The 32 random bytes go to a private staging file that is
/// fsynced, then hard-linked into place, so a crash leaves either no `master.key` or
/// a complete one, never an empty file. `replace` renames the key over a damaged
/// file instead. Without it, a key a concurrent creator linked first is read instead.
fn create_master(home: &Path, replace: bool) -> Result<Key, StoreError> {
    let mut key = Key::zeroed();
    random(&mut key.0[..])?;
    let master = home.join(MASTER_FILE);
    let staging = home.join(MASTER_STAGING_FILE);
    remove_if_exists(&staging)?;
    write_new_private(&staging, &key.0[..])?;
    let placed = if replace {
        fs::rename(&staging, &master)
    } else {
        fs::hard_link(&staging, &master)
    };
    // Unlinking the staged name leaves the master as its only name.
    let _ = remove_if_exists(&staging);
    match placed {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return read_master(home),
        Err(err) => return Err(err.into()),
    }
    sync_dir(home)?;
    let read = read_master(home)?;
    if read.expose() != key.expose() {
        return Err(StoreError::KeyFilesUnsafe);
    }
    Ok(read)
}

/// HKDF-SHA256 over the fixed application salt, one output block of 32 bytes.
fn derive(master: &Key, info: &[u8]) -> Key {
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), master.expose());
    // The pseudorandom key is the root of every derived key: wipe the copy here.
    // The `Hkdf` value itself is not wipeable: hkdf 0.12 keeps its HMAC state (keyed
    // by the same PRK) in a private field, with no zeroizing accessor. It is dropped
    // when this function returns.
    prk.as_mut_slice().zeroize();
    let mut key = Key::zeroed();
    hkdf.expand(info, &mut key.0[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Write `bytes` to a new file that only its owner can read, refusing a symlink
/// and an existing file (`O_CREAT|O_EXCL`).
fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_private_new(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Migration from the pre-WO-06c key layout
// ---------------------------------------------------------------------------

fn legacy_keys_dir_of(path: &Path) -> PathBuf {
    parent_of(path).join(LEGACY_KEYS_DIR)
}

fn legacy_backup_path(path: &Path) -> PathBuf {
    sibling(path, LEGACY_BACKUP_SUFFIX)
}

/// True when either old key file is present. The store is then under the old
/// DEK (or the rekey finished but its cleanup did not).
fn legacy_keys_present(path: &Path) -> bool {
    let keys = legacy_keys_dir_of(path);
    keys.join(LEGACY_KEK_FILE).exists() || keys.join(LEGACY_DEK_FILE).exists()
}

/// True when anything, file or link, sits where the legacy backup goes.
fn legacy_backup_exists(path: &Path) -> bool {
    fs::symlink_metadata(legacy_backup_path(path)).is_ok()
}

/// True when a non-empty file at `path` is a plaintext database.
fn is_plaintext_store(path: &Path) -> Result<bool, StoreError> {
    if is_empty_or_missing(path)? {
        return Ok(false);
    }
    is_plaintext(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
}

/// The old data key, unwrapped from `keys/store.kek` and `keys/store.dek`, once it is
/// proven to open the store. Read-only: a wrong key changes nothing on disk.
fn legacy_dek_opens(path: &Path) -> Result<Key, StoreError> {
    let keys_dir = legacy_keys_dir_of(path);
    check_legacy_keys_dir(&keys_dir)?;
    let kek = read_kek(&keys_dir)?;
    let wrapped = read_key_file(&keys_dir.join(LEGACY_DEK_FILE))?;
    let old = unwrap_dek(&kek, &wrapped)?;
    drop(keyed_open(path, OpenFlags::SQLITE_OPEN_READ_ONLY, &old)?);
    Ok(old)
}

/// Re-key the store from the old DEK to the derived key, once, crash-safely.
///
/// A copy of the database is written first; the rekey runs in place; the
/// derived key is verified against the live file. The old key files and the
/// backup are removed by [`cleanup_legacy_migration`], only after that verify.
fn migrate_legacy(path: &Path, store_key: &Key) -> Result<(), StoreError> {
    let old = legacy_dek_opens(path)?;
    let backup = legacy_backup_path(path);
    let backup_present = match fs::symlink_metadata(&backup) {
        Ok(meta) if meta.is_file() => true,
        Ok(_) => {
            // A symlink or other entry where the backup belongs: unlink it and
            // write a real copy. Never follow it.
            remove_key_file(&backup)?;
            false
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(err) => return Err(err.into()),
    };
    if !backup_present {
        checkpoint_legacy(path, &old)?;
        copy_private(path, &backup)?;
        sync_dir(parent_of(path))?;
    }
    crash_point("after-legacy-backup")?;
    rekey(path, &old, store_key)?;
    // The verify is the proof the rekey took: only now may anything be removed.
    keyed_open(path, OpenFlags::SQLITE_OPEN_READ_WRITE, store_key)?;
    crash_point("after-legacy-rekey")?;
    Ok(())
}

/// Fold the old-keyed store's WAL into the main file before it is copied.
fn checkpoint_legacy(path: &Path, key: &Key) -> Result<(), StoreError> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(MIGRATION_BUSY_TIMEOUT)?;
    apply_key(&conn, key)?;
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    if busy != 0 {
        return Err(migration_error(
            "legacy store is in use by another connection",
        ));
    }
    Ok(())
}

/// Copy the encrypted database to a private sibling. The copy is ciphertext
/// under the old DEK, so it is never plaintext; it is removed once the derived
/// key is verified.
fn copy_private(src: &Path, dst: &Path) -> Result<(), StoreError> {
    let mut source = File::open(src)?;
    let mut target = create_private_new(dst)?;
    io::copy(&mut source, &mut target)?;
    target.sync_all()?;
    Ok(())
}

/// Re-key the live store in place from `old` to `new` with SQLCipher's
/// `PRAGMA rekey`.
fn rekey(path: &Path, old: &Key, new: &Key) -> Result<(), StoreError> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(MIGRATION_BUSY_TIMEOUT)?;
    apply_key(&conn, old)?;
    conn.execute_batch(&raw_key_pragma("rekey", new))?;
    // The rewritten pages may sit in the WAL; fold them back before the verify.
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        row.get::<_, i64>(0)
    });
    Ok(())
}

/// Remove the old key files and the encrypted backup. Called only after the
/// derived key opened the live store.
fn cleanup_legacy_migration(path: &Path) -> Result<(), StoreError> {
    let keys_dir = legacy_keys_dir_of(path);
    for name in [LEGACY_DEK_FILE, LEGACY_KEK_FILE] {
        remove_key_file(&keys_dir.join(name))?;
    }
    // Best effort: only removes the directory when it is empty.
    let _ = fs::remove_dir(&keys_dir);
    if discard_legacy_backup(path)? {
        sync_dir(parent_of(path))?;
    }
    Ok(())
}

/// Unlink a key file without following a symlink. Missing is fine.
fn remove_key_file(path: &Path) -> Result<(), StoreError> {
    let prior = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    unlink_verified(path, identity(&prior))?;
    Ok(())
}

/// Unlink the encrypted legacy backup. True when something was removed.
fn discard_legacy_backup(path: &Path) -> Result<bool, StoreError> {
    let backup = legacy_backup_path(path);
    let prior = match fs::symlink_metadata(&backup) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    match unlink_verified(&backup, identity(&prior)) {
        Ok(()) => Ok(true),
        Err(Refused::Missing) => Ok(false),
        Err(Refused::Unsafe) => Err(migration_error(
            "legacy backup changed while it was checked; left in place",
        )),
        Err(Refused::Io(err)) => Err(err.into()),
    }
}

// ---------------------------------------------------------------------------
// Plaintext -> SQLCipher migration
// ---------------------------------------------------------------------------

/// Migrate the plaintext store at `path` to SQLCipher under `store_key`.
/// Crash-safe and idempotent:
///
/// 1. Fold the plaintext WAL into the main file, and check no journal is live.
/// 2. Export into a sibling file (`0600`) and verify it against the original.
/// 3. Re-check the journal, then delete the plaintext WAL and shared-memory index.
/// 4. Hard-link the original to a backup, then rename the export over `path`.
///
/// A crash before step 4 leaves the plaintext store in place, and the next open
/// starts over. A crash after step 4 leaves the encrypted store plus a plaintext
/// backup, which the next keyed open zeroes and removes.
fn migrate_plaintext(path: &Path, store_key: &Key) -> Result<(), StoreError> {
    let scratch = sibling(path, MIGRATION_SCRATCH_SUFFIX);
    remove_if_exists(&scratch)?;
    discard_backup(path)?;
    checkpoint_plaintext(path)?;
    crash_point("after-checkpoint")?;
    if let Err(err) = export_and_verify(path, &scratch, store_key) {
        // Best effort: the scratch file is encrypted under a key nothing uses.
        let _ = fs::remove_file(&scratch);
        return Err(err);
    }
    crash_point("after-export")?;
    // The export read through the plaintext WAL. A journal that is live now means
    // a connection wrote after the export, so the swap must not go ahead.
    if let Err(err) = ensure_no_live_journal(path) {
        let _ = fs::remove_file(&scratch);
        return Err(err);
    }
    remove_plaintext_side_files(path)?;
    fs::hard_link(path, sibling(path, PLAINTEXT_BACKUP_SUFFIX))?;
    crash_point("after-hard-link")?;
    fs::rename(&scratch, path)?;
    sync_dir(parent_of(path))?;
    crash_point("after-rename")?;
    Ok(())
}

fn export_and_verify(path: &Path, scratch: &Path, store_key: &Key) -> Result<(), StoreError> {
    // Create the scratch file private before SQLite writes into it.
    drop(create_private_new(scratch)?);
    export_plaintext(path, scratch, store_key)?;
    verify_export(path, scratch, store_key)
}

/// Fold the plaintext store's WAL into the main file, and refuse to go on if
/// another connection still holds the journal. A reader that holds the WAL for a
/// moment is waited for, not treated as a refusal.
fn checkpoint_plaintext(path: &Path) -> Result<(), StoreError> {
    {
        let plain = Connection::open(path)?;
        plain.busy_timeout(MIGRATION_BUSY_TIMEOUT)?;
        harden_connection(&plain)?;
        let busy: i64 = plain.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        if busy != 0 {
            return Err(migration_error(
                "plaintext store is in use by another connection",
            ));
        }
    }
    ensure_no_live_journal(path)
}

/// A non-empty plaintext WAL or rollback journal means a connection still writes to
/// the store, so its rows are not all in the main file yet.
fn ensure_no_live_journal(path: &Path) -> Result<(), StoreError> {
    for suffix in ["-wal", "-journal"] {
        if fs::metadata(sibling(path, suffix)).is_ok_and(|meta| meta.len() > 0) {
            return Err(migration_error("plaintext store still has a live journal"));
        }
    }
    Ok(())
}

/// Delete the plaintext store's WAL and shared-memory index. Both are empty after
/// the checkpoint, and removing them stops a later connection replaying them into
/// the encrypted store. Called only while `path` is still the plaintext store.
fn remove_plaintext_side_files(path: &Path) -> Result<(), StoreError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        remove_if_exists(&sibling(path, suffix))?;
    }
    Ok(())
}

/// Copy the whole plaintext database at `plain` into the new encrypted file
/// `enc`, with SQLCipher's `sqlcipher_export`.
fn export_plaintext(plain: &Path, enc: &Path, store_key: &Key) -> Result<(), StoreError> {
    let conn = Connection::open(plain)?;
    conn.busy_timeout(MIGRATION_BUSY_TIMEOUT)?;
    harden_connection(&conn)?;
    let key = raw_key_text(store_key);
    conn.execute(
        "ATTACH DATABASE ?1 AS encrypted KEY ?2",
        params![utf8(enc)?, key.as_str()],
    )?;
    conn.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))?;
    let user_version: i64 = conn.query_row("PRAGMA main.user_version", [], |row| row.get(0))?;
    conn.execute_batch(&format!(
        "PRAGMA encrypted.user_version = {user_version}; DETACH DATABASE encrypted;"
    ))?;
    Ok(())
}

type SchemaRow = (String, String, String, String);

/// The export must match the original before it may replace it: an intact
/// encrypted file, the same schema, the same row count per table, and the same
/// `user_version`.
fn verify_export(plain: &Path, enc: &Path, store_key: &Key) -> Result<(), StoreError> {
    let old = Connection::open(plain)?;
    harden_connection(&old)?;
    let new = Connection::open(enc)?;
    apply_key(&new, store_key)?;
    let mismatch = |what: &str| migration_error(format!("export check failed: {what}"));
    let integrity: String = new.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(mismatch("integrity_check"));
    }
    let schema =
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name";
    let old_schema = schema_rows(&old, schema)?;
    if old_schema != schema_rows(&new, schema)? {
        return Err(mismatch("schema"));
    }
    for (kind, name, _, _) in &old_schema {
        if kind != "table" {
            continue;
        }
        let count = format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\""));
        let before: i64 = old.query_row(&count, [], |row| row.get(0))?;
        let after: i64 = new.query_row(&count, [], |row| row.get(0))?;
        if before != after {
            return Err(mismatch("row count"));
        }
    }
    let before: i64 = old.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let after: i64 = new.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if before != after {
        return Err(mismatch("user_version"));
    }
    Ok(())
}

fn schema_rows(conn: &Connection, query: &str) -> Result<Vec<SchemaRow>, StoreError> {
    let mut stmt = conn.prepare(query)?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

// ---------------------------------------------------------------------------
// Legacy wrapping (read-only, for the migration above)
// ---------------------------------------------------------------------------

fn read_kek(keys_dir: &Path) -> Result<Key, StoreError> {
    let raw = read_key_file(&keys_dir.join(LEGACY_KEK_FILE))?;
    if raw.len() != KEY_LEN {
        return Err(StoreError::KeyRejected);
    }
    let mut kek = Key::zeroed();
    kek.0.copy_from_slice(&raw[..]);
    Ok(kek)
}

/// Wrap `dek` under `kek` as `magic || nonce || ciphertext+tag`. Only the
/// migration's own tests write the old layout; production only unwraps it.
#[cfg(test)]
fn wrap_dek(kek: &Key, dek: &Key) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    random(&mut nonce)?;
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(kek.expose()));
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: dek.expose(),
                aad: DEK_AAD,
            },
        )
        .map_err(|_| StoreError::KeyRejected)?;
    let mut out = Vec::with_capacity(DEK_MAGIC.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(DEK_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn unwrap_dek(kek: &Key, wrapped: &[u8]) -> Result<Key, StoreError> {
    let body = wrapped
        .strip_prefix(DEK_MAGIC)
        .ok_or(StoreError::KeyRejected)?;
    if body.len() < NONCE_LEN {
        return Err(StoreError::KeyRejected);
    }
    let (nonce, sealed) = body.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(kek.expose()));
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: DEK_AAD,
                },
            )
            .map_err(|_| StoreError::KeyRejected)?,
    );
    if plain.len() != KEY_LEN {
        return Err(StoreError::KeyRejected);
    }
    let mut dek = Key::zeroed();
    dek.0.copy_from_slice(&plain[..]);
    Ok(dek)
}

// ---------------------------------------------------------------------------
// SQLCipher key handling
// ---------------------------------------------------------------------------

/// Hand `key` to SQLCipher as a raw key and check it. SQLCipher only checks the
/// key on first use, so a wrong key surfaces here as "not a database". The
/// connection is hardened before the key is set, so no decrypted page is ever
/// read on a connection that is not yet wiped.
fn apply_key(conn: &Connection, key: &Key) -> Result<(), StoreError> {
    // SQLCipher's process-global init must have finished before the first key.
    ensure_sqlcipher_ready();
    harden_connection(conn)?;
    conn.execute_batch(&raw_key_pragma("key", key))?;
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(()),
        Err(err) if not_a_database(&err) => Err(StoreError::KeyRejected),
        Err(err) => Err(err.into()),
    }
}

/// How long [`ensure_sqlcipher_ready`] waits for the process's one-time SQLCipher
/// init. That init is short even on a loaded host, so the deadline only keeps a
/// genuinely broken library from hanging every opener forever.
const SQLCIPHER_READY_WAIT: Duration = Duration::from_secs(30);

/// Serializes and completes SQLCipher's process-global initialization before any
/// key is applied.
///
/// The bundled amalgamation sets SQLite's `sqlite3GlobalConfig.isInit` flag
/// *before* it runs `SQLITE_EXTRA_INIT` (`sqlcipher_extra_init`), and it runs that
/// extra init outside the init mutex. A second thread that opens a connection
/// inside the window returns from `sqlite3_initialize` at once, so its
/// `PRAGMA key` sees `sqlcipher_init == 0` and fails; `Store::open` reports that
/// as an error. A saturated parallel test run opens many stores at once, which is
/// exactly the window that made `Store::open` panic intermittently.
///
/// Every keyed open goes through here. The first thread runs a throwaway keyed
/// open until SQLCipher accepts a key; [`Once`] makes every other thread wait for
/// that, so no `PRAGMA key` runs against a half-initialised library. Once the
/// init has finished, later calls are a single atomic load.
static SQLCIPHER_READY: Once = Once::new();

fn ensure_sqlcipher_ready() {
    SQLCIPHER_READY.call_once(|| {
        let deadline = Instant::now() + SQLCIPHER_READY_WAIT;
        while !sqlcipher_accepts_a_key() {
            if Instant::now() >= deadline {
                // A genuinely broken init is reported by the real keyed open;
                // this barrier must never turn it into a hang.
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
}

/// One throwaway raw-keyed open on a private in-memory database. True once
/// SQLCipher accepts a key, which is the signal that its global init finished.
fn sqlcipher_accepts_a_key() -> bool {
    let Ok(conn) = Connection::open_in_memory() else {
        return false;
    };
    // A fixed throwaway key for a database that never reaches disk.
    let mut key = Key::zeroed();
    key.0[0] = 1;
    conn.execute_batch(&raw_key_pragma("key", &key)).is_ok()
}

/// Settings every connection to a store uses. Freed SQLCipher memory is wiped, and
/// temporary tables and sorter spill stay in memory, so no plaintext reaches a
/// temp file. Both are per connection (`temp_store`) or per process (the memory
/// wipe can only be turned on, never off).
fn harden_connection(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch("PRAGMA cipher_memory_security = ON; PRAGMA temp_store = MEMORY;")?;
    Ok(())
}

/// Append SQLCipher's raw-key text form, `x'<64 hex digits>'`, to `out`.
fn push_raw_key(out: &mut String, key: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("x'");
    for &byte in key {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out.push('\'');
}

/// `PRAGMA <keyword> = "x'<hex>'";` for SQLCipher. The buffer is sized up front, so
/// the key text is written once and never copied by a reallocation.
fn raw_key_pragma(keyword: &str, key: &Key) -> Zeroizing<String> {
    let mut sql = Zeroizing::new(String::with_capacity(PRAGMA_KEY_CAPACITY));
    sql.push_str("PRAGMA ");
    sql.push_str(keyword);
    sql.push_str(" = \"");
    push_raw_key(&mut sql, key.expose());
    sql.push_str("\";");
    sql
}

fn raw_key_text(key: &Key) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::new());
    push_raw_key(&mut text, key.expose());
    text
}

// ---------------------------------------------------------------------------
// Leftovers and file hardening
// ---------------------------------------------------------------------------

/// Remove what an interrupted plaintext migration may have left beside the
/// store. Only called after the store opened with its key, so `path` is already
/// encrypted.
fn remove_migration_leftovers(path: &Path) -> Result<(), StoreError> {
    let scratch_removed = remove_if_exists(&sibling(path, MIGRATION_SCRATCH_SUFFIX))?;
    let backup_removed = discard_backup(path)?;
    // A legacy backup is NOT removed here. Its ciphertext is under the retired DEK, so
    // nothing readable proves it is a copy of this store. It is removed only by
    // `cleanup_legacy_migration`, after a migration that this process verified.
    if scratch_removed || backup_removed {
        sync_dir(parent_of(path))?;
    }
    Ok(())
}

/// Remove the plaintext backup of a migration. A regular file is zeroed through a
/// verified descriptor before it is unlinked. A symlink is only unlinked, never written
/// through. The live store's own inode (a crash after the hard link leaves exactly that)
/// is never zeroed. A backup that fails verification is left in place and reported.
fn discard_backup(path: &Path) -> Result<bool, StoreError> {
    let backup = sibling(path, PLAINTEXT_BACKUP_SUFFIX);
    let prior = match fs::symlink_metadata(&backup) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    let removed = if prior.is_file() && !shares_store_inode(path, &prior) {
        zero_and_remove(&backup, &prior)
    } else {
        unlink_verified(&backup, identity(&prior))
    };
    match removed {
        Ok(()) => Ok(true),
        // A reader that cleans up at the same moment removed it first: same outcome.
        Err(Refused::Missing) => Ok(false),
        Err(Refused::Unsafe) => Err(migration_error(
            "plaintext backup is not a single regular file, or changed while it was checked; left in place",
        )),
        Err(Refused::Io(err)) => Err(err.into()),
    }
}

/// Overwrite a plaintext copy with zeros, then unlink it. A naive scan of its
/// blocks finds no rows. SSD wear levelling and APFS snapshots can keep old blocks,
/// so this narrows the window; it does not erase the copy. The copy is opened without
/// following a symlink, must have one name, and is zeroed only through that descriptor.
fn zero_and_remove(path: &Path, prior: &fs::Metadata) -> Result<(), Refused> {
    let mut file = open_verified(path, OpenOptions::new().write(true), Some(prior), false)?;
    zero_file(&mut file)?;
    let inode = identity(&file.metadata()?);
    drop(file);
    unlink_verified(path, inode)
}

/// Overwrite every byte of `file` with zeros, then sync it. A freshly opened handle
/// starts at byte zero, so the whole file is covered.
fn zero_file(file: &mut File) -> io::Result<()> {
    let zeros = [0u8; 4096];
    let mut left = file.metadata()?.len();
    while left > 0 {
        let chunk = usize::try_from(left).map_or(zeros.len(), |n| n.min(zeros.len()));
        file.write_all(&zeros[..chunk])?;
        left -= chunk as u64;
    }
    file.sync_all()
}

/// Why a key, lock or backup file was not opened.
enum Refused {
    /// The file is not there.
    Missing,
    /// A symlink, a non-regular file, another owner, a second name, loose key
    /// permissions, a different inode from the one checked, or a parent that moved.
    Unsafe,
    /// Any other failure.
    Io(io::Error),
}

impl From<io::Error> for Refused {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Refused::Missing,
            _ => Refused::Io(err),
        }
    }
}

impl From<Refused> for StoreError {
    fn from(refused: Refused) -> Self {
        match refused {
            Refused::Missing => StoreError::KeyMissing,
            Refused::Unsafe => StoreError::KeyFilesUnsafe,
            Refused::Io(err) => err.into(),
        }
    }
}

/// The (device, inode) pair that names one file. Without unix there is no inode to
/// compare, so every file counts as the same one.
#[cfg(unix)]
type Identity = (u64, u64);
#[cfg(not(unix))]
type Identity = ();

#[cfg(unix)]
fn identity(meta: &fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn identity(_: &fs::Metadata) -> Identity {}

/// True when the backup and the live store are one inode. A crash after the migration's
/// hard link leaves exactly that, and zeroing it would zero the store. Unknown counts as
/// shared, so the store is never zeroed by mistake.
fn shares_store_inode(store: &Path, backup: &fs::Metadata) -> bool {
    match fs::metadata(store) {
        Ok(live) => identity(&live) == identity(backup),
        Err(_) => true,
    }
}

/// Unlink `path` only while it still names the inode that was checked. A swap in the
/// meantime is reported as a mismatch, and the new entry is left alone.
fn unlink_verified(path: &Path, expect: Identity) -> Result<(), Refused> {
    if identity(&fs::symlink_metadata(path)?) != expect {
        return Err(Refused::Unsafe);
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Open a key, lock or backup file, then check the open descriptor. The path is never
/// checked and then reopened: `O_NOFOLLOW` refuses a symlink in the last component, and
/// every later read, write or zeroing goes through the returned descriptor. The file must
/// be a regular file owned by this user with exactly one name, and a key (`private`) must
/// have no group or other permission bits. `prior` is the `symlink_metadata` taken before
/// the open, if any, and the descriptor must be that inode. The parent directory must be a
/// real directory, and the same one before and after the open.
fn open_verified(
    path: &Path,
    options: &OpenOptions,
    prior: Option<&fs::Metadata>,
    private: bool,
) -> Result<File, Refused> {
    let parent = parent_of(path);
    let parent_before = dir_identity(parent)?;
    race_point(path);
    let file = open_no_follow(path, options)?;
    let meta = file.metadata()?;
    if !meta.is_file() || !single_owner(&meta, private) {
        return Err(Refused::Unsafe);
    }
    if prior.is_some_and(|prior| identity(prior) != identity(&meta)) {
        return Err(Refused::Unsafe);
    }
    if dir_identity(parent)? != parent_before {
        return Err(Refused::Unsafe);
    }
    Ok(file)
}

/// Open `path` with `options`, refusing a symlink in its last component and closing the
/// descriptor on exec. `O_NONBLOCK` keeps an open of a FIFO from waiting for a writer;
/// the caller then refuses anything that is not a regular file.
#[cfg(unix)]
fn open_no_follow(path: &Path, options: &OpenOptions) -> Result<File, Refused> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = options.clone();
    match options
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => Err(Refused::Unsafe),
        Err(err) => Err(err.into()),
    }
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path, options: &OpenOptions) -> Result<File, Refused> {
    options.open(path).map_err(Refused::from)
}

/// Owned by this user, one name, and for a key no group or other permission bits.
#[cfg(unix)]
fn single_owner(meta: &fs::Metadata, private: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    meta.uid() == uid && meta.nlink() == 1 && (!private || meta.mode() & 0o077 == 0)
}

#[cfg(not(unix))]
fn single_owner(_: &fs::Metadata, _: bool) -> bool {
    true
}

/// The identity of `dir`, which must be a real directory. A symlink is refused, so the
/// names beneath it are the ones that were checked.
fn dir_identity(dir: &Path) -> Result<Identity, Refused> {
    let meta = fs::symlink_metadata(dir)?;
    if meta.is_dir() {
        Ok(identity(&meta))
    } else {
        Err(Refused::Unsafe)
    }
}

/// Read a key file through a verified descriptor. It must be a regular file with one
/// name that only its owner can read. Anything else fails closed, and the file is not
/// tightened.
fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let prior = prior_key_slot(path)?.ok_or(StoreError::KeyMissing)?;
    // Checked before the open: a FIFO or device would block or be read as a key.
    if !prior.is_file() {
        return Err(StoreError::KeyFilesUnsafe);
    }
    let mut file = open_verified(path, OpenOptions::new().read(true), Some(&prior), true)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The legacy `keys/` directory must be a real directory owned by this user, with no
/// group or other permission bits. A symlink would send the key files, and any
/// permission change, to wherever it points. Refused, never tightened.
fn check_legacy_keys_dir(keys_dir: &Path) -> Result<(), StoreError> {
    if private_dir_or_missing(keys_dir, LEGACY_KEYS_DIR_DENIED_BITS)? {
        Ok(())
    } else {
        Err(StoreError::KeyFilesUnsafe)
    }
}

/// The store directory must be a real directory owned by this user, and no other user may
/// be able to write into it. The migration renames and unlinks by path inside it, so a
/// writer other than the owner could swap those entries. Refused, never tightened.
fn check_store_dir(path: &Path) -> Result<(), StoreError> {
    if private_dir_or_missing(parent_of(path), STORE_DIR_DENIED_BITS)? {
        Ok(())
    } else {
        Err(StoreError::StoreDirUnsafe)
    }
}

/// Check the store directory, create it `0700` if it is missing, then check it again:
/// the directory that exists after creation is the one that must pass. Runs before the
/// store file or any key file is touched. An existing directory is never chmod-ed here.
pub(super) fn prepare_store_dir(path: &Path) -> Result<(), StoreError> {
    check_store_dir(path)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }
    check_store_dir(path)
}

/// True when `dir` is missing, or is a real directory (never a symlink) owned by this
/// user whose mode grants no bit in `denied` to anyone else. Nothing is followed or changed.
fn private_dir_or_missing(dir: &Path, denied: u32) -> io::Result<bool> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => Ok(meta.is_dir() && owned_by(&meta, current_uid(), denied)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err),
    }
}

/// Owned by `uid`, and no `denied` permission bit set.
#[cfg(unix)]
fn owned_by(meta: &fs::Metadata, uid: u32, denied: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == uid && meta.mode() & denied == 0
}

#[cfg(not(unix))]
fn owned_by(_: &fs::Metadata, _: u32, _: u32) -> bool {
    true
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// The `symlink_metadata` of a key slot, taken before the slot is opened. A symlink is
/// refused here, before anything is opened through it. None when the slot is absent.
fn prior_key_slot(path: &Path) -> Result<Option<fs::Metadata>, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(StoreError::KeyFilesUnsafe),
        Ok(meta) => Ok(Some(meta)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

// Test seam: `Err` at the named migration step, as if the process died there. The
// step's files are left exactly as a crash would leave them.
#[cfg(test)]
thread_local! {
    static CRASH_AT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn crash_point(step: &'static str) -> Result<(), StoreError> {
    if CRASH_AT.with(|at| at.get() == Some(step)) {
        return Err(migration_error(format!("injected crash at {step}")));
    }
    Ok(())
}

#[cfg(not(test))]
#[inline]
fn crash_point(_step: &'static str) -> Result<(), StoreError> {
    Ok(())
}

// Test seam for the check-then-open window. Once armed for `victim`, the next verified
// open of that path first swaps it for a symlink to `decoy`, as an attacker would
// between the `symlink_metadata` check and the open.
#[cfg(all(test, unix))]
thread_local! {
    static SWAP_BEFORE_OPEN: std::cell::RefCell<Option<(PathBuf, PathBuf)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn arm_swap(victim: &Path, decoy: &Path) {
    SWAP_BEFORE_OPEN.with(|slot| {
        *slot.borrow_mut() = Some((victim.to_path_buf(), decoy.to_path_buf()));
    });
}

/// True once the armed swap has fired, or when none was armed.
#[cfg(all(test, unix))]
fn swap_fired() -> bool {
    SWAP_BEFORE_OPEN.with(|slot| slot.borrow().is_none())
}

#[cfg(all(test, unix))]
fn race_point(path: &Path) {
    SWAP_BEFORE_OPEN.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(victim, _)| victim == path) {
            let (_, decoy) = slot.take().expect("an armed swap");
            let _ = fs::remove_file(path);
            std::os::unix::fs::symlink(decoy, path).expect("plant the symlink");
        }
    });
}

#[cfg(not(all(test, unix)))]
#[inline]
fn race_point(_: &Path) {}

/// Open options that create a file as `0600`, never wider. They also refuse a symlink
/// in the last path component and close on exec.
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
}

fn create_private_new(path: &Path) -> io::Result<File> {
    private_options().write(true).create_new(true).open(path)
}

/// Remove `path` if it exists. True when something was removed.
fn remove_if_exists(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn random(buf: &mut [u8]) -> Result<(), StoreError> {
    getrandom::fill(buf).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(())
}

/// The directory holding `path`, or `.` for a bare file name.
fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn utf8(path: &Path) -> Result<&str, StoreError> {
    path.to_str()
        .ok_or_else(|| migration_error("store path is not valid UTF-8"))
}

fn migration_error(reason: impl Into<String>) -> StoreError {
    StoreError::StoreMigration {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NewMemoryItem, Store};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::tempdir;

    /// The first 16 bytes of every plaintext SQLite database.
    const PLAINTEXT_HEADER: &[u8] = b"SQLite format 3\0";

    fn memory<'a>(title: &'a str, body: &'a str) -> NewMemoryItem<'a> {
        NewMemoryItem {
            kind: "fact",
            title,
            body,
            fact_key: None,
            confidence: Some(0.9),
            source: "test",
            trust: "owner",
            tainted: false,
            state: "active",
            supersedes_id: None,
            valid_from: None,
            valid_to: None,
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// A plaintext store, shaped like the pre-SQLCipher build wrote it: WAL mode.
    fn plaintext_store(path: &Path) -> Store {
        let conn = Connection::open(path).unwrap();
        let _: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .unwrap();
        Store::from_connection(conn, None).unwrap()
    }

    /// Write a key file the way the store does: owner-only.
    fn write_key(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// Every file under `dir`, recursively, read in full.
    fn bytes_under(dir: &Path) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.extend(bytes_under(&path));
            } else {
                out.push(fs::read(&path).unwrap());
            }
        }
        out
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn random_key() -> Key {
        let mut key = Key::zeroed();
        random(&mut key.0[..]).unwrap();
        key
    }

    /// Write the pre-WO-06c layout: `keys/store.kek` and `keys/store.dek`
    /// wrapping a fresh random DEK. Returns the DEK the store must be keyed with.
    fn write_legacy_layout(path: &Path) -> Key {
        let keys = legacy_keys_dir_of(path);
        fs::create_dir_all(&keys).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let kek = random_key();
        let dek = random_key();
        write_key(&keys.join(LEGACY_KEK_FILE), kek.expose());
        write_key(&keys.join(LEGACY_DEK_FILE), &wrap_dek(&kek, &dek).unwrap());
        dek
    }

    /// A store in the old layout, keyed with the old DEK and holding one row.
    fn legacy_keyed_store(path: &Path) -> (Store, Key) {
        let dek = write_legacy_layout(path);
        let conn = Connection::open(path).unwrap();
        // The key must be set before any other statement, so the first bytes
        // SQLite writes are SQLCipher pages.
        apply_key(&conn, &dek).unwrap();
        (Store::from_connection(conn, None).unwrap(), dek)
    }

    #[cfg(unix)]
    #[test]
    fn fresh_home_mints_one_private_master_key() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("fresh").join(".auxesis");
        let path = home.join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store
                .create_memory_item("agent-a", &memory("needle-title", "needle-body"))
                .unwrap();
        }
        assert_eq!(mode(&home.join(MASTER_FILE)), 0o600);
        assert_eq!(mode(&home), 0o700, "the master-key directory must be 0700");
        assert!(!legacy_keys_present(&path), "a legacy key file was written");
        let file = fs::read(&path).unwrap();
        assert!(!file.starts_with(PLAINTEXT_HEADER), "header is plaintext");
        assert!(
            !contains(&file, b"needle-body"),
            "row text reached the file"
        );
        // The derived key opens it; a bare SQLite open does not.
        assert!(open_keyed(&path).is_ok());
        let bare = Connection::open(&path).unwrap();
        let err = bare
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_err();
        assert!(
            matches!(&err, rusqlite::Error::SqliteFailure(code, _) if code.code == ErrorCode::NotADatabase),
            "{err:?}"
        );
    }

    #[test]
    fn the_store_is_unreadable_with_a_wrong_or_missing_master_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let id = {
            let store = Store::open(&path).unwrap();
            store
                .create_memory_item("agent-a", &memory("Passport", "renewal due in March"))
                .unwrap()
                .id
        };
        let store_bytes = fs::read(&path).unwrap();
        let master = dir.path().join(MASTER_FILE);
        let real = fs::read(&master).unwrap();

        // A wrong master key derives a store key that does not unlock the file.
        write_key(&master, &[7u8; KEY_LEN]);
        assert!(matches!(Store::open(&path), Err(StoreError::KeyRejected)));
        assert!(matches!(
            open_keyed_readonly(&path),
            Err(StoreError::KeyRejected)
        ));

        // A missing master key beside an encrypted store is never silently
        // replaced by a fresh one.
        fs::remove_file(&master).unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::KeyMissing)));
        assert!(
            !master.exists(),
            "a missing master key was silently re-minted"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            store_bytes,
            "a failed open changed the store"
        );

        // The real key restores access.
        write_key(&master, &real);
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.memory_item("agent-a", id).unwrap().unwrap().body,
            "renewal due in March"
        );
    }

    #[test]
    fn derived_store_and_vault_keys_differ_per_info_and_are_stable_across_restarts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let home = dir.path();
        let store_a = store_key(home).unwrap();
        let vault_a = vault_key(home).unwrap();
        assert!(
            store_a.expose() != vault_a.expose(),
            "store and vault keys must differ"
        );
        // Stable across restarts: the same master.key re-derives the same keys.
        drop(Store::open(&path).unwrap());
        assert!(store_key(home).unwrap().expose() == store_a.expose());
        assert!(vault_key(home).unwrap().expose() == vault_a.expose());
        // A fresh home mints a different root, so its keys differ too.
        let other = tempdir().unwrap();
        drop(Store::open(&other.path().join("store.db")).unwrap());
        assert!(store_key(other.path()).unwrap().expose() != store_a.expose());
        assert!(vault_key(other.path()).unwrap().expose() != vault_a.expose());
    }

    #[test]
    fn legacy_layout_migrates_to_the_derived_key_and_keeps_every_row() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let id = {
            let (store, _dek) = legacy_keyed_store(&path);
            store
                .create_memory_item("agent-a", &memory("Passport", "renewal due in March"))
                .unwrap()
                .id
        };
        assert!(!dir.path().join(MASTER_FILE).exists());
        assert!(legacy_keys_dir_of(&path).join(LEGACY_KEK_FILE).exists());

        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.memory_item("agent-a", id).unwrap().unwrap().body,
            "renewal due in March"
        );
        drop(store);

        // New layout only: the derived key opens it, old keys and backup are gone.
        assert_eq!(mode(&dir.path().join(MASTER_FILE)), 0o600);
        assert!(!legacy_keys_present(&path));
        assert!(!legacy_backup_path(&path).exists());
        let derived = store_key(dir.path()).unwrap();
        let conn = keyed_open(&path, OpenFlags::SQLITE_OPEN_READ_ONLY, &derived).unwrap();
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM memory_items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn a_crash_in_the_middle_of_the_legacy_migration_recovers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let id = {
            let (store, _dek) = legacy_keyed_store(&path);
            store
                .create_memory_item("agent-a", &memory("Lease", "notice period 3 months"))
                .unwrap()
                .id
        };

        // Crash after the backup copy: the old key files and the backup are both
        // present, and the live store is still under the old DEK.
        CRASH_AT.with(|at| at.set(Some("after-legacy-backup")));
        let crashed = Store::open(&path);
        CRASH_AT.with(|at| at.set(None));
        assert!(crashed.is_err(), "the injected crash did not fire");
        assert!(legacy_keys_dir_of(&path).join(LEGACY_KEK_FILE).exists());
        assert!(legacy_backup_path(&path).exists());

        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.memory_item("agent-a", id).unwrap().unwrap().body,
            "notice period 3 months"
        );
        drop(store);
        assert!(!legacy_keys_present(&path));
        assert!(!legacy_backup_path(&path).exists());
        assert!(!fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));
    }

    #[test]
    fn a_crash_after_the_rekey_is_cleaned_on_the_next_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let id = {
            let (store, _dek) = legacy_keyed_store(&path);
            store
                .create_memory_item("agent-a", &memory("Lease", "notice period 3 months"))
                .unwrap()
                .id
        };
        // Crash after the derived key verified but before the old files went:
        // the next open finds the store under the derived key and just cleans up.
        CRASH_AT.with(|at| at.set(Some("after-legacy-rekey")));
        let crashed = Store::open(&path);
        CRASH_AT.with(|at| at.set(None));
        assert!(crashed.is_err(), "the injected crash did not fire");
        assert!(legacy_keys_present(&path));
        assert!(legacy_backup_path(&path).exists());

        let store = Store::open(&path).unwrap();
        assert_eq!(store.memory_item("agent-a", id).unwrap().unwrap().id, id);
        drop(store);
        assert!(!legacy_keys_present(&path));
        assert!(!legacy_backup_path(&path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_loose_master_key_is_refused_and_not_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let master = dir.path().join(MASTER_FILE);
        fs::set_permissions(&master, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::KeyFilesUnsafe)
        ));
        assert!(matches!(
            open_keyed_readonly(&path),
            Err(StoreError::KeyFilesUnsafe)
        ));
        assert_eq!(mode(&master), 0o644, "the master key was tightened");
        fs::set_permissions(&master, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Store::open(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_master_key_is_refused_and_the_decoy_is_untouched() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let master = dir.path().join(MASTER_FILE);
        let decoy = dir.path().join("decoy.key");
        write_key(&decoy, &[7u8; KEY_LEN]);
        fs::remove_file(&master).unwrap();
        symlink(&decoy, &master).unwrap();

        assert!(matches!(
            Store::open(&path),
            Err(StoreError::KeyFilesUnsafe)
        ));
        assert!(matches!(
            open_keyed_readonly(&path),
            Err(StoreError::KeyFilesUnsafe)
        ));
        assert_eq!(fs::read(&decoy).unwrap(), vec![7u8; KEY_LEN]);
    }

    #[test]
    fn a_master_key_never_reaches_an_error_or_a_debug_line() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let key = store_key(dir.path()).unwrap();
        let hex = raw_key_text(&key);
        let digits = hex.as_str()[2..hex.len() - 1].to_string();
        assert!(format!("{key:?}").contains("redacted"));
        assert!(!format!("{key:?}").contains(&digits));

        let master = dir.path().join(MASTER_FILE);
        write_key(&master, &[7u8; KEY_LEN]);
        let err = match Store::open(&path) {
            Ok(_) => panic!("a wrong master key must refuse the open"),
            Err(err) => err,
        };
        let text = format!("{err} {err:?}");
        assert!(!text.contains(&digits), "the key reached an error: {text}");
    }

    #[test]
    fn a_damaged_master_key_fails_closed_and_the_store_bytes_are_left_alone() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let master = dir.path().join(MASTER_FILE);
        let store_bytes = fs::read(&path).unwrap();
        let real = fs::read(&master).unwrap();

        write_key(&master, &real[..KEY_LEN - 1]);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::StoreMigration { .. })
        ));
        write_key(&master, b"");
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::StoreMigration { .. })
        ));
        assert_eq!(
            fs::read(&path).unwrap(),
            store_bytes,
            "a failed open changed the store"
        );

        write_key(&master, &real);
        assert!(Store::open(&path).is_ok());
    }

    /// The error a store open must return. A successful open is a test failure.
    fn open_refusal(path: &Path) -> StoreError {
        match Store::open(path) {
            Ok(_) => panic!("the store open must be refused"),
            Err(err) => err,
        }
    }

    /// A FIFO named `master.key` blocks any open that waits for a writer. The open
    /// must refuse it at once instead.
    #[cfg(unix)]
    #[test]
    fn a_fifo_master_key_is_refused_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let master = dir.path().join(MASTER_FILE);
        fs::remove_file(&master).unwrap();
        let c_path = std::ffi::CString::new(master.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let store_path = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Store::open(&store_path).is_err());
        });
        let refused = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("Store::open blocked on a FIFO master.key");
        assert!(refused, "a FIFO master.key opened as a key");
    }

    /// A crash between creating and writing `master.key` leaves it empty. With no
    /// store data beside it, nothing depends on it, so it is replaced.
    #[test]
    fn an_empty_master_key_beside_no_store_is_replaced() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_key(&dir.path().join(MASTER_FILE), b"");
        drop(Store::open(&path).expect("an empty master.key with no store is replaced"));
        let master = dir.path().join(MASTER_FILE);
        assert_eq!(fs::metadata(&master).unwrap().len(), KEY_LEN as u64);
        assert!(!dir.path().join(MASTER_STAGING_FILE).exists());
        drop(Store::open(&path).unwrap());
    }

    /// The same damage beside store data is refused with a bilingual reason, and
    /// neither the key nor the store is touched.
    #[test]
    fn an_empty_master_key_beside_store_data_is_refused_and_kept() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let master = dir.path().join(MASTER_FILE);
        let store_bytes = fs::read(&path).unwrap();
        write_key(&master, b"");
        let err = open_refusal(&path);
        assert!(matches!(err, StoreError::StoreMigration { .. }), "{err}");
        assert!(err.to_string().contains("master.key"), "{err}");
        assert_eq!(fs::metadata(&master).unwrap().len(), 0);
        assert_eq!(fs::read(&path).unwrap(), store_bytes);
    }

    /// A staged key left by a crash never blocks a fresh mint, and is cleared.
    #[test]
    fn a_staged_master_key_left_by_a_crash_is_cleared_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        fs::write(dir.path().join(MASTER_STAGING_FILE), b"half written").unwrap();
        drop(Store::open(&path).unwrap());
        assert!(!dir.path().join(MASTER_STAGING_FILE).exists());
    }

    /// Plaintext rows with the old key files beside them: the old files are ignored
    /// and the plaintext store migrates, keeping every row.
    #[test]
    fn a_plaintext_store_with_legacy_key_files_migrates_and_keeps_its_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let id = {
            let plain = plaintext_store(&path);
            plain
                .create_memory_item("agent-a", &memory("Lease", "notice period 3 months"))
                .unwrap()
                .id
        };
        // An old build crashed mid-plaintext-migration and left its key files.
        write_legacy_layout(&path);
        let store = Store::open(&path).expect("the plaintext store migrates");
        assert!(store.memory_item("agent-a", id).unwrap().is_some());
        assert!(!fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));
    }

    /// An empty store with a legacy backup is refused, and no key or backup is removed.
    #[test]
    fn an_empty_store_with_a_legacy_backup_is_refused_and_nothing_is_deleted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_legacy_layout(&path);
        fs::write(&path, b"").unwrap();
        let backup = legacy_backup_path(&path);
        fs::write(&backup, b"ciphertext").unwrap();
        let err = open_refusal(&path);
        assert!(matches!(err, StoreError::StoreMigration { .. }), "{err}");
        assert_eq!(fs::read(&backup).unwrap(), b"ciphertext");
        assert!(legacy_keys_present(&path));
    }

    /// An empty store beside legacy keys is created, and the keys are not deleted:
    /// nothing proves a migration ran.
    #[test]
    fn an_empty_store_beside_legacy_keys_keeps_the_key_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_legacy_layout(&path);
        fs::write(&path, b"").unwrap();
        drop(Store::open(&path).unwrap());
        assert!(
            legacy_keys_present(&path),
            "legacy keys deleted without proof"
        );
    }

    /// Legacy keys that do not open the store mint no master over it.
    #[test]
    fn a_legacy_key_that_does_not_open_the_store_mints_no_master() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let master = dir.path().join(MASTER_FILE);
        fs::remove_file(&master).unwrap();
        write_legacy_layout(&path);
        let err = open_refusal(&path);
        assert!(matches!(err, StoreError::KeyRejected), "{err}");
        assert!(
            !master.exists(),
            "a master was minted over an encrypted store"
        );
    }

    /// A legacy backup with no keys beside it is kept on open: nothing proves it is
    /// this store's copy, so it is never deleted on a guess.
    #[test]
    fn an_orphaned_legacy_backup_is_kept_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        fs::write(legacy_backup_path(&path), b"orphan ciphertext").unwrap();
        drop(Store::open(&path).unwrap());
        assert_eq!(
            fs::read(legacy_backup_path(&path)).unwrap(),
            b"orphan ciphertext"
        );
    }

    /// The SQLCipher key statement is built in the buffer reserved for it.
    #[test]
    fn the_key_statement_is_built_in_its_reserved_buffer() {
        let key = random_key();
        let sql = raw_key_pragma("rekey", &key);
        assert_eq!(sql.len(), PRAGMA_KEY_CAPACITY);
        assert_eq!(sql.capacity(), PRAGMA_KEY_CAPACITY);
    }

    /// The derivation is the standard HKDF-SHA256 expansion of the extracted key.
    #[test]
    fn derive_matches_the_standard_hkdf_expansion() {
        let master = random_key();
        let standard = Hkdf::<Sha256>::new(Some(HKDF_SALT), master.expose());
        let mut expect = [0u8; KEY_LEN];
        standard.expand(STORE_INFO, &mut expect).unwrap();
        assert_eq!(derive(&master, STORE_INFO).expose(), &expect[..]);
    }

    #[test]
    fn fts5_search_works_on_the_encrypted_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store
                .create_memory_item("agent-a", &memory("Sourdough", "starter feeds on tuesdays"))
                .unwrap();
            store
                .create_memory_item("agent-a", &memory("Tax", "quarterly vat return"))
                .unwrap();
            let hits = store.search_memory("agent-a", "starter", 10).unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].title, "Sourdough");
        }
        let reopened = Store::open(&path).unwrap();
        let hits = reopened.search_memory("agent-a", "vat", 10).unwrap();
        assert_eq!(
            hits.iter()
                .map(|item| item.title.as_str())
                .collect::<Vec<_>>(),
            ["Tax"]
        );
    }

    #[test]
    fn plaintext_store_migrates_once_and_keeps_every_row() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let id = {
            let plain = plaintext_store(&path);
            plain.create_session("agent-a", Some("kept")).unwrap();
            plain
                .create_memory_item("agent-a", &memory("Passport", "renewal due in March"))
                .unwrap()
                .id
        };
        assert!(fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));

        // The second pass is a plain keyed open: same rows, nothing left behind.
        for _ in 0..2 {
            let store = Store::open(&path).unwrap();
            let item = store
                .memory_item("agent-a", id)
                .unwrap()
                .expect("row survived");
            assert_eq!(item.body, "renewal due in March");
            assert_eq!(
                store.search_memory("agent-a", "passport", 5).unwrap().len(),
                1
            );
        }
        assert!(!fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));
        assert!(!sibling(&path, PLAINTEXT_BACKUP_SUFFIX).exists());
        assert!(!sibling(&path, MIGRATION_SCRATCH_SUFFIX).exists());
        let raw = open_keyed(&path).unwrap();
        let sessions: i64 = raw
            .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sessions, 1);
    }

    #[test]
    fn interrupted_migration_leftovers_are_cleaned_on_the_next_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let plain = plaintext_store(&path);
            plain
                .create_memory_item("agent-a", &memory("Lease", "notice period 3 months"))
                .unwrap();
        }
        // A crash left a half-written export and a stale backup beside the store.
        fs::write(sibling(&path, MIGRATION_SCRATCH_SUFFIX), b"half written").unwrap();
        fs::write(sibling(&path, PLAINTEXT_BACKUP_SUFFIX), b"stale").unwrap();
        let store = Store::open(&path).unwrap();
        assert_eq!(store.search_memory("agent-a", "lease", 5).unwrap().len(), 1);
        assert!(!sibling(&path, MIGRATION_SCRATCH_SUFFIX).exists());
        assert!(!sibling(&path, PLAINTEXT_BACKUP_SUFFIX).exists());
    }

    #[test]
    fn plaintext_backup_left_after_the_swap_is_removed_on_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        // A crash after the swap left the plaintext copy beside the encrypted store.
        fs::write(sibling(&path, PLAINTEXT_BACKUP_SUFFIX), PLAINTEXT_HEADER).unwrap();
        drop(Store::open(&path).unwrap());
        assert!(!sibling(&path, PLAINTEXT_BACKUP_SUFFIX).exists());
    }

    #[test]
    fn read_only_opener_reads_the_encrypted_store_and_refuses_plaintext() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(plaintext_store(&path));
        assert!(matches!(
            open_keyed_readonly(&path),
            Err(StoreError::NotEncrypted)
        ));
        drop(Store::open(&path).unwrap());
        let reader = open_keyed_readonly(&path).unwrap();
        let tables: i64 = reader
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        assert!(tables > 0);
        assert!(reader
            .execute_batch("CREATE TABLE refused (x INTEGER);")
            .is_err());
    }

    #[test]
    fn zero_byte_file_reads_as_empty_and_is_never_written_unkeyed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        fs::write(&path, b"").unwrap();
        let reader = open_keyed_readonly(&path).unwrap();
        let tables: i64 = reader
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tables, 0);
        assert!(open_keyed(&path).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_loose_store_directory_is_refused_and_not_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o775)).unwrap();
        let path = home.join("store.db");
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::StoreDirUnsafe)
        ));
        assert_eq!(mode(&home), 0o775, "the store directory was chmod-ed");
        assert!(
            fs::read_dir(&home).unwrap().next().is_none(),
            "a file was created in the loose directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_reader_refuses_a_loose_store_directory_too() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let path = home.join("store.db");
        drop(Store::open(&path).unwrap());
        fs::set_permissions(&home, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(matches!(
            open_keyed_readonly(&path),
            Err(StoreError::StoreDirUnsafe)
        ));
        assert!(matches!(open_keyed(&path), Err(StoreError::StoreDirUnsafe)));
        assert_eq!(mode(&home), 0o775, "the store directory was chmod-ed");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_keyed_readonly(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_store_directory_is_refused_and_its_target_is_left_alone() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
        let home = dir.path().join("home");
        symlink(&elsewhere, &home).unwrap();
        assert!(matches!(
            Store::open(&home.join("store.db")),
            Err(StoreError::StoreDirUnsafe)
        ));
        assert_eq!(mode(&elsewhere), 0o755, "the link target was chmod-ed");
        assert!(
            fs::read_dir(&elsewhere).unwrap().next().is_none(),
            "a store was written through the link"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_loose_legacy_keys_directory_is_refused_and_not_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(legacy_keyed_store(&path));
        let keys = legacy_keys_dir_of(&path);
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::KeyFilesUnsafe)
        ));
        assert_eq!(mode(&keys), 0o755, "the keys directory was chmod-ed");
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_store_directory_is_created_private() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("fresh").join("home");
        let path = home.join("store.db");
        drop(Store::open(&path).unwrap());
        assert_eq!(mode(&home), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_is_refused_when_another_owner_or_another_user_can_change_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let uid = current_uid();
        let with_mode = |mode: u32| {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
            fs::symlink_metadata(dir.path()).unwrap()
        };
        // The store directory: others may read it, but not write into it.
        assert!(owned_by(&with_mode(0o755), uid, STORE_DIR_DENIED_BITS));
        assert!(
            !owned_by(&with_mode(0o775), uid, STORE_DIR_DENIED_BITS),
            "group write passed the check"
        );
        assert!(
            !owned_by(&with_mode(0o757), uid, STORE_DIR_DENIED_BITS),
            "other write passed the check"
        );
        // The legacy `keys/`: nobody but the owner may get at it.
        assert!(owned_by(
            &with_mode(0o700),
            uid,
            LEGACY_KEYS_DIR_DENIED_BITS
        ));
        assert!(
            !owned_by(&with_mode(0o750), uid, LEGACY_KEYS_DIR_DENIED_BITS),
            "group access passed the check"
        );
        assert!(
            !owned_by(&with_mode(0o755), uid, LEGACY_KEYS_DIR_DENIED_BITS),
            "other access passed the check"
        );
        // A directory of another owner is refused whatever its mode.
        let private = with_mode(0o700);
        assert!(
            !owned_by(&private, uid.wrapping_add(1), STORE_DIR_DENIED_BITS),
            "a directory of another owner passed the check"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_legacy_key_file_is_refused_and_the_decoy_is_never_used() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(legacy_keyed_store(&path));
        let keys = legacy_keys_dir_of(&path);
        let decoy = dir.path().join("decoy.kek");
        write_key(&decoy, &[7u8; KEY_LEN]);
        fs::remove_file(keys.join(LEGACY_KEK_FILE)).unwrap();
        symlink(&decoy, keys.join(LEGACY_KEK_FILE)).unwrap();

        assert!(matches!(
            Store::open(&path),
            Err(StoreError::KeyFilesUnsafe)
        ));
        assert_eq!(fs::read(&decoy).unwrap(), vec![7u8; KEY_LEN]);
    }

    #[test]
    fn a_master_key_with_a_second_name_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let alias = dir.path().join("master-alias");
        fs::hard_link(dir.path().join(MASTER_FILE), &alias).unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::KeyFilesUnsafe)
        ));
        fs::remove_file(&alias).unwrap();
        assert!(Store::open(&path).is_ok());
    }

    /// A file whose inode differs from the one checked is refused, on both the read
    /// and the zeroing path. The file that is really there opens fine.
    #[cfg(unix)]
    #[test]
    fn a_file_swapped_for_another_inode_after_the_check_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let master = dir.path().join(MASTER_FILE);
        let other = dir.path().join("other.key");
        write_key(&other, &[7u8; KEY_LEN]);
        // The check saw `other`, but the path names the real master key.
        let seen = fs::symlink_metadata(&other).unwrap();
        assert!(matches!(
            open_verified(&master, OpenOptions::new().read(true), Some(&seen), true),
            Err(Refused::Unsafe)
        ));
        let copy = dir.path().join("copy");
        fs::write(&copy, b"plaintext rows").unwrap();
        assert!(matches!(
            zero_and_remove(&copy, &seen),
            Err(Refused::Unsafe)
        ));
        assert_eq!(fs::read(&copy).unwrap(), b"plaintext rows");
        let real = fs::symlink_metadata(&master).unwrap();
        assert!(open_verified(&master, OpenOptions::new().read(true), Some(&real), true).is_ok());
    }

    /// Bytes that a test plants behind a symlink. The swap must never reach them.
    #[cfg(unix)]
    const DECOY: &[u8] = b"decoy: must survive";

    /// Arm a swap of `victim` for a symlink to `decoy`, then run `open`. The swap must
    /// have reached the open, and the decoy must come through untouched.
    #[cfg(unix)]
    fn open_after_swap<T>(victim: &Path, decoy: &Path, open: impl FnOnce() -> T) -> T {
        fs::write(decoy, DECOY).unwrap();
        arm_swap(victim, decoy);
        let result = open();
        assert!(swap_fired(), "the swap never reached the open");
        assert_eq!(
            fs::read(decoy).unwrap(),
            DECOY,
            "the symlink target was touched"
        );
        result
    }

    /// A swap between the check and the open of the master key fails closed.
    #[cfg(unix)]
    #[test]
    fn a_swapped_master_key_is_refused_and_its_target_is_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let victim = dir.path().join(MASTER_FILE);
        let result = open_after_swap(&victim, &dir.path().join("decoy"), || Store::open(&path));
        assert!(matches!(result, Err(StoreError::KeyFilesUnsafe)));
    }

    /// A swap of the lock file between the check and the open fails closed, before any
    /// key is read or any migration starts.
    #[cfg(unix)]
    #[test]
    fn a_swapped_lock_is_refused_and_its_target_is_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(Store::open(&path).unwrap());
        let victim = dir.path().join(LOCK_FILE);
        let result = open_after_swap(&victim, &dir.path().join("decoy"), || Store::open(&path));
        assert!(matches!(result, Err(StoreError::KeyFilesUnsafe)));
    }

    /// A swap of the plaintext backup between its check and its zeroing fails closed:
    /// the symlink target is never zeroed, and the migration reports the refusal.
    #[cfg(unix)]
    #[test]
    fn a_swapped_backup_is_refused_and_its_target_is_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        fs::write(&path, b"live bytes").unwrap();
        let backup = sibling(&path, PLAINTEXT_BACKUP_SUFFIX);
        fs::write(&backup, b"plaintext rows").unwrap();
        let result = open_after_swap(&backup, &dir.path().join("decoy"), || discard_backup(&path));
        assert!(matches!(result, Err(StoreError::StoreMigration { .. })));
    }

    #[test]
    fn a_backup_that_is_the_live_store_is_unlinked_not_zeroed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        fs::write(&path, b"live bytes").unwrap();
        fs::hard_link(&path, sibling(&path, PLAINTEXT_BACKUP_SUFFIX)).unwrap();
        assert!(discard_backup(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"live bytes");
        assert!(!sibling(&path, PLAINTEXT_BACKUP_SUFFIX).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_backup_is_unlinked_and_its_target_is_untouched() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        fs::write(&path, b"live bytes").unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"keep me").unwrap();
        symlink(&target, sibling(&path, PLAINTEXT_BACKUP_SUFFIX)).unwrap();
        assert!(discard_backup(&path).unwrap());
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
        assert!(fs::symlink_metadata(sibling(&path, PLAINTEXT_BACKUP_SUFFIX)).is_err());
    }

    #[test]
    fn a_live_plaintext_journal_refuses_the_swap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        fs::write(&path, b"").unwrap();
        fs::write(sibling(&path, "-wal"), b"").unwrap();
        ensure_no_live_journal(&path).unwrap();
        fs::write(sibling(&path, "-wal"), b"frames").unwrap();
        assert!(ensure_no_live_journal(&path).is_err());
    }

    #[test]
    fn plaintext_side_files_are_removed_before_the_swap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        fs::write(&path, b"").unwrap();
        for suffix in ["-wal", "-shm", "-journal"] {
            fs::write(sibling(&path, suffix), b"side").unwrap();
        }
        remove_plaintext_side_files(&path).unwrap();
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(!sibling(&path, suffix).exists(), "{suffix} survived");
        }
    }

    /// A crash at each plaintext-migration step, then a reopen. Every row must
    /// survive, and no plaintext may be left in the store, its backup, or its
    /// scratch file.
    #[test]
    fn a_crash_at_every_migration_step_recovers_to_the_encrypted_store() {
        const STEPS: [&str; 5] = [
            "after-checkpoint",
            "after-export",
            "after-hard-link",
            "after-rename",
            "before-leftover-removal",
        ];
        for step in STEPS {
            let dir = tempdir().unwrap();
            let path = dir.path().join("store.db");
            let id = {
                let plain = plaintext_store(&path);
                plain.create_session("agent-a", Some("kept")).unwrap();
                plain
                    .create_memory_item("agent-a", &memory("Passport", "renewal due in March"))
                    .unwrap()
                    .id
            };

            CRASH_AT.with(|at| at.set(Some(step)));
            let crashed = Store::open(&path);
            CRASH_AT.with(|at| at.set(None));
            assert!(crashed.is_err(), "{step}: the injected crash did not fire");

            let store = Store::open(&path).unwrap_or_else(|err| panic!("{step}: {err}"));
            let item = store
                .memory_item("agent-a", id)
                .unwrap()
                .unwrap_or_else(|| panic!("{step}: a row was lost"));
            assert_eq!(item.body, "renewal due in March", "{step}");
            drop(store);
            assert!(
                !fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER),
                "{step}: the store is plaintext"
            );
            assert!(
                !sibling(&path, PLAINTEXT_BACKUP_SUFFIX).exists(),
                "{step}: a plaintext backup was left"
            );
            assert!(
                !sibling(&path, MIGRATION_SCRATCH_SUFFIX).exists(),
                "{step}: the scratch file was left"
            );
            assert!(open_keyed_readonly(&path).is_ok(), "{step}");
        }
    }

    /// Rows that exist only in the plaintext WAL (a crash before any checkpoint)
    /// survive the migration, and no file keeps them in the clear afterwards.
    #[test]
    fn rows_held_only_in_the_plaintext_wal_survive_and_stay_out_of_the_clear() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let plain = plaintext_store(&path);
        plain
            .create_memory_item("agent-a", &memory("Wal", "walresident needle"))
            .unwrap();
        // A crash leaves the WAL unfolded. Leak the connection so nothing checkpoints it.
        std::mem::forget(plain);
        assert!(contains(
            &fs::read(sibling(&path, "-wal")).unwrap(),
            b"walresident needle"
        ));

        let store = Store::open(&path).unwrap();
        assert_eq!(
            store
                .search_memory("agent-a", "walresident", 5)
                .unwrap()
                .len(),
            1
        );
        drop(store);
        for file in bytes_under(dir.path()) {
            assert!(
                !contains(&file, b"walresident needle"),
                "row text reached a file in the clear"
            );
        }
    }

    /// Two first opens race on a plaintext store: the lock makes one migrate and
    /// the other read the result. Both see every row.
    #[test]
    fn concurrent_first_opens_migrate_once_and_keep_every_row() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let id = {
            let plain = plaintext_store(&path);
            plain
                .create_memory_item("agent-a", &memory("Lease", "notice period 3 months"))
                .unwrap()
                .id
        };
        std::thread::scope(|scope| {
            let openers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        let store = Store::open(&path).expect("concurrent open");
                        store.memory_item("agent-a", id).unwrap().is_some()
                    })
                })
                .collect();
            for opener in openers {
                assert!(opener.join().unwrap(), "a row was lost");
            }
        });
        assert!(!fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));
    }

    /// A CLI reader that opens the store while the daemon migrates sees either
    /// every row or a clear error. The daemon's start is retried while the reader
    /// holds the journal, and it completes.
    #[test]
    fn a_cli_reader_during_migration_sees_whole_rows_or_a_clear_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let plain = plaintext_store(&path);
            for i in 0..40 {
                plain
                    .create_memory_item("agent-a", &memory(&format!("row {i}"), "body"))
                    .unwrap();
            }
        }
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                while !done.load(Ordering::SeqCst) {
                    let Ok(conn) = open_keyed_readonly(&path) else {
                        continue;
                    };
                    // Busy or unreadable mid-swap is an error, never a wrong answer.
                    if let Ok(count) =
                        conn.query_row("SELECT count(*) FROM memory_items", [], |row| {
                            row.get::<_, i64>(0)
                        })
                    {
                        assert_eq!(count, 40, "a reader saw a partial store");
                    }
                }
            });
            let mut migrated = false;
            for _ in 0..20 {
                if Store::open(&path).is_ok() {
                    migrated = true;
                    break;
                }
            }
            done.store(true, Ordering::SeqCst);
            reader.join().unwrap();
            assert!(migrated, "the migration never completed");
        });
        assert!(!fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));
    }
}
