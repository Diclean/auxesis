//! The local evidence registry sink.
//!
//! The original bytes live at `<home>/evidence/<sha256>` (0600, written to a
//! temp name then renamed), sealed with AES-256-GCM under a key derived from
//! the store's `master.key`; the name stays the SHA-256 of the plaintext. A
//! blob from before that is sealed in place the first time it is
//! read, or by [`migrate_blobs`] at daemon start. The `documents` /
//! `evidence_source` rows live in
//! the store. A known SHA-256 skips the blob and the `documents` row and
//! appends only the new source, so the same original fetched from a second
//! message is recognised as one document with two provenances. Bytes are
//! consumed here and never returned.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::{cell::RefCell, sync::mpsc};

use aux_mail::{EvidenceAttachment, EvidenceRef, EvidenceSink};
use aux_store::{DocumentEraseResult, NewEvidenceDocument, Store, StoreError};

/// Failure to erase a registered evidence document.
#[derive(Debug, thiserror::Error)]
pub enum EraseError {
    /// The encrypted registry refused the operation.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The hash prefix is not 8–64 lowercase hexadecimal characters.
    #[error("a document hash prefix is 8 to 64 lowercase hex characters")]
    BadPrefix,
    /// No document starts with the prefix.
    #[error("no document has that hash")]
    UnknownDocument,
    /// Several documents start with the prefix.
    #[error("several documents start with that hash: give more characters")]
    AmbiguousPrefix,
    /// The blob cleanup failed; the tombstone remains for restart recovery.
    #[error("the erased evidence blob could not be removed")]
    BlobCleanup,
}

#[cfg(test)]
thread_local! {
    static APPEND_AFTER_LOOKUP: RefCell<Option<(mpsc::Sender<bool>, mpsc::Receiver<()>)>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn run_append_after_lookup_hook(known: bool) {
    APPEND_AFTER_LOOKUP.with(|slot| {
        if let Some((ready, resume)) = slot.borrow_mut().take() {
            ready.send(known).unwrap();
            resume.recv().unwrap();
        }
    });
}

/// Owner erase: commit registry deletion first, then remove the sealed blob.
/// If the process stops between those steps, startup recovery sees the durable
/// tombstone and finishes cleanup before the daemon serves requests.
pub fn erase_document(store: &Store, home: &Path, prefix: &str) -> Result<String, EraseError> {
    if !(8..=64).contains(&prefix.len())
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EraseError::BadPrefix);
    }
    let matches = store.documents_by_hash_prefix(prefix)?;
    let Some(document) = matches.first() else {
        return Err(EraseError::UnknownDocument);
    };
    if matches.len() > 1 {
        return Err(EraseError::AmbiguousPrefix);
    }
    let hash = document.content_hash.clone();
    let lifecycle = aux_store::evidence_lifecycle_lock(&hash);
    let _lifecycle_guard = kernel_core::lock_recover(&lifecycle);
    match store.erase_document_by_hash_prefix(&hash)? {
        DocumentEraseResult::Erased(hash) => {
            remove_blob(home, &hash)?;
            store.finish_evidence_erasure(&hash)?;
            Ok(hash)
        }
        DocumentEraseResult::NotFound => Err(EraseError::UnknownDocument),
        DocumentEraseResult::Ambiguous => Err(EraseError::AmbiguousPrefix),
        DocumentEraseResult::InvalidPrefix => Err(EraseError::BadPrefix),
    }
}

/// Finish all post-commit blob deletions left by an interrupted owner erase.
pub fn recover_erased_evidence(store: &Store, home: &Path) -> Result<usize, EraseError> {
    let hashes = store.pending_evidence_erases()?;
    let mut removed = 0;
    for hash in hashes {
        let lifecycle = aux_store::evidence_lifecycle_lock(&hash);
        let _lifecycle_guard = kernel_core::lock_recover(&lifecycle);
        remove_blob(home, &hash)?;
        store.finish_evidence_erasure(&hash)?;
        removed += 1;
    }
    Ok(removed)
}

fn remove_blob(home: &Path, hash: &str) -> Result<(), EraseError> {
    if !is_lowercase_sha256(hash) {
        return Err(EraseError::BlobCleanup);
    }
    let handle =
        kernel_core::SandboxHome::open_existing(home).map_err(|_| EraseError::BlobCleanup)?;
    match handle.remove_file(&Path::new("evidence").join(hash)) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(EraseError::BlobCleanup),
    }
}

/// The registry sink the mail tool and the receipts collector share.
pub struct StoreEvidence {
    home: PathBuf,
    store: Arc<Mutex<Store>>,
}

impl StoreEvidence {
    /// Back the registry with `store`, writing blobs below `home`.
    pub fn new(home: impl Into<PathBuf>, store: Arc<Mutex<Store>>) -> Self {
        Self {
            home: home.into(),
            store,
        }
    }
}

/// True when `value` is exactly 64 lowercase hexadecimal characters.
///
/// The store's own guard rejects anything else; checking here too keeps a bad
/// hash from ever shaping a blob path.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl EvidenceSink for StoreEvidence {
    fn append(&self, attachment: EvidenceAttachment) -> Result<EvidenceRef, String> {
        if !is_lowercase_sha256(&attachment.sha256) {
            return Err("content_hash is not a lowercase SHA-256 hex digest".to_string());
        }
        let sha256 = attachment.sha256.clone();
        let lifecycle = aux_store::evidence_lifecycle_lock(&sha256);
        let _lifecycle_guard = kernel_core::lock_recover(&lifecycle);
        let storage_path = format!("evidence/{sha256}");
        let (known, erasure_pending) = {
            let store = kernel_core::lock_recover(&self.store);
            (
                store
                    .evidence_document_id(&sha256)
                    .map_err(|err| err.to_string())?
                    .is_some(),
                store
                    .evidence_erasure_pending(&sha256)
                    .map_err(|err| err.to_string())?,
            )
        };
        #[cfg(test)]
        run_append_after_lookup_hook(known);
        if erasure_pending {
            return Err("a previous owner erase is still being finalized".into());
        }
        if !known {
            write_sealed(&self.home, &sha256, &attachment.bytes)?;
        }
        let source = serde_json::json!({
            "imap": {
                "account": attachment.account,
                "folder": attachment.folder,
                "uid": attachment.uid,
                "message_id": attachment.message_id,
                "part": attachment.part,
                "file_name": attachment.file_name,
            }
        })
        .to_string();
        let seen_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let document = NewEvidenceDocument {
            content_hash: &sha256,
            storage_path: &storage_path,
            size_bytes: attachment.size as i64,
            mime_type: &attachment.mime,
            original_name: &attachment.file_name,
            account_id: &attachment.account,
            captured_at: &seen_at,
        };
        let append = kernel_core::lock_recover(&self.store)
            .append_evidence(&document, &source, &seen_at)
            .map_err(|err| err.to_string())?;
        Ok(EvidenceRef {
            sha256,
            duplicate: append.duplicate,
        })
    }
}

/// Seal `plain` and write it atomically, 0600, at `evidence/<sha256>`.
fn write_sealed(home: &Path, sha256: &str, plain: &[u8]) -> Result<(), String> {
    let key = aux_store::evidence_key(home).map_err(|err| format!("evidence key: {err}"))?;
    let sealed = aux_store::seal_evidence(&key, sha256, plain).map_err(|err| err.to_string())?;
    let handle = kernel_core::SandboxHome::open_existing(home)
        .map_err(|err| format!("opening the evidence home: {err}"))?;
    handle
        .create_dir(Path::new("evidence"))
        .map_err(|err| format!("creating the evidence directory: {err}"))?;
    handle
        .write_atomic(&Path::new("evidence").join(sha256), &sealed, 0o600)
        .map_err(|err| format!("writing evidence/{sha256}: {err}"))
}

/// The original bytes of the blob named `sha256`. A plaintext blob written
/// before the sealing is accepted only if its bytes hash to its name, and is
/// sealed in place before it is returned. Crate-private: outside this crate
/// the bytes leave only through the bridge's claim (`queue::claimed_blob`).
pub(crate) fn read_blob(home: &Path, sha256: &str) -> Result<Vec<u8>, String> {
    open_or_seal(home, sha256).map(|(plain, _)| plain)
}

/// The plaintext, and whether a plaintext blob was sealed on this read.
fn open_or_seal(home: &Path, sha256: &str) -> Result<(Vec<u8>, bool), String> {
    if !is_lowercase_sha256(sha256) {
        return Err("content_hash is not a lowercase SHA-256 hex digest".to_string());
    }
    let raw = std::fs::read(home.join("evidence").join(sha256)).map_err(|err| err.to_string())?;
    let key = aux_store::evidence_key(home).map_err(|err| format!("evidence key: {err}"))?;
    if let Some(plain) = aux_store::open_evidence(&key, sha256, &raw) {
        return Ok((plain, false));
    }
    if aux_invoices::sha256_hex(&raw) != sha256 {
        return Err("the evidence blob does not open".to_string());
    }
    write_sealed(home, sha256, &raw)?;
    Ok((raw, true))
}

/// Seal every plaintext blob left in plaintext. Returns how many were
/// sealed and how many files neither open nor hash to their name (left as they
/// are, maybe in plaintext, for the owner to purge). Idempotent. Fails only
/// without the evidence key.
pub fn migrate_blobs(home: &Path) -> Result<(usize, usize), String> {
    let Ok(entries) = std::fs::read_dir(home.join("evidence")) else {
        return Ok((0, 0));
    };
    aux_store::evidence_key(home).map_err(|err| format!("evidence key: {err}"))?;
    let (mut sealed, mut stray) = (0, 0);
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        match open_or_seal(home, &name) {
            Ok((_, true)) => sealed += 1,
            Ok((_, false)) => {}
            Err(_) => stray += 1,
        }
    }
    Ok((sealed, stray))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attachment(part: &str) -> EvidenceAttachment {
        EvidenceAttachment {
            sha256: "a".repeat(64),
            file_name: "invoice.pdf".to_string(),
            mime: "application/pdf".to_string(),
            size: 4,
            bytes: b"data".to_vec(),
            account: "personal".to_string(),
            folder: "INBOX".to_string(),
            uid: 7,
            message_id: "<7@fixture.test>".to_string(),
            part: part.to_string(),
        }
    }

    /// A keyed store in `home`, which also mints its `master.key`.
    fn disk_store(home: &Path) -> Arc<Mutex<Store>> {
        std::fs::create_dir_all(home).unwrap();
        let store = Store::open(&kernel_core::store_path(home)).unwrap();
        Arc::new(Mutex::new(store))
    }

    /// 32 known bytes inside a fictional original.
    const SLICE: &[u8; 32] = b"P<FRAFICTIVE<<MIRA<<<<<<<<<<<<<<";

    fn fixture() -> (String, Vec<u8>) {
        let mut bytes = b"%PDF-1.7 fictional ID scan\n".to_vec();
        bytes.extend_from_slice(SLICE);
        bytes.extend_from_slice(&[b'.'; 512]);
        (aux_invoices::sha256_hex(&bytes), bytes)
    }

    fn holds_slice(bytes: &[u8]) -> bool {
        bytes.windows(SLICE.len()).any(|window| window == SLICE)
    }

    #[test]
    fn an_ingested_blob_holds_no_plaintext_and_reads_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let sink = StoreEvidence::new(&home, disk_store(&home));
        let (sha256, bytes) = fixture();
        let mut doc = attachment("2");
        (doc.sha256, doc.size, doc.bytes) = (sha256.clone(), bytes.len(), bytes.clone());
        sink.append(doc).unwrap();

        let on_disk = std::fs::read(home.join("evidence").join(&sha256)).unwrap();
        assert!(!holds_slice(&on_disk), "the plaintext slice is on disk");
        assert!(on_disk.starts_with(b"AUXEVD01"), "the blob is sealed");
        assert_eq!(read_blob(&home, &sha256).unwrap(), bytes);
    }

    #[test]
    fn a_plaintext_blob_is_sealed_once_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let _store = disk_store(&home);
        let (sha256, bytes) = fixture();
        let blob = home.join("evidence").join(&sha256);
        std::fs::create_dir_all(home.join("evidence")).unwrap();
        std::fs::write(&blob, &bytes).unwrap();
        // A plaintext file whose bytes do not match its name is never adopted.
        let stray = home.join("evidence").join("b".repeat(64));
        std::fs::write(&stray, b"not the original").unwrap();

        assert_eq!(
            migrate_blobs(&home).unwrap(),
            (1, 1),
            "one sealed, one stray"
        );
        let sealed = std::fs::read(&blob).unwrap();
        assert!(!holds_slice(&sealed), "the plaintext was not removed");
        assert_eq!(
            migrate_blobs(&home).unwrap(),
            (0, 1),
            "a re-run seals nothing"
        );
        assert_eq!(std::fs::read(&blob).unwrap(), sealed, "rewritten");
        assert_eq!(read_blob(&home, &sha256).unwrap(), bytes);
        assert!(read_blob(&home, &"b".repeat(64)).is_err());

        // A plaintext blob read before any migration is sealed on that read.
        std::fs::write(&blob, &bytes).unwrap();
        assert_eq!(read_blob(&home, &sha256).unwrap(), bytes);
        assert!(!holds_slice(&std::fs::read(&blob).unwrap()));
    }

    #[test]
    fn an_invalid_hash_is_refused_before_a_blob_path_is_built() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let sink = StoreEvidence::new(&home, store);

        let mut bad = attachment("2");
        bad.sha256 = "../escape".to_string();
        let error = match sink.append(bad) {
            Ok(_) => panic!("an invalid hash must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("SHA-256"), "{error}");

        let mut upper = attachment("2");
        upper.sha256 = "A".repeat(64);
        assert!(sink.append(upper).is_err(), "uppercase hex is refused");

        assert!(
            !home.join("evidence").exists(),
            "no blob directory is created for a refused hash"
        );
    }

    #[test]
    fn a_known_hash_writes_one_blob_and_a_source_per_part() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            kernel_core::config_path(&home),
            "version = 1\n\n[privacy]\nmode = \"open\"\n",
        )
        .unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&kernel_core::store_path(&home)).unwrap(),
        ));
        let sink = StoreEvidence::new(&home, Arc::clone(&store));

        let first = sink.append(attachment("2")).expect("first append");
        assert!(!first.duplicate, "the first append is new");
        assert_eq!(read_blob(&home, &"a".repeat(64)).unwrap(), b"data");

        let second = sink.append(attachment("3")).expect("second append");
        assert!(second.duplicate, "the second append is a duplicate");

        // One document row, two source rows: the same original from two parts.
        let conn = aux_store::open_keyed_readonly(&kernel_core::store_path(&home)).unwrap();
        let documents: i64 = conn
            .query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))
            .unwrap();
        let sources: i64 = conn
            .query_row("SELECT COUNT(*) FROM evidence_source", [], |row| row.get(0))
            .unwrap();
        assert_eq!((documents, sources), (1, 2));
        let source: String = conn
            .query_row("SELECT source FROM evidence_source LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(source.contains("\"uid\":7"), "{source}");
        assert!(source.contains("\"part\":\"2\""), "{source}");
    }

    #[test]
    fn an_append_paused_after_lookup_cannot_recreate_an_erased_row() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let store_path = kernel_core::store_path(&home);
        let store = disk_store(&home);
        let sink = StoreEvidence::new(&home, Arc::clone(&store));
        let hash = "b".repeat(64);
        let mut first = attachment("2");
        first.sha256 = hash.clone();
        sink.append(first).expect("register the original");

        let (known_tx, known_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let append_sink = StoreEvidence::new(&home, Arc::clone(&store));
        let append_hash = hash.clone();
        let append = std::thread::spawn(move || {
            let mut attachment = attachment("3");
            attachment.sha256 = append_hash;
            APPEND_AFTER_LOOKUP.with(|slot| *slot.borrow_mut() = Some((known_tx, resume_rx)));
            append_sink.append(attachment)
        });
        assert!(known_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("append reached the lookup/erase interleave"));

        let erase_home = home.clone();
        let erase_path = store_path.clone();
        let erase_prefix = hash[..12].to_string();
        let lifecycle = aux_store::evidence_lifecycle_lock(&hash);
        let serializes = lifecycle.try_lock().is_err();
        let erase = move || {
            erase_document(
                &Store::open(&erase_path).unwrap(),
                &erase_home,
                &erase_prefix,
            )
        };
        if serializes {
            let erase = std::thread::spawn(erase);
            resume_tx.send(()).unwrap();
            append.join().unwrap().expect("append completes");
            erase.join().unwrap().expect("erase completes");
        } else {
            erase().expect("erase between lookup and append");
            resume_tx.send(()).unwrap();
            append.join().unwrap().expect("append completes");
        }

        let rows = kernel_core::lock_recover(&store)
            .documents_by_hash_prefix(&hash)
            .unwrap();
        assert!(rows.is_empty(), "append recreated erased row");
        assert!(!home.join("evidence").join(hash).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_blob_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let sink = StoreEvidence::new(&home, disk_store(&home));
        sink.append(attachment("2")).unwrap();
        let blob = home.join("evidence").join("a".repeat(64));
        assert_eq!(
            std::fs::metadata(&blob).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
