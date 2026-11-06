//! The signed catalog.
//!
//! `catalog/index.toml` is signed with Ed25519; `index.toml.sig` holds the
//! signature over the **exact bytes** of `index.toml` as base64 on one line.
//! `index.toml` lists one `entries/<name>.toml` file per extension together
//! with that file's sha256. Verification order is fixed:
//!
//! 1. the signature over the index bytes;
//! 2. `catalog_version` is not lower than the cached one;
//! 3. every entry file's sha256 equals its index line.
//!
//! Any failure refuses the whole catalog and the last good cache is kept.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{catalog_cache_dir, hex};

/// The only `format` value slice 1 understands.
pub const CATALOG_FORMAT: u32 = 1;

/// Everything that can refuse a catalog.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// Reading the catalog tree failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TOML in the index or an entry did not parse.
    #[error("invalid TOML: {0}")]
    Toml(String),
    /// The signature was not valid base64 or not 64 bytes.
    #[error("index signature is malformed")]
    SignatureShape,
    /// Ed25519 verification failed: unsigned or tampered index.
    #[error("index signature does not verify (unsigned or tampered)")]
    SignatureInvalid,
    /// A `format` this build does not understand.
    #[error("unsupported catalog format {0}")]
    UnsupportedFormat(u32),
    /// A name did not match `[a-z0-9-]{1,40}` or the file stem.
    #[error("entry name `{0}` is invalid")]
    InvalidName(String),
    /// An entry file's sha256 did not match its index line.
    #[error("entry `{name}` sha256 mismatch (index {expected}, file {actual})")]
    EntryHashMismatch {
        /// Entry name.
        name: String,
        /// The hash recorded in `index.toml`.
        expected: String,
        /// The hash of the bytes on disk.
        actual: String,
    },
    /// The index named an entry file the tree does not contain.
    #[error("entry file `{0}` is missing")]
    MissingEntryFile(String),
    /// The incoming `catalog_version` is lower than the cached one.
    #[error("catalog version {incoming} is lower than the cached {cached}")]
    VersionRollback {
        /// The version offered.
        incoming: String,
        /// The version already accepted.
        cached: String,
    },
    /// The catalog is structurally unusable (empty, duplicate name, ...).
    #[error("catalog is unusable: {0}")]
    Unusable(String),
}

impl From<toml::de::Error> for CatalogError {
    fn from(err: toml::de::Error) -> Self {
        CatalogError::Toml(err.to_string())
    }
}

/// `catalog/index.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// Catalog format; must be [`CATALOG_FORMAT`].
    pub format: u32,
    /// Monotonic version, e.g. `2026.10.09-1`.
    pub catalog_version: String,
    /// One line per extension.
    #[serde(default, rename = "entry")]
    pub entries: Vec<IndexEntry>,
}

/// One `[[entry]]` line of the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// `[a-z0-9-]{1,40}`, equal to the file stem.
    pub name: String,
    /// Path relative to the catalog root, e.g. `entries/datagouv-mcp.toml`.
    pub file: String,
    /// Hex sha256 of the entry file bytes.
    pub sha256: String,
}

/// `kind` in an entry. Slice 1 installs only [`EntryKind::Mcp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    /// An MCP server (stdio in slice 1).
    Mcp,
    /// A set of `skills/*.md` templates (Phase 1).
    SkillPack,
    /// A `kernel-privacy` language or domain pack (Phase 1).
    DetectorPack,
}

/// `sensitivity` in an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// Public data.
    Public,
    /// Owner data.
    Sensitive,
}

/// `[source].type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    /// An npm package or tarball.
    Npm,
    /// A uv package or sdist.
    Uv,
    /// A single downloadable executable.
    Binary,
}

/// `[source]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// How the artefact is obtained.
    #[serde(rename = "type")]
    pub kind: SourceType,
    /// npm/uv package name, or a download URL/path for a binary or tarball.
    pub package: String,
    /// Hex sha256 of the exact bytes installed.
    pub sha256: String,
}

/// `[run].transport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// A local child over stdin/stdout.
    Stdio,
    /// A remote endpoint (Phase 1).
    Http,
}

/// `[run]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    /// `stdio` (installed) or `http` (Phase 1).
    pub transport: Transport,
    /// Executable resolved inside the install dir.
    pub command: String,
    /// Arguments passed verbatim.
    #[serde(default)]
    pub args: Vec<String>,
}

/// One `[[tools]]` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryTool {
    /// Remote tool name.
    pub name: String,
    /// Model-visible description; **data**, never an instruction.
    #[serde(default)]
    pub description: String,
    /// `host:port` allowlist; `[]` means no network at all.
    #[serde(default)]
    pub network: Vec<String>,
    /// Environment variable names injected from `~/.auxesis/.env`.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// `none | api-key | oauth2`; oauth2 is Phase 1.
    #[serde(default)]
    pub auth: String,
    /// Extra paths; non-empty is Phase 1.
    #[serde(default)]
    pub fs: Vec<String>,
}

/// `[oauth]` on an entry: the generic authorization-code + PKCE flow E5 runs
/// locally (Phase 1).
///
/// Every URL is absolute. The daemon refuses anything that is not `https`
/// (or, under the test-only seam, `http` on loopback), so a catalog entry can
/// never move the token exchange to a relay or a plaintext host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// The provider's authorization endpoint the app opens.
    pub authorization_url: String,
    /// The provider's token endpoint; the only host the exchange reaches.
    pub token_url: String,
    /// Public client id of the installed app (not a secret).
    pub client_id: String,
    /// Requested scopes.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional `.env` name holding the client secret (never the value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_env: Option<String>,
}

/// `entries/<name>.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// `[a-z0-9-]{1,40}`.
    pub name: String,
    /// Extension kind.
    pub kind: EntryKind,
    /// Pinned version; never a range.
    pub version: String,
    /// SPDX licence id.
    pub licence: String,
    /// `false` only for local/git installs (never in a signed entry).
    #[serde(default)]
    pub reviewed: bool,
    /// Data class.
    pub sensitivity: Sensitivity,
    /// English summary.
    #[serde(default)]
    pub summary_en: String,
    /// French summary.
    #[serde(default)]
    pub summary_fr: String,
    /// Where the artefact comes from.
    pub source: Source,
    /// How it runs.
    pub run: Run,
    /// Advertised tools.
    #[serde(default, rename = "tools")]
    pub tools: Vec<EntryTool>,
    /// Optional `[oauth]` flow (Phase 1, E5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
    /// Optional migration metadata from the old catalog (`repo_url`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<toml::Value>,
}

impl Entry {
    /// Every `host:port` any of its tools declares, de-duplicated.
    pub fn network_allowlist(&self) -> Vec<(String, u16)> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for tool in &self.tools {
            for host in &tool.network {
                if let Some(pair) = parse_host_port(host) {
                    if seen.insert(pair.clone()) {
                        out.push(pair);
                    }
                }
            }
        }
        out
    }

    /// Every secret env name any of its tools declares, de-duplicated.
    pub fn secret_names(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for tool in &self.tools {
            for name in &tool.secrets {
                if seen.insert(name.clone()) {
                    out.push(name.clone());
                }
            }
        }
        out
    }

    /// Whether this entry can be installed by slice 1.
    pub fn installable(&self) -> Result<(), CatalogError> {
        self.validate()?;
        if self.kind != EntryKind::Mcp {
            return Err(CatalogError::Unusable(format!(
                "kind `{:?}` is Phase 1",
                self.kind
            )));
        }
        if self.run.transport != Transport::Stdio {
            return Err(CatalogError::Unusable(
                "http transport is Phase 1".to_owned(),
            ));
        }
        if self.tools.iter().any(|tool| !tool.fs.is_empty()) {
            return Err(CatalogError::Unusable("fs paths are Phase 1".to_owned()));
        }
        if self.source.sha256.trim().is_empty() {
            return Err(CatalogError::Unusable(
                "source is not pinned yet".to_owned(),
            ));
        }
        Ok(())
    }

    /// The version and secret-name rules, checked at catalog parse and install.
    pub fn validate(&self) -> Result<(), CatalogError> {
        if !valid_version(&self.version) {
            return Err(CatalogError::Unusable(format!(
                "version `{}` is not a pinned `[0-9A-Za-z.+-]` string",
                self.version
            )));
        }
        for tool in &self.tools {
            for secret in &tool.secrets {
                if !valid_secret_name(&self.name, secret) {
                    return Err(CatalogError::Unusable(format!(
                        "secret `{secret}` is outside the `{}` namespace",
                        secret_prefix(&self.name)
                    )));
                }
            }
        }
        // An `[oauth]` client secret is read from `.env`: it must be this
        // extension's own key, never another extension's or a provider key.
        if let Some(secret) = self
            .oauth
            .as_ref()
            .and_then(|oauth| oauth.client_secret_env.as_deref())
        {
            if !secret.is_empty() && !valid_secret_name(&self.name, secret) {
                return Err(CatalogError::Unusable(format!(
                    "oauth client secret `{secret}` is outside the `{}` namespace",
                    secret_prefix(&self.name)
                )));
            }
        }
        Ok(())
    }
}

/// A pinned version: `[0-9A-Za-z.+-]{1,64}`, no `..`, no leading `.`/`-`.
pub fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && !version.starts_with('.')
        && !version.starts_with('-')
        && !version.contains("..")
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

/// The `EXT_<NAME_UPPER_SNAKE>__` prefix an extension's secrets must carry.
///
/// The separator is a **double** underscore: with names that may not start,
/// end or double a hyphen, `-` → `_` is injective, so `foo` (`EXT_FOO__`) and
/// `foo-bar` (`EXT_FOO_BAR__`) can never share a key. Names may not hold `_`
/// ([`super::valid_name`]): `foo_bar` would share `foo-bar`'s prefix, and a
/// legacy `demo_` would give `EXT_DEMO___`, which starts with `demo`'s
/// `EXT_DEMO__`, so removing `demo` (a prefix sweep) would erase its keys.
pub fn secret_prefix(extension: &str) -> String {
    format!("EXT_{}__", extension.to_ascii_uppercase().replace('-', "_"))
}

/// Whether `secret` is this extension's own
/// `EXT_<NAME_UPPER_SNAKE>__<KEY>` name, `KEY = [A-Z0-9]+(_[A-Z0-9]+)*`.
pub fn valid_secret_name(extension: &str, secret: &str) -> bool {
    let prefix = secret_prefix(extension);
    let Some(key) = secret.strip_prefix(&prefix) else {
        return false;
    };
    // No `__` inside KEY, and no empty `_`-separated part.
    !key.is_empty()
        && !key.contains("__")
        && key.split('_').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
}

/// Parse `host:port` (case-insensitive host, no wildcard).
pub fn parse_host_port(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('/') {
        return None;
    }
    let port: u16 = port.trim().parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((host, port))
}

/// Verify the signature over `index_bytes` and parse the index.
pub fn verify_index(
    index_bytes: &[u8],
    signature_b64: &str,
    key: &VerifyingKey,
) -> Result<Index, CatalogError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| CatalogError::SignatureShape)?;
    let signature = Signature::from_slice(&raw).map_err(|_| CatalogError::SignatureShape)?;
    key.verify_strict(index_bytes, &signature)
        .map_err(|_| CatalogError::SignatureInvalid)?;
    let text = std::str::from_utf8(index_bytes).map_err(|_| CatalogError::SignatureShape)?;
    let index: Index = toml::from_str(text)?;
    if index.format != CATALOG_FORMAT {
        return Err(CatalogError::UnsupportedFormat(index.format));
    }
    Ok(index)
}

/// Load and verify a catalog tree from `dir` (free-function form of
/// [`Catalog::load_dir`]).
pub fn load_catalog_dir(dir: &Path, key: &VerifyingKey) -> Result<Catalog, CatalogError> {
    Catalog::load_dir(dir, key)
}

/// The signed, verified catalog held in memory.
#[derive(Debug, Clone)]
pub struct Catalog {
    /// The parsed index.
    pub index: Index,
    /// The parsed entries, keyed by name.
    pub entries: BTreeMap<String, Entry>,
}

impl Catalog {
    /// Load and verify a catalog tree (`index.toml`, `index.toml.sig`,
    /// `entries/*.toml`) from a directory.
    pub fn load_dir(dir: &Path, key: &VerifyingKey) -> Result<Self, CatalogError> {
        let index_bytes = std::fs::read(dir.join("index.toml"))?;
        let signature = std::fs::read_to_string(dir.join("index.toml.sig"))?;
        let index = verify_index(&index_bytes, &signature, key)?;
        Self::from_index(dir, index)
    }

    /// Parse the entry files listed by an already-verified index.
    pub fn from_index(dir: &Path, index: Index) -> Result<Self, CatalogError> {
        if index.entries.is_empty() {
            return Err(CatalogError::Unusable("no entries".to_owned()));
        }
        let mut entries = BTreeMap::new();
        for line in &index.entries {
            if !super::valid_name(&line.name) {
                return Err(CatalogError::InvalidName(line.name.clone()));
            }
            if line.file != format!("entries/{}.toml", line.name) {
                return Err(CatalogError::InvalidName(line.name.clone()));
            }
            let bytes = std::fs::read(dir.join(&line.file))
                .map_err(|_| CatalogError::MissingEntryFile(line.file.clone()))?;
            let actual = hex(&Sha256::digest(&bytes));
            if actual != line.sha256.to_ascii_lowercase() {
                return Err(CatalogError::EntryHashMismatch {
                    name: line.name.clone(),
                    expected: line.sha256.clone(),
                    actual,
                });
            }
            let text = String::from_utf8(bytes)
                .map_err(|_| CatalogError::Unusable("entry is not UTF-8".to_owned()))?;
            let entry: Entry = toml::from_str(&text)?;
            if entry.name != line.name {
                return Err(CatalogError::InvalidName(entry.name));
            }
            entry.validate()?;
            if entries.insert(entry.name.clone(), entry).is_some() {
                return Err(CatalogError::Unusable(format!(
                    "duplicate entry `{}`",
                    line.name
                )));
            }
        }
        Ok(Self { index, entries })
    }

    /// The entry named `name`, when present.
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }

    /// The entry, or the typed reason it is not installable.
    pub fn installable(&self, name: &str) -> Result<&Entry, CatalogError> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| CatalogError::Unusable(format!("unknown extension `{name}`")))?;
        entry.installable()?;
        Ok(entry)
    }

    /// Case-insensitive substring search over name and summaries.
    pub fn search(&self, text: &str) -> Vec<&Entry> {
        let needle = text.to_lowercase();
        self.entries
            .values()
            .filter(|entry| {
                needle.is_empty()
                    || entry.name.contains(needle.as_str())
                    || entry.summary_en.to_lowercase().contains(needle.as_str())
                    || entry.summary_fr.to_lowercase().contains(needle.as_str())
            })
            .collect()
    }
}

/// Compare two `catalog_version` strings.
///
/// The shape is `YYYY.MM.DD-N`: numeric date fields compared in order, then
/// the trailing `-N` counter. A string that does not parse falls back to a
/// plain lexicographic compare, so the rule never accepts a lower version by
/// accident.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    fn parse(version: &str) -> Option<(Vec<u64>, u64)> {
        let (date, seq) = match version.rsplit_once('-') {
            Some((date, seq)) => (date, seq.parse::<u64>().ok()?),
            None => (version, 0),
        };
        let mut fields = Vec::new();
        for part in date.split('.') {
            fields.push(part.parse::<u64>().ok()?);
        }
        if fields.is_empty() {
            return None;
        }
        Some((fields, seq))
    }
    match (parse(a), parse(b)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => a.cmp(b),
    }
}

/// The on-disk catalog cache (`~/.auxesis/catalog/`, 0700).
#[derive(Debug, Clone)]
pub struct CatalogCache {
    dir: PathBuf,
}

impl CatalogCache {
    /// The cache rooted at `~/.auxesis/catalog/`.
    pub fn new(home: &Path) -> Self {
        Self {
            dir: catalog_cache_dir(home),
        }
    }

    /// The directory the cache lives in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The `catalog_version` already accepted, when a cache exists.
    pub fn cached_version(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("catalog_version"))
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    }

    /// Refuse an incoming version lower than the cached one.
    pub fn check_monotonic(&self, incoming: &str) -> Result<(), CatalogError> {
        if let Some(cached) = self.cached_version() {
            if compare_versions(incoming, &cached) == std::cmp::Ordering::Less {
                return Err(CatalogError::VersionRollback {
                    incoming: incoming.to_owned(),
                    cached,
                });
            }
        }
        Ok(())
    }

    /// Store a verified catalog tree and its version (0700).
    pub fn store(
        &self,
        catalog: &Catalog,
        index_bytes: &[u8],
        signature: &str,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(self.dir.join("entries"))?;
        super::install::set_mode(&self.dir, 0o700)?;
        std::fs::write(self.dir.join("index.toml"), index_bytes)?;
        std::fs::write(self.dir.join("index.toml.sig"), signature)?;
        std::fs::write(
            self.dir.join("catalog_version"),
            format!("{}\n", catalog.index.catalog_version),
        )?;
        for name in catalog.entries.keys() {
            let file = catalog
                .index
                .entries
                .iter()
                .find(|line| &line.name == name)
                .map(|line| line.file.clone())
                .unwrap_or_else(|| format!("entries/{name}.toml"));
            // Re-encode the verified entry so the cache is self-consistent.
            let text = toml::to_string(&catalog.entries[name])
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            let target = self.dir.join(file);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(target, text)?;
        }
        Ok(())
    }

    /// Load and verify the cached tree, when present.
    pub fn load(&self, key: &VerifyingKey) -> Result<Option<Catalog>, CatalogError> {
        if !self.dir.join("index.toml").is_file() {
            return Ok(None);
        }
        Catalog::load_dir(&self.dir, key).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;

    const TEST_SEED: [u8; 32] = [7u8; 32];

    fn key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    fn signed_index(version: &str, entries: &[(&str, &str)]) -> (Vec<u8>, String, Index) {
        let mut text = format!("format = 1\ncatalog_version = \"{version}\"\n");
        let mut parsed = Vec::new();
        for (name, hash) in entries {
            text.push_str(&format!(
                "[[entry]]\nname = \"{name}\"\nfile = \"entries/{name}.toml\"\nsha256 = \"{hash}\"\n"
            ));
            parsed.push(IndexEntry {
                name: (*name).to_owned(),
                file: format!("entries/{name}.toml"),
                sha256: (*hash).to_owned(),
            });
        }
        let bytes = text.into_bytes();
        let signature =
            base64::engine::general_purpose::STANDARD.encode(key().sign(&bytes).to_bytes());
        let index = Index {
            format: 1,
            catalog_version: version.to_owned(),
            entries: parsed,
        };
        (bytes, signature, index)
    }

    fn entry_toml(name: &str) -> String {
        format!(
            r#"name = "{name}"
kind = "mcp"
version = "1.0.0"
licence = "MIT"
reviewed = true
sensitivity = "public"
summary_en = "demo"
summary_fr = "demo"
[source]
type = "binary"
package = "server"
sha256 = "{hash}"
[run]
transport = "stdio"
command = "server"
[[tools]]
name = "ping"
description = "Ping"
network = []
secrets = []
auth = "none"
fs = []
"#,
            hash = "a".repeat(64)
        )
    }

    #[test]
    fn unsigned_or_tampered_index_is_refused() {
        let (bytes, signature, _) = signed_index("2026.10.09-1", &[]);
        let mut tampered = bytes.clone();
        tampered.push(b'\n');
        assert!(matches!(
            verify_index(&tampered, &signature, &key().verifying_key()),
            Err(CatalogError::SignatureInvalid)
        ));
        // A different key refuses the genuine signature.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            verify_index(&bytes, &signature, &other.verifying_key()),
            Err(CatalogError::SignatureInvalid)
        ));
    }

    #[test]
    fn entry_hash_mismatch_and_missing_file_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (bytes, signature, _) = signed_index("2026.10.09-1", &[("demo", &"b".repeat(64))]);
        fs::write(dir.path().join("index.toml"), &bytes).unwrap();
        fs::write(dir.path().join("index.toml.sig"), &signature).unwrap();
        fs::create_dir_all(dir.path().join("entries")).unwrap();
        fs::write(dir.path().join("entries/demo.toml"), entry_toml("demo")).unwrap();
        let err = Catalog::load_dir(dir.path(), &key().verifying_key()).unwrap_err();
        assert!(matches!(err, CatalogError::EntryHashMismatch { .. }));
    }

    #[test]
    fn lower_catalog_version_is_refused_and_cache_kept() {
        let home = tempfile::tempdir().unwrap();
        let cache = CatalogCache::new(home.path());
        fs::create_dir_all(cache.dir()).unwrap();
        fs::write(cache.dir().join("catalog_version"), "2026.10.09-2\n").unwrap();
        assert!(matches!(
            cache.check_monotonic("2026.10.09-1"),
            Err(CatalogError::VersionRollback { .. })
        ));
        assert!(cache.check_monotonic("2026.10.09-2").is_ok());
        assert!(cache.check_monotonic("2026.10.10-0").is_ok());
        // The cached version survived the refusal.
        assert_eq!(cache.cached_version().as_deref(), Some("2026.10.09-2"));
    }

    #[test]
    fn version_compare_orders_dates_then_counters() {
        use std::cmp::Ordering;
        assert_eq!(
            compare_versions("2026.10.09-1", "2026.10.09-2"),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("2026.10.10-0", "2026.10.09-9"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("2026.10.09-1", "2026.10.09-1"),
            Ordering::Equal
        );
    }

    #[test]
    fn a_verified_catalog_loads_and_searches() {
        let dir = tempfile::tempdir().unwrap();
        let body = entry_toml("demo");
        let hash = hex(&Sha256::digest(body.as_bytes()));
        let (bytes, signature, _) = signed_index("2026.10.09-1", &[("demo", &hash)]);
        fs::write(dir.path().join("index.toml"), &bytes).unwrap();
        fs::write(dir.path().join("index.toml.sig"), &signature).unwrap();
        fs::create_dir_all(dir.path().join("entries")).unwrap();
        fs::write(dir.path().join("entries/demo.toml"), &body).unwrap();
        let catalog = Catalog::load_dir(dir.path(), &key().verifying_key()).unwrap();
        assert!(catalog.entry("demo").is_some());
        assert_eq!(catalog.search("demo").len(), 1);
        assert!(catalog.installable("demo").is_ok());
    }

    #[test]
    fn host_port_parsing_is_exact() {
        assert_eq!(
            parse_host_port("Example.ORG:443"),
            Some(("example.org".to_owned(), 443))
        );
        assert_eq!(parse_host_port("example.org"), None);
        assert_eq!(parse_host_port("example.org:0"), None);
        assert_eq!(parse_host_port("example.org:notaport"), None);
    }

    #[test]
    fn index_file_must_be_exactly_entries_name_toml() {
        let dir = tempfile::tempdir().unwrap();
        let body = entry_toml("demo");
        let hash = hex(&Sha256::digest(body.as_bytes()));
        fs::create_dir_all(dir.path().join("sub/entries")).unwrap();
        fs::write(dir.path().join("sub/entries/demo.toml"), &body).unwrap();
        let index = Index {
            format: 1,
            catalog_version: "2026.10.09-1".to_owned(),
            entries: vec![IndexEntry {
                name: "demo".to_owned(),
                file: "sub/entries/demo.toml".to_owned(),
                sha256: hash,
            }],
        };
        // The stem matches the name, but the path is not exactly
        // `entries/demo.toml`: the index is refused.
        assert!(Catalog::from_index(dir.path(), index).is_err());
    }

    #[test]
    fn a_secret_name_outside_the_namespace_is_refused_at_parse() {
        let dir = tempfile::tempdir().unwrap();
        let body = entry_toml_with_secret("demo", "AUX_KEY_DEEPSEEK");
        let hash = hex(&Sha256::digest(body.as_bytes()));
        let (bytes, signature, _) = signed_index("2026.10.09-1", &[("demo", &hash)]);
        fs::write(dir.path().join("index.toml"), &bytes).unwrap();
        fs::write(dir.path().join("index.toml.sig"), &signature).unwrap();
        fs::create_dir_all(dir.path().join("entries")).unwrap();
        fs::write(dir.path().join("entries/demo.toml"), &body).unwrap();
        let err = Catalog::load_dir(dir.path(), &key().verifying_key()).unwrap_err();
        assert!(matches!(err, CatalogError::Unusable(_)));
    }

    #[test]
    fn secret_names_use_the_double_underscore_namespace() {
        assert!(
            valid_secret_name("foo-bar", "EXT_FOO_BAR__TOKEN"),
            "the hyphenated name maps to the double-underscore separator"
        );
        assert!(
            !valid_secret_name("foo", "EXT_FOO_BAR_TOKEN"),
            "`foo` must not claim `foo-bar`'s single-underscore name"
        );
        assert!(
            !valid_secret_name("foo", "EXT_FOO__BAR__X"),
            "a `__` inside KEY is refused"
        );
        assert!(!valid_secret_name("foo", "EXT_FOO__"));
        assert!(!valid_secret_name("foo", "EXT_FOO__bar"));
        assert!(valid_secret_name("foo", "EXT_FOO__TOKEN"));
        assert!(valid_secret_name("foo", "EXT_FOO__A_B_C"));
    }

    #[test]
    fn a_cross_extension_secret_name_is_refused_at_parse() {
        let dir = tempfile::tempdir().unwrap();
        // `foo` may not declare a key that belongs to `foo-bar`.
        let body = entry_toml_with_secret("foo", "EXT_FOO_BAR_TOKEN");
        let hash = hex(&Sha256::digest(body.as_bytes()));
        let (bytes, signature, _) = signed_index("2026.10.09-1", &[("foo", &hash)]);
        fs::write(dir.path().join("index.toml"), &bytes).unwrap();
        fs::write(dir.path().join("index.toml.sig"), &signature).unwrap();
        fs::create_dir_all(dir.path().join("entries")).unwrap();
        fs::write(dir.path().join("entries/foo.toml"), &body).unwrap();
        let err = Catalog::load_dir(dir.path(), &key().verifying_key()).unwrap_err();
        assert!(matches!(err, CatalogError::Unusable(_)));
    }

    #[test]
    fn an_oauth_client_secret_outside_the_namespace_is_refused() {
        let body = format!(
            r#"{}
[oauth]
authorization_url = "https://auth.example/authorize"
token_url = "https://auth.example/token"
client_id = "test-client"
client_secret_env = "AUX_KEY_DEEPSEEK"
"#,
            entry_toml("demo")
        );
        let entry: Entry = toml::from_str(&body).unwrap();
        assert!(
            matches!(entry.validate(), Err(CatalogError::Unusable(_))),
            "a provider key must never be an extension's OAuth secret"
        );
        // The extension's own namespaced key is accepted.
        let own = body.replace("AUX_KEY_DEEPSEEK", "EXT_DEMO__CLIENT_SECRET");
        let entry: Entry = toml::from_str(&own).unwrap();
        assert!(entry.validate().is_ok());
    }

    fn entry_toml_with_secret(name: &str, secret: &str) -> String {
        format!(
            r#"name = "{name}"
kind = "mcp"
version = "1.0.0"
licence = "MIT"
reviewed = true
sensitivity = "public"
summary_en = "demo"
summary_fr = "demo"
[source]
type = "binary"
package = "server"
sha256 = "{hash}"
[run]
transport = "stdio"
command = "server"
[[tools]]
name = "ping"
description = "Ping"
network = []
secrets = ["{secret}"]
auth = "none"
fs = []
"#,
            hash = "a".repeat(64)
        )
    }
}
