//! Extensions, slice 1 — the app side.
//!
//! An extension is a pinned `mcp` server listed in a signed catalog, installed
//! explicitly, mounted per agent and run on the Mac under a Seatbelt profile
//! generated from its entry. This module owns the whole app-side path:
//!
//! - [`catalog`] — the signed `index.toml` + `.sig`, per-entry files, the
//!   monotonic `catalog_version` and the on-disk cache;
//! - [`install`] — sha256 verification **before** unpack, the
//!   `~/.auxesis/extensions/<name>@<version>/` tree, `--ignore-scripts` (no
//!   lifecycle script ever runs) and `remove`;
//! - [`session`] — the sandboxed stdio child, the `kernel-net` egress proxy and
//!   the identity pin;
//! - [`mount`] — per-agent mounts, the freeze on identity drift and the
//!   `kernel-broker` registration (broker default `ask`);
//! - [`ledger`] — the `ext.*` rows on the existing `events` table.
//!
//! Only `kind = "mcp"`, `transport = "stdio"` and an empty `fs` list are
//! installable in slice 1. Everything the contract marks *Phase 1* is refused
//! with a typed [`ExtError::Phase1`], never half-built.
//!
//! # The signing key
//!
//! [`CATALOG_PUBKEY`] is a **clearly marked placeholder**: the owner decides
//! where the production signing key lives. Tests never use this constant; they
//! verify against a generated test key passed into [`catalog::verify_index`].
//! Until the owner installs the real key, a production catalog is refused —
//! which is the fail-closed direction.

pub mod catalog;
pub mod install;
pub mod ledger;
pub mod mount;
pub mod oauth;
pub mod session;

#[cfg(test)]
mod scenarios;

use std::io::Read;
use std::path::{Path, PathBuf};

pub use catalog::{
    compare_versions, load_catalog_dir, verify_index, Catalog, CatalogCache, CatalogError, Entry,
    EntryKind, EntryTool, Index, IndexEntry, OAuthConfig, Sensitivity, Source, SourceType,
    Transport, CATALOG_FORMAT,
};
pub use install::{
    install, remove, verify_installed, verify_installed_report, InstallError, InstallOptions,
    InstalledExtension, VerifiedInstall,
};
pub use mount::{
    freeze, is_frozen, is_mounted, mount, mounted_extensions, unmount, ExtensionHost,
    ExtensionState, MountError,
};
pub use oauth::{
    access_token, loopback_endpoints_allowed, oauth_endpoints, refresh_tokens, FileTokenStore,
    OAuthEndpoints, OAuthError, PendingFlow, TokenSet, TokenStore, OAUTH_TIMEOUT, TOKEN_TIMEOUT,
};
pub use session::{
    discover_session, pinned_tools, session_for, spawn_egress, verify_identity, EgressHandle,
    ExtensionSession, SessionError, SessionOptions, ToolPin,
};

/// The Ed25519 public key the shipped catalog is signed with.
///
/// **PLACEHOLDER — OPEN ITEM.** These bytes are not a real signing key. The
/// owner decides the production key's location (an offline file on the owner's
/// Mac, 0600, outside `~/.auxesis`), then this constant is replaced with its
/// 32-byte public half. Until then every signed catalog is refused, so nothing
/// installs from an unverified index.
pub const CATALOG_PUBKEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// `text` safe on one terminal line: every character of the Unicode
/// categories Cc (controls), Cf (format: bidi, invisible, tags, interlinear
/// annotation), Zl and Zp (line and paragraph separators) is shown as
/// `\u{..}`. The Cf set is spelled by range (Unicode 15.1), with no new
/// dependency; an unassigned code point inside a range is escaped too.
pub fn escape_text(text: &str) -> String {
    let hidden = |c: char| {
        c.is_control()
            || matches!(
                c,
                '\u{00ad}' | '\u{061c}' | '\u{06dd}' | '\u{070f}' | '\u{08e2}' | '\u{180e}'
            )
            || matches!(c, '\u{feff}' | '\u{110bd}' | '\u{110cd}')
            || matches!(c, '\u{0600}'..='\u{0605}' | '\u{0890}'..='\u{0891}')
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}')
            || matches!(c, '\u{2060}'..='\u{206f}' | '\u{fff9}'..='\u{fffb}')
            || matches!(c, '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}')
            || matches!(c, '\u{1d173}'..='\u{1d17a}' | '\u{e0000}'..='\u{e007f}')
    };
    text.chars()
        .map(|c| match hidden(c) {
            true => format!("\\u{{{:x}}}", u32::from(c)),
            false => c.to_string(),
        })
        .collect()
}

/// A value JSON-quoted, then [`escape_text`]: never rendered, never reordered.
pub fn quoted<T: serde::Serialize + ?Sized>(value: &T) -> String {
    escape_text(&serde_json::to_string(value).unwrap_or_else(|_| "none".to_owned()))
}

/// `~/.auxesis/extensions/` — every install, the identity rows and the mounts.
pub fn extensions_dir(home: &Path) -> PathBuf {
    home.join("extensions")
}

/// `~/.auxesis/extensions/<name>@<version>/` — one install.
pub fn install_dir(home: &Path, name: &str, version: &str) -> PathBuf {
    extensions_dir(home).join(format!("{name}@{version}"))
}

/// `~/.auxesis/catalog/` — the verified on-disk catalog cache (0700).
pub fn catalog_cache_dir(home: &Path) -> PathBuf {
    home.join("catalog")
}

pub(crate) enum ReadAt {
    Absent,
    Unreadable,
    Text(String),
}

pub(crate) fn read_text_at_checked(
    handle: &kernel_core::SandboxHome,
    rel: &Path,
    max: u64,
) -> ReadAt {
    let file = match handle.open_read_existing(rel, max) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return ReadAt::Absent,
        Err(_) => return ReadAt::Unreadable,
    };
    let mut bytes = Vec::new();
    if file.take(max + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > max {
        return ReadAt::Unreadable;
    }
    match String::from_utf8(bytes) {
        Ok(text) => ReadAt::Text(text),
        Err(_) => ReadAt::Unreadable,
    }
}

/// Decode a 32-byte Ed25519 public key, or `None` when the bytes are not a
/// valid curve point.
///
/// The all-zero [`CATALOG_PUBKEY`] placeholder is refused explicitly: an
/// all-zero compressed point happens to decode on some backends, and it must
/// never verify a catalog. Until the owner installs the real key this returns
/// `None` for the production constant, so nothing is browsable or installable.
pub fn catalog_key(bytes: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    if bytes == &[0u8; 32] {
        return None;
    }
    ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()
}

/// Load the verified catalog the app ships/uses, or `None` when the
/// production key is still the placeholder or no verified cache exists.
pub fn load_verified_catalog(home: &Path) -> Option<Catalog> {
    let key = catalog_key(&CATALOG_PUBKEY)?;
    CatalogCache::new(home).load(&key).ok().flatten()
}

/// Every error the extensions path can return.
#[derive(Debug, thiserror::Error)]
pub enum ExtError {
    /// A catalog signature, entry hash or version rule failed.
    #[error("catalog refused: {0}")]
    Catalog(#[from] CatalogError),
    /// An install, verify or remove failed.
    #[error("install refused: {0}")]
    Install(#[from] InstallError),
    /// A mount, unmount or freeze failed.
    #[error("mount refused: {0}")]
    Mount(#[from] MountError),
    /// A session could not be built or started.
    #[error("session refused: {0}")]
    Session(#[from] SessionError),
    /// A feature the contract marks Phase 1 was requested in slice 1.
    #[error("not available in slice 1 (Phase 1): {0}")]
    Phase1(String),
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The `[a-z0-9-]{1,40}` name rule.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        // No leading/trailing or doubled hyphen: the `-` -> `_` map must be
        // injective, so `foo` and `foo-bar` can never share a secret prefix.
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

/// Hex-encode a digest.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Parse a lowercase hex string into bytes; `None` when it is not valid hex.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = (bytes[index] as char).to_digit(16)?;
        let lo = (bytes[index + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        index += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercase_kebab() {
        assert!(valid_name("datagouv-mcp"));
        assert!(valid_name("a"));
        assert!(!valid_name("Datagouv"));
        assert!(!valid_name("a_b"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"x".repeat(41)));
    }

    #[test]
    fn names_refuse_hyphen_edges_and_doubles() {
        assert!(!valid_name("-a"), "a leading hyphen must be refused");
        assert!(!valid_name("a-"), "a trailing hyphen must be refused");
        assert!(!valid_name("a--b"), "a double hyphen must be refused");
        assert!(valid_name("a-b"));
        assert!(valid_name("datagouv-mcp"));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(hex(&bytes), "000fa5ff");
        assert_eq!(unhex("000fa5ff").unwrap(), bytes);
        assert!(unhex("0").is_none());
        assert!(unhex("zz").is_none());
    }

    /// Captured with sha2 0.10.9: the catalog, install and verify checks all
    /// compare `hex(&Sha256::digest(..))` with a pinned hash, so an installed
    /// extension still verifies after a sha2 upgrade.
    #[test]
    fn old_version_vector_extension_hash() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex(&Sha256::digest(b"fixed extension artifact\n")),
            "22dfbd63cf3e0defa40148b9233793e808df71ca6ee704462181978dde18f1c0"
        );
    }

    #[test]
    fn the_placeholder_key_refuses_every_catalog() {
        assert_eq!(CATALOG_PUBKEY, [0u8; 32]);
        assert!(
            catalog_key(&CATALOG_PUBKEY).is_none(),
            "the all-zero placeholder must never verify a catalog"
        );
    }

    #[test]
    fn production_refuses_a_catalog_when_the_key_is_the_placeholder() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("catalog");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.toml"), b"format = 1\n").unwrap();
        assert!(
            load_verified_catalog(home.path()).is_none(),
            "the placeholder key must refuse every catalog, even a present cache"
        );
    }

    // EXT-ANCHOR-10: a sample of Cc, Cf, Zl and Zp characters is escaped, tags
    // and interlinear annotation included; printable text is kept as it is.
    #[test]
    fn escape_text_escapes_sampled_controls_formats_and_separators() {
        let hidden = "\u{1b}\u{85}\u{ad}\u{600}\u{61c}\u{180e}\u{200b}\u{200e}\u{2028}\u{2029}\
                      \u{202e}\u{2066}\u{feff}\u{fff9}\u{fffa}\u{fffb}\u{110bd}\u{1d173}\
                      \u{e0001}\u{e0041}\u{e007f}";
        for c in hidden.chars() {
            let shown = escape_text(&format!("a{c}b"));
            assert_eq!(shown, format!("a\\u{{{:x}}}b", u32::from(c)), "{c:?}");
        }
        assert_eq!(escape_text("café 中 🙂 a-b_c"), "café 中 🙂 a-b_c");
    }
}
