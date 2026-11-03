//! Hygiene guard: the workspace lockfile must contain exactly
//! one `reqwest`, on the version every crate was unified to.
//!
//! This test reads `Cargo.lock` directly: it fails the moment a second
//! reqwest sneaks back in (for example through an old pin), before CI has to
//! notice a duplicate TLS stack.

use std::path::Path;

fn lockfile() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn reqwest_versions(lock: &str) -> Vec<String> {
    let mut versions = Vec::new();
    for block in lock.split("[[package]]") {
        let mut name = None;
        let mut version = None;
        for line in block.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("name = ") {
                name = Some(value.trim_matches('"').to_string());
            }
            if let Some(value) = line.strip_prefix("version = ") {
                version = Some(value.trim_matches('"').to_string());
            }
        }
        if name.as_deref() == Some("reqwest") {
            versions.push(version.unwrap_or_default());
        }
    }
    versions
}

#[test]
fn exactly_one_reqwest_version() {
    let versions = reqwest_versions(&lockfile());
    assert_eq!(
        versions.len(),
        1,
        "reqwest must be unified to one version, found {versions:?}"
    );
    assert!(
        versions[0].starts_with("0.13."),
        "unified reqwest must be the 0.13 line, found {}",
        versions[0]
    );
}

#[test]
fn no_reqwest_0_12_left() {
    let versions = reqwest_versions(&lockfile());
    assert!(
        versions.iter().all(|version| !version.starts_with("0.12.")),
        "reqwest 0.12 is still in the lock: {versions:?}"
    );
}
