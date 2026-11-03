//! The held-out sets live outside the tree (PUB-2): in `$AUXESIS_EVAL_DIR`,
//! default `~/.auxesis-eval/heldout/`, at their kernel-relative paths. Each is
//! pinned by the SHA-256 of the whole file. A missing file is skipped and said
//! so; a present file whose hash differs refuses the run. With
//! `AUXESIS_EVAL_REQUIRE_HELDOUT=1` (the private nightly), a missing file
//! refuses the run too, so a skip can never be read as the bar being met.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// `path sha256` lines, kernel-relative, `#` comments allowed.
///
/// The pins are embedded rather than read from `HELDOUT-PINS.txt`: the public
/// export ships no `*heldout*` file, so a compile-time `include_str!` would
/// break the export. They mirror the tracked pins file.
const PINS: &str = "\
qa/privacy-eval/heldout-2.jsonl 4dd3991327a558740042b292a8d2ac74d7bc3174f7c5c766cf88335d4fd04155
qa/privacy-eval/heldout.txt b7169bc6d23e717cf7b8b58a75a6c3a97d09f610ff6f3861408b9f8fe2bcaa73
";

/// The v1 split: one held-out case id per line.
pub(crate) const HELDOUT_1: &str = "qa/privacy-eval/heldout.txt";
/// The frozen Tier C held-out set (TIERC-HELDOUT-2). Fix builders never read it.
pub(crate) const HELDOUT_2: &str = "qa/privacy-eval/heldout-2.jsonl";

/// A held-out file: its verified text, or the path where it was looked for.
#[derive(Debug)]
pub(crate) enum HeldOut {
    Present(String),
    Absent(PathBuf),
}

/// `$AUXESIS_EVAL_DIR` when set, else `$HOME/.auxesis-eval/heldout`.
pub(crate) fn eval_dir() -> Result<PathBuf, String> {
    if let Some(dir) = env::var_os("AUXESIS_EVAL_DIR").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".auxesis-eval/heldout"))
        .ok_or_else(|| "held-out: neither AUXESIS_EVAL_DIR nor HOME is set".to_string())
}

/// Load `rel` from `dir` against the committed pins.
pub(crate) fn load(dir: &Path, rel: &str) -> Result<HeldOut, String> {
    let required = env::var("AUXESIS_EVAL_REQUIRE_HELDOUT").is_ok_and(|v| v == "1");
    required_or_skip(load_pinned(PINS, dir, rel)?, required)
}

/// A missing set is a skip, unless the caller requires the sets.
fn required_or_skip(set: HeldOut, required: bool) -> Result<HeldOut, String> {
    match set {
        HeldOut::Absent(path) if required => Err(format!(
            "held-out set absent: {} (AUXESIS_EVAL_REQUIRE_HELDOUT=1)",
            path.display()
        )),
        set => Ok(set),
    }
}

fn load_pinned(pins: &str, dir: &Path, rel: &str) -> Result<HeldOut, String> {
    let want = pin(pins, rel)?;
    let path = dir.join(rel);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HeldOut::Absent(path)),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let got = crate::sha256_hex(&bytes);
    if got != want {
        return Err(format!(
            "held-out {rel}: sha256 {got} != pin {want} (recorded pins); re-baselining needs a lead decision"
        ));
    }
    String::from_utf8(bytes)
        .map(HeldOut::Present)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn pin<'a>(pins: &'a str, rel: &str) -> Result<&'a str, String> {
    pins.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(path, _)| *path == rel)
        .map(|(_, hash)| hash.trim())
        .ok_or_else(|| format!("held-out {rel}: no pin for it"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system temp dir, removed by the caller.
    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("privacy-eval-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("qa/privacy-eval")).expect("scratch dir");
        dir
    }

    /// The invented body every test writes; never a held-out line.
    const BODY: &str = "synthetic\n";

    fn pins_for(hash: &str) -> String {
        format!("# test pins\nqa/privacy-eval/set.jsonl {hash}\n")
    }

    #[test]
    fn a_missing_held_out_file_fails_when_the_sets_are_required() {
        let dir = scratch("required");
        let pins = pins_for(&crate::sha256_hex(BODY.as_bytes()));
        let got =
            load_pinned(&pins, &dir, "qa/privacy-eval/set.jsonl").expect("absent is no error");
        fs::remove_dir_all(&dir).expect("cleanup");
        let error = required_or_skip(got, true).expect_err("required + absent must fail");
        assert!(error.contains("AUXESIS_EVAL_REQUIRE_HELDOUT"), "{error}");
    }

    #[test]
    fn a_missing_held_out_file_is_skipped_not_failed() {
        let dir = scratch("absent");
        let pins = pins_for(&crate::sha256_hex(BODY.as_bytes()));
        let got = load_pinned(&pins, &dir, "qa/privacy-eval/set.jsonl");
        fs::remove_dir_all(&dir).expect("cleanup");
        match got {
            Ok(HeldOut::Absent(path)) => assert!(path.ends_with("qa/privacy-eval/set.jsonl")),
            other => panic!("a missing file must be a skip, got {other:?}"),
        }
    }

    #[test]
    fn a_held_out_file_whose_hash_differs_from_its_pin_fails() {
        let dir = scratch("mismatch");
        fs::write(dir.join("qa/privacy-eval/set.jsonl"), BODY).expect("write");
        let pins = pins_for(&"0".repeat(64));
        let got = load_pinned(&pins, &dir, "qa/privacy-eval/set.jsonl");
        fs::remove_dir_all(&dir).expect("cleanup");
        let error = got.expect_err("a hash mismatch must fail");
        assert!(error.contains("!= pin"), "{error}");
    }

    #[test]
    fn a_held_out_file_matching_its_pin_is_read() {
        let dir = scratch("match");
        fs::write(dir.join("qa/privacy-eval/set.jsonl"), BODY).expect("write");
        let pins = pins_for(&crate::sha256_hex(BODY.as_bytes()));
        let got = load_pinned(&pins, &dir, "qa/privacy-eval/set.jsonl");
        fs::remove_dir_all(&dir).expect("cleanup");
        match got {
            Ok(HeldOut::Present(text)) => assert_eq!(text, BODY),
            other => panic!("a pinned file must load, got {other:?}"),
        }
    }

    #[test]
    fn an_unpinned_path_fails() {
        let error = load_pinned("", Path::new("/nonexistent"), "qa/privacy-eval/set.jsonl")
            .expect_err("no pin, no run");
        assert!(error.contains("no pin"), "{error}");
    }

    #[test]
    fn both_committed_sets_are_pinned() {
        for rel in [HELDOUT_1, HELDOUT_2] {
            let hash = pin(PINS, rel).expect("pinned");
            assert_eq!(hash.len(), 64, "{rel}");
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "{rel}");
        }
    }

    /// The private tree keeps the pins file; the public export does not ship it.
    /// When it is there, the embedded copy must agree with it.
    #[test]
    fn the_embedded_pins_match_the_tracked_file_when_present() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("HELDOUT-PINS.txt");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return,
            Err(error) => panic!("{}: {error}", path.display()),
        };
        for rel in [HELDOUT_1, HELDOUT_2] {
            assert_eq!(pin(PINS, rel), pin(&text, rel), "{rel}");
        }
    }
}
