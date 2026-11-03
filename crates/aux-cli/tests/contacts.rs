//! `aux contacts` end to end against the real `aux` binary, in a sandbox home.
//!
//! The contacts file lives outside the home. Nothing it names may reach the
//! output of the command or the store file on disk.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VCARD: &str = include_str!("fixtures/contacts.vcf");
const CSV: &str = include_str!("fixtures/contacts.csv");

/// Run `aux contacts <args>` with the sandbox environment the project mandates.
fn aux(dir: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aux"))
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .expect("run aux")
}

fn text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

/// A sandbox: a temp dir, the home under it, and the contacts file beside it.
fn sandbox() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".auxesis");
    let file = dir.path().join("contacts.vcf");
    std::fs::write(&file, VCARD).unwrap();
    (dir, home, file)
}

/// Every regular file under `dir`, at any depth.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files
}

/// Every file under `dir`: its path, its size and when it changed.
fn listing(dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    for path in files_under(dir) {
        let meta = std::fs::metadata(&path).unwrap();
        out.push((path, meta.len(), meta.modified().unwrap()));
    }
    out
}

fn assert_no_raw_names(what: &str, bytes: &[u8]) {
    for needle in [
        "Camille",
        "Exemple",
        "camille.exemple",
        "Kovács",
        "Pieter",
        "王小明",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{what} holds a raw `{needle}`"
        );
    }
}

#[test]
fn import_prints_counts_and_the_store_holds_no_clear_name() {
    let (dir, home, file) = sandbox();
    let file = file.to_str().unwrap();

    let imported = aux(
        dir.path(),
        &home,
        &["contacts", "import", file, "--country", "FR"],
    );
    assert!(imported.status.success(), "{}", text(&imported.stderr));
    let shown = text(&imported.stdout);
    assert!(
        shown.contains("Stored 4 contacts from this file (4 e-mail addresses, 6 phone numbers)."),
        "{shown}"
    );
    assert_no_raw_names("the import output", imported.stdout.as_slice());
    assert_no_raw_names("the import errors", imported.stderr.as_slice());

    // Every file of the home, the WAL tail included, is free of clear names.
    let files = files_under(&home);
    assert!(
        files.iter().any(|path| path.ends_with("store.db")),
        "{files:?}"
    );
    for path in files {
        assert_no_raw_names(&path.display().to_string(), &std::fs::read(&path).unwrap());
    }

    // Importing the same file again adds nothing.
    let again = aux(
        dir.path(),
        &home,
        &["contacts", "import", file, "--country", "FR"],
    );
    let again = text(&again.stdout);
    assert!(
        again.contains("Stored 4 contacts from this file"),
        "{again}"
    );
    assert_eq!(
        text(&aux(dir.path(), &home, &["contacts", "list"]).stdout)
            .matches("file:contacts.vcf: 4 contacts")
            .count(),
        1
    );
}

#[test]
fn list_counts_without_names_and_shows_names_on_request() {
    let (dir, home, file) = sandbox();
    let file = file.to_str().unwrap();
    assert!(aux(
        dir.path(),
        &home,
        &["contacts", "import", file, "--country", "FR"]
    )
    .status
    .success());

    let counted = aux(dir.path(), &home, &["contacts", "list"]);
    let counted_text = text(&counted.stdout);
    assert!(
        counted_text.contains(
            "file:contacts.vcf: 4 contacts (4 e-mail addresses, 6 phone numbers), enabled"
        ),
        "{counted_text}"
    );
    assert!(
        counted_text.contains("Private mode uses 4 people."),
        "{counted_text}"
    );
    assert_no_raw_names("the count", counted.stdout.as_slice());

    let named = text(&aux(dir.path(), &home, &["contacts", "list", "--show"]).stdout);
    assert!(named.contains("- Camille Exemple"), "{named}");
}

#[test]
fn an_empty_store_says_the_next_step_and_clear_needs_yes() {
    let (dir, home, file) = sandbox();
    let empty = text(&aux(dir.path(), &home, &["contacts", "list"]).stdout);
    assert!(empty.contains("aux contacts import <file>"), "{empty}");
    assert!(empty.contains("Importez d'abord vos contacts"), "{empty}");

    let file = file.to_str().unwrap();
    assert!(aux(
        dir.path(),
        &home,
        &["contacts", "import", file, "--country", "FR"]
    )
    .status
    .success());
    let refused = aux(dir.path(), &home, &["contacts", "clear"]);
    assert!(!refused.status.success());
    assert!(text(&refused.stderr).contains("--yes"));
    assert!(text(&aux(dir.path(), &home, &["contacts", "list"]).stdout)
        .contains("file:contacts.vcf: 4 contacts"));

    let cleared = aux(dir.path(), &home, &["contacts", "clear", "--yes"]);
    assert!(cleared.status.success());
    assert!(text(&cleared.stdout).contains("Cleared 4 contacts."));
}

#[test]
fn remove_drops_one_contact_by_address() {
    let (dir, home, file) = sandbox();
    let file = file.to_str().unwrap();
    assert!(aux(
        dir.path(),
        &home,
        &["contacts", "import", file, "--country", "FR"]
    )
    .status
    .success());

    let removed = aux(
        dir.path(),
        &home,
        &["contacts", "remove", "camille.exemple@example.invalid"],
    );
    assert!(removed.status.success(), "{}", text(&removed.stderr));
    assert!(text(&aux(dir.path(), &home, &["contacts", "list"]).stdout)
        .contains("file:contacts.vcf: 3 contacts"));
}

#[test]
fn a_national_number_without_a_country_is_kept_out_and_warned_about() {
    let (dir, home, file) = sandbox();
    let file = file.to_str().unwrap();
    let imported = aux(dir.path(), &home, &["contacts", "import", file]);
    assert!(imported.status.success(), "{}", text(&imported.stderr));
    let shown = text(&imported.stdout);
    assert!(
        shown.contains("warning: 1 contact(s) need country"),
        "{shown}"
    );
    assert!(!shown.contains("06 98"), "{shown}");
}

/// Run a dry run of the import of `file`.
fn dry_run(dir: &Path, home: &Path, file: &str) -> Output {
    aux(dir, home, &["contacts", "import", file, "--dry-run"])
}

#[test]
fn a_dry_run_writes_nothing_and_refuses_a_store_it_would_migrate() {
    let (dir, home, file) = sandbox();
    let file = file.to_str().unwrap();

    let dry = dry_run(dir.path(), &home, file);
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    let shown = text(&dry.stdout);
    assert!(shown.contains("Dry run: nothing was written."), "{shown}");

    // The dry run created no home, no store and no key: the home is still absent.
    assert!(!home.exists(), "the dry run created {}", home.display());
    // Nothing at all was written beside the contacts file.
    let files = files_under(dir.path());
    assert!(
        files.iter().all(|path| path.ends_with("contacts.vcf")),
        "the dry run wrote {files:?}"
    );

    // A store of the current schema: the dry run reads it and changes nothing.
    std::fs::create_dir_all(&home).unwrap();
    let db = home.join("store.db");
    drop(aux_store::Store::open(&db).unwrap());
    let before = listing(&home);
    let dry = dry_run(dir.path(), &home, file);
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    // The store, its WAL and its lock are as they were.
    assert_eq!(listing(&home), before);

    // A store behind the current schema: the dry run refuses it.
    let conn = aux_store::open_keyed(&db).unwrap();
    conn.execute("UPDATE meta SET value='26' WHERE key='schema_version'", [])
        .unwrap();
    drop(conn);
    let dry = dry_run(dir.path(), &home, file);
    assert!(
        !dry.status.success(),
        "the dry run must refuse a store it would have to migrate"
    );
    let shown = text(&dry.stderr);
    assert!(shown.contains("without --dry-run first"), "{shown}");

    // A store newer than this build: the dry run refuses it too.
    let conn = aux_store::open_keyed(&db).unwrap();
    conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'", [])
        .unwrap();
    drop(conn);
    let dry = dry_run(dir.path(), &home, file);
    assert!(!dry.status.success(), "a newer store must be refused");
    let shown = text(&dry.stderr);
    assert!(shown.contains("this build is older"), "{shown}");
}

#[test]
fn two_files_are_two_sources_and_a_reimport_replaces_only_its_own() {
    let (dir, home, file) = sandbox();
    let vcard = file.to_str().unwrap();
    let csv_path = dir.path().join("more.csv");
    std::fs::write(&csv_path, CSV).unwrap();
    let csv = csv_path.to_str().unwrap();
    for import in [vcard, csv] {
        assert!(aux(
            dir.path(),
            &home,
            &["contacts", "import", import, "--country", "FR"]
        )
        .status
        .success());
    }

    let listed = text(&aux(dir.path(), &home, &["contacts", "list"]).stdout);
    assert!(listed.contains("file:contacts.vcf: 4 contacts"), "{listed}");
    assert!(listed.contains("file:more.csv: 4 contacts"), "{listed}");
    // The two files name the same four people, so the union is four.
    assert!(listed.contains("Private mode uses 4 people."), "{listed}");

    // Re-importing the CSV with one person fewer replaces only that source.
    std::fs::write(&csv_path, "name,email\nAnna Example,anna@example.invalid\n").unwrap();
    assert!(aux(dir.path(), &home, &["contacts", "import", csv])
        .status
        .success());
    let listed = text(&aux(dir.path(), &home, &["contacts", "list"]).stdout);
    assert!(listed.contains("file:contacts.vcf: 4 contacts"), "{listed}");
    assert!(listed.contains("file:more.csv: 1 contact "), "{listed}");
}
