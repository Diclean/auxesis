//! `aux contacts`: the owner's local contacts, the names Private mode checks.
//!
//! A contact comes from a source. The file source reads a vCard (v3 or v4) or a
//! CSV export (generic, Google or Outlook headers). Each file is stored under its
//! own tag (`file:<name>`), so importing a file again replaces only that file's
//! contacts. Names, e-mail addresses and phone numbers go only into the encrypted
//! store. The daemon mounts the union of the sources `[contacts] sources` enables
//! (`aux_runtime::known_names`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aux_crm::CRM_CONTACT_SOURCE;
// The parse/import core is shared with the daemon (`POST /v1/contacts/import`).
#[cfg(test)]
use aux_runtime::contacts_import::*;
use aux_runtime::contacts_import::{preview_file, store_error, FileSource};
#[cfg(test)]
use aux_runtime::known_names::CONTACT_LIMIT;
use aux_runtime::known_names::{
    contacts_index, enabled_kinds, kind_of, ContactSource, NO_CONTACTS_HINT,
};
use aux_store::{ContactRecord, Store};
use clap::{Args, Subcommand};

/// `aux contacts`.
#[derive(Debug, Args)]
pub(crate) struct ContactsArgs {
    #[command(subcommand)]
    action: ContactsAction,
}

#[derive(Debug, Subcommand)]
enum ContactsAction {
    /// Import a vCard (.vcf, v3 or v4) or a CSV export (generic, Google or Outlook
    /// headers). The file is read and never copied. Its contacts are stored under
    /// `file:<name>`: importing the same file again replaces them, and other files
    /// are kept. Each contact also creates its CRM party, or updates the one it matches
    /// by address or number.
    Import {
        /// The file to import.
        file: PathBuf,
        /// The country of national-format phone numbers (ISO 3166-1, e.g. FR).
        /// Without it, a national number is not kept; it is never assumed to be French.
        #[arg(long, value_name = "ISO")]
        country: Option<String>,
        /// Print the parties the import would create and merge, and the conflicts;
        /// write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Count the stored contacts per source; `--show` also lists their names.
    List {
        /// List the names.
        #[arg(long)]
        show: bool,
    },
    /// Remove one contact, by e-mail address or by name, from every file source it is
    /// stored in. A later import of the same file stores it again. The CRM's parties are
    /// not changed by this command. Vault tokens already minted for it are not changed
    /// either.
    Remove {
        /// An e-mail address, or a name.
        target: String,
    },
    /// Delete the stored contacts: all of them, or only those of one file source. The
    /// CRM's parties are kept.
    Clear {
        /// Only the contacts of this source, such as `file:contacts.vcf`.
        #[arg(long, value_name = "TAG")]
        source: Option<String>,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

/// Run `aux contacts`. Output carries counts and, on request, names; errors never name anyone.
pub(crate) fn run(args: ContactsArgs) -> ExitCode {
    let home = kernel_core::auxesis_home();
    let result = match args.action {
        ContactsAction::Import {
            file,
            country,
            dry_run: true,
        } => dry_run_store(&home).and_then(|store| dry_run(&store, &file, country.as_deref())),
        ContactsAction::Import { file, country, .. } => open_writable(&home)
            .and_then(|store| import_file(&store, &home, &file, country.as_deref())),
        ContactsAction::List { show } => list(&home, show),
        ContactsAction::Remove { target } => {
            open_writable(&home).and_then(|store| remove_one(&store, &target))
        }
        ContactsAction::Clear { source, yes } => {
            open_writable(&home).and_then(|store| clear_all(&store, source.as_deref(), yes))
        }
    };
    match result {
        Ok(text) => {
            println!("{}", text.trim_end());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("aux contacts: {}", printable(&err));
            ExitCode::FAILURE
        }
    }
}

/// The store a dry run reads: opened read-only, so the dry run writes nothing.
/// A home with no store is previewed against an empty in-memory store: the dry
/// run creates neither the home nor the store. A store this build does not
/// read is refused, and so is a store that is being written.
fn dry_run_store(home: &Path) -> Result<Store, String> {
    // The home is verified — the guard refuses the real `~/.auxesis` — and it is
    // never created: a dry run makes no home.
    let db = match kernel_core::SandboxHome::open_existing(home) {
        Ok(verified) => verified
            .real_path()
            .map_err(|err| format!("cannot open the home: {err}"))?
            .join("store.db"),
        // No home yet: there is nothing to read, and the dry run creates none.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Store::open_in_memory().map_err(store_error);
        }
        Err(err) => return Err(format!("cannot open the home: {err}")),
    };
    // A home without a store: nothing is stored yet.
    if !db.exists() {
        return Store::open_in_memory().map_err(store_error);
    }
    let store = Store::open_readonly(&db).map_err(store_error)?;
    // A store whose version cannot be read is behind this build too.
    let version = store.schema_version().unwrap_or(-1);
    if version != aux_store::SCHEMA_VERSION {
        let reason = if version > aux_store::SCHEMA_VERSION {
            "this build is older than the store, it cannot read it"
        } else {
            "run the import without --dry-run first, it migrates the store"
        };
        return Err(format!(
            "the store is at schema {version} and this build reads {}: {reason}",
            aux_store::SCHEMA_VERSION
        ));
    }
    Ok(store)
}

fn import_file(
    store: &Store,
    home: &Path,
    file: &Path,
    country: Option<&str>,
) -> Result<String, String> {
    let source = FileSource::new(file);
    let summary = aux_runtime::contacts_import::import_file(store, file, country, None)?;
    let mut text = summary.to_string();
    match enabled_kinds(home) {
        Ok(kinds) if !kinds.iter().any(|kind| kind.as_str() == source.kind()) => text.push_str(
            "note: the file source is not enabled in [contacts] sources, so these contacts \
             are stored but not used for names yet.\n",
        ),
        Ok(_) => {}
        Err(err) => text.push_str(&format!("warning: {err}\n")),
    }
    Ok(text)
}

/// `aux contacts import --dry-run`: the plan, counts and column names only. The store
/// is only read.
fn dry_run(store: &Store, file: &Path, country: Option<&str>) -> Result<String, String> {
    let preview = preview_file(store, file, country)?;
    let mut text = format!(
        "Dry run: nothing was written.\n\
         Would create {} parties, merge {} into existing ones, refuse {}.\n\
         Conflicts: {} (an existing card value would be kept).\n",
        preview.would_create, preview.would_update, preview.would_refuse, preview.conflicts
    );
    if let Some(csv) = &preview.csv {
        let mapped: Vec<String> = csv
            .mapped
            .iter()
            .map(|(column, role)| format!("{column} → {role}"))
            .collect();
        text.push_str(&format!("Columns: {}.\n", mapped.join(", ")));
        if !csv.unmapped.is_empty() {
            text.push_str(&format!("Ignored: {}.\n", csv.unmapped.join(", ")));
        }
    }
    if preview.summary.no_country > 0 {
        text.push_str(&format!(
            "warning: {} contact(s) need country: re-run with --country <ISO code>.\n",
            preview.summary.no_country
        ));
    }
    Ok(text)
}

fn list(home: &Path, show: bool) -> Result<String, String> {
    let kinds = enabled_kinds(home)?;
    let snapshot =
        aux_store::contacts_snapshot_at(&kernel_core::store_path(home)).map_err(store_error)?;
    Ok(list_text(&snapshot.records, &kinds, show))
}

/// The store of `home`, opened for writing (created and migrated on first use).
pub(crate) fn open_writable(home: &Path) -> Result<Store, String> {
    let verified = kernel_core::verified_home_or_verify(home)
        .map_err(|err| format!("cannot open the home: {err}"))?;
    Store::open_verified(&verified).map_err(store_error)
}

/// Text fit for a terminal: control characters (C0, DEL, C1, ESC, BEL) are shown as
/// `\u{..}`, so a name or a tag cannot move the cursor or set colours. Red stage:
/// the text is passed through.
pub(crate) fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// The stored contacts, per source: a count, and the names when `show` is set. A
/// source that `enabled` does not name is marked, and the line says how many
/// people Private mode uses. With no contacts, the next step in English and French.
pub(crate) fn list_text(records: &[ContactRecord], enabled: &[String], show: bool) -> String {
    if records.is_empty() {
        return format!("No contacts stored. {NO_CONTACTS_HINT}\n");
    }
    let is_enabled = |tag: &str| enabled.iter().any(|kind| kind.as_str() == kind_of(tag));
    let mut sources: Vec<&str> = Vec::new();
    for record in records {
        if !sources.contains(&record.source.as_str()) {
            sources.push(record.source.as_str());
        }
    }
    let mut text = String::new();
    for source in sources {
        let of_source: Vec<&ContactRecord> = records
            .iter()
            .filter(|record| record.source == source)
            .collect();
        let emails: usize = of_source.iter().map(|record| record.emails.len()).sum();
        let phones: usize = of_source.iter().map(|record| record.phones.len()).sum();
        let state = if is_enabled(source) {
            "enabled"
        } else {
            "not enabled"
        };
        text.push_str(&format!(
            "{}: {} ({}, {}), {state}\n",
            printable(source),
            count(of_source.len(), "contact", "contacts"),
            count(emails, "e-mail address", "e-mail addresses"),
            count(phones, "phone number", "phone numbers"),
        ));
        if show {
            for record in of_source {
                let name = record_display(record);
                let name = if name.is_empty() {
                    "(no name)".to_string()
                } else {
                    name
                };
                text.push_str(&format!("  - {}\n", printable(&name)));
            }
        }
    }
    let used: Vec<ContactRecord> = records
        .iter()
        .filter(|record| is_enabled(record.source.as_str()))
        .cloned()
        .collect();
    text.push_str(&format!(
        "Private mode uses {}.\n",
        count(contacts_index(&used).len(), "person", "people")
    ));
    text
}

/// `n` and the noun for it: `one` when `n` is one, `many` otherwise.
fn count(n: usize, one: &str, many: &str) -> String {
    let noun = if n == 1 { one } else { many };
    format!("{n} {noun}")
}

/// Remove one contact, by e-mail address or by name, from every source it is stored
/// in. A name that several stored contacts share is refused: remove them by address.
pub(crate) fn remove_one(store: &Store, target: &str) -> Result<String, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("give an e-mail address or a name".to_string());
    }
    let records = store.contacts().map_err(store_error)?;
    let hits: Vec<usize> = records
        .iter()
        .enumerate()
        // The CRM's rows are its parties' names: `aux crm` changes them, not this command.
        .filter(|(_, record)| record.source != CRM_CONTACT_SOURCE && matches_target(record, target))
        .map(|(index, _)| index)
        .collect();
    if hits.is_empty() {
        return Err("no contact has that e-mail address or name".to_string());
    }
    if !target.contains('@') && hits.len() > 1 {
        return Err(format!(
            "{} stored contacts match that name: remove them by e-mail address instead.",
            hits.len()
        ));
    }
    let kept: Vec<ContactRecord> = records
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !hits.contains(index))
        .map(|(_, record)| record)
        .collect();
    store.replace_contacts(&kept).map_err(store_error)?;
    Ok(if hits.len() == 1 {
        "Removed one stored contact.".to_string()
    } else {
        format!("Removed {} stored copies of one contact.", hits.len())
    })
}

/// Delete the stored contacts: all of them, or only those of `source`. Refused
/// unless `confirmed`, and it says how many it would delete. The CRM's rows stay: they
/// are its parties' names, and the index keeps them masked.
pub(crate) fn clear_all(
    store: &Store,
    source: Option<&str>,
    confirmed: bool,
) -> Result<String, String> {
    let records = store.contacts().map_err(store_error)?;
    let (removed, kept): (Vec<&ContactRecord>, Vec<&ContactRecord>) =
        records.iter().partition(|record| {
            record.source != CRM_CONTACT_SOURCE && source.is_none_or(|tag| record.source == tag)
        });
    let count_removed = removed.len();
    if count_removed == 0 {
        return Ok("No contacts to clear.\n".to_string());
    }
    if !confirmed {
        return Err(format!(
            "this deletes {count_removed} contacts: run it again with --yes to confirm"
        ));
    }
    let kept: Vec<ContactRecord> = kept.into_iter().cloned().collect();
    store.replace_contacts(&kept).map_err(store_error)?;
    Ok(format!("Cleared {count_removed} contacts.\n"))
}

/// The name of a stored contact, for the list: its display name, else its given and family names.
fn record_display(record: &ContactRecord) -> String {
    match &record.display_name {
        Some(name) => name.clone(),
        None => record
            .given
            .iter()
            .chain(&record.family)
            .cloned()
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// A name as one comparable key: case and spacing do not matter.
fn name_key<'a>(display: Option<&str>, parts: impl Iterator<Item = &'a str>) -> String {
    let text = match display {
        Some(display) => display.to_string(),
        None => parts.collect::<Vec<_>>().join(" "),
    };
    text.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

fn record_name_key(record: &ContactRecord) -> String {
    name_key(
        record.display_name.as_deref(),
        record
            .given
            .iter()
            .chain(&record.family)
            .map(String::as_str),
    )
}

/// Whether a stored contact is the one `target` names: an address, or a name in
/// any of its usual orders.
fn matches_target(record: &ContactRecord, target: &str) -> bool {
    if target.contains('@') {
        return record
            .emails
            .iter()
            .any(|email| email.eq_ignore_ascii_case(target));
    }
    let wanted = name_key(Some(target), std::iter::empty());
    let given_family = name_key(
        None,
        record
            .given
            .iter()
            .chain(&record.family)
            .map(String::as_str),
    );
    let family_given = name_key(
        None,
        record
            .family
            .iter()
            .chain(&record.given)
            .map(String::as_str),
    );
    [record_name_key(record), given_family, family_given].contains(&wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VCARD: &str = include_str!("../tests/fixtures/contacts.vcf");
    const CSV: &str = include_str!("../tests/fixtures/contacts.csv");
    /// Three fictional people: a French national number, a US number and a GB number.
    const CRM_SEED: &str = include_str!("../tests/fixtures/crm-seed.vcf");

    fn by_email<'a>(people: &'a [Parsed], email: &str) -> &'a Parsed {
        people
            .iter()
            .find(|p| p.emails.iter().any(|e| e == email))
            .expect("a person with that address")
    }

    #[test]
    fn vcard_v3_and_v4_yield_the_fictional_people() {
        let people = parse_vcards(VCARD).people;
        assert_eq!(people.len(), 4);

        let camille = by_email(&people, "camille.exemple@example.invalid");
        assert_eq!(camille.display_name.as_deref(), Some("Camille Exemple"));
        assert_eq!(camille.given, ["Camille"]);
        assert_eq!(camille.family, ["Exemple"]);
        assert_eq!(camille.nicknames, ["Cam", "Milla"]);
        assert_eq!(camille.phones, ["+33 6 12 34 56 78", "06 98 76 54 32"]);

        let anna = by_email(&people, "anna.kovacs@example.invalid");
        assert_eq!(anna.display_name.as_deref(), Some("Kovács Anna"));
        // The `tel:` URI prefix of a v4 card is not part of the number.
        assert_eq!(anna.phones, ["+36-20-123-4567", "+386 40 123 456"]);

        let pieter = by_email(&people, "pieter.vandermerwe@example.invalid");
        assert_eq!(pieter.given, ["Pieter"]);
        assert_eq!(pieter.family, ["van", "der", "Merwe"]);

        let wang = by_email(&people, "wang.xiaoming@example.invalid");
        assert_eq!(wang.display_name.as_deref(), Some("王小明"));
        assert_eq!(wang.family, ["王"]);
        assert_eq!(wang.given, ["小明"]);
    }

    #[test]
    fn vcard_unfolds_continuation_lines_and_unescapes_values() {
        let text = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Camille\r\n  Exemple\r\n\
                    NICKNAME:Cam\\, the best\r\n\
                    EMAIL;TYPE=INTERNET:\r\n camille@example.invalid\r\nEND:VCARD\r\n";
        let people = parse_vcards(text).people;
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].display_name.as_deref(), Some("Camille Exemple"));
        assert_eq!(people[0].nicknames, ["Cam, the best"]);
        assert_eq!(people[0].emails, ["camille@example.invalid"]);
    }

    #[test]
    fn csv_generic_header_is_detected() {
        let people = parse_csv(CSV).unwrap();
        assert_eq!(people.len(), 4);
        let camille = by_email(&people, "camille.exemple@example.invalid");
        assert_eq!(camille.display_name.as_deref(), Some("Camille Exemple"));
        assert_eq!(camille.phones, ["+33 6 12 34 56 78"]);
    }

    #[test]
    fn google_export_header_is_detected_and_skips_type_columns() {
        let text = "Name,Given Name,Family Name,Nickname,E-mail 1 - Type,E-mail 1 - Value,\
                    E-mail 2 - Value,Phone 1 - Type,Phone 1 - Value\n\
                    Camille Exemple,Camille,Exemple,Cam,Home,camille.exemple@example.invalid,\
                    ,Mobile,+33 6 12 34 56 78\n";
        let people = parse_csv(text).unwrap();
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].emails, ["camille.exemple@example.invalid"]);
        assert_eq!(people[0].phones, ["+33 6 12 34 56 78"]);
        assert_eq!(people[0].nicknames, ["Cam"]);
        assert_eq!(people[0].family, ["Exemple"]);
    }

    #[test]
    fn outlook_export_header_is_detected() {
        let text = "First Name,Last Name,Display Name,E-mail Address,Mobile Phone,Business Phone\n\
                    Pieter,van der Merwe,Pieter van der Merwe,pieter.vandermerwe@example.invalid,\
                    +27 82 123 4567,\n";
        let people = parse_csv(text).unwrap();
        assert_eq!(people.len(), 1);
        assert_eq!(
            people[0].display_name.as_deref(),
            Some("Pieter van der Merwe")
        );
        assert_eq!(people[0].family, ["van", "der", "Merwe"]);
        assert_eq!(people[0].phones, ["+27 82 123 4567"]);
    }

    #[test]
    fn csv_quoted_fields_and_crlf_line_ends() {
        let text = "name,email,phone\r\n\
                    \"Exemple, Camille\",camille.exemple@example.invalid,\"+33 6 12 34 56 78\"\r\n";
        let people = parse_csv(text).unwrap();
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].display_name.as_deref(), Some("Exemple, Camille"));
        assert_eq!(people[0].phones, ["+33 6 12 34 56 78"]);
    }

    #[test]
    fn csv_without_a_recognised_header_is_refused() {
        assert!(parse_csv("foo,bar\n1,2\n").is_err());
    }

    #[test]
    fn international_numbers_normalise_to_e164_for_fr_hu_si_za_and_cn() {
        let ok = |raw: &str| normalise_phone(raw, None).unwrap();
        assert_eq!(ok("+33 6 12 34 56 78"), "+33612345678");
        assert_eq!(ok("+36-20-123-4567"), "+36201234567");
        assert_eq!(ok("+386 40 123 456"), "+38640123456");
        assert_eq!(ok("+27 82 123 4567"), "+27821234567");
        assert_eq!(ok("+86 138 0013 8000"), "+8613800138000");
        assert_eq!(ok("0033 6 12 34 56 78"), "+33612345678");
        assert_eq!(ok("+33 (0)6 12 34 56 78"), "+33612345678");
    }

    #[test]
    fn a_national_number_needs_a_known_country() {
        assert_eq!(
            normalise_phone("06 12 34 56 78", None),
            Err(PhoneError::NoCountry)
        );
        assert_eq!(
            normalise_phone("06 12 34 56 78", Some("ZZ")),
            Err(PhoneError::NoCountry)
        );
        let read = |raw: &str, country: &str| normalise_phone(raw, Some(country)).unwrap();
        assert_eq!(read("06 12 34 56 78", "FR"), "+33612345678");
        assert_eq!(read("06 20 123 4567", "HU"), "+36201234567");
        assert_eq!(read("040 123 456", "SI"), "+38640123456");
        assert_eq!(read("082 123 4567", "ZA"), "+27821234567");
        assert_eq!(read("0138 0013 8000", "CN"), "+8613800138000");
    }

    #[test]
    fn text_and_wrong_lengths_are_not_phone_numbers() {
        assert_eq!(
            normalise_phone("call me", Some("FR")),
            Err(PhoneError::Invalid)
        );
        assert_eq!(normalise_phone("+33 6 12", None), Err(PhoneError::Invalid));
        assert_eq!(
            normalise_phone("+33 6 12 34 56 78 90 12 34 56 78", None),
            Err(PhoneError::Invalid)
        );
    }

    /// A store under a fresh temp dir.
    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        (dir, store)
    }

    /// A file named `name` in `dir`, holding `text`, as a file source.
    fn file_source(dir: &tempfile::TempDir, name: &str, text: &str) -> FileSource {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        FileSource::new(&path)
    }

    /// A stored contact with one name, one address and no phone, under `source`.
    fn record(source: &str, name: &str, email: &str) -> ContactRecord {
        ContactRecord {
            source: source.to_string(),
            display_name: Some(name.to_string()),
            emails: vec![email.to_string()],
            ..ContactRecord::default()
        }
    }

    fn enabled_file() -> Vec<String> {
        vec!["file".to_string()]
    }

    #[test]
    fn each_file_is_stored_under_its_own_tag_and_a_reimport_replaces_only_it() {
        let (dir, store) = store();
        let vcard = file_source(&dir, "contacts.vcf", VCARD);
        let csv = file_source(&dir, "more.csv", CSV);
        assert_eq!(import_source(&store, &vcard, Some("FR")).unwrap().stored, 4);
        assert_eq!(import_source(&store, &csv, Some("FR")).unwrap().stored, 4);
        let records = store.contacts().unwrap();
        assert_eq!(records.len(), 8);
        assert_eq!(
            records
                .iter()
                .filter(|r| r.source == "file:contacts.vcf")
                .count(),
            4
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r.source == "file:more.csv")
                .count(),
            4
        );

        // The same file again: still four, and the other file is untouched.
        import_source(&store, &vcard, Some("FR")).unwrap();
        assert_eq!(store.contacts().unwrap().len(), 8);

        // A smaller version of the same file replaces its own contacts only.
        let smaller = file_source(
            &dir,
            "contacts.vcf",
            "BEGIN:VCARD\nVERSION:3.0\nFN:Solo Person\nEMAIL:solo@example.invalid\nEND:VCARD\n",
        );
        import_source(&store, &smaller, Some("FR")).unwrap();
        let records = store.contacts().unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|r| r.source == "file:contacts.vcf")
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r.source == "file:more.csv")
                .count(),
            4
        );
    }

    #[test]
    fn a_national_phone_without_a_country_is_kept_out_and_the_person_is_kept() {
        let (dir, store) = store();
        let summary =
            import_source(&store, &file_source(&dir, "contacts.vcf", VCARD), None).unwrap();
        assert_eq!(summary.stored, 4);
        assert_eq!(summary.no_country, 1, "Camille's `06 98 76 54 32`");
        let camille = store
            .contacts()
            .unwrap()
            .into_iter()
            .find(|record| record.emails.iter().any(|e| e.starts_with("camille.")))
            .expect("Camille is kept");
        assert_eq!(camille.phones, ["+33612345678"]);
    }

    #[test]
    fn repeats_within_one_file_merge_by_address_or_number() {
        let (dir, store) = store();
        let text = "BEGIN:VCARD\nVERSION:3.0\nFN:Camille Exemple\n\
                    EMAIL:camille.exemple@example.invalid\nTEL:+33 6 12 34 56 78\nEND:VCARD\n\
                    BEGIN:VCARD\nVERSION:3.0\nFN:Camille E.\n\
                    EMAIL:camille.exemple@example.invalid\nEND:VCARD\n";
        let summary =
            import_source(&store, &file_source(&dir, "repeats.vcf", text), Some("FR")).unwrap();
        assert_eq!((summary.stored, summary.merged), (1, 1));
        assert_eq!(store.contacts().unwrap().len(), 1);
    }

    #[test]
    fn a_name_with_no_address_or_number_is_stored_once_across_reimports() {
        let (dir, store) = store();
        let file = file_source(&dir, "names.csv", "name\nPieter van der Merwe\n");
        import_source(&store, &file, None).unwrap();
        let again = import_source(&store, &file, None).unwrap();
        assert_eq!(again.stored, 1);
        assert_eq!(store.contacts().unwrap().len(), 1);
    }

    #[test]
    fn a_file_that_is_neither_vcard_nor_csv_is_refused_and_stores_nothing() {
        let (dir, store) = store();
        let file = file_source(&dir, "notes.txt", "hello world\n");
        assert!(import_source(&store, &file, None).is_err());
        assert!(store.contacts().unwrap().is_empty());
    }

    /// The CRM party count, and the CRM contacts the index mounts.
    fn crm_counts(store: &Store) -> (usize, usize) {
        let mounted = store
            .contacts()
            .unwrap()
            .iter()
            .filter(|record| record.source == aux_store::CRM_CONTACT_SOURCE)
            .count();
        (store.parties().unwrap().len(), mounted)
    }

    #[test]
    fn a_vcard_seeds_one_party_per_person_with_e164_phones() {
        let (dir, store) = store();
        let path = dir.path().join("crm-seed.vcf");
        std::fs::write(&path, CRM_SEED).unwrap();

        let text = import_file(&store, dir.path(), &path, Some("FR")).unwrap();
        assert!(
            text.contains("CRM: 3 parties created, 0 updated, 0 refused."),
            "{text}"
        );
        assert_eq!(
            crm_counts(&store),
            (3, 3),
            "the index mounts the three parties"
        );
        let parties = store.parties().unwrap();
        let mut phones: Vec<&str> = parties
            .iter()
            .flat_map(|party| party.phones.iter().map(String::as_str))
            .collect();
        phones.sort_unstable();
        assert_eq!(phones, ["+14155550137", "+33612345678", "+442079460958"]);
        assert!(parties
            .iter()
            .all(|party| party.origin == "contacts:file:crm-seed.vcf"));
    }

    #[test]
    fn importing_the_same_file_again_creates_no_second_party() {
        let (dir, store) = store();
        let path = dir.path().join("crm-seed.vcf");
        std::fs::write(&path, CRM_SEED).unwrap();
        import_file(&store, dir.path(), &path, Some("FR")).unwrap();
        let ids: Vec<i64> = store.parties().unwrap().iter().map(|p| p.id).collect();

        let text = import_file(&store, dir.path(), &path, Some("FR")).unwrap();
        assert!(
            text.contains("CRM: 0 parties created, 0 updated, 0 refused."),
            "{text}"
        );
        let again: Vec<i64> = store.parties().unwrap().iter().map(|p| p.id).collect();
        assert_eq!(ids, again);
        assert_eq!(crm_counts(&store), (3, 3));
    }

    #[test]
    fn a_national_number_with_no_country_needs_country_and_the_party_keeps_its_address() {
        let (dir, store) = store();
        let path = dir.path().join("crm-seed.vcf");
        std::fs::write(&path, CRM_SEED).unwrap();

        let text = import_file(&store, dir.path(), &path, None).unwrap();
        assert!(
            text.contains("warning: 1 contact(s) need country"),
            "{text}"
        );
        assert!(text.contains("CRM: 3 parties created"), "{text}");
        let camille = store
            .parties()
            .unwrap()
            .into_iter()
            .find(|party| party.emails.iter().any(|e| e.starts_with("camille.")))
            .expect("Camille is a party");
        assert!(
            camille.phones.is_empty(),
            "no country, so no number is kept"
        );
        assert_eq!(camille.emails, ["camille.exemple@example.invalid"]);
    }

    #[test]
    fn the_summary_names_nobody() {
        let (dir, store) = store();
        let summary =
            import_source(&store, &file_source(&dir, "contacts.vcf", VCARD), None).unwrap();
        let shown = summary.to_string();
        assert!(
            !shown.contains("Camille") && !shown.contains("camille."),
            "{shown}"
        );
        assert!(
            shown.contains("warning: 1 contact(s) need country"),
            "{shown}"
        );
    }

    #[test]
    fn clear_and_remove_leave_the_crm_rows_that_keep_its_parties_masked() {
        let (dir, store) = store();
        import_source(
            &store,
            &file_source(&dir, "contacts.vcf", VCARD),
            Some("FR"),
        )
        .unwrap();
        let party = record(
            CRM_CONTACT_SOURCE,
            "Jean Fictif",
            "jean.fictif@example.invalid",
        );
        store
            .replace_source_contacts(CRM_CONTACT_SOURCE, &[party])
            .unwrap();
        let crm_rows = || {
            store
                .contacts()
                .unwrap()
                .iter()
                .filter(|record| record.source == CRM_CONTACT_SOURCE)
                .count()
        };

        assert!(remove_one(&store, "jean.fictif@example.invalid").is_err());
        assert_eq!(
            clear_all(&store, Some(CRM_CONTACT_SOURCE), true).unwrap(),
            "No contacts to clear.\n"
        );
        assert_eq!(
            clear_all(&store, None, true).unwrap(),
            "Cleared 4 contacts.\n"
        );
        assert_eq!(crm_rows(), 1, "the party is still indexed after a clear");
    }

    #[test]
    fn the_list_counts_each_source_and_marks_the_disabled_ones() {
        let records = vec![
            record("file:a.vcf", "Camille Exemple", "camille@example.invalid"),
            record("file:b.csv", "Anna Example", "anna@example.invalid"),
        ];
        let text = list_text(&records, &enabled_file(), false);
        assert!(
            text.contains("file:a.vcf: 1 contact (1 e-mail address, 0 phone numbers)"),
            "{text}"
        );
        assert!(text.contains("file:b.csv: 1 contact"), "{text}");
        assert!(!text.contains("not enabled"), "{text}");
        assert!(text.contains("Private mode uses 2 people."), "{text}");
        assert!(
            !text.contains("Camille") && !text.contains("Anna"),
            "{text}"
        );

        let disabled = list_text(&records, &[], false);
        assert!(disabled.contains("not enabled"), "{disabled}");
        assert!(
            disabled.contains("Private mode uses 0 people."),
            "{disabled}"
        );
    }

    #[test]
    fn the_list_names_people_only_on_request() {
        let records = vec![record(
            "file:a.vcf",
            "Camille Exemple",
            "camille@example.invalid",
        )];
        assert!(list_text(&records, &enabled_file(), true).contains("  - Camille Exemple"));
    }

    #[test]
    fn an_empty_list_says_the_next_step_in_english_and_french() {
        let text = list_text(&[], &enabled_file(), false);
        assert!(text.contains("aux contacts import <file>"), "{text}");
        assert!(
            text.contains("Importez d'abord vos contacts : aux contacts import <fichier>"),
            "{text}"
        );
    }

    #[test]
    fn remove_drops_every_stored_copy_of_one_address_across_sources() {
        let (dir, store) = store();
        import_source(&store, &file_source(&dir, "a.vcf", VCARD), Some("FR")).unwrap();
        import_source(&store, &file_source(&dir, "b.csv", CSV), Some("FR")).unwrap();
        assert_eq!(store.contacts().unwrap().len(), 8);

        remove_one(&store, "camille.exemple@example.invalid").unwrap();

        let left = store.contacts().unwrap();
        assert_eq!(left.len(), 6);
        assert!(left
            .iter()
            .all(|record| !record.emails.iter().any(|e| e.starts_with("camille."))));
    }

    #[test]
    fn remove_refuses_a_name_stored_twice_and_removes_nothing() {
        let (dir, store) = store();
        let a = file_source(
            &dir,
            "a.csv",
            "name,email\nCamille Exemple,a@example.invalid\n",
        );
        let b = file_source(
            &dir,
            "b.csv",
            "name,email\nCamille Exemple,b@example.invalid\n",
        );
        import_source(&store, &a, None).unwrap();
        import_source(&store, &b, None).unwrap();
        assert!(remove_one(&store, "Camille Exemple").is_err());
        assert_eq!(store.contacts().unwrap().len(), 2);
    }

    #[test]
    fn remove_by_a_unique_name_drops_that_person() {
        let (dir, store) = store();
        import_source(&store, &file_source(&dir, "a.vcf", VCARD), Some("FR")).unwrap();
        remove_one(&store, "Kovács Anna").unwrap();
        assert_eq!(store.contacts().unwrap().len(), 3);
        assert!(remove_one(&store, "Nobody Here").is_err());
    }

    #[test]
    fn clear_one_source_keeps_the_others_and_clear_needs_yes() {
        let (dir, store) = store();
        import_source(&store, &file_source(&dir, "a.vcf", VCARD), Some("FR")).unwrap();
        import_source(&store, &file_source(&dir, "b.csv", CSV), Some("FR")).unwrap();
        assert!(clear_all(&store, None, false).is_err());
        assert_eq!(store.contacts().unwrap().len(), 8);

        clear_all(&store, Some("file:a.vcf"), true).unwrap();
        let left = store.contacts().unwrap();
        assert_eq!(left.len(), 4);
        assert!(left.iter().all(|record| record.source == "file:b.csv"));

        clear_all(&store, None, true).unwrap();
        assert!(store.contacts().unwrap().is_empty());
    }

    /// One vCard card, as text, with `lines` between BEGIN and END.
    fn card(lines: &str) -> String {
        format!("BEGIN:VCARD\nVERSION:2.1\n{lines}\nEND:VCARD\n")
    }

    #[test]
    fn quoted_printable_names_decode_for_slovenian_hungarian_and_han() {
        let text = [
            card(
                "FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Bo=C5=BEidar Ho=C5=BEi=C4=8D\n\
                  N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Ho=C5=BEi=C4=8D;Bo=C5=BEidar;;;",
            ),
            card(
                "FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Kov=C3=A1cs Anna\n\
                  N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Kov=C3=A1cs;Anna;;;",
            ),
            card(
                "FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E7=8E=8B=E5=B0=8F=E6=98=8E\n\
                  N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E7=8E=8B;=E5=B0=8F=E6=98=8E;;;",
            ),
        ]
        .concat();
        let cards = parse_vcards(&text);
        assert_eq!(cards.refused_charset + cards.encoded_fields, 0);
        let people = cards.people;
        assert_eq!(people.len(), 3);
        assert_eq!(people[0].display_name.as_deref(), Some("Božidar Hožič"));
        assert_eq!(people[0].family, ["Hožič"]);
        assert_eq!(people[0].given, ["Božidar"]);
        assert_eq!(people[1].display_name.as_deref(), Some("Kovács Anna"));
        assert_eq!(people[2].display_name.as_deref(), Some("王小明"));
        assert_eq!(people[2].family, ["王"]);
        assert_eq!(people[2].given, ["小明"]);
    }

    #[test]
    fn a_quoted_printable_soft_break_joins_the_next_line() {
        let text = "BEGIN:VCARD\r\nVERSION:2.1\r\n\
                    FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Bo=C5=BEidar Ho=C5=BEi=C4=\r\n\
                    =8D\r\nEND:VCARD\r\n";
        let people = parse_vcards(text).people;
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].display_name.as_deref(), Some("Božidar Hožič"));
    }

    #[test]
    fn latin1_and_windows_1252_charsets_decode() {
        let text = [
            card(
                "FN;CHARSET=ISO-8859-1;ENCODING=QUOTED-PRINTABLE:Gy=F6ngyi Ny=E1ri\n\
                  N;CHARSET=ISO-8859-1;ENCODING=QUOTED-PRINTABLE:Ny=E1ri;Gy=F6ngyi;;;",
            ),
            card("FN;CHARSET=WINDOWS-1252;ENCODING=QUOTED-PRINTABLE:Jean=96Marc"),
        ]
        .concat();
        let cards = parse_vcards(&text);
        assert_eq!(cards.refused_charset, 0);
        let people = cards.people;
        assert_eq!(people[0].display_name.as_deref(), Some("Gyöngyi Nyári"));
        assert_eq!(people[0].family, ["Nyári"]);
        assert_eq!(people[0].given, ["Gyöngyi"]);
        assert_eq!(people[1].display_name.as_deref(), Some("Jean–Marc"));
    }

    #[test]
    fn an_unsupported_charset_refuses_its_card_and_counts_it() {
        let text = [
            card("FN;CHARSET=SHIFT_JIS;ENCODING=QUOTED-PRINTABLE:=82=C9=82=A4"),
            card("FN:Solo Person\nEMAIL:solo@example.invalid"),
        ]
        .concat();
        let cards = parse_vcards(&text);
        assert_eq!(cards.refused_charset, 1);
        assert_eq!(cards.people.len(), 1);
        assert_eq!(cards.people[0].display_name.as_deref(), Some("Solo Person"));
    }

    #[test]
    fn a_base64_text_field_is_skipped_and_counted() {
        let text = card(
            "FN;ENCODING=BASE64:S292YWNz\n\
             N;CHARSET=UTF-8:Kovács;Anna;;;\n\
             EMAIL:anna@example.invalid",
        );
        let cards = parse_vcards(&text);
        assert_eq!(cards.encoded_fields, 1);
        let people = cards.people;
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].display_name.as_deref(), Some("Anna Kovács"));
    }

    #[test]
    fn a_plain_value_that_still_looks_encoded_is_never_stored() {
        let text = card("FN:Bo=C5=BEidar\nEMAIL:bozidar@example.invalid");
        let cards = parse_vcards(&text);
        assert_eq!(cards.encoded_fields, 1);
        let people = cards.people;
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].display_name, None);
        assert_eq!(people[0].emails, ["bozidar@example.invalid"]);
    }

    #[test]
    fn an_import_counts_refused_cards_and_encoded_fields_in_its_summary() {
        let (dir, store) = store();
        let text = [
            card("FN;CHARSET=SHIFT_JIS;ENCODING=QUOTED-PRINTABLE:=82=C9=82=A4"),
            card("FN;ENCODING=BASE64:S292YWNz\nEMAIL:anna@example.invalid"),
        ]
        .concat();
        let summary = import_source(&store, &file_source(&dir, "mixed.vcf", &text), None).unwrap();
        assert_eq!(summary.refused_charset, 1);
        assert_eq!(summary.encoded_fields, 1);
        assert_eq!(summary.stored, 1);
        let shown = summary.to_string();
        assert!(shown.contains("1 card(s) use a character set"), "{shown}");
        assert!(shown.contains("1 field(s) are base64"), "{shown}");
    }

    #[test]
    fn printable_shows_control_characters_as_escapes() {
        assert_eq!(printable("a\u{1b}[31mb\u{7}"), "a\\u{1b}[31mb\\u{7}");
        assert_eq!(printable("a\u{9b}b"), "a\\u{9b}b");
        assert_eq!(printable("Božidar 王小明"), "Božidar 王小明");
    }

    #[test]
    fn list_escapes_control_characters_in_names_and_source_tags() {
        let hostile = ContactRecord {
            source: "file:a\u{1b}.vcf".to_string(),
            display_name: Some("Eve\u{1b}[31mRed\u{7}".to_string()),
            emails: vec!["eve@example.invalid".to_string()],
            ..ContactRecord::default()
        };
        let text = list_text(&[hostile], &enabled_file(), true);
        assert!(
            text.chars().all(|c| c == '\n' || !c.is_control()),
            "{text:?}"
        );
        assert!(text.contains("Eve\\u{1b}[31mRed\\u{7}"), "{text}");
        assert!(text.contains("file:a\\u{1b}.vcf"), "{text}");
    }

    #[test]
    fn an_import_past_the_limit_stores_nothing_and_says_so_in_two_languages() {
        let (dir, store) = store();
        let text: String = (0..CONTACT_LIMIT + 1)
            .map(|n| card(&format!("FN:Person {n}")))
            .collect();
        let err = import_source(&store, &file_source(&dir, "many.vcf", &text), None).unwrap_err();
        assert!(
            err.contains("would be 20001, over the limit of 20000"),
            "{err}"
        );
        assert!(err.contains("Nothing was stored."), "{err}");
        assert!(err.contains("Rien n'a été enregistré."), "{err}");
        assert!(store.contacts().unwrap().is_empty());
    }

    #[test]
    fn the_combined_limit_counts_every_source_and_refuses_the_second_atomically() {
        // The scaled repro: a.csv fills a limit of 3, then b.csv pushes the union to 4.
        let (dir, store) = store();
        let a = file_source(
            &dir,
            "a.csv",
            "name,email\nAna Uno,ana@example.invalid\nBo Dos,bo@example.invalid\n",
        );
        import_source_with_limit(&store, &a, None, 3).unwrap();
        let b = file_source(
            &dir,
            "b.csv",
            "name,email\nCy Tres,cy@example.invalid\nDi Cuatro,di@example.invalid\n",
        );
        let err = import_source_with_limit(&store, &b, None, 3).unwrap_err();
        assert!(err.contains("would be 4, over the limit of 3"), "{err}");
        let records = store.contacts().unwrap();
        assert_eq!(records.len(), 2, "b stored nothing");
        assert!(records.iter().all(|record| record.source == "file:a.csv"));
    }

    #[test]
    fn a_reimport_of_one_source_counts_its_replacement_not_its_old_rows() {
        let (dir, store) = store();
        let a = file_source(&dir, "a.csv", "name,email\nAna Uno,ana@example.invalid\nBo Dos,bo@example.invalid\nCy Tres,cy@example.invalid\n");
        import_source_with_limit(&store, &a, None, 3).unwrap();
        // The same file again replaces its three rows: still within the limit.
        let again = import_source_with_limit(&store, &a, None, 3).unwrap();
        assert_eq!(again.stored, 3);
        assert_eq!(store.contacts().unwrap().len(), 3);
        // A second source of one person would make four.
        let b = file_source(&dir, "b.csv", "name,email\nDi Cuatro,di@example.invalid\n");
        assert!(import_source_with_limit(&store, &b, None, 3)
            .unwrap_err()
            .contains("would be 4"));
    }

    /// The exact repro at the kernel's cap: 20,000 in a.vcf, then 15,001 in b.vcf.
    #[test]
    #[ignore = "perf: 35,001 cards at full scale"]
    fn the_exact_repro_at_full_scale_is_refused_whole() {
        let (dir, store) = store();
        let a: String = (0..CONTACT_LIMIT)
            .map(|n| card(&format!("FN:Person {n}")))
            .collect();
        import_source(&store, &file_source(&dir, "a.vcf", &a), None).unwrap();
        let mut b: String = (0..15_000)
            .map(|n| card(&format!("FN:Other {n}")))
            .collect();
        b.push_str(&card("FN:Dragica Unionlast"));
        let err = import_source(&store, &file_source(&dir, "b.vcf", &b), None).unwrap_err();
        assert!(err.contains("would be 35001"), "{err}");
        assert_eq!(store.contacts().unwrap().len(), CONTACT_LIMIT);
    }

    #[test]
    fn a_quoted_printable_name_keeps_no_control_characters() {
        // ESC, CR and LF decode from the quoted-printable value; none may be stored.
        let text = card("FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=1BR=C3=B3za\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:R=C3=B3za;=1BMaria;;;\nNICKNAME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Ana=0D=0ABogdan");
        let people = parse_vcards(&text).people;
        assert_eq!(people[0].display_name.as_deref(), Some("Róza"));
        assert_eq!(people[0].family, ["Róza"]);
        assert_eq!(people[0].given, ["Maria"]);
        assert!(people[0]
            .nicknames
            .iter()
            .all(|nick| nick.chars().all(|c| !c.is_control())));
    }

    #[test]
    fn a_trailing_soft_break_before_end_does_not_swallow_the_card() {
        let text = "BEGIN:VCARD\nVERSION:2.1\nFN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Bo=C5=BEidar=\nEND:VCARD\nBEGIN:VCARD\nVERSION:3.0\nFN:Solo Person\nEND:VCARD\n";
        let cards = parse_vcards(text);
        assert_eq!(cards.people.len(), 2, "both cards close");
        assert_eq!(cards.encoded_fields, 1, "the dangling escape is counted");
        assert_eq!(cards.people[0].display_name, None);
        assert_eq!(cards.people[1].display_name.as_deref(), Some("Solo Person"));
    }

    // CSV-CARD-2: a CSV row fills the whole client card. Fictional data only.
    const CARD_CSV: &str = "Company,Name,Email,Street,Postcode,City,Country,VAT,Tags,Notes,Sector\n\
        Atelier Fictif,,contact@atelier-fictif.test,1 rue Imaginaire,75000,Paris,France,FR00999999999,client; design,Pays à 30 jours,Graphisme\n\
        Studio Exemple,Camille Exemple,camille@studio-exemple.test,,,,,,,,\n";

    fn card_file(dir: &tempfile::TempDir, text: &str) -> PathBuf {
        let path = dir.path().join("clients.csv");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn party_named<'a>(parties: &'a [aux_store::Party], name: &str) -> &'a aux_store::Party {
        parties.iter().find(|p| p.display_name == name).unwrap()
    }

    #[test]
    fn a_company_row_fills_one_company_card() {
        let (dir, store) = store();
        import_file(&store, dir.path(), &card_file(&dir, CARD_CSV), None).unwrap();
        let parties = store.parties().unwrap();
        assert_eq!(parties.len(), 2);
        let company = party_named(&parties, "Atelier Fictif");
        assert_eq!(company.kind, aux_store::PartyKind::Company);
        assert_eq!(
            company.addresses,
            ["1 rue Imaginaire, 75000, Paris, France"]
        );
        assert_eq!(company.tags, ["client", "design"]);
        assert_eq!(
            company.notes,
            "Pays à 30 jours\nVAT: FR00999999999\nSector: Graphisme"
        );
    }

    #[test]
    fn a_person_with_a_company_is_one_person_whose_notes_hold_it() {
        let (dir, store) = store();
        import_file(&store, dir.path(), &card_file(&dir, CARD_CSV), None).unwrap();
        let parties = store.parties().unwrap();
        let person = party_named(&parties, "Camille Exemple");
        assert_eq!(person.kind, aux_store::PartyKind::Person);
        assert_eq!(person.notes, "Company: Studio Exemple");
        assert!(!parties.iter().any(|p| p.display_name == "Studio Exemple"));
    }

    #[test]
    fn a_dry_run_writes_nothing_and_prints_the_plan() {
        let (dir, store) = store();
        let text = dry_run(&store, &card_file(&dir, CARD_CSV), None).unwrap();
        assert!(text.contains("Would create 2 parties, merge 0"), "{text}");
        assert!(text.contains("Conflicts: 0"), "{text}");
        assert!(text.contains("Company → company"), "{text}");
        assert!(store.parties().unwrap().is_empty());
        assert!(store.contacts().unwrap().is_empty());
    }

    #[test]
    fn a_reimport_creates_no_party_and_repeats_no_note_or_tag() {
        let (dir, store) = store();
        let path = card_file(&dir, CARD_CSV);
        import_file(&store, dir.path(), &path, None).unwrap();
        let before = store.parties().unwrap();
        let text = import_file(&store, dir.path(), &path, None).unwrap();
        assert!(text.contains("CRM: 0 parties created"), "{text}");
        assert_eq!(store.parties().unwrap(), before);
    }

    #[test]
    fn a_conflicting_address_keeps_the_old_one_and_is_reported() {
        let (dir, store) = store();
        let path = card_file(&dir, CARD_CSV);
        import_file(&store, dir.path(), &path, None).unwrap();
        let moved = CARD_CSV.replace("1 rue Imaginaire", "9 avenue Inventée");
        std::fs::write(&path, &moved).unwrap();
        let plan = dry_run(&store, &path, None).unwrap();
        assert!(plan.contains("Conflicts: 1"), "{plan}");
        let text = import_file(&store, dir.path(), &path, None).unwrap();
        assert!(text.contains("warning: 1 conflict(s)"), "{text}");
        let parties = store.parties().unwrap();
        let company = party_named(&parties, "Atelier Fictif");
        assert_eq!(
            company.addresses,
            ["1 rue Imaginaire, 75000, Paris, France"]
        );
    }
}
