//! The owner's contacts, as the privacy gate and the skill recipient policy see them.
//!
//! One [`ContactIndex`] feeds both consumers: [`names_dictionary`] compiles the
//! names a gate matches (since 2026-10-19 a private gate drops those matches and
//! hides no name, and the local name model is no longer mounted), and the same index is the
//! `known-contacts` directory of a skill run. A session reads the index once, at
//! start, so a session never mixes two versions of the contacts.
//!
//! The contacts come from the encrypted store. Each source (`file`, `crm`; Apple
//! planned) stores its contacts under its own tag, and the index is built from
//! the union of the sources `[contacts] sources` enables. The CRM is enabled by
//! default: it has no contacts until a party exists, and every party write
//! refreshes its source. With none stored, the names dictionary is empty: a
//! private gate still tokenises every pattern value and issues the text marked
//! names-not-checked, and a `known-contacts` skill refuses every recipient. It never fails open: a config that names an
//! unknown source, or does not parse, mounts nothing. E-mail addresses and phone
//! numbers need no contact list: the deterministic recognisers mask them in
//! every mode.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aux_store::ContactRecord;
use kernel_privacy::known_names::NameDictionaryError;
use kernel_privacy::{ContactIndex, NameDictionary, PersonDraft};

/// The owner's contacts, shared by the sessions and the skill runs of a process.
pub type Contacts = Arc<ContactIndex>;

/// The next step when no contact is stored, in English and French. A private
/// refusal for lack of contacts should carry it.
pub const NO_CONTACTS_HINT: &str = "Import your contacts first: aux contacts import <file> / \
     Importez d'abord vos contacts : aux contacts import <fichier>";

/// The source kinds this build knows. `[contacts] sources` names them.
pub const KNOWN_KINDS: &[&str] = &["file", "crm"];

/// A place the owner's contacts come from. Each source stores its contacts under
/// its own tag, so an import replaces only the contacts of that source.
pub trait ContactSource {
    /// The kind, the name `[contacts] sources` lists it under (e.g. `file`).
    fn kind(&self) -> &'static str;
    /// The tag each contact is stored under (e.g. `file:contacts.vcf`).
    fn name(&self) -> String;
    /// The people this source holds. Phones are as written: the importer
    /// normalises them to E.164.
    fn fetch(&self) -> Result<Fetched, String>;
}

/// What a source fetched: its contacts, and what it refused to read.
#[derive(Debug, Default)]
pub struct Fetched {
    /// The contacts, each under the source's tag.
    pub contacts: Vec<ContactRecord>,
    /// Cards or fields the source could not read, and did not import.
    pub refusals: Refusals,
}

/// What a source refused, counted; never the values.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Refusals {
    /// Cards in a character set this build does not read.
    pub charset_cards: usize,
    /// Fields that are base64, or quoted-printable that does not decode.
    pub encoded_fields: usize,
    /// vCard `TZ:` values that are not IANA names: no zone was kept.
    pub time_zone_ignored: usize,
}

/// The kind of a stored source tag: the part before the first `:`.
pub fn kind_of(tag: &str) -> &str {
    tag.split(':').next().unwrap_or(tag)
}

/// The `[contacts]` table of config.toml. Other tables are ignored here.
#[derive(serde::Deserialize)]
struct ContactsConfig {
    contacts: Option<ContactsSection>,
}

#[derive(serde::Deserialize)]
struct ContactsSection {
    sources: Option<Vec<String>>,
}

/// The source kinds `home`'s config enables, from `[contacts] sources`. No
/// config, or no `sources` key, enables `file` and `crm` (the CRM source is
/// empty until a party exists, so enabling it costs nothing). The `crm` source
/// is always added, whatever the config says: a party's names must stay masked,
/// so an explicit `sources = ["file"]` cannot turn the CRM off. A config that
/// does not parse, or that names an unknown kind, is an error: the caller mounts
/// nothing. The error never quotes the config's contents.
pub fn enabled_kinds(home: &Path) -> Result<Vec<String>, String> {
    let default = || vec!["file".to_string(), "crm".to_string()];
    let text = match std::fs::read_to_string(kernel_core::config_path(home)) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(default()),
        Err(_) => return Err("config.toml cannot be read".to_string()),
    };
    let config: ContactsConfig = toml::from_str(&text)
        .map_err(|_| "config.toml does not parse: [contacts] cannot be read".to_string())?;
    let Some(sources) = config.contacts.and_then(|section| section.sources) else {
        return Ok(default());
    };
    if let Some(unknown) = sources
        .iter()
        .find(|kind| !KNOWN_KINDS.contains(&kind.as_str()))
    {
        // A key pasted as a source is never quoted.
        let unknown = if is_secret_shaped(unknown) {
            "<source>".to_string()
        } else {
            format!("`{unknown}`")
        };
        return Err(format!(
            "unknown contact source {unknown} in [contacts] sources; known sources: {}",
            KNOWN_KINDS.join(", ")
        ));
    }
    let mut kinds = sources;
    if !kinds.iter().any(|kind| kind == "crm") {
        kinds.push("crm".to_string());
    }
    Ok(kinds)
}

/// Whether the kernel's secret scrubber would touch `text`: such a value is
/// never quoted in an error.
///
/// A percent-decoded copy counts too: `%73k-…` and `%2573k-…` are the same
/// key, so a decoded copy that the scrubber would touch hides the value just
/// the same — and so is every deeper layer (`%25252573k-…`). Bytes that are
/// not valid UTF-8 cannot be shown safely, so they count as secret-shaped
/// too.
fn is_secret_shaped(text: &str) -> bool {
    if kernel_broker::redact_secrets(text) != text {
        return true;
    }
    // The scrubber has read the value once already: that read is charged to
    // the budget too.
    decoded_copy_is_secret_shaped(text, text.len(), |copy| {
        kernel_broker::redact_secrets(copy) != copy
    })
}

/// How many percent-escape layers are peeled before a value is taken at face
/// value: `%73k-…`, `%2573k-…` and `%252573k-…` are one key.
const MAX_DECODE_ROUNDS: usize = 16;

/// The work budget of one value: every byte the scrubber or the decoder
/// reads is charged, so the whole check stays within 16 × the length of the
/// input and never exceeds 4 MiB.
const MAX_REDACT_WORK: usize = 4 * 1024 * 1024;

/// Whether a percent-decoded copy of `text` reads as a credential.
///
/// The decoder peels one escape layer per round and `secret_shaped` is called
/// with every copy as it is produced: only the current copy is ever kept, so
/// a value that nests its escapes deeply cannot pile up into a pile of
/// copies.
///
/// The work is bounded twice over: at most [`MAX_DECODE_ROUNDS`] rounds, and
/// at most [`MAX_REDACT_WORK`] bytes of work across the whole check — every
/// byte the scrubber and the decoder read is charged, so the bytes decoded
/// stay within 16 × the length of the input and the total never exceeds
/// 4 MiB. A value that is still changing when the budget or the round cap
/// runs out cannot be shown safely: it counts as secret-shaped.
fn decoded_copy_is_secret_shaped(
    text: &str,
    mut spent: usize,
    secret_shaped: impl Fn(&str) -> bool,
) -> bool {
    let budget = text.len().saturating_mul(16).min(MAX_REDACT_WORK);
    let mut current = text.to_string();
    for _ in 0..MAX_DECODE_ROUNDS {
        // A round that does not fit the budget is never started.
        if spent.saturating_add(current.len()) > budget {
            return true;
        }
        spent = spent.saturating_add(current.len());
        let next = match String::from_utf8(decode_once(&current)) {
            Ok(next) => next,
            // Bytes that are not valid UTF-8 cannot be shown safely.
            Err(_) => return true,
        };
        if next == current {
            // The text stopped changing: there is no deeper copy to read.
            return false;
        }
        // The scrubber reads the copy too: its bytes are charged as well.
        if spent.saturating_add(next.len()) > budget {
            return true;
        }
        spent = spent.saturating_add(next.len());
        if secret_shaped(&next) {
            return true;
        }
        current = next;
    }
    // The round cap ran out while the text was still changing.
    true
}

/// One percent-decoding round: the bytes of `text` with every valid `%XX`
/// escape replaced by its byte. A malformed escape is kept as written.
fn decode_once(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(byte) = bytes.get(index + 1..index + 3).and_then(hex_pair) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The byte of two hex digits.
fn hex_pair(pair: &[u8]) -> Option<u8> {
    match pair {
        [high, low] => Some((hex_value(*high)? << 4) | hex_value(*low)?),
        _ => None,
    }
}

/// The value of one hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The most contacts the union of the enabled sources may hold: the kernel's cap on a
/// contacts index. Past it, nothing is masked silently.
pub const CONTACT_LIMIT: usize = kernel_privacy::SeedLimits::DEFAULT.max_contacts;

/// The caps of every index the contacts are mounted in: the contact limit, and a pattern
/// budget the full limit never reaches (at most 64 name variants and 32 values per list,
/// per person). The kernel's default budget is 200,000 patterns, which left people out
/// silently at about 18,000 with ordinary name forms.
pub const MOUNT_LIMITS: kernel_privacy::SeedLimits = kernel_privacy::SeedLimits {
    max_patterns: CONTACT_LIMIT * 160,
    ..kernel_privacy::SeedLimits::DEFAULT
};

/// An empty index with the mount's caps.
pub fn new_contacts_index() -> ContactIndex {
    ContactIndex::with_limits(MOUNT_LIMITS)
}

/// The union of the enabled sources is over the limit, so the mount refuses. Counts
/// only: never a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverLimit {
    /// How many people the union holds, the ones the cap left out included.
    pub people: usize,
    /// The limit the union passed.
    pub limit: usize,
}

impl std::fmt::Display for OverLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the contacts of the enabled sources are over the limit of {} ({} people): \
             Private mode is refused until they are reduced, for example \
             `aux contacts clear --source <tag> --yes`. / \
             les contacts des sources activées dépassent la limite de {} ({} personnes) : \
             le mode privé est refusé jusqu'à ce qu'ils soient réduits, par exemple \
             `aux contacts clear --source <tag> --yes`.",
            self.limit, self.people, self.limit, self.people
        )
    }
}

/// The owner's contacts, read from the store of the process's verified home
/// (`aux contacts import` fills it). A process with no registered home, or with
/// no stored contacts, gets an empty index.
pub fn owner_contacts() -> Contacts {
    match kernel_core::verified_home().and_then(|home| home.real_path()) {
        Ok(home) => owner_contacts_at(&home),
        Err(_) => Arc::new(ContactIndex::new()),
    }
}

/// The contacts of `home` from the enabled sources, mounted as an index. A store or
/// config that cannot be read gives an empty index, so the gate refuses rather than
/// fail open. A union past the limit is refused by [`owner_contacts_at_limit`].
pub fn owner_contacts_at(home: &Path) -> Contacts {
    owner_contacts_at_limit(home, CONTACT_LIMIT).unwrap_or_else(|_| empty_contacts())
}

/// The union of the enabled sources of `home`, mounted as an index, or refused with
/// [`OverLimit`] when it passes `limit`: a subset is never masked. A store or config
/// that cannot be read gives an empty index (the gate refuses). The index is rebuilt
/// only when the store's contacts version, the enabled kinds or the limit change; the
/// version is read on its own, so a turn does not decode the contacts again.
pub fn owner_contacts_at_limit(home: &Path, limit: usize) -> Result<Contacts, OverLimit> {
    // (store path, contacts version, enabled kinds, limit) → the mount or its refusal.
    type Cached = (
        PathBuf,
        i64,
        Vec<String>,
        usize,
        Result<Contacts, OverLimit>,
    );
    static CACHE: Mutex<Vec<Cached>> = Mutex::new(Vec::new());
    let Ok(kinds) = enabled_kinds(home) else {
        return Ok(empty_contacts());
    };
    let store = kernel_core::store_path(home);
    let Ok(version) = aux_store::contacts_version_at(&store) else {
        return Ok(empty_contacts());
    };
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let hit = cache
        .iter()
        .find(|(path, cached_version, enabled, cached_limit, _)| {
            *path == store
                && *cached_version == version
                && *enabled == kinds
                && *cached_limit == limit
        });
    if let Some((_, _, _, _, cached)) = hit {
        return cached.clone();
    }
    let Ok(snapshot) = aux_store::contacts_snapshot_at(&store) else {
        return Ok(empty_contacts());
    };
    let records: Vec<ContactRecord> = snapshot
        .records
        .into_iter()
        .filter(|record| {
            kinds
                .iter()
                .any(|kind| kind.as_str() == kind_of(&record.source))
        })
        .collect();
    let (index, dropped) = contacts_index_report(&records);
    let people = index.len() + dropped;
    if dropped > 0 || index.len() >= limit {
        // A count only: the daemon never logs a name, an address or a number.
        tracing::warn!(
            limit,
            people,
            not_mounted = dropped,
            "the contacts of the enabled sources reached the limit"
        );
    }
    let result = if dropped > 0 || index.len() > limit {
        Err(OverLimit { people, limit })
    } else {
        Ok(Arc::new(index))
    };
    cache.retain(|(path, _, _, cached_limit, _)| !(*path == store && *cached_limit == limit));
    cache.push((store, snapshot.version, kinds, limit, result.clone()));
    result
}

/// An empty index: no names, so a private gate refuses rather than fail open.
pub fn empty_contacts() -> Contacts {
    Arc::new(ContactIndex::new())
}

/// The names dictionary of `contacts`, built once per contacts index. The index is
/// replaced exactly when the contacts generation changes (see
/// [`owner_contacts_at_limit`]), and a cached entry holds its index, so an identity is
/// never reused while cached. The two most recent are kept.
pub fn names_for(contacts: &Contacts) -> Result<Arc<NameDictionary>, NameDictionaryError> {
    static CACHE: Mutex<Vec<(Contacts, Arc<NameDictionary>)>> = Mutex::new(Vec::new());
    let hit = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|(index, _)| Arc::ptr_eq(index, contacts))
        .map(|(_, names)| Arc::clone(names));
    if let Some(names) = hit {
        return Ok(names);
    }
    let names = names_dictionary(contacts)?;
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.push((Arc::clone(contacts), Arc::clone(&names)));
    if cache.len() > 2 {
        cache.remove(0);
    }
    Ok(names)
}

/// The index of `records`, and how many the kernel refused at its limit: the count is
/// the number of contacts left out, never their values.
pub fn contacts_index_report(records: &[ContactRecord]) -> (ContactIndex, usize) {
    let mut index = new_contacts_index();
    let mut dropped = 0;
    for record in records {
        let refused_before = index.refused();
        if index.add_person(person_draft(record)).is_none() && index.refused() > refused_before {
            dropped += 1;
        }
    }
    (index, dropped)
}

/// An index of `records`: the same people, merged the way the kernel merges them
/// (one e-mail address or one phone number is one person).
pub fn contacts_index(records: &[ContactRecord]) -> ContactIndex {
    contacts_index_report(records).0
}

/// The kernel's draft for one contact. The kernel takes no draft without an
/// address, a number, or a given, family or nickname name, so a contact whose
/// only name is its display name keeps that name as a known form. The display
/// name is masked either way.
pub fn person_draft(record: &ContactRecord) -> PersonDraft {
    let bare_name =
        record.given.is_empty() && record.family.is_empty() && record.nicknames.is_empty();
    let nicknames = if bare_name {
        record.display_name.iter().cloned().collect()
    } else {
        record.nicknames.clone()
    };
    PersonDraft {
        display_name: record.display_name.clone().map(Into::into),
        given: record.given.iter().cloned().map(Into::into).collect(),
        family: record.family.iter().cloned().map(Into::into).collect(),
        nicknames: nicknames.into_iter().map(Into::into).collect(),
        emails: record.emails.iter().cloned().map(Into::into).collect(),
        phones: record.phones.iter().cloned().map(Into::into).collect(),
        ibans: Vec::new(),
    }
}

/// The stored records of `index`, in the form the store keeps them. A display
/// name kept as a nickname (see [`person_draft`]) is not written back as one.
pub fn records_of(index: &ContactIndex) -> Vec<ContactRecord> {
    fn text<T: Deref<Target = String>>(value: &T) -> String {
        value.as_str().to_string()
    }
    index
        .people()
        .map(|person| {
            let display_name = person.display_name.as_ref().map(text);
            ContactRecord {
                source: String::new(),
                nicknames: person
                    .nicknames
                    .iter()
                    .map(text)
                    .filter(|nick| Some(nick) != display_name.as_ref())
                    .collect(),
                display_name,
                given: person.given.iter().map(text).collect(),
                family: person.family.iter().map(text).collect(),
                emails: person.emails.iter().map(text).collect(),
                phones: person.phones.iter().map(text).collect(),
                // The kernel index masks names, not zones: the importer keeps
                // the zone beside the index, and the CRM store carries it.
                time_zone: None,
            }
        })
        .collect()
}

/// The names dictionary for `contacts`: each person's display name, their given
/// and family names together, and each nickname. The kernel compiles every
/// surface form of these (either order, initials, possessives), so a bare
/// given name is not added on its own.
pub fn names_dictionary(
    contacts: &ContactIndex,
) -> Result<Arc<NameDictionary>, NameDictionaryError> {
    let mut names: Vec<String> = Vec::new();
    for person in contacts.people() {
        if let Some(display) = &person.display_name {
            names.push(display.as_str().to_string());
        }
        if !person.given.is_empty() && !person.family.is_empty() {
            let full: Vec<&str> = person
                .given
                .iter()
                .chain(person.family.iter())
                .map(|part| part.as_str())
                .collect();
            names.push(full.join(" "));
        }
        names.extend(
            person
                .nicknames
                .iter()
                .map(|nick| nick.as_str().to_string()),
        );
    }
    Ok(Arc::new(NameDictionary::new(names)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::privacy::{admit_call, Destination, PathId, PrivacyMode};
    use kernel_privacy::safetext::Gate;
    use kernel_privacy::safetext::{Detector, StandardDetector};

    /// A private grant for local display: C9 is the covered row private mode
    /// tokenises on.
    fn private_grant() -> kernel_core::privacy::Grant {
        admit_call(PathId::C9, PrivacyMode::Private, Destination::LocalDisplay)
            .expect("C9 is covered in private mode")
    }

    #[test]
    fn a_known_contact_name_passes_in_private_and_its_address_is_masked() {
        // NAMES-OFF (owner, 2026-10-19): a private gate hides no name.
        let mut contacts = ContactIndex::new();
        contacts.add_from_header("Camille Exemple", "camille.exemple@example.invalid");
        let names = names_dictionary(&contacts).unwrap();
        assert!(!names.is_empty());

        let mut gate = Gate::for_grant_with_dictionary(&private_grant(), [7u8; 32], names);
        let (text, _) = gate
            .text("Dis bonjour à Camille Exemple, camille.exemple@example.invalid.")
            .unwrap();
        let text = text.as_str();
        assert!(
            text.starts_with("Dis bonjour à Camille Exemple, ⟦EMAIL_"),
            "{text}"
        );
    }

    #[test]
    fn no_contacts_leave_a_private_gate_names_unchecked() {
        let names = names_dictionary(&owner_contacts()).unwrap();
        assert!(names.is_empty());

        // No refusal: the text is issued, names not checked, the mail masked.
        let mut gate = Gate::for_grant_with_dictionary(&private_grant(), [7u8; 32], names);
        let (safe, _) = gate
            .text("Dis bonjour à Camille Exemple, camille@exemple.fr.")
            .unwrap();
        assert!(!safe.names_checked());
        assert!(
            !safe.as_str().contains("camille@exemple.fr"),
            "{}",
            safe.as_str()
        );
    }

    /// A home under a fresh temp dir, with `records` stored under the file source.
    fn stored(records: &[ContactRecord]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let store = aux_store::Store::open(&home.join("store.db")).unwrap();
        store
            .replace_source_contacts("file:contacts.vcf", records)
            .unwrap();
        drop(store);
        (dir, home)
    }

    /// Write `text` as the home's config.toml.
    fn write_config(home: &Path, text: &str) {
        std::fs::write(kernel_core::config_path(home), text).unwrap();
    }

    fn camille_record() -> ContactRecord {
        ContactRecord {
            source: String::new(),
            display_name: Some("Camille Exemple".to_string()),
            given: vec!["Camille".to_string()],
            family: vec!["Exemple".to_string()],
            nicknames: Vec::new(),
            emails: vec!["camille.exemple@example.invalid".to_string()],
            phones: vec!["+33612345678".to_string()],
            time_zone: None,
        }
    }

    #[test]
    fn stored_contacts_are_mounted_into_the_private_gate() {
        let (_dir, home) = stored(&[camille_record()]);
        let contacts = owner_contacts_at(&home);
        assert_eq!(contacts.len(), 1);

        let names = names_dictionary(&contacts).unwrap();
        assert!(masks(&names, "Camille Exemple"));
    }

    #[test]
    fn a_contact_stored_after_an_earlier_read_is_seen_by_the_next_read() {
        let (_dir, home) = stored(&[]);
        assert!(owner_contacts_at(&home).is_empty());

        aux_store::Store::open(&home.join("store.db"))
            .unwrap()
            .replace_source_contacts("file:contacts.vcf", &[camille_record()])
            .unwrap();
        assert_eq!(owner_contacts_at(&home).len(), 1);
    }

    #[test]
    fn a_contact_removed_from_the_store_is_gone_from_the_next_read() {
        let (_dir, home) = stored(&[camille_record()]);
        assert_eq!(owner_contacts_at(&home).len(), 1);

        aux_store::Store::open(&home.join("store.db"))
            .unwrap()
            .replace_source_contacts("file:contacts.vcf", &[])
            .unwrap();
        assert!(owner_contacts_at(&home).is_empty());
    }

    #[test]
    fn an_unreadable_store_gives_no_contacts_and_never_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("store.db"), b"not a database, only bytes").unwrap();
        assert!(owner_contacts_at(dir.path()).is_empty());
    }

    #[test]
    fn no_config_enables_the_file_and_crm_sources() {
        let (_dir, home) = stored(&[camille_record()]);
        assert_eq!(
            enabled_kinds(&home),
            Ok(vec!["file".to_string(), "crm".to_string()])
        );
        assert_eq!(owner_contacts_at(&home).len(), 1);
    }

    #[test]
    fn a_crm_party_is_mounted_without_any_config() {
        // The CRM source is on by default: a party written under it reaches the
        // index with no `[contacts] sources` line.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let store = aux_store::Store::open(&home.join("store.db")).unwrap();
        store
            .replace_source_contacts(
                "crm",
                &[ContactRecord {
                    source: "crm".to_string(),
                    display_name: Some("Camille Exemple".to_string()),
                    nicknames: vec!["Camille".to_string()],
                    emails: vec!["camille.exemple@example.invalid".to_string()],
                    ..ContactRecord::default()
                }],
            )
            .unwrap();
        drop(store);

        let contacts = owner_contacts_at(&home);
        assert_eq!(contacts.len(), 1);
        let names = names_dictionary(&contacts).unwrap();
        assert!(masks(&names, "Camille"));
    }

    #[test]
    fn an_explicit_source_list_cannot_turn_the_crm_off() {
        // `sources = ["file"]` still mounts `crm`: a party's names must stay
        // masked even when the owner edits the contacts sources.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write_config(&home, "[contacts]\nsources = [\"file\"]\n");
        let store = aux_store::Store::open(&home.join("store.db")).unwrap();
        store
            .replace_source_contacts(
                "crm",
                &[ContactRecord {
                    source: "crm".to_string(),
                    display_name: Some("Camille Exemple".to_string()),
                    nicknames: vec!["Camille".to_string()],
                    emails: vec!["camille.exemple@example.invalid".to_string()],
                    ..ContactRecord::default()
                }],
            )
            .unwrap();
        drop(store);

        assert_eq!(
            enabled_kinds(&home),
            Ok(vec!["file".to_string(), "crm".to_string()])
        );
        let contacts = owner_contacts_at(&home);
        assert_eq!(contacts.len(), 1);
        assert!(masks(&names_dictionary(&contacts).unwrap(), "Camille"));
    }

    #[test]
    fn an_empty_source_list_mounts_nothing() {
        let (_dir, home) = stored(&[camille_record()]);
        write_config(&home, "[contacts]\nsources = []\n");
        assert!(owner_contacts_at(&home).is_empty());
    }

    #[test]
    fn an_unknown_source_name_fails_closed_and_is_named() {
        let (_dir, home) = stored(&[camille_record()]);
        write_config(&home, "[contacts]\nsources = [\"file\", \"apple\"]\n");
        assert!(owner_contacts_at(&home).is_empty());
        let error = enabled_kinds(&home).unwrap_err();
        assert!(error.contains("`apple`"), "{error}");
        assert!(error.contains("file"), "{error}");
        // CONFIG-ERR-ECHO-2: a key pasted as a source is never quoted.
        write_config(&home, "[contacts]\nsources = [\"sk-proj-CANARY-7f3k9q\"]\n");
        let error = enabled_kinds(&home).unwrap_err();
        assert!(!error.contains("CANARY"), "{error}");
        assert!(error.contains("unknown contact source <source>"), "{error}");
        // CONFIG-ERR-ECHO-2 (review): a percent-encoded key is the same key,
        // encoded once, twice, or in another case.
        for canary in [
            "%73k-proj-CANARY-7f3k9q",
            "%2573k-proj-CANARY-7f3k9q",
            "%53K-PROJ-CANARY-7f3k9q",
        ] {
            write_config(&home, &format!("[contacts]\nsources = [\"{canary}\"]\n"));
            let error = enabled_kinds(&home).unwrap_err();
            assert!(!error.contains("CANARY"), "{error}");
            assert!(error.contains("unknown contact source <source>"), "{error}");
        }
    }

    #[test]
    fn a_contact_source_hidden_however_many_times_it_is_encoded_never_shows() {
        // CONFIG-ECHO-DECODE-LOOP: `%25252573k-…` is the same key as `sk-…`,
        // four escape layers deep, and `%252525252573k-…` six layers deep. The
        // decoder peels every layer, so neither reaches the error.
        let (_dir, home) = stored(&[camille_record()]);
        for canary in [
            "%25252573k-proj-CANARY-7f3k9q",
            "%252525252573k-proj-CANARY-7f3k9q",
        ] {
            write_config(&home, &format!("[contacts]\nsources = [\"{canary}\"]\n"));
            let error = enabled_kinds(&home).unwrap_err();
            assert!(!error.contains("CANARY"), "{error}");
            assert!(error.contains("unknown contact source <source>"), "{error}");
        }
    }

    #[test]
    fn a_megabyte_of_nested_escapes_is_hidden_and_the_work_stays_bounded() {
        // CONFIG-ECHO-DECODE-LOOP (review): a value that nests its escapes
        // deeply must not make the decoder work without bound. The decoder
        // stops at its budget while the text is still changing, so the source
        // is hidden — and it stops fast.
        let (_dir, home) = stored(&[camille_record()]);
        let canary = format!("%25{}73k-proj-CANARY-7f3k9q", "25".repeat(98));
        let source = format!("{canary}{}", "x".repeat(1_000_000 - canary.len()));
        write_config(&home, &format!("[contacts]\nsources = [\"{source}\"]\n"));
        let started = std::time::Instant::now();
        let error = enabled_kinds(&home).unwrap_err();
        let elapsed = started.elapsed();
        assert!(!error.contains("CANARY"), "{error}");
        assert!(error.contains("unknown contact source <source>"), "{error}");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the decoder took {elapsed:?} on a megabyte"
        );
    }

    #[test]
    fn a_config_that_does_not_parse_fails_closed() {
        let (_dir, home) = stored(&[camille_record()]);
        write_config(&home, "[contacts\nsources = ");
        assert!(owner_contacts_at(&home).is_empty());
        assert!(enabled_kinds(&home).is_err());
    }

    #[test]
    fn two_sources_mount_as_one_union_with_one_person_per_address() {
        let (_dir, home) = stored(&[camille_record()]);
        let mut same_person = camille_record();
        same_person.display_name = Some("C. Exemple".to_string());
        aux_store::Store::open(&home.join("store.db"))
            .unwrap()
            .replace_source_contacts("file:other.csv", &[same_person])
            .unwrap();
        assert_eq!(owner_contacts_at(&home).len(), 1);
        assert_eq!(
            aux_store::Store::open(&home.join("store.db"))
                .unwrap()
                .contacts()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn records_round_trip_through_the_index() {
        let index = contacts_index(&[camille_record()]);
        assert_eq!(records_of(&index), vec![camille_record()]);
    }

    #[test]
    fn a_contact_with_only_a_display_name_is_mounted() {
        // The kernel takes no draft without a given, family or nickname, so a
        // name-only contact must still reach the dictionary.
        let record = ContactRecord {
            display_name: Some("Pieter van der Merwe".to_string()),
            ..ContactRecord::default()
        };
        let index = contacts_index(std::slice::from_ref(&record));
        assert_eq!(index.len(), 1);
        assert_eq!(records_of(&index), vec![record]);
        assert!(!names_dictionary(&index).unwrap().is_empty());
    }

    #[test]
    fn one_phone_number_is_one_person_across_two_records() {
        let mut other = camille_record();
        other.display_name = Some("C. Exemple".to_string());
        other.emails.clear();
        let index = contacts_index(&[camille_record(), other]);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn a_union_over_the_limit_reports_how_many_were_not_mounted() {
        let limit = kernel_privacy::SeedLimits::DEFAULT.max_contacts;
        let records: Vec<ContactRecord> = (0..=limit)
            .map(|n| ContactRecord {
                source: "file:many.vcf".to_string(),
                display_name: Some(format!("Person {n}")),
                ..ContactRecord::default()
            })
            .collect();
        let (index, dropped) = contacts_index_report(&records);
        assert_eq!(index.len(), limit);
        assert_eq!(dropped, 1);
    }

    /// `n` contacts, as the union of two files: the names, addresses and numbers
    /// are all distinct, so each one is a person.
    fn union_of(n: usize) -> Vec<ContactRecord> {
        (0..n)
            .map(|k| ContactRecord {
                source: format!("file:{}.vcf", if k % 2 == 0 { "a" } else { "b" }),
                display_name: Some(format!("Pessoa{k} Apelido{k}")),
                given: vec![format!("Pessoa{k}")],
                family: vec![format!("Apelido{k}")],
                nicknames: Vec::new(),
                emails: vec![format!("contact{k}@example.invalid")],
                phones: vec![format!("+3368{k:07}")],
                time_zone: None,
            })
            .collect()
    }

    /// Where one Private turn spends its time with 20,000 contacts. Run in release:
    /// `cargo test --release -p aux-runtime perf_ -- --ignored --nocapture`.
    #[test]
    #[ignore = "perf: run in release with --ignored --nocapture"]
    fn perf_20k_contacts_one_private_turn_stages() {
        let records = union_of(20_000);

        let started = std::time::Instant::now();
        let index = contacts_index(&records);
        eprintln!(
            "perf contacts_index (20000): {:?} -> {} people",
            started.elapsed(),
            index.len()
        );

        let started = std::time::Instant::now();
        let names = names_dictionary(&index).unwrap();
        eprintln!(
            "perf names_dictionary: {:?} -> {} names",
            started.elapsed(),
            names.len()
        );

        let started = std::time::Instant::now();
        let checks = StandardDetector::with_dictionary(Arc::clone(&names)).checks_names();
        eprintln!(
            "perf StandardDetector::with_dictionary: {:?} (checks={checks})",
            started.elapsed()
        );

        let started = std::time::Instant::now();
        let mut gate =
            Gate::for_grant_with_dictionary(&private_grant(), [7u8; 32], Arc::clone(&names));
        eprintln!(
            "perf Gate::for_grant_with_dictionary: {:?}",
            started.elapsed()
        );

        let started = std::time::Instant::now();
        let (text, _) = gate
            .text("Écris à Pessoa7 Apelido7 (contact7@example.invalid).")
            .unwrap();
        eprintln!(
            "perf gate.text: {:?} ({} chars)",
            started.elapsed(),
            text.as_str().len()
        );
        assert!(!text.as_str().contains("contact7@example.invalid"));
    }

    /// The dictionary `names` matches all of `name` in a text (it holds it).
    fn masks(names: &Arc<NameDictionary>, name: &str) -> bool {
        let text = format!("Escreva para {name}.");
        let spans = kernel_privacy::Recognizer::analyze(names.as_ref(), &text);
        let at = "Escreva para ".len();
        spans
            .iter()
            .any(|span| span.start <= at && at + name.len() <= span.end)
    }

    /// One person per name, under the file source.
    fn persons(names: &[&str]) -> Vec<ContactRecord> {
        names
            .iter()
            .map(|name| {
                let (given, family) = name.split_once(' ').unwrap_or((name, ""));
                ContactRecord {
                    source: "file:contacts.vcf".to_string(),
                    display_name: Some(name.to_string()),
                    given: vec![given.to_string()],
                    family: vec![family.to_string()],
                    emails: vec![format!("{}@example.invalid", given.to_lowercase())],
                    ..ContactRecord::default()
                }
            })
            .collect()
    }

    fn store_replace(home: &Path, records: &[ContactRecord]) {
        aux_store::Store::open(&home.join("store.db"))
            .unwrap()
            .replace_source_contacts("file:contacts.vcf", records)
            .unwrap();
    }

    #[test]
    fn a_mount_over_the_limit_is_refused_and_never_masks_a_subset() {
        let (_dir, home) = stored(&persons(&[
            "Nome0 Sobrenome",
            "Nome1 Sobrenome",
            "Nome2 Sobrenome",
            "Nome3 Sobrenome",
            "Nome4 Sobrenome",
            "Nome5 Sobrenome",
        ]));
        let over = owner_contacts_at_limit(&home, 5).unwrap_err();
        assert_eq!(
            over,
            OverLimit {
                people: 6,
                limit: 5
            }
        );
        assert!(over.to_string().contains("over the limit of 5"), "{over}");
        assert!(over.to_string().contains("(6 people)"), "{over}");
        assert_eq!(owner_contacts_at_limit(&home, 6).unwrap().len(), 6);
    }

    #[test]
    fn the_names_dictionary_is_built_once_per_contacts_generation() {
        let (_dir, home) = stored(&[camille_record()]);
        let first = owner_contacts_at(&home);
        let names_a = names_for(&first).unwrap();
        let names_b = names_for(&owner_contacts_at(&home)).unwrap();
        assert!(
            Arc::ptr_eq(&names_a, &names_b),
            "a second turn reuses the dictionary"
        );
        assert!(masks(&names_a, "Camille Exemple"));

        // An import replaces the contacts: the next dictionary comes from them.
        store_replace(&home, &persons(&["Dragica Unionlast"]));
        let names_c = names_for(&owner_contacts_at(&home)).unwrap();
        assert!(
            !Arc::ptr_eq(&names_a, &names_c),
            "an import rebuilds the dictionary"
        );
        assert!(masks(&names_c, "Dragica Unionlast"));
        assert!(!masks(&names_c, "Camille Exemple"));

        // A remove, then a clear, rebuild it again.
        store_replace(&home, &[]);
        let names_d = names_for(&owner_contacts_at(&home)).unwrap();
        assert!(
            !Arc::ptr_eq(&names_c, &names_d),
            "a removal rebuilds the dictionary"
        );
        assert!(!masks(&names_d, "Dragica Unionlast"));
    }

    /// The kernel's default pattern budget refuses people with ordinary name forms before
    /// the contact limit: all 20,000 must mount, none may be left out silently.
    #[test]
    fn twenty_thousand_people_with_ordinary_names_are_all_mounted() {
        let records = union_of(CONTACT_LIMIT);
        let (index, dropped) = contacts_index_report(&records);
        assert_eq!(dropped, 0, "the default pattern budget refused people");
        assert_eq!(index.len(), CONTACT_LIMIT);
    }
}
