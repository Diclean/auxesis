//! The contacts import core, shared by `aux contacts import` and the daemon's
//! `POST /v1/contacts/import`: the vCard and CSV readers, the E.164 normalisation,
//! the per-source store write and the CRM party seeding. Nothing here prints or
//! logs a value: a summary and a preview carry counts and column names only.

use std::fmt;
use std::path::{Path, PathBuf};

use aux_crm::{CrmError, NewParty, Party, PartyKind, Seeded};
use aux_store::{ContactRecord, Store};

use crate::known_names::{
    contacts_index_report, person_draft, records_of, ContactSource, Fetched, Refusals,
    CONTACT_LIMIT,
};

/// The largest contact file read. A real export is a few megabytes.
const MAX_FILE_BYTES: u64 = 20 * 1024 * 1024;

/// One person as the file wrote them, before phone normalisation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub display_name: Option<String>,
    pub given: Vec<String>,
    pub family: Vec<String>,
    pub nicknames: Vec<String>,
    pub emails: Vec<String>,
    /// Phone numbers as written. The import normalises them to E.164.
    pub phones: Vec<String>,
    /// The vCard `TZ:` IANA zone, validated. A UTC offset is not a zone and is
    /// left unset.
    pub time_zone: Option<String>,
    /// The rest of a CSV row's client card.
    pub card: Card,
}

/// What a CSV row says beyond names, addresses and numbers: it fills the CRM card.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Card {
    /// A row with a company and no person name is the company itself.
    pub company: bool,
    /// The postal address, its parts joined in one line.
    pub address: Option<String>,
    pub tags: Vec<String>,
    /// Note lines: the notes cell, then `Header: value` lines.
    pub notes: Vec<String>,
}

/// Why a phone number could not be put in E.164.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneError {
    /// A national-format number, and no known country to read it against.
    NoCountry,
    /// Not a phone number that E.164 can hold.
    Invalid,
}

/// What an import did. Counts only: a summary never names anyone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Contacts stored from this source, after merging the repeats within it.
    pub stored: usize,
    /// Entries merged into another entry of the same file (one address or number).
    pub merged: usize,
    /// Entries with no name, address or number.
    pub skipped: usize,
    /// Contacts that need a country: a national-format number and no country given,
    /// so that number was not kept.
    pub no_country: usize,
    /// Phone numbers kept out: not a number E.164 can hold.
    pub invalid: usize,
    /// E-mail addresses stored from this source.
    pub emails: usize,
    /// Phone numbers stored from this source.
    pub phones: usize,
    /// CRM parties created from this source.
    pub parties_created: usize,
    /// CRM parties updated from this source: a contact matched one by address or number.
    pub parties_updated: usize,
    /// Card values that differ from what the party already holds: the old one was kept.
    pub conflicts: usize,
    /// Contacts that did not become a CRM party, such as one with a refused address.
    pub parties_refused: usize,
    /// Cards not imported: a character set this build does not read.
    pub refused_charset: usize,
    /// Fields not imported: base64, or quoted-printable that does not decode.
    pub encoded_fields: usize,
    /// Entries not imported: another size cap of the kernel.
    pub capped: usize,
    /// vCard `TZ:` values that are not IANA names (a UTC offset is not a zone):
    /// no zone was kept for those contacts.
    pub time_zone_ignored: usize,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Stored {} contacts from this file ({} e-mail addresses, {} phone numbers).",
            self.stored, self.emails, self.phones
        )?;
        if self.merged > 0 {
            writeln!(
                f,
                "{} entries repeated another entry of the file and were merged.",
                self.merged
            )?;
        }
        if self.no_country > 0 {
            writeln!(
                f,
                "warning: {} contact(s) need country: a phone number has no country code and \
                 was not kept. Re-run with --country <ISO code>, for example --country FR.",
                self.no_country
            )?;
        }
        writeln!(
            f,
            "CRM: {} parties created, {} updated, {} refused.",
            self.parties_created, self.parties_updated, self.parties_refused
        )?;
        if self.conflicts > 0 {
            writeln!(
                f,
                "warning: {} conflict(s): an address differs from the one the client card \
                 holds; the card kept its address.",
                self.conflicts
            )?;
        }
        if self.invalid > 0 {
            writeln!(
                f,
                "warning: {} phone number(s) are not valid and were not kept.",
                self.invalid
            )?;
        }
        if self.skipped > 0 {
            writeln!(
                f,
                "{} entries had no name, address or number and were skipped.",
                self.skipped
            )?;
        }
        if self.refused_charset > 0 {
            writeln!(
                f,
                "warning: {} card(s) use a character set this build does not read \
                 (UTF-8, ISO-8859-1 or Windows-1252) and were not imported.",
                self.refused_charset
            )?;
        }
        if self.encoded_fields > 0 {
            writeln!(
                f,
                "warning: {} field(s) are base64 or do not decode and were not imported.",
                self.encoded_fields
            )?;
        }
        if self.capped > 0 {
            writeln!(
                f,
                "{} entries were refused by a size cap and not imported.",
                self.capped
            )?;
        }
        if self.time_zone_ignored > 0 {
            writeln!(
                f,
                "warning: {} time zone(s) are not an IANA name (a UTC offset is not a \
                 zone) and were not kept.",
                self.time_zone_ignored
            )?;
        }
        Ok(())
    }
}

/// A vCard or CSV file the owner imports. Its contacts are stored under `file:<name>`.
pub struct FileSource {
    path: PathBuf,
}

impl FileSource {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl ContactSource for FileSource {
    fn kind(&self) -> &'static str {
        "file"
    }

    fn name(&self) -> String {
        let file = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("file:{file}")
    }

    fn fetch(&self) -> Result<Fetched, String> {
        let text = read_text(&self.path)?;
        Ok(fetched_of(parse_text(&text)?.cards, &self.name()))
    }
}

fn fetched_of(cards: Cards, source: &str) -> Fetched {
    Fetched {
        contacts: cards
            .people
            .into_iter()
            .map(|person| record_of(person, source))
            .collect(),
        refusals: Refusals {
            charset_cards: cards.refused_charset,
            encoded_fields: cards.encoded_fields,
            time_zone_ignored: cards.time_zone_ignored,
        },
    }
}

/// Refuse a country code this build cannot read national numbers against.
pub fn check_country(code: &str) -> Result<(), String> {
    if aux_crm::country_codes().any(|known| known.eq_ignore_ascii_case(code)) {
        return Ok(());
    }
    let known: Vec<&str> = aux_crm::country_codes().collect();
    Err(format!(
        "unknown country code `{code}`: use one of {}",
        known.join(", ")
    ))
}

/// Import the contact file at `path` as `aux contacts import` does: store its contacts
/// under `file:<name>` and seed or update the CRM parties, putting `tag` on each.
pub fn import_file(
    store: &Store,
    path: &Path,
    country: Option<&str>,
    tag: Option<&str>,
) -> Result<Summary, String> {
    country.map(check_country).transpose()?;
    let doc = parse_text(&read_text(path)?)?;
    let dropped = doc.csv.as_ref().map_or(0, |csv| csv.dropped_rows);
    let name = FileSource::new(path).name();
    let origin = format!("contacts:{name}");
    let cards = card_drafts(&doc.cards.people, &origin, country);
    let fetched = fetched_of(doc.cards, &name);
    let (records, mut summary) = plan_fetched(store, &name, fetched, country, CONTACT_LIMIT)?;
    store
        .replace_source_contacts(&name, &records)
        .map_err(store_error)?;
    summary.skipped += dropped;
    // A row the party stage refused already is one refused row, not two.
    let parties: Vec<String> = records
        .iter()
        .filter_map(|record| aux_crm::refusal(&party_draft(record, &origin)))
        .collect();
    seed_parties(store, &name, tag, &mut summary)?;
    let cards_refused: Vec<String> = cards.iter().filter_map(aux_crm::refusal).collect();
    summary.parties_refused += extra_refusals(&parties, &cards_refused);
    summary.conflicts = aux_crm::Crm::new(store).fill_cards(cards).map_err(|err| {
        // The import is half done: the contacts are stored, the cards are not.
        format!(
            "the import is partially imported: {} contact(s) saved, \
             the client cards were not filled: {}",
            summary.stored,
            crm_error(err)
        )
    })?;
    Ok(summary)
}

/// The card rows refused that the party stage did not: one row, not two.
fn extra_refusals(parties: &[String], cards: &[String]) -> usize {
    cards.iter().filter(|key| !parties.contains(key)).count()
}

/// The card drafts of the rows that fill a client card, named and numbered as their
/// party is, so [`aux_crm::Crm::fill_cards`] finds it.
fn card_drafts(people: &[Parsed], origin: &str, country: Option<&str>) -> Vec<NewParty> {
    let has_card = |card: &Card| {
        card.company || card.address.is_some() || !card.tags.is_empty() || !card.notes.is_empty()
    };
    people
        .iter()
        .filter(|person| has_card(&person.card))
        .map(|person| {
            let phones: Vec<String> = person
                .phones
                .iter()
                .filter_map(|raw| normalise_phone(raw, country).ok())
                .collect();
            let display_name = person
                .display_name
                .clone()
                .or_else(|| person.emails.first().cloned())
                .or_else(|| phones.first().cloned())
                .unwrap_or_default();
            NewParty {
                kind: if person.card.company {
                    PartyKind::Company
                } else {
                    PartyKind::Person
                },
                display_name,
                emails: person.emails.clone(),
                phones,
                addresses: person.card.address.iter().cloned().collect(),
                tags: person.card.tags.clone(),
                notes: person.card.notes.join("\n"),
                origin: origin.to_string(),
                ..NewParty::default()
            }
        })
        .collect()
}

/// What an import would do, found without writing anything. Counts and column names only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    /// `vcard` or `csv`.
    pub format: &'static str,
    /// The header columns used and ignored, for a CSV.
    pub csv: Option<CsvReport>,
    /// The import summary; its `parties_*` fields stay zero (see the two counts below).
    pub summary: Summary,
    /// Contacts that would create a party.
    pub would_create: usize,
    /// Contacts that match a live party by address or number (or by name when they have
    /// neither), which the import would update or leave as it is.
    pub would_update: usize,
    /// Rows the CRM would refuse: they become no party, as in the import.
    pub would_refuse: usize,
    /// Card values that differ from the card the import would fill: it keeps the old one.
    pub conflicts: usize,
}

/// Read the contact file at `path` and say what [`import_file`] would do with it. The
/// store is only read, so a preview changes nothing.
pub fn preview_file(store: &Store, path: &Path, country: Option<&str>) -> Result<Preview, String> {
    country.map(check_country).transpose()?;
    let doc = parse_text(&read_text(path)?)?;
    let name = FileSource::new(path).name();
    let cards = card_drafts(&doc.cards.people, &format!("contacts:{name}"), country);
    let fetched = fetched_of(doc.cards, &name);
    let (records, mut summary) = plan_fetched(store, &name, fetched, country, CONTACT_LIMIT)?;
    summary.skipped += doc.csv.as_ref().map_or(0, |csv| csv.dropped_rows);
    let live = aux_crm::Crm::new(store).list().map_err(crm_error)?;
    // The parties the import would leave: the live ones, then those it would create.
    let mut seen: Vec<Party> = live;
    let origin = format!("contacts:{name}");
    let (mut would_create, mut would_update, mut would_refuse) = (0, 0, 0);
    let mut refused: Vec<String> = Vec::new();
    for record in &records {
        let mut draft = party_draft(record, &origin);
        draft.display_name = draft.display_name.trim().to_string();
        if let Some(key) = aux_crm::refusal(&draft) {
            // The CRM refuses this row: it becomes no party.
            refused.push(key);
            would_refuse += 1;
            continue;
        }
        draft.emails = draft
            .emails
            .iter()
            .map(|e| e.trim().to_lowercase())
            .collect();
        // The same rule as `aux_crm::Crm::seed_batch`.
        match aux_crm::matching(&seen, &draft) {
            Some(index) => {
                would_update += 1;
                seen[index].emails.extend(draft.emails);
                seen[index].phones.extend(draft.phones);
            }
            None => {
                would_create += 1;
                seen.push(party_of(&draft));
            }
        }
    }
    // The cards the import would fill, and the conflicts they would find.
    let mut conflicts = 0;
    for card in &cards {
        if aux_crm::refusal(card).is_some() {
            continue;
        }
        let Some(index) = aux_crm::matching(&seen, card) else {
            continue;
        };
        let (filled, clashes) = aux_crm::card_filled(&seen[index], card);
        conflicts += clashes;
        // The card keeps the address it had: the next row finds the same one.
        seen[index].addresses = filled.addresses;
    }
    // A row the party stage refused already is one refused row, not two.
    let cards_refused: Vec<String> = cards.iter().filter_map(aux_crm::refusal).collect();
    would_refuse += extra_refusals(&refused, &cards_refused);
    Ok(Preview {
        format: if doc.csv.is_some() { "csv" } else { "vcard" },
        csv: doc.csv,
        summary,
        would_create,
        would_update,
        would_refuse,
        conflicts,
    })
}

/// The party a draft would create: the same fields, without a row id.
fn party_of(draft: &NewParty) -> Party {
    Party {
        display_name: draft.display_name.clone(),
        emails: draft.emails.clone(),
        phones: draft.phones.clone(),
        origin: draft.origin.clone(),
        ..Party::default()
    }
}

/// The text of a contact file: a regular file (never a directory, a pipe or a
/// device) under the size cap, in UTF-8. The file is opened once, without
/// following a final symlink and without blocking on a FIFO; every check and
/// the read then use that one handle, so the path cannot be swapped between
/// the check and the read. Directories above the file may be links (`/tmp` is
/// one on macOS): the owner names the path, and it is read where it resolves.
fn read_text(path: &Path) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| match err.raw_os_error() {
            Some(libc::ELOOP) => "the path is a symbolic link".to_string(),
            _ => format!("cannot read the file: {}", err.kind()),
        })?;
    let meta = file
        .metadata()
        .map_err(|err| format!("cannot read the file: {}", err.kind()))?;
    if !meta.is_file() {
        return Err("the path is not a regular file".to_string());
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err("the file is larger than 20 MB".to_string());
    }
    // The cap holds even if the file grows after the check.
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("cannot read the file: {}", err.kind()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("the file is larger than 20 MB".to_string());
    }
    String::from_utf8(bytes).map_err(|_| "the file is not UTF-8 text".to_string())
}

/// What a contact file holds: its cards, and for a CSV the header's columns.
struct Document {
    cards: Cards,
    csv: Option<CsvReport>,
}

fn parse_text(text: &str) -> Result<Document, String> {
    if text.contains("BEGIN:VCARD") {
        return Ok(Document {
            cards: parse_vcards(text),
            csv: None,
        });
    }
    let (people, report) = parse_csv_report(text)?;
    Ok(Document {
        cards: Cards {
            people,
            ..Cards::default()
        },
        csv: Some(report),
    })
}

fn record_of(person: Parsed, source: &str) -> ContactRecord {
    ContactRecord {
        source: source.to_string(),
        display_name: person.display_name,
        given: person.given,
        family: person.family,
        nicknames: person.nicknames,
        emails: person.emails,
        phones: person.phones,
        time_zone: person.time_zone,
    }
}

/// Import one source: fetch its contacts, normalise their phones to E.164 with
/// `country`, merge the entries that share an address or a number, and replace the
/// contacts stored under the source's tag. The other sources are kept.
pub fn import_source(
    store: &Store,
    source: &dyn ContactSource,
    country: Option<&str>,
) -> Result<Summary, String> {
    import_source_with_limit(store, source, country, CONTACT_LIMIT)
}

/// Import one source. The import is refused as a whole, and nothing is stored, when
/// the contacts of all sources together would pass `limit`: this source's rows
/// replace its earlier ones, so they are counted, not added to them.
pub fn import_source_with_limit(
    store: &Store,
    source: &dyn ContactSource,
    country: Option<&str>,
    limit: usize,
) -> Result<Summary, String> {
    let name = source.name();
    let (records, summary) = plan_fetched(store, &name, source.fetch()?, country, limit)?;
    store
        .replace_source_contacts(&name, &records)
        .map_err(store_error)?;
    Ok(summary)
}

/// Everything an import does short of writing: the records it would store under `name`
/// and its summary, or the refusal. The store is only read.
fn plan_fetched(
    store: &Store,
    name: &str,
    fetched: Fetched,
    country: Option<&str>,
    limit: usize,
) -> Result<(Vec<ContactRecord>, Summary), String> {
    let mut summary = Summary::default();
    let mut index = crate::known_names::new_contacts_index();
    // The kernel merges the rows that share an address or a number, so the
    // zone travels beside the index: keyed by the same identifiers, then put
    // back on the merged record.
    let mut zones: Vec<(String, String)> = Vec::new();
    let mut own_over = 0;
    summary.refused_charset = fetched.refusals.charset_cards;
    summary.encoded_fields = fetched.refusals.encoded_fields;
    summary.time_zone_ignored = fetched.refusals.time_zone_ignored;
    for mut contact in fetched.contacts {
        let mut phones = Vec::new();
        let mut needs_country = false;
        for raw in &contact.phones {
            match normalise_phone(raw, country) {
                Ok(e164) => phones.push(e164),
                Err(PhoneError::NoCountry) => needs_country = true,
                Err(PhoneError::Invalid) => summary.invalid += 1,
            }
        }
        if needs_country {
            summary.no_country += 1;
        }
        contact.phones = phones;
        if let Some(zone) = contact
            .time_zone
            .as_deref()
            .and_then(aux_crm::valid_time_zone)
        {
            for key in contact
                .emails
                .iter()
                .map(|email| email.to_ascii_lowercase())
                .chain(contact.phones.iter().cloned())
            {
                zones.push((key, zone.clone()));
            }
        }
        let before = index.len();
        let refused_before = index.refused();
        match index.add_person(person_draft(&contact)) {
            Some(_) if index.len() > before => {}
            Some(_) => summary.merged += 1,
            None if index.refused() > refused_before && index.len() >= CONTACT_LIMIT => {
                own_over += 1;
            }
            None if index.refused() > refused_before => summary.capped += 1,
            None => summary.skipped += 1,
        }
    }
    if own_over > 0 {
        return Err(over_limit_refusal(index.len() + own_over, limit));
    }
    let mut records = records_of(&index);
    for record in &mut records {
        record.source = name.to_string();
        record.time_zone = zone_of(record, &zones);
    }
    // The union of the other sources as stored, and this source's new rows.
    let mut union: Vec<ContactRecord> = store
        .contacts()
        .map_err(store_error)?
        .into_iter()
        .filter(|record| record.source != name)
        .collect();
    union.extend(records.iter().cloned());
    let (merged, dropped) = contacts_index_report(&union);
    let total = merged.len() + dropped;
    if dropped > 0 || total > limit {
        return Err(over_limit_refusal(total, limit));
    }
    summary.stored = records.len();
    summary.emails = records.iter().map(|record| record.emails.len()).sum();
    summary.phones = records.iter().map(|record| record.phones.len()).sum();
    Ok((records, summary))
}

/// The zone the imported rows gave one merged record: the first address or
/// number it shares with a row that carried a zone.
fn zone_of(record: &ContactRecord, zones: &[(String, String)]) -> Option<String> {
    for email in &record.emails {
        if let Some((_, zone)) = zones
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(email))
        {
            return Some(zone.clone());
        }
    }
    for phone in &record.phones {
        if let Some((_, zone)) = zones.iter().find(|(key, _)| key == phone) {
            return Some(zone.clone());
        }
    }
    None
}

/// Seed the CRM parties of the contacts stored under `source`. A contact creates the
/// party it describes, or updates the one it matches by address or number, so importing
/// the same file again creates no second party. `tag`, when given, is put on every party
/// the file created or matched. Counts go into `summary`.
pub fn seed_parties(
    store: &Store,
    source: &str,
    tag: Option<&str>,
    summary: &mut Summary,
) -> Result<(), String> {
    let origin = format!("contacts:{source}");
    let drafts: Vec<NewParty> = store
        .contacts()
        .map_err(store_error)?
        .iter()
        .filter(|record| record.source == source)
        .map(|record| {
            let mut draft = party_draft(record, &origin);
            draft.tags.extend(tag.map(str::to_string));
            draft
        })
        .collect();
    let crm = aux_crm::Crm::new(store);
    for result in crm.seed_batch(drafts).map_err(crm_error)? {
        match result {
            Ok(Seeded::Created(_)) => summary.parties_created += 1,
            Ok(Seeded::Updated(party)) => {
                summary.parties_updated += 1;
                add_tag(&crm, party, tag)?;
            }
            Ok(Seeded::Unchanged(party)) => add_tag(&crm, party, tag)?,
            Err(_) => summary.parties_refused += 1,
        }
    }
    Ok(())
}

/// Put `tag` on a party that matched an import row; a created party already carries it.
fn add_tag(crm: &aux_crm::Crm, party: aux_crm::Party, tag: Option<&str>) -> Result<(), String> {
    let Some(tag) = tag.filter(|tag| !party.tags.iter().any(|have| have == tag)) else {
        return Ok(());
    };
    let mut tags = party.tags;
    tags.push(tag.to_string());
    crm.update(
        party.id,
        NewParty {
            kind: party.kind,
            display_name: party.display_name,
            name_variants: party.name_variants,
            emails: party.emails,
            phones: party.phones,
            addresses: party.addresses,
            tags,
            notes: party.notes,
            time_zone: party.time_zone,
            origin: party.origin,
        },
    )
    .map(|_| ())
    .map_err(crm_error)
}

/// The CRM party a stored contact describes: a person named by the card's name, or by
/// its first address or number when the card has none.
fn party_draft(record: &ContactRecord, origin: &str) -> NewParty {
    let display_name = record
        .display_name
        .clone()
        .or_else(|| record.emails.first().cloned())
        .or_else(|| record.phones.first().cloned())
        .unwrap_or_default();
    NewParty {
        kind: PartyKind::Person,
        display_name,
        name_variants: record
            .given
            .iter()
            .chain(&record.family)
            .chain(&record.nicknames)
            .cloned()
            .collect(),
        emails: record.emails.clone(),
        phones: record.phones.clone(),
        // A stored value is validated again on the way to the card.
        time_zone: record
            .time_zone
            .as_deref()
            .and_then(aux_crm::valid_time_zone),
        origin: origin.to_string(),
        ..NewParty::default()
    }
}

pub fn crm_error(err: CrmError) -> String {
    format!("the CRM: {err}")
}

/// The refusal of an import whose union would pass the limit. Counts only, in English
/// and French.
pub fn over_limit_refusal(total: usize, limit: usize) -> String {
    format!(
        "Import refused: the contacts of all sources would be {total}, over the limit of {limit}. \
         Nothing was stored. / Import refusé : les contacts de toutes les sources seraient \
         {total}, au-delà de la limite de {limit}. Rien n'a été enregistré."
    )
}

/// The people a vCard file holds, and what it refused to read.
#[derive(Debug, Default)]
pub struct Cards {
    pub people: Vec<Parsed>,
    /// Cards in a character set this build does not read: not imported.
    pub refused_charset: usize,
    /// Base64 or undecodable fields: skipped.
    pub encoded_fields: usize,
    /// Cards whose `TZ:` is not an IANA name: no zone was kept.
    pub time_zone_ignored: usize,
}

/// Parse a vCard file (v3 or v4, and v2.1 with its bare parameters). Every
/// `BEGIN:VCARD` block is one person.
pub fn parse_vcards(text: &str) -> Cards {
    let mut cards = Cards::default();
    // The card being read, whether it is refused for its character set, and
    // whether it carried a `TZ:` that is not an IANA name.
    let mut current: Option<(Parsed, bool, bool)> = None;
    for line in unfold(text) {
        let Some((head, value)) = line.split_once(':') else {
            continue;
        };
        // `item1.TEL;TYPE=CELL` → `TEL`: a group prefix and parameters are not part of the name.
        let name = head.split(';').next().unwrap_or_default();
        let name = name
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        match name.as_str() {
            "BEGIN" if value.eq_ignore_ascii_case("VCARD") => {
                current = Some((Parsed::default(), false, false));
            }
            "END" if value.eq_ignore_ascii_case("VCARD") => {
                if let Some((person, refused, zone_ignored)) = current.take() {
                    if refused {
                        cards.refused_charset += 1;
                    } else {
                        // A later valid `TZ:` line keeps the zone: nothing ignored.
                        if zone_ignored && person.time_zone.is_none() {
                            cards.time_zone_ignored += 1;
                        }
                        cards.people.push(finish(person));
                    }
                }
            }
            _ => {
                if let Some((person, refused, zone_ignored)) = current.as_mut() {
                    match read_field(&name, head, value) {
                        Field::Text(text) => {
                            *zone_ignored |=
                                apply_vcard_property(person, &name, &controls_as_spaces(&text));
                        }
                        Field::Encoded => cards.encoded_fields += 1,
                        Field::Charset => *refused = true,
                        Field::Unused => {}
                    }
                }
            }
        }
    }
    cards
}

/// The vCard properties the reader uses: the names, the nicknames, the addresses, the numbers
/// and the client's own time zone.
const READ_PROPERTIES: [&str; 6] = ["FN", "N", "NICKNAME", "EMAIL", "TEL", "TZ"];

/// What one vCard property holds, once its encoding is read.
enum Field {
    /// The decoded text.
    Text(String),
    /// Base64, or quoted-printable that does not decode: the field is skipped.
    Encoded,
    /// A character set this build does not read: the card is refused.
    Charset,
    /// A property the reader does not use.
    Unused,
}

/// Read one property's value: decode it from its encoding and character set. A
/// plain value that still carries an escape is an undeclared encoding, not a name.
fn read_field(name: &str, head: &str, value: &str) -> Field {
    if !READ_PROPERTIES.contains(&name) {
        return Field::Unused;
    }
    let encoding = encoding_of(head);
    if encoding.base64 {
        return Field::Encoded;
    }
    // A declared charset must be one this build reads; with none, the value is UTF-8.
    let charset = match encoding.charset.as_deref() {
        None => Charset::Utf8,
        Some(declared) => match charset_named(declared) {
            Some(charset) => charset,
            None => return Field::Charset,
        },
    };
    if encoding.quoted_printable {
        let Some(bytes) = quoted_printable_bytes(value) else {
            return Field::Encoded;
        };
        return match decode_bytes(&bytes, charset) {
            Some(text) => Field::Text(text),
            None => Field::Charset,
        };
    }
    if looks_encoded(value) {
        return Field::Encoded;
    }
    Field::Text(value.to_string())
}

/// The encoding parameters of a vCard property. v3 and v4 write `ENCODING=`; v2.1
/// writes the encoding bare (`QUOTED-PRINTABLE`, `BASE64`, `B`).
#[derive(Debug, Default)]
struct Encoding {
    quoted_printable: bool,
    base64: bool,
    /// The declared charset, upper-cased.
    charset: Option<String>,
}

fn encoding_of(head: &str) -> Encoding {
    let mut encoding = Encoding::default();
    for param in head.split(';').skip(1) {
        let param = param.trim().to_ascii_uppercase();
        if let Some(charset) = param.strip_prefix("CHARSET=") {
            encoding.charset = Some(charset.to_string());
            continue;
        }
        let kind = param.strip_prefix("ENCODING=").unwrap_or(param.as_str());
        match kind {
            "QUOTED-PRINTABLE" => encoding.quoted_printable = true,
            "BASE64" | "B" => encoding.base64 = true,
            _ => {}
        }
    }
    encoding
}

/// The charsets this build reads. Anything else refuses the card.
#[derive(Clone, Copy)]
enum Charset {
    Utf8,
    Latin1,
    Windows1252,
}

/// The charset a declared name (upper-cased) names, when this build reads it.
fn charset_named(name: &str) -> Option<Charset> {
    match name {
        "UTF-8" | "UTF8" | "US-ASCII" | "ASCII" => Some(Charset::Utf8),
        "ISO-8859-1" | "ISO8859-1" | "ISO-LATIN-1" | "LATIN1" => Some(Charset::Latin1),
        "WINDOWS-1252" | "CP1252" => Some(Charset::Windows1252),
        _ => None,
    }
}

/// The text of `bytes` in `charset`; None when the bytes are not valid in it.
fn decode_bytes(bytes: &[u8], charset: Charset) -> Option<String> {
    match charset {
        Charset::Utf8 => String::from_utf8(bytes.to_vec()).ok(),
        Charset::Latin1 => Some(bytes.iter().map(|&byte| char::from(byte)).collect()),
        Charset::Windows1252 => bytes.iter().map(|&byte| windows_1252(byte)).collect(),
    }
}

/// One Windows-1252 byte as a char. 0x80–0x9F are typographic characters; five
/// codes are unassigned and refuse the text.
fn windows_1252(byte: u8) -> Option<char> {
    const HIGH: [u32; 32] = [
        0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, //
        0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017D, 0, //
        0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, //
        0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
    ];
    match byte {
        0x80..=0x9F => match HIGH[usize::from(byte - 0x80)] {
            0 => None,
            code => char::from_u32(code),
        },
        _ => Some(char::from(byte)),
    }
}

/// The bytes a quoted-printable value holds: `=XX` is one byte. A soft break was
/// already joined by [`unfold`]. None when an escape is not two hex digits.
fn quoted_printable_bytes(value: &str) -> Option<Vec<u8>> {
    let raw = value.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'=' {
            let hex = raw.get(index + 1..index + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let hex = std::str::from_utf8(hex).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            bytes.push(raw[index]);
            index += 1;
        }
    }
    Some(bytes)
}

/// Whether a plain value still carries a quoted-printable escape (`=XX`).
fn looks_encoded(value: &str) -> bool {
    value
        .as_bytes()
        .windows(3)
        .any(|w| w[0] == b'=' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

/// Set one vCard property on the person being read. Other properties are
/// ignored. Returns true for a `TZ:` that was present but is not an IANA name.
fn apply_vcard_property(person: &mut Parsed, name: &str, value: &str) -> bool {
    match name {
        "FN" => {
            person.display_name = non_empty(unescape(value));
            false
        }
        "N" => {
            // `family;given;additional;prefix;suffix`: only the first two are kept.
            let parts = split_raw(value, ';');
            person.family = words(&unescape(parts.first().copied().unwrap_or_default()));
            person.given = words(&unescape(parts.get(1).copied().unwrap_or_default()));
            false
        }
        "NICKNAME" => {
            for nick in split_raw(value, ',') {
                person.nicknames.extend(non_empty(unescape(nick)));
            }
            false
        }
        "EMAIL" => {
            let address = strip_scheme(value, "mailto:");
            person.emails.extend(non_empty(unescape(address)));
            false
        }
        "TEL" => {
            person
                .phones
                .extend(non_empty(strip_scheme(value, "tel:").to_string()));
            false
        }
        // `TZ:Europe/Paris` is the client's zone. `TZ:-05:00` is a UTC offset,
        // not a zone: it is left unset instead of being guessed into one.
        "TZ" => {
            person.time_zone = aux_crm::valid_time_zone(value);
            person.time_zone.is_none() && !value.trim().is_empty()
        }
        _ => false,
    }
}

/// Parse a CSV file. The header row picks the name, e-mail and phone columns.
/// The header may be the generic `name,email,phone`, the Google Contacts export
/// (`Given Name`, `E-mail 1 - Value`, `Phone 1 - Value`, ...) or the Outlook one
/// (`First Name`, `E-mail Address`, `Mobile Phone`, ...).
pub fn parse_csv(text: &str) -> Result<Vec<Parsed>, String> {
    parse_csv_report(text).map(|(people, _)| people)
}

/// [`parse_csv`], and which header columns it used and ignored. HubSpot
/// (`Phone Number`, `Company Name`) and Pipedrive (`Person - Name`, `Person - Email`)
/// headers are read as well; every other column is ignored and only named in the report.
pub fn parse_csv_report(text: &str) -> Result<(Vec<Parsed>, CsvReport), String> {
    let mut rows = csv_rows(text).into_iter();
    let header = rows.next().ok_or("the file is empty")?;
    let columns = Columns::from_header(&header);
    if !columns.recognised() {
        return Err("no name, company, e-mail or phone column in the first row".to_string());
    }
    let mut report = columns.report(&header);
    let mut people = Vec::new();
    for row in rows {
        let cell = |index: Option<usize>| {
            index
                .and_then(|i| row.get(i))
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        let many = |indexes: &[usize]| -> Vec<String> {
            indexes
                .iter()
                .filter_map(|&i| row.get(i))
                .flat_map(|value| value.split([',', ';']).flat_map(|part| part.split(":::")))
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect()
        };
        let mut person = finish(Parsed {
            display_name: cell(columns.name),
            given: words(&cell(columns.given).unwrap_or_default()),
            family: words(&cell(columns.family).unwrap_or_default()),
            nicknames: cell(columns.nickname).into_iter().collect(),
            emails: many(&columns.emails)
                .into_iter()
                .filter(|address| address.contains('@'))
                .collect(),
            phones: many(&columns.phones),
            // A CSV has no time-zone column; the zone comes from a vCard `TZ:`.
            time_zone: None,
            card: Card::default(),
        });
        let text = |index: usize| cell(Some(index)).map(|value| controls_as_spaces(&value));
        // A Google export writes the address twice: `Address 1 - Formatted` holds
        // the whole line, and the parts hold it again. The parts win: one address.
        let mut address: Vec<String> = columns.address.iter().filter_map(|&i| text(i)).collect();
        if address.is_empty() {
            address = columns
                .address_formatted
                .and_then(text)
                .into_iter()
                .collect();
        }
        person.card.address = (!address.is_empty()).then(|| address.join(", "));
        person.card.tags = columns.tags.iter().flat_map(|&i| many(&[i])).collect();
        person
            .card
            .notes
            .extend(columns.notes.iter().filter_map(|&i| text(i)));
        let company = columns.company.and_then(text);
        match (company, &person.display_name) {
            (Some(company), None) => {
                person.display_name = Some(company);
                person.card.company = true;
            }
            (Some(company), Some(_)) => person.card.notes.push(format!("Company: {company}")),
            (None, _) => {}
        }
        for &(index, label) in &columns.labelled {
            if let Some(value) = text(index) {
                let label = label.map_or_else(|| header_label(&header[index]), str::to_string);
                person.card.notes.push(format!("{label}: {value}"));
            }
        }
        if person.display_name.is_some()
            || !person.given.is_empty()
            || !person.family.is_empty()
            || !person.emails.is_empty()
            || !person.phones.is_empty()
        {
            people.push(person);
        } else {
            report.dropped_rows += 1;
        }
    }
    Ok((people, report))
}

/// Which columns of a CSV header the import used. Header names only, never a cell.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CsvReport {
    /// Each used column with what it was read as (`name`, `given`, `family`, `nickname`,
    /// `email`, `phone`, `company`, `address`, `tags`, `notes`, `note line`).
    pub mapped: Vec<(String, &'static str)>,
    /// The ignored columns, by header name.
    pub unmapped: Vec<String>,
    /// Rows with no name, address or number in a used column.
    pub dropped_rows: usize,
}

/// The columns of a CSV file, found by name in its header row.
#[derive(Default)]
struct Columns {
    name: Option<usize>,
    given: Option<usize>,
    family: Option<usize>,
    nickname: Option<usize>,
    emails: Vec<usize>,
    phones: Vec<usize>,
    company: Option<usize>,
    /// Address, street, postcode, city, country: joined in header order.
    address: Vec<usize>,
    /// The whole address on one line, as a Google export writes it.
    address_formatted: Option<usize>,
    tags: Vec<usize>,
    notes: Vec<usize>,
    /// Columns kept as `Label: value` note lines; `None` labels with the header.
    labelled: Vec<(usize, Option<&'static str>)>,
}

/// A header cell as the report shows it: no control characters, at most 64 characters.
fn header_label(raw: &str) -> String {
    controls_as_spaces(raw.trim()).chars().take(64).collect()
}

impl Columns {
    fn report(&self, header: &[String]) -> CsvReport {
        let roles = [
            (self.name, "name"),
            (self.given, "given"),
            (self.family, "family"),
            (self.nickname, "nickname"),
        ]
        .into_iter()
        .filter_map(|(index, role)| index.map(|index| (index, role)))
        .chain(self.company.map(|index| (index, "company")))
        .chain(self.emails.iter().map(|&index| (index, "email")))
        .chain(self.phones.iter().map(|&index| (index, "phone")))
        .chain(self.address.iter().map(|&index| (index, "address")))
        .chain(self.tags.iter().map(|&index| (index, "tags")))
        .chain(self.notes.iter().map(|&index| (index, "notes")))
        .chain(self.labelled.iter().map(|&(index, _)| (index, "note line")));
        let mut by_index: Vec<(usize, &'static str)> = roles.collect();
        by_index.sort_by_key(|(index, _)| *index);
        let mut report = CsvReport::default();
        for (index, raw) in header.iter().enumerate() {
            match by_index.iter().find(|(used, _)| *used == index) {
                Some((_, role)) => report.mapped.push((header_label(raw), role)),
                None => report.unmapped.push(header_label(raw)),
            }
        }
        report
    }

    fn from_header(header: &[String]) -> Self {
        let mut columns = Self::default();
        for (index, raw) in header.iter().enumerate() {
            let name = raw.trim().to_lowercase();
            // `E-mail 1 - Type` and `Phone 1 - Label` name a kind, not a value.
            if name.contains("type") || name.contains("label") || name.contains("extension") {
                continue;
            }
            // The Google export numbers its columns: `Organization 1 - Name`,
            // `Address 1 - Street`.
            if name.starts_with("organization ") || name.starts_with("organisation ") {
                if name.ends_with(" - name") {
                    columns.company.get_or_insert(index);
                } else {
                    // The other organization columns are kept as note lines.
                    columns.labelled.push((index, None));
                }
                continue;
            }
            if name.starts_with("address ") || name.starts_with("adresse ") {
                if name.ends_with(" - formatted") {
                    columns.address_formatted = Some(index);
                } else {
                    columns.address.push(index);
                }
                continue;
            }
            match name.as_str() {
                "name" | "full name" | "display name" | "fn" | "person - name" => {
                    columns.name.get_or_insert(index);
                }
                "given name" | "first name" | "firstname" => {
                    columns.given.get_or_insert(index);
                }
                "family name" | "last name" | "surname" | "lastname" => {
                    columns.family.get_or_insert(index);
                }
                "nickname" => {
                    columns.nickname.get_or_insert(index);
                }
                "company"
                | "company name"
                | "société"
                | "societe"
                | "entreprise"
                | "organisation"
                | "organization"
                | "organisation - name"
                | "organization - name"
                    if columns.company.is_none() =>
                {
                    columns.company = Some(index);
                }
                "address" | "adresse" | "street" | "rue" | "postcode" | "post code"
                | "postal code" | "code postal" | "zip" | "zip code" | "city" | "ville"
                | "country" | "pays" => columns.address.push(index),
                "tags" | "tag" | "étiquettes" | "etiquettes" => columns.tags.push(index),
                "notes" | "note" | "remarques" | "remarque" => columns.notes.push(index),
                "vat"
                | "vat number"
                | "vat id"
                | "tva"
                | "n° tva"
                | "numéro de tva"
                | "tva intracommunautaire" => columns.labelled.push((index, Some("VAT"))),
                _ if name.contains("mail") => columns.emails.push(index),
                _ if name.contains("phone") || name.contains("mobile") || name == "tel" => {
                    columns.phones.push(index);
                }
                // Company id, SIRET, SIREN and every unknown column: a `Header: value` line.
                _ if !name.is_empty() => columns.labelled.push((index, None)),
                _ => {}
            }
        }
        columns
    }

    fn recognised(&self) -> bool {
        self.name.is_some()
            || self.given.is_some()
            || self.family.is_some()
            || !self.emails.is_empty()
            || !self.phones.is_empty()
            || self.company.is_some()
    }
}

/// Normalise one phone number to E.164. An international number (`+`, or `00`)
/// needs no country; a national one is read against `country` (ISO 3166-1
/// alpha-2), and is refused when none is given.
pub fn normalise_phone(raw: &str, country: Option<&str>) -> Result<String, PhoneError> {
    aux_crm::to_e164(raw, country).map_err(|err| match err {
        CrmError::UnknownCountry { .. } => PhoneError::NoCountry,
        _ => PhoneError::Invalid,
    })
}

/// Join folded lines: a line that starts with a space or a tab continues the one before.
fn unfold(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines: Vec<String> = Vec::new();
    for raw in text.lines() {
        if let Some(last) = lines.last_mut() {
            if let Some(rest) = raw.strip_prefix([' ', '\t']) {
                last.push_str(rest);
                continue;
            }
            // A quoted-printable line that ends in `=` is a soft break: the value goes on.
            if soft_break(last) && !is_card_boundary(raw) {
                last.pop();
                last.push_str(raw);
                continue;
            }
        }
        lines.push(raw.to_string());
    }
    lines
}

/// Whether `line` opens or closes a card. A soft break never joins one: a value that
/// dangles on `=` before `END:VCARD` stays a broken field, and the card closes.
fn is_card_boundary(line: &str) -> bool {
    let upper = line.trim().to_ascii_uppercase();
    upper == "END:VCARD" || upper == "BEGIN:VCARD"
}

/// `text` with every control character (ESC, CR, LF, the rest of C0 and C1) replaced by a
/// space, so a decoded value cannot hide a name from the dictionary or move a terminal.
fn controls_as_spaces(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Whether `line` is a quoted-printable property whose value ends in a soft break.
fn soft_break(line: &str) -> bool {
    let head = line.split_once(':').map_or("", |(head, _)| head);
    line.ends_with('=') && head.to_ascii_uppercase().contains("QUOTED-PRINTABLE")
}

/// Split `value` at each `sep` that is not escaped by a backslash. The parts
/// keep their escapes; [`unescape`] reads them.
fn split_raw(value: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (index, c) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == sep {
            parts.push(&value[start..index]);
            start = index + c.len_utf8();
        }
    }
    parts.push(&value[start..]);
    parts
}

/// Read the vCard escapes: `\,` `\;` `\\` and `\n`.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push(' '),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// `value` without `scheme` (case-insensitive), when it starts with it. A v4
/// `TEL` may be a URI such as `tel:+33…`; a v3 `EMAIL` may be `mailto:…`.
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> &'a str {
    let value = value.trim();
    match value.get(..scheme.len()) {
        Some(head) if head.eq_ignore_ascii_case(scheme) => &value[scheme.len()..],
        _ => value,
    }
}

/// Split a CSV or vCard text into rows of cells (RFC 4180: quotes, doubled
/// quotes, CRLF or LF). Blank lines are dropped.
fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    // A French Excel export separates its columns with `;`, not `,`.
    let head = text.split('\n').next().unwrap_or_default().replace('"', "");
    let many_semicolons = head.matches(';').count() > head.matches(',').count();
    let separator = if many_semicolons { ';' } else { ',' };
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c != '"' {
                field.push(c);
            } else if chars.peek() == Some(&'"') {
                chars.next();
                field.push('"');
            } else {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            c if c == separator => row.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows.retain(|row| row.iter().any(|cell| !cell.trim().is_empty()));
    rows
}

/// Split a name into its words: `van der Merwe` → `van`, `der`, `Merwe`.
fn words(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_string).collect()
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Give a person without a display name the name built from the given and family names.
fn finish(mut person: Parsed) -> Parsed {
    if person.display_name.is_none() && (!person.given.is_empty() || !person.family.is_empty()) {
        let full: Vec<&str> = person
            .given
            .iter()
            .chain(person.family.iter())
            .map(String::as_str)
            .collect();
        person.display_name = Some(full.join(" "));
    }
    person
}

/// A store failure, worded for the contacts commands and the daemon.
pub fn store_error(err: aux_store::StoreError) -> String {
    format!("the contact store: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hubspot_header_is_read() {
        let text = "First Name,Last Name,Email,Phone Number,Mobile Phone Number,Company Name\n\
                    Camille,Exemple,camille@exemple.test,+33 6 00 00 00 11,+33 6 00 00 00 12,Atelier\n";
        let (people, report) = parse_csv_report(text).unwrap();
        assert_eq!(people[0].display_name.as_deref(), Some("Camille Exemple"));
        assert_eq!(people[0].emails, ["camille@exemple.test"]);
        assert_eq!(people[0].phones.len(), 2);
        assert!(report.unmapped.is_empty());
        assert_eq!(report.mapped[5], ("Company Name".to_string(), "company"));
        assert_eq!(people[0].card.notes, ["Company: Atelier"]);
    }

    #[test]
    fn pipedrive_header_is_read() {
        let text = "Person - Name,Person - Email,Person - Phone,Organization - Name\n\
                    Camille Exemple,camille@exemple.test,+33 6 00 00 00 11,Atelier\n";
        let (people, report) = parse_csv_report(text).unwrap();
        assert_eq!(people[0].display_name.as_deref(), Some("Camille Exemple"));
        assert_eq!(people[0].phones, ["+33 6 00 00 00 11"]);
        assert_eq!(report.mapped[0], ("Person - Name".to_string(), "name"));
        assert_eq!(
            report.mapped[3],
            ("Organization - Name".to_string(), "company")
        );
    }

    #[test]
    fn rows_with_nothing_the_import_reads_are_counted() {
        let text = "Name,Email,Notes\nCamille Exemple,,Atelier\n,,Orphan\n";
        let (people, report) = parse_csv_report(text).unwrap();
        assert_eq!(people.len(), 1);
        assert_eq!(report.dropped_rows, 1);
    }

    #[test]
    fn a_directory_is_not_a_contact_file() {
        // A directory created for this test, not `std::env::temp_dir()`: on
        // this host the temp dir can be `/tmp`, itself a symlink, which
        // O_NOFOLLOW rejects before the directory check is reached.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_text(dir.path()).unwrap_err(),
            "the path is not a regular file"
        );
    }

    const CARD: &str = "BEGIN:VCARD\nVERSION:3.0\nFN:Camille Exemple\nEND:VCARD\n";

    #[test]
    fn a_symlink_to_a_contact_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.vcf");
        std::fs::write(&real, CARD).unwrap();
        let link = dir.path().join("link.vcf");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(read_text(&link).unwrap_err(), "the path is a symbolic link");
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe.vcf");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        // No writer is open: a blocking open would hang here forever.
        assert_eq!(
            read_text(&fifo).unwrap_err(),
            "the path is not a regular file"
        );
    }

    #[test]
    fn a_file_under_a_linked_directory_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::write(real_dir.join("c.vcf"), CARD).unwrap();
        let linked_dir = dir.path().join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).unwrap();
        assert!(read_text(&linked_dir.join("c.vcf"))
            .unwrap()
            .contains("BEGIN:VCARD"));
    }

    #[test]
    fn a_french_semicolon_csv_is_read() {
        // A French Excel export separates its columns with `;`.
        let text = "Société;Email;Tel\nAtelier;c@x.test;0612345678\n";
        let (people, report) = parse_csv_report(text).unwrap();
        assert_eq!(people[0].emails, ["c@x.test"]);
        assert_eq!(people[0].phones, ["0612345678"]);
        assert_eq!(report.mapped.len(), 3);
    }

    #[test]
    fn a_google_export_header_is_mapped() {
        // The Google export numbers its columns: `Organization 1 - Name`,
        // `Address 1 - Street`.
        let text = "Name,Given Name,Family Name,Organization 1 - Type,\
                    Organization 1 - Name,Organization 1 - Title,Address 1 - Type,\
                    Address 1 - Formatted,Address 1 - Street,\
                    Address 1 - City,Address 1 - Postal Code,Address 1 - Country,\
                    Phone 1 - Type,Phone 1 - Value,E-mail 1 - Type,E-mail 1 - Value,\
                    Group Membership\n\
                    Camille Exemple,Camille,Exemple,Work,Atelier,Directrice,Home,\
                    \"12 rue de la Paix, Paris, 75011, France\",12 rue de la Paix,Paris,75011,\
                    France,Mobile,+33 6 12 34 56 78,Home,\
                    camille@example.invalid,Clients\n";
        let (people, _) = parse_csv_report(text).unwrap();
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].emails, ["camille@example.invalid"]);
        assert_eq!(people[0].phones, ["+33 6 12 34 56 78"]);
        // The address is shown once: the parts win over the formatted line.
        assert_eq!(
            people[0].card.address.as_deref(),
            Some("12 rue de la Paix, Paris, 75011, France")
        );
        let notes = &people[0].card.notes;
        assert!(notes.contains(&"Company: Atelier".to_string()), "{notes:?}");
        // The other organization columns are kept as note lines.
        assert!(
            notes.contains(&"Organization 1 - Title: Directrice".to_string()),
            "{notes:?}"
        );
    }

    #[test]
    fn a_vcard_iana_zone_is_read_and_reaches_the_contact_and_the_client_card() {
        let cards = parse_vcards(
            "BEGIN:VCARD\nVERSION:4.0\nFN:Camille Exemple\nTZ:Europe/Paris\nEND:VCARD\n\
             BEGIN:VCARD\nVERSION:4.0\nFN:Jonas Weber\nTZ:-05:00\nEND:VCARD\n",
        );
        assert_eq!(cards.people[0].time_zone.as_deref(), Some("Europe/Paris"));
        assert_eq!(cards.people[1].time_zone, None, "an offset is not a zone");
        assert_eq!(cards.time_zone_ignored, 1, "the report counts the offset");

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        let file = dir.path().join("contacts.vcf");
        std::fs::write(
            &file,
            "BEGIN:VCARD\nVERSION:4.0\nFN:Camille Exemple\nEMAIL:camille@example.test\n\
             TZ:Europe/Paris\nEND:VCARD\n\
             BEGIN:VCARD\nVERSION:4.0\nFN:Jonas Weber\nEMAIL:jonas@example.test\n\
             TZ:-05:00\nEND:VCARD\n",
        )
        .unwrap();
        let summary = import_file(&store, &file, None, None).unwrap();
        assert_eq!(summary.time_zone_ignored, 1);
        assert!(
            summary.to_string().contains("not an IANA name"),
            "the report says the offset was not kept: {summary}"
        );
        // `contacts` also holds the `crm` source the party seeding refreshed.
        let contacts: Vec<_> = store
            .contacts()
            .unwrap()
            .into_iter()
            .filter(|record| record.source == "file:contacts.vcf")
            .collect();
        assert_eq!(contacts[0].time_zone.as_deref(), Some("Europe/Paris"));
        assert_eq!(contacts[1].time_zone, None, "an offset is not a zone");
        let parties = store.parties().unwrap();
        assert_eq!(parties[0].time_zone.as_deref(), Some("Europe/Paris"));
        assert_eq!(parties[1].time_zone, None);
    }

    #[test]
    fn a_card_fill_failure_says_the_import_is_partially_imported() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = Store::open(&db).unwrap();
        let file = dir.path().join("contacts.csv");
        let text = "Name,Email,Address\nCamille,camille@exemple.test,1 rue\n";
        std::fs::write(&file, text).unwrap();
        // A party update that always fails: the client cards cannot be filled.
        let conn = aux_store::open_keyed(&db).unwrap();
        let trigger =
            "CREATE TRIGGER no_card BEFORE UPDATE ON party BEGIN SELECT RAISE(ABORT, 'no'); END;";
        conn.execute_batch(trigger).unwrap();
        drop(conn);

        let err = import_file(&store, &file, None, None).unwrap_err();
        assert!(err.contains("partially imported"), "{err}");
        // The error says what was saved and what was not.
        assert!(err.contains("1 contact(s) saved"), "{err}");
        assert!(err.contains("client cards were not filled"), "{err}");
    }

    #[test]
    fn the_dry_run_agrees_with_the_import() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        let file = dir.path().join("contacts.csv");
        // `camille@exemple` has no dotted domain: it is not an e-mail address.
        // Jonas is one contact with two addresses: the card keeps the first.
        let text = "Name,Email,Address\nCamille,camille@exemple,1 rue\n\
                    Jonas,jonas@x.test,1 rue\nJonas,jonas@x.test,2 rue\n";
        std::fs::write(&file, text).unwrap();
        let preview = preview_file(&store, &file, None).unwrap();
        let summary = import_file(&store, &file, None, None).unwrap();
        // The bad row is refused once: as a party and as a card, it is one row.
        assert_eq!(summary.parties_refused, 1, "{summary:?}");
        // The dry run refuses the same rows, and finds the same conflicts.
        assert_eq!(preview.would_refuse, summary.parties_refused);
        assert_eq!(preview.conflicts, summary.conflicts);
        assert_eq!(summary.conflicts, 1);
    }

    #[test]
    fn a_company_named_twice_is_one_party() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        let file = dir.path().join("contacts.csv");
        // The same company, once without an e-mail address and once with one.
        std::fs::write(&file, "Company,Email\nAcme,\nAcme,info@acme.test\n").unwrap();
        let summary = import_file(&store, &file, None, None).unwrap();
        // One party, not two: the second row finds the first one.
        assert_eq!(summary.parties_created, 1, "{summary:?}");
        assert_eq!(summary.parties_updated, 1, "{summary:?}");
    }

    #[test]
    fn two_people_who_share_a_name_but_not_an_email_stay_two() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        let file = dir.path().join("contacts.csv");
        std::fs::write(
            &file,
            "Name,Email\nJean Martin,jean@alpha.test\nJean Martin,jean@beta.test\n",
        )
        .unwrap();
        let summary = import_file(&store, &file, None, None).unwrap();
        assert_eq!(summary.parties_created, 2, "{summary:?}");
    }
}
