//! `aux-crm` — the owner's clients, stored locally and tokenised on the way out.
//!
//! This crate owns the CRM logic; [`aux_store`] owns the SQLCipher tables and
//! the migration that creates them. The CRM contract moved out of this
//! repository (see `docs/README.md`). A party is a person or a company, with
//! every name variant the owner wants masked, its addresses and its E.164
//! numbers at rest. The real values never leave the Mac: anything read into a
//! provider context goes through the kernel's `admit()` and gate like any other
//! text.
//!
//! # The one invariant: every party write refreshes the contacts index
//!
//! The CRM is a contacts source named `crm`, enabled by default. Every write
//! through [`Crm`] (create, update, archive, forget, merge) rebuilds that source
//! in the `contacts` table, so the kernel's union mount sees the party on the
//! next provider call with no other step. The acceptance test for that property
//! lives in `auxd` (it builds the real turn and a fake provider); the tests here
//! prove the store side of the same contract.
//!
//! # Phones are E.164
//!
//! A number that is already E.164 passes through. A national number needs an
//! explicit country: [`to_e164`] returns [`CrmError::UnknownCountry`] rather
//! than guessing, so nothing is ever read against France by default.

pub mod skills;
pub mod timeline;

use aux_store::{Store, StoreError};

pub use aux_store::{Followup, Interaction, NewParty, Party, PartyKind, CRM_CONTACT_SOURCE};
pub use skills::{
    CrmToday, DueFollowupView, InteractionDraft, LoggedInteraction, MemoryDraft, PartyBrief,
    PartyMatch, LOG_INTERACTION_PROVENANCE,
};
pub use timeline::{CalendarEvent, Direction, MailThread};

/// The tag on a party the owner added from a suggestion.
pub const PROSPECT_TAG: &str = "prospect";

/// Why a CRM write was refused. A refusal happens before any row is written.
#[derive(Debug, thiserror::Error)]
pub enum CrmError {
    /// The store rejected the write.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A party with no display name would have nothing to show or mask.
    #[error("a party needs a display name")]
    EmptyDisplayName,
    /// The origin is the audit trail of where a party came from.
    #[error("a party needs an origin such as `owner`")]
    EmptyOrigin,
    /// An e-mail address that is not one.
    #[error("`{value}` is not an e-mail address")]
    InvalidEmail {
        /// The value as written, so the caller can correct it.
        value: String,
    },
    /// A value that claims to be a time zone but is not an IANA name.
    #[error("`{value}` is not an IANA time zone such as Europe/Paris")]
    InvalidTimeZone {
        /// The value as written, so the caller can correct it.
        value: String,
    },
    /// A national phone number and no country to read it against.
    #[error("`{raw}` is a national phone number and no country is known; a country is required, none is assumed")]
    UnknownCountry {
        /// The number as written.
        raw: String,
    },
    /// A phone number E.164 cannot hold.
    #[error("`{raw}` is not a phone number E.164 can hold")]
    InvalidPhone {
        /// The number as written.
        raw: String,
    },
    /// An id that resolved to no live party.
    #[error("party {id} not found")]
    PartyNotFound {
        /// The requested id.
        id: i64,
    },
    /// A merge whose source or target is not a live party.
    #[error("parties {from} and {to} cannot be merged")]
    MergeRefused {
        /// The source id.
        from: i64,
        /// The target id.
        to: i64,
    },
    /// A follow-up date that is not a calendar date.
    #[error("`{value}` is not a date a follow-up can be due on")]
    InvalidDue {
        /// The value as written, so the caller can correct it.
        value: String,
    },
    /// A follow-up with no author would have no provenance.
    #[error("a follow-up needs a created-by reference")]
    EmptyCreatedBy,
    /// A follow-up with no reason would say nothing.
    #[error("a follow-up needs a note")]
    EmptyFollowupNote,
    /// A thread reference that cannot be stored: empty, over 998 bytes, or
    /// carrying a control character.
    #[error("a mail thread needs a bounded, control-free message id")]
    InvalidMessageId,
    /// The kernel gate refused to issue the summary, so nothing is stored.
    #[error("the kernel gate refused to issue the summary")]
    SummaryRefused,
    /// A log-interaction kind outside the interaction contract.
    #[error("`{value}` is not a kind an interaction can be")]
    InvalidInteractionKind {
        /// The value as written, so the caller can correct it.
        value: String,
    },
    /// A logged interaction with no timestamp.
    #[error("a logged interaction needs a time")]
    EmptyInteractionAt,
    /// A logged interaction with no source reference.
    #[error("a logged interaction needs a source reference")]
    EmptySourceRef,
    /// A logged interaction with no summary.
    #[error("a logged interaction needs a summary")]
    EmptyInteractionSummary,
    /// A memory kind outside the memory contract.
    #[error("`{value}` is not a memory kind")]
    InvalidMemoryKind {
        /// The value as written, so the caller can correct it.
        value: String,
    },
    /// A memory item with no title.
    #[error("a memory item needs a title")]
    EmptyMemoryTitle,
    /// A memory item with no body.
    #[error("a memory item needs a body")]
    EmptyMemoryBody,
}

/// What a seeding write did to the party a draft named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seeded {
    /// No live party matched, so a new one was stored.
    Created(Party),
    /// A live party matched and the draft added names, addresses or numbers to it.
    Updated(Party),
    /// A live party matched and already held everything the draft says.
    Unchanged(Party),
}

impl Seeded {
    /// The party, whichever way the write went.
    pub fn party(&self) -> &Party {
        match self {
            Seeded::Created(party) | Seeded::Updated(party) | Seeded::Unchanged(party) => party,
        }
    }
}

/// A country a national phone number can be read against: the ISO code, the
/// calling code, and the trunk prefix an international number drops.
struct Country {
    iso: &'static str,
    calling: &'static str,
    trunk: &'static str,
}

/// The countries this build knows. A country outside the list is
/// [`CrmError::UnknownCountry`], never a guess.
const COUNTRIES: &[Country] = &[
    Country {
        iso: "BE",
        calling: "32",
        trunk: "0",
    },
    Country {
        iso: "CH",
        calling: "41",
        trunk: "0",
    },
    Country {
        iso: "CN",
        calling: "86",
        trunk: "0",
    },
    Country {
        iso: "DE",
        calling: "49",
        trunk: "0",
    },
    Country {
        iso: "ES",
        calling: "34",
        trunk: "",
    },
    Country {
        iso: "FR",
        calling: "33",
        trunk: "0",
    },
    Country {
        iso: "GB",
        calling: "44",
        trunk: "0",
    },
    Country {
        iso: "HU",
        calling: "36",
        trunk: "06",
    },
    Country {
        iso: "IT",
        calling: "39",
        trunk: "",
    },
    Country {
        iso: "NL",
        calling: "31",
        trunk: "0",
    },
    Country {
        iso: "PT",
        calling: "351",
        trunk: "",
    },
    Country {
        iso: "SI",
        calling: "386",
        trunk: "0",
    },
    Country {
        iso: "US",
        calling: "1",
        // NANP national numbers are written with the leading `1` (`1 (202)
        // 555-0100`); the international form drops it.
        trunk: "1",
    },
    Country {
        iso: "ZA",
        calling: "27",
        trunk: "0",
    },
];

/// One row of [`Crm::recent`]: a live party and its latest interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyActivity {
    /// The party.
    pub party: Party,
    /// When the latest interaction happened (UTC), if any.
    pub last_interaction_at: Option<String>,
}

pub fn latest_contact_at(interactions: &[Interaction]) -> Option<String> {
    interactions
        .iter()
        .map(|interaction| interaction.at.clone())
        .max_by(|a, b| instant(a).cmp(&instant(b)))
}

/// A timeline time safe to send or show: the stored value only when it is
/// strict RFC 3339, otherwise the store's own clock (old rows are untrusted).
pub fn safe_interaction_at(store: &Store, at: &str) -> String {
    let at = at.trim();
    if chrono::DateTime::parse_from_rfc3339(at).is_ok() {
        at.to_string()
    } else {
        // A local statement; a fixed instant still beats model text.
        store
            .now_rfc3339()
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
    }
}

/// One page of [`Crm::recent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentPage {
    /// The page's rows.
    pub rows: Vec<PartyActivity>,
    /// Every matching party, before the page.
    pub total: usize,
}

/// The CRM over one open store.
///
/// Every write method validates and normalises the draft, then calls the store,
/// whose party writes refresh the `crm` contacts source inside the same
/// transaction. The index therefore cannot lag a party write, whoever calls the
/// store API.
pub struct Crm<'a> {
    store: &'a Store,
}

impl<'a> Crm<'a> {
    /// A CRM over `store`.
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// Create a party and refresh the contacts index. Returns the stored party.
    pub fn create(&self, draft: NewParty) -> Result<Party, CrmError> {
        let draft = normalise(draft)?;
        let id = self.store.insert_party(&draft)?;
        self.stored(id)
    }

    /// One party by id, archived or not.
    pub fn get(&self, id: i64) -> Result<Option<Party>, CrmError> {
        Ok(self.store.party(id)?)
    }

    /// The live (non-archived) parties, oldest first.
    pub fn list(&self) -> Result<Vec<Party>, CrmError> {
        Ok(self.store.parties()?)
    }

    /// Every live party's e-mail address and its stored IANA time zone, the
    /// address lower-case. A party without a zone, or with one the store no
    /// longer holds as an IANA name, adds nothing: a stored value is validated
    /// before it is used, never trusted blindly.
    pub fn client_time_zones(&self) -> Result<Vec<(String, String)>, CrmError> {
        let mut zones = Vec::new();
        for party in self.store.parties()? {
            let Some(zone) = party.time_zone.as_deref().and_then(valid_time_zone) else {
                continue;
            };
            for email in &party.emails {
                zones.push((email.to_ascii_lowercase(), zone.clone()));
            }
        }
        Ok(zones)
    }

    /// One page of the live parties, newest activity first: by latest
    /// interaction, then parties with none by last write. `kind` filters;
    /// `total` counts every match before the page.
    pub fn recent(
        &self,
        kind: Option<PartyKind>,
        offset: usize,
        limit: usize,
    ) -> Result<RecentPage, CrmError> {
        let mut rows = Vec::new();
        for party in self.list()? {
            if kind.is_some_and(|kind| kind != party.kind) {
                continue;
            }
            let interactions = self.store.interactions_for_party(party.id)?;
            let last_interaction_at = latest_contact_at(&interactions);
            rows.push(PartyActivity {
                party,
                last_interaction_at,
            });
        }
        rows.sort_by(|a, b| {
            let (a_at, b_at) = (
                a.last_interaction_at.as_deref().map(instant),
                b.last_interaction_at.as_deref().map(instant),
            );
            b_at.cmp(&a_at)
                .then_with(|| b.party.updated_at.cmp(&a.party.updated_at))
                .then_with(|| b.party.id.cmp(&a.party.id))
        });
        let total = rows.len();
        let rows = rows.into_iter().skip(offset).take(limit).collect();
        Ok(RecentPage { rows, total })
    }

    /// Overwrite a live party and refresh the contacts index. Returns the stored
    /// party; an unknown or archived id is [`CrmError::PartyNotFound`].
    pub fn update(&self, id: i64, draft: NewParty) -> Result<Party, CrmError> {
        let draft = normalise(draft)?;
        if !self.store.update_party(id, &draft)? {
            return Err(CrmError::PartyNotFound { id });
        }
        self.stored(id)
    }

    /// Archive a live party; its rows stay, its names leave the index.
    pub fn archive(&self, id: i64) -> Result<(), CrmError> {
        if !self.store.archive_party(id)? {
            return Err(CrmError::PartyNotFound { id });
        }
        Ok(())
    }

    /// Hard-delete a party, its interactions, follow-ups and memory items. The
    /// store audits the delete.
    pub fn forget(&self, id: i64) -> Result<(), CrmError> {
        if !self.store.forget_party(id)? {
            return Err(CrmError::PartyNotFound { id });
        }
        Ok(())
    }

    /// Merge `from` into `to`.
    pub fn merge(&self, from: i64, to: i64) -> Result<(), CrmError> {
        if !self.store.merge_parties(from, to)? {
            return Err(CrmError::MergeRefused { from, to });
        }
        Ok(())
    }

    /// Seed a batch of contacts. Each draft creates the party it describes, or
    /// updates the live party it matches: one with the same e-mail address or the
    /// same E.164 number. A draft with neither matches a live party with the same
    /// origin and display name, so a re-run never duplicates a contact. The index
    /// is refreshed once, after the batch. A refused draft is an error for that
    /// entry only; the others are still written.
    pub fn seed_batch(
        &self,
        drafts: Vec<NewParty>,
    ) -> Result<Vec<Result<Seeded, CrmError>>, CrmError> {
        let mut live = self.store.parties()?;
        let results = drafts
            .into_iter()
            .map(|draft| self.seed_one(draft, &mut live))
            .collect();
        self.sync()?;
        Ok(results)
    }

    /// Promote an unknown mail sender to a party in one step: a person with the
    /// sender's name (the address, when the mail gives none) and address, origin
    /// `mail:<account>`. The owner confirmed it, so the event log records
    /// `source=mail confirmed_by=owner` with the id, never the name. A sender that
    /// a live party already holds is returned as it is: promoting twice changes
    /// nothing.
    pub fn promote_sender(
        &self,
        account: &str,
        name: &str,
        email: &str,
    ) -> Result<Seeded, CrmError> {
        let account = account.trim();
        if account.is_empty() {
            return Err(CrmError::EmptyOrigin);
        }
        let display_name = if name.trim().is_empty() { email } else { name };
        let draft = normalise(NewParty {
            kind: PartyKind::Person,
            display_name: display_name.to_string(),
            emails: vec![email.to_string()],
            origin: format!("mail:{account}"),
            ..NewParty::default()
        })?;
        let live = self.store.parties()?;
        if let Some(index) = matching(&live, &draft) {
            return Ok(Seeded::Unchanged(live[index].clone()));
        }
        let id = self.store.insert_party(&draft)?;
        self.store.log_event(
            "crm.party_promoted",
            &format!("{{\"id\":{id},\"source\":\"mail\",\"confirmed_by\":\"owner\"}}"),
        )?;
        self.sync()?;
        Ok(Seeded::Created(self.stored(id)?))
    }

    /// Add a suggested sender as a prospect: [`Crm::promote_sender`], then the
    /// `prospect` tag on a party this call created. A party that already holds the
    /// address keeps its tags, so a client is never demoted.
    pub fn add_prospect(&self, account: &str, name: &str, email: &str) -> Result<Seeded, CrmError> {
        let seeded = self.promote_sender(account, name, email)?;
        let Seeded::Created(party) = &seeded else {
            return Ok(seeded);
        };
        let mut draft = NewParty::from(party);
        draft.tags.push(PROSPECT_TAG.to_string());
        Ok(Seeded::Created(self.update(party.id, draft)?))
    }

    /// Never suggest this sender again.
    pub fn ignore_prospect(&self, email: &str) -> Result<(), CrmError> {
        Ok(self.store.ignore_sender(email)?)
    }

    /// Rebuild the `crm` contacts source from the live parties. The write
    /// methods already do this in their transaction; it is public for an
    /// importer that writes many rows before one refresh.
    pub fn sync(&self) -> Result<(), CrmError> {
        self.store.sync_crm_contacts()?;
        Ok(())
    }

    /// One draft of a seed batch, written without refreshing the index. `live` holds the
    /// live parties as the batch has left them, so a match needs no store read.
    fn seed_one(&self, draft: NewParty, live: &mut Vec<Party>) -> Result<Seeded, CrmError> {
        let draft = normalise(draft)?;
        let Some(index) = matching(live, &draft) else {
            let id = self.store.insert_party(&draft)?;
            let stored = self.stored(id)?;
            live.push(stored.clone());
            return Ok(Seeded::Created(stored));
        };
        let current = live[index].clone();
        let grown = grown(&current, &draft);
        if grown.name_variants == current.name_variants
            && grown.emails == current.emails
            && grown.phones == current.phones
            && grown.time_zone == current.time_zone
        {
            return Ok(Seeded::Unchanged(current));
        }
        if !self.store.update_party(current.id, &grown)? {
            return Err(CrmError::PartyNotFound { id: current.id });
        }
        let stored = self.stored(current.id)?;
        live[index] = stored.clone();
        Ok(Seeded::Updated(stored))
    }

    /// Fill the cards of the live parties that import rows match (same rule as
    /// [`Crm::seed_batch`]) with the rows' kind, address, tags and notes; see
    /// [`card_filled`]. A row that matches nothing or is refused changes nothing.
    /// Returns the conflicts: values the card already held otherwise and kept.
    pub fn fill_cards(&self, drafts: Vec<NewParty>) -> Result<usize, CrmError> {
        let mut live = self.store.parties()?;
        let mut conflicts = 0;
        for draft in drafts {
            let Ok(draft) = normalise(draft) else {
                continue;
            };
            let Some(index) = matching(&live, &draft) else {
                continue;
            };
            let (filled, clashes) = card_filled(&live[index], &draft);
            conflicts += clashes;
            if filled != NewParty::from(&live[index])
                && self.store.update_party(live[index].id, &filled)?
            {
                live[index] = self.stored(live[index].id)?;
            }
        }
        self.sync()?;
        Ok(conflicts)
    }

    /// Read back a party after a successful write; a row that just committed is
    /// there, so a miss is a store inconsistency, not a missing id.
    /// The store this CRM writes through; the timeline module reads parties
    /// and writes interactions and follow-ups here.
    pub(crate) fn store_ref(&self) -> &Store {
        self.store
    }

    fn stored(&self, id: i64) -> Result<Party, CrmError> {
        self.store.party(id)?.ok_or(CrmError::PartyNotFound { id })
    }
}

/// Put a phone number in E.164. A `+` number (or a `00` prefix) is already
/// international; a national number is read against `country`, and a missing or
/// unknown country is [`CrmError::UnknownCountry`].
pub fn to_e164(raw: &str, country: Option<&str>) -> Result<String, CrmError> {
    let body = raw.split(char::is_alphabetic).next().unwrap_or_default();
    // `+33 (0)6 …` is the French habit of printing the trunk `0` in brackets.
    let body = body.replace("(0)", "");
    let body = body.trim();
    let stray_plus = body.contains('+') && !body.starts_with('+');
    let stray_symbol = body
        .chars()
        .any(|c| !(c.is_ascii_digit() || " .-()/+".contains(c)));
    if stray_plus || stray_symbol {
        return Err(CrmError::InvalidPhone {
            raw: raw.to_string(),
        });
    }
    let digits: String = body.chars().filter(char::is_ascii_digit).collect();
    let international = if body.starts_with('+') {
        digits
    } else if let Some(rest) = digits.strip_prefix("00") {
        rest.to_string()
    } else {
        let iso = country.ok_or_else(|| CrmError::UnknownCountry {
            raw: raw.to_string(),
        })?;
        let country = COUNTRIES
            .iter()
            .find(|known| known.iso.eq_ignore_ascii_case(iso))
            .ok_or_else(|| CrmError::UnknownCountry {
                raw: raw.to_string(),
            })?;
        let national = match digits.strip_prefix(country.trunk) {
            Some(rest) if !country.trunk.is_empty() => rest,
            _ => digits.as_str(),
        };
        format!("{}{national}", country.calling)
    };
    // E.164 holds at most 15 digits; no number is shorter than 8 with its code.
    let valid = (8..=15).contains(&international.len())
        && !international.starts_with('0')
        && international.bytes().all(|byte| byte.is_ascii_digit());
    if !valid {
        return Err(CrmError::InvalidPhone {
            raw: raw.to_string(),
        });
    }
    Ok(format!("+{international}"))
}

/// The ISO codes [`to_e164`] reads a national number against.
pub fn country_codes() -> impl Iterator<Item = &'static str> {
    COUNTRIES.iter().map(|known| known.iso)
}

/// The index in `live` of the party a draft is the same person as: one that holds one of
/// its e-mail addresses or E.164 numbers. A draft with neither matches on origin and
/// display name; a row whose number no party holds falls back on the same row.
pub fn matching(live: &[Party], draft: &NewParty) -> Option<usize> {
    let found = live.iter().position(|party| {
        if draft.emails.is_empty() && draft.phones.is_empty() {
            party.origin == draft.origin && party.display_name == draft.display_name
        } else {
            draft
                .emails
                .iter()
                .any(|email| party.emails.contains(email))
                || draft
                    .phones
                    .iter()
                    .any(|phone| party.phones.contains(phone))
        }
    });
    // A row whose number no party holds is the row named the same way when one
    // side carries no address at all (a company row, then the same company with
    // its e-mail): two people who share a name but hold different e-mails stay two.
    found.or_else(|| {
        live.iter().position(|party| {
            party.origin == draft.origin
                && party.display_name == draft.display_name
                && (party.emails.is_empty() && party.phones.is_empty()
                    || draft.emails.is_empty() && draft.phones.is_empty())
        })
    })
}

/// The live party after a draft is seeded into it: its own name, origin, addresses,
/// tags and notes stay, and the draft's names, addresses and numbers join its lists.
/// A draft name that differs from the party's display name is kept as a variant, so
/// the index still masks it.
fn grown(live: &Party, draft: &NewParty) -> NewParty {
    let mut name_variants = live.name_variants.clone();
    for variant in draft
        .name_variants
        .iter()
        .chain(std::iter::once(&draft.display_name))
    {
        if *variant != live.display_name {
            push_unique(&mut name_variants, variant.clone());
        }
    }
    let mut emails = live.emails.clone();
    for email in &draft.emails {
        push_unique(&mut emails, email.clone());
    }
    let mut phones = live.phones.clone();
    for phone in &draft.phones {
        push_unique(&mut phones, phone.clone());
    }
    NewParty {
        kind: live.kind,
        display_name: live.display_name.clone(),
        name_variants,
        emails,
        phones,
        addresses: live.addresses.clone(),
        tags: live.tags.clone(),
        notes: live.notes.clone(),
        // An import that carries no zone keeps the card's, never clears it.
        time_zone: draft.time_zone.clone().or_else(|| live.time_zone.clone()),
        origin: live.origin.clone(),
    }
}

/// The conflicts [`Crm::fill_cards`] would report for `draft` against `live`, written
/// nowhere: 0 when the draft matches no live party or is refused.
pub fn card_conflicts(live: &[Party], draft: NewParty) -> usize {
    let Ok(draft) = normalise(draft) else {
        return 0;
    };
    matching(live, &draft).map_or(0, |index| card_filled(&live[index], &draft).1)
}

/// The live party once an import row's card is put in it, and the conflicts. A value
/// the card holds is never overwritten: tags and note lines are appended without
/// repeats (within the store caps), the address is set only on a card that has none,
/// and a different address is a conflict. The party becomes a company only when the
/// row names a company and the card carries that very name.
pub fn card_filled(live: &Party, draft: &NewParty) -> (NewParty, usize) {
    let mut card = NewParty::from(live);
    let mut conflicts = 0;
    if draft.kind == PartyKind::Company && live.display_name == draft.display_name {
        card.kind = PartyKind::Company;
    }
    for address in &draft.addresses {
        if card.addresses.is_empty() {
            card.addresses.push(address.clone());
        } else if !card.addresses.contains(address) {
            conflicts += 1;
        }
    }
    for tag in &draft.tags {
        if card.tags.len() < aux_store::PARTY_LIST_MAX {
            push_unique(&mut card.tags, tag.clone());
        }
    }
    for line in draft.notes.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let fits = card.notes.len() + line.len() < aux_store::PARTY_NOTES_MAX_BYTES;
        if fits && !card.notes.lines().any(|have| have.trim() == line) {
            if !card.notes.is_empty() {
                card.notes.push('\n');
            }
            card.notes.push_str(line);
        }
    }
    (card, conflicts)
}

/// The key of a refused row: the reason the CRM gives for it.
pub fn refusal(draft: &NewParty) -> Option<String> {
    normalise(draft.clone()).err().map(|err| err.to_string())
}

/// Normalise a draft before the store sees it: trimmed names, lower-case
/// e-mails, E.164 phones and no duplicate list entries.
fn normalise(draft: NewParty) -> Result<NewParty, CrmError> {
    let display_name = draft.display_name.trim().to_string();
    if display_name.is_empty() {
        return Err(CrmError::EmptyDisplayName);
    }
    let origin = draft.origin.trim().to_string();
    if origin.is_empty() {
        return Err(CrmError::EmptyOrigin);
    }
    let mut emails = Vec::new();
    for raw in &draft.emails {
        let email = raw.trim().to_ascii_lowercase();
        if !looks_like_email(&email) {
            return Err(CrmError::InvalidEmail { value: raw.clone() });
        }
        push_unique(&mut emails, email);
    }
    let mut phones = Vec::new();
    for raw in &draft.phones {
        let e164 = to_e164(raw, None)?;
        push_unique(&mut phones, e164);
    }
    let mut name_variants = Vec::new();
    for raw in &draft.name_variants {
        let variant = raw.trim();
        if !variant.is_empty() {
            push_unique(&mut name_variants, variant.to_string());
        }
    }
    let time_zone = match draft.time_zone.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => Some(
            valid_time_zone(raw).ok_or_else(|| CrmError::InvalidTimeZone {
                value: raw.to_string(),
            })?,
        ),
    };
    Ok(NewParty {
        kind: draft.kind,
        display_name,
        name_variants,
        emails,
        phones,
        addresses: trim_list(&draft.addresses),
        tags: trim_list(&draft.tags),
        notes: draft.notes.trim().to_string(),
        time_zone,
        origin,
    })
}

/// The IANA time zone `raw` names, trimmed, or `None` when it does not name
/// one. A UTC offset (`-05:00`) is not a zone; `UTC` is.
pub fn valid_time_zone(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty() {
        return None;
    }
    name.parse::<chrono_tz::Tz>().ok().map(|_| name.to_string())
}

/// Whether `value` looks like one mailbox: one `@`, a non-empty local part and a
/// dotted domain, no whitespace.
fn looks_like_email(value: &str) -> bool {
    if value.contains(char::is_whitespace) {
        return false;
    }
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

/// Trim every entry, drop the empty ones and keep the first of a duplicate.
fn trim_list(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty() {
            push_unique(&mut out, value.to_string());
        }
    }
    out
}

/// Append `value` unless the list already holds it.
fn push_unique(target: &mut Vec<String>, value: String) {
    if !target.contains(&value) {
        target.push(value);
    }
}

/// An interaction time as an instant, so `10:00+02:00` sorts before `09:30Z`.
/// A value that is not RFC 3339 sorts before every parsed one, by its text.
fn instant(at: &str) -> (Option<chrono::DateTime<chrono::Utc>>, &str) {
    let parsed = chrono::DateTime::parse_from_rfc3339(at)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc));
    (parsed, at)
}

/// A fictional person party, the fixture every test starts from.
#[cfg(test)]
fn camille() -> NewParty {
    NewParty {
        kind: PartyKind::Person,
        display_name: "Camille Exemple".to_string(),
        name_variants: vec!["Camille".to_string(), "Exemple".to_string()],
        emails: vec!["Camille.Exemple@Exemple.test".to_string()],
        phones: vec!["+33612345678".to_string()],
        addresses: vec!["1 rue du Test".to_string()],
        tags: vec!["client".to_string()],
        notes: "note".to_string(),
        time_zone: None,
        origin: "owner".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn a_client_zone_is_validated_and_reaches_the_directory_map() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let mut draft = camille();
        draft.time_zone = Some("Europe/Paris".to_string());
        let party = crm.create(draft).unwrap();
        assert_eq!(party.time_zone.as_deref(), Some("Europe/Paris"));
        assert_eq!(
            crm.client_time_zones().unwrap(),
            vec![(
                "camille.exemple@exemple.test".to_string(),
                "Europe/Paris".to_string()
            )]
        );

        // A UTC offset is not a zone: the write is refused, nothing guessed.
        let mut bad = camille();
        bad.display_name = "Jonas Weber".to_string();
        bad.emails = vec!["jonas@example.test".to_string()];
        bad.time_zone = Some("-05:00".to_string());
        assert!(matches!(
            crm.create(bad),
            Err(CrmError::InvalidTimeZone { .. })
        ));
        assert_eq!(crm.list().unwrap().len(), 1);

        // A card without a zone adds nothing to the directory.
        let mut cleared = NewParty::from(&crm.get(party.id).unwrap().unwrap());
        cleared.time_zone = None;
        crm.update(party.id, cleared).unwrap();
        assert!(crm.client_time_zones().unwrap().is_empty());
    }

    fn crm_contacts(store: &Store) -> Vec<aux_store::ContactRecord> {
        store
            .contacts()
            .unwrap()
            .into_iter()
            .filter(|record| record.source == CRM_CONTACT_SOURCE)
            .collect()
    }

    #[test]
    fn recent_orders_by_instant_not_by_text() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let utc = crm.create(camille()).unwrap();
        let mut other = camille();
        other.display_name = "Person Two".to_string();
        other.name_variants = vec!["Person Two".to_string()];
        other.emails = vec!["person2@fixture.test".to_string()];
        let paris = crm.create(other).unwrap();
        // 10:00+02:00 is 08:00Z, older than 09:30Z, though its text sorts later.
        store
            .insert_interaction(utc.id, "note", "2026-10-18T09:30:00Z", "a", "s", "test")
            .unwrap();
        store
            .insert_interaction(
                paris.id,
                "note",
                "2026-10-18T10:00:00+02:00",
                "b",
                "s",
                "test",
            )
            .unwrap();
        let page = crm.recent(None, 0, 10).unwrap();
        let ids: Vec<i64> = page.rows.iter().map(|row| row.party.id).collect();
        assert_eq!(ids, vec![utc.id, paris.id]);
    }

    #[test]
    fn to_e164_passes_international_and_reads_national_with_a_country() {
        assert_eq!(to_e164("+33612345678", None).unwrap(), "+33612345678");
        assert_eq!(to_e164("0033612345678", None).unwrap(), "+33612345678");
        assert_eq!(
            to_e164("06 12 34 56 78", Some("FR")).unwrap(),
            "+33612345678"
        );
        assert_eq!(
            to_e164("+33 (0)6 12 34 56 78", None).unwrap(),
            "+33612345678"
        );
    }

    #[test]
    fn the_national_trunk_of_each_country_is_dropped() {
        // France and the UK drop a leading `0`; the NANP national form carries
        // a leading `1` that the international form drops.
        assert_eq!(
            to_e164("06 12 34 56 78", Some("FR")).unwrap(),
            "+33612345678"
        );
        assert_eq!(
            to_e164("020 7946 0958", Some("GB")).unwrap(),
            "+442079460958"
        );
        assert_eq!(
            to_e164("1 (202) 555-0100", Some("US")).unwrap(),
            "+12025550100"
        );
        // The already-international NANP form is unchanged.
        assert_eq!(to_e164("+12025550100", None).unwrap(), "+12025550100");
    }

    #[test]
    fn a_national_number_without_a_known_country_is_a_typed_error() {
        assert!(matches!(
            to_e164("06 12 34 56 78", None),
            Err(CrmError::UnknownCountry { .. })
        ));
        // An ISO code this build does not know is not guessed either.
        assert!(matches!(
            to_e164("06 12 34 56 78", Some("XX")),
            Err(CrmError::UnknownCountry { .. })
        ));
        // A national number with no country is unknown, not invalid; an
        // international number E.164 cannot hold is invalid.
        assert!(matches!(
            to_e164("123", None),
            Err(CrmError::UnknownCountry { .. })
        ));
        assert!(matches!(
            to_e164("+123", None),
            Err(CrmError::InvalidPhone { .. })
        ));
        assert!(matches!(
            to_e164("+12345678901234567890", None),
            Err(CrmError::InvalidPhone { .. })
        ));
    }

    #[test]
    fn create_normalises_and_syncs_the_contacts_index() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let party = crm.create(camille()).unwrap();

        assert_eq!(party.display_name, "Camille Exemple");
        assert_eq!(party.emails, vec!["camille.exemple@exemple.test"]);
        assert_eq!(party.phones, vec!["+33612345678"]);

        let records = crm_contacts(&store);
        assert_eq!(records.len(), 1, "the party is one crm contact");
        assert_eq!(records[0].display_name.as_deref(), Some("Camille Exemple"));
        assert!(records[0].nicknames.contains(&"Camille".to_string()));
        assert!(records[0].nicknames.contains(&"Exemple".to_string()));
        assert_eq!(records[0].emails, vec!["camille.exemple@exemple.test"]);
        assert_eq!(records[0].phones, vec!["+33612345678"]);
    }

    #[test]
    fn a_bad_draft_is_refused_before_any_row_is_written() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);

        let mut empty = camille();
        empty.display_name = "   ".to_string();
        assert!(matches!(crm.create(empty), Err(CrmError::EmptyDisplayName)));

        let mut bad_email = camille();
        bad_email.emails = vec!["not-an-address".to_string()];
        assert!(matches!(
            crm.create(bad_email),
            Err(CrmError::InvalidEmail { .. })
        ));

        let mut national = camille();
        national.phones = vec!["06 12 34 56 78".to_string()];
        assert!(matches!(
            crm.create(national),
            Err(CrmError::UnknownCountry { .. })
        ));
        assert!(store.parties().unwrap().is_empty());
        assert!(crm_contacts(&store).is_empty());
    }

    #[test]
    fn every_write_refreshes_the_index() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let party = crm.create(camille()).unwrap();

        // Update: the new variant is in, the old one is gone.
        let mut edited = camille();
        edited.display_name = "Camille Exemple-Weber".to_string();
        edited.name_variants = vec!["Camille Exemple-Weber".to_string()];
        let edited = crm.update(party.id, edited).unwrap();
        assert_eq!(edited.display_name, "Camille Exemple-Weber");
        let records = crm_contacts(&store);
        assert_eq!(records.len(), 1);
        assert!(records[0]
            .nicknames
            .contains(&"Camille Exemple-Weber".to_string()));
        assert!(!records[0].nicknames.contains(&"Camille".to_string()));

        // Archive: the source is rebuilt empty.
        crm.archive(party.id).unwrap();
        assert!(crm_contacts(&store).is_empty());
        assert!(matches!(
            crm.update(party.id, camille()),
            Err(CrmError::PartyNotFound { .. })
        ));
    }

    #[test]
    fn merge_absorbs_the_source_and_refreshes_the_index() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let a = crm.create(camille()).unwrap();
        let mut second = camille();
        second.display_name = "C. Exemple".to_string();
        second.name_variants = vec!["Camille E.".to_string()];
        second.emails = vec!["c@exemple.test".to_string()];
        second.phones.clear();
        let b = crm.create(second).unwrap();

        crm.merge(a.id, b.id).unwrap();
        assert!(crm.get(a.id).unwrap().unwrap().archived);

        let records = crm_contacts(&store);
        assert_eq!(records.len(), 1, "only the live target is a crm contact");
        assert!(records[0].nicknames.contains(&"Camille".to_string()));
        assert!(records[0].nicknames.contains(&"Camille E.".to_string()));
        assert!(records[0].emails.contains(&"c@exemple.test".to_string()));
        assert!(matches!(
            crm.merge(a.id, b.id),
            Err(CrmError::MergeRefused { .. })
        ));
    }

    #[test]
    fn forget_removes_the_party_and_refreshes_the_index() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let party = crm.create(camille()).unwrap();
        assert_eq!(crm_contacts(&store).len(), 1);

        crm.forget(party.id).unwrap();
        assert!(crm.get(party.id).unwrap().is_none());
        assert!(crm_contacts(&store).is_empty());
        assert!(matches!(
            crm.forget(party.id),
            Err(CrmError::PartyNotFound { .. })
        ));
    }

    /// A fictional contact as the CSV or vCard import writes it.
    fn contact(name: &str, email: &str, phone: &str) -> NewParty {
        NewParty {
            display_name: name.to_string(),
            emails: vec![email.to_string()],
            phones: vec![phone.to_string()],
            origin: "contacts:file:crm-seed.vcf".to_string(),
            ..NewParty::default()
        }
    }

    #[test]
    fn cn_is_a_known_country_for_national_numbers() {
        assert!(country_codes().any(|iso| iso == "CN"));
        assert_eq!(
            to_e164("0138 0013 8000", Some("CN")).unwrap(),
            "+8613800138000"
        );
    }

    #[test]
    fn seeding_twice_never_duplicates_a_party() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let drafts = || {
            vec![
                contact(
                    "Camille Exemple",
                    "camille.exemple@exemple.test",
                    "+33612345678",
                ),
                contact("Jean Fictif", "jean.fictif@exemple.test", "+14155550137"),
            ]
        };

        let first = crm.seed_batch(drafts()).unwrap();
        assert!(first
            .iter()
            .all(|result| matches!(result, Ok(Seeded::Created(_)))));
        let ids: Vec<i64> = first
            .iter()
            .map(|result| result.as_ref().unwrap().party().id)
            .collect();

        let second = crm.seed_batch(drafts()).unwrap();
        assert!(second
            .iter()
            .all(|result| matches!(result, Ok(Seeded::Unchanged(_)))));
        let again: Vec<i64> = second
            .iter()
            .map(|result| result.as_ref().unwrap().party().id)
            .collect();
        assert_eq!(ids, again);
        assert_eq!(store.parties().unwrap().len(), 2);
        assert_eq!(crm_contacts(&store).len(), 2);
    }

    #[test]
    fn drafts_in_one_batch_see_each_other() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let results = crm
            .seed_batch(vec![
                contact(
                    "Camille Exemple",
                    "camille.exemple@exemple.test",
                    "+33612345678",
                ),
                contact("Camille Exemple", "camille@exemple.test", "+33612345678"),
            ])
            .unwrap();

        assert!(matches!(results[0], Ok(Seeded::Created(_))));
        let Ok(Seeded::Updated(party)) = &results[1] else {
            panic!("the second draft shares the number, so it grows the first party");
        };
        assert_eq!(party.emails.len(), 2);
        assert_eq!(store.parties().unwrap().len(), 1);
    }

    #[test]
    fn a_draft_matches_a_party_by_phone_and_grows_it() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let camille_id = crm.create(camille()).unwrap().id;

        // Same number, no address: the same person, nothing new to add.
        let same = crm
            .seed_batch(vec![NewParty {
                display_name: "Camille Exemple".to_string(),
                name_variants: vec!["Camille".to_string(), "Exemple".to_string()],
                phones: vec!["+33612345678".to_string()],
                origin: "contacts:file:crm-seed.vcf".to_string(),
                ..NewParty::default()
            }])
            .unwrap();
        assert!(matches!(same[0], Ok(Seeded::Unchanged(_))));

        // Same number, a second address: the party grows, its origin stays.
        let grown = crm
            .seed_batch(vec![NewParty {
                display_name: "Camille Exemple".to_string(),
                emails: vec!["camille@exemple.test".to_string()],
                phones: vec!["+33612345678".to_string()],
                origin: "contacts:file:crm-seed.vcf".to_string(),
                ..NewParty::default()
            }])
            .unwrap()
            .remove(0)
            .unwrap();
        let Seeded::Updated(party) = grown else {
            panic!("a new address must update the party");
        };
        assert_eq!(party.id, camille_id);
        assert_eq!(party.origin, "owner");
        assert_eq!(party.emails.len(), 2);
        assert_eq!(store.parties().unwrap().len(), 1);
    }

    #[test]
    fn a_draft_without_an_address_or_number_matches_by_origin_and_name() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let nameless = || NewParty {
            display_name: "Jean Fictif".to_string(),
            origin: "contacts:file:crm-seed.vcf".to_string(),
            ..NewParty::default()
        };

        let first = crm.seed_batch(vec![nameless()]).unwrap().remove(0).unwrap();
        let second = crm.seed_batch(vec![nameless()]).unwrap().remove(0).unwrap();
        assert!(matches!(first, Seeded::Created(_)));
        assert!(matches!(second, Seeded::Unchanged(_)));
        assert_eq!(store.parties().unwrap().len(), 1);
    }

    #[test]
    fn a_refused_draft_fails_alone_and_the_rest_of_the_batch_is_written() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let results = crm
            .seed_batch(vec![
                contact("Camille Exemple", "not-an-address", "+33612345678"),
                contact("Jean Fictif", "jean.fictif@exemple.test", "+14155550137"),
            ])
            .unwrap();

        assert!(matches!(results[0], Err(CrmError::InvalidEmail { .. })));
        assert!(matches!(results[1], Ok(Seeded::Created(_))));
        assert_eq!(store.parties().unwrap().len(), 1);
        assert_eq!(crm_contacts(&store).len(), 1);
    }

    #[test]
    fn promoting_a_sender_creates_one_party_and_a_second_call_changes_nothing() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);

        let first = crm
            .promote_sender("fictif", "Jean Fictif", "Jean.Fictif@Exemple.test")
            .unwrap();
        let Seeded::Created(party) = first else {
            panic!("an unknown sender is created");
        };
        assert_eq!(party.display_name, "Jean Fictif");
        assert_eq!(party.emails, vec!["jean.fictif@exemple.test"]);
        assert_eq!(party.origin, "mail:fictif");

        let second = crm
            .promote_sender("fictif", "Jean Fictif", "jean.fictif@exemple.test")
            .unwrap();
        assert_eq!(second, Seeded::Unchanged(party.clone()));
        assert_eq!(store.parties().unwrap().len(), 1);
        assert_eq!(crm_contacts(&store).len(), 1);

        // The audit row names the source and the confirmer, and carries the id only.
        let events = store.event_payloads("crm.party_promoted").unwrap();
        assert_eq!(
            events,
            vec![format!(
                "{{\"id\":{},\"source\":\"mail\",\"confirmed_by\":\"owner\"}}",
                party.id
            )]
        );
    }

    #[test]
    fn adding_a_prospect_tags_a_new_party_and_never_retags_an_existing_one() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let added = crm
            .add_prospect("fictif", "Jean Fictif", "jean.fictif@exemple.test")
            .unwrap();
        assert_eq!(added.party().tags, vec!["prospect".to_string()]);
        assert_eq!(added.party().origin, "mail:fictif");

        let again = crm
            .add_prospect("fictif", "Jean Fictif", "jean.fictif@exemple.test")
            .unwrap();
        assert!(matches!(again, Seeded::Unchanged(_)));
        assert_eq!(
            store.parties().unwrap()[0].tags,
            vec!["prospect".to_string()]
        );

        crm.ignore_prospect("Camille@Exemple.test").unwrap();
        assert!(store
            .ignored_senders()
            .unwrap()
            .contains("camille@exemple.test"));
    }

    #[test]
    fn promoting_a_sender_without_a_name_uses_the_address() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let party = crm
            .promote_sender("fictif", "  ", "jean.fictif@exemple.test")
            .unwrap();
        assert_eq!(party.party().display_name, "jean.fictif@exemple.test");
    }

    #[test]
    fn promoting_an_address_a_party_holds_changes_nothing() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let camille_id = crm.create(camille()).unwrap().id;

        let promoted = crm
            .promote_sender("fictif", "Camille", "CAMILLE.exemple@exemple.test")
            .unwrap();
        assert_eq!(promoted.party().id, camille_id);
        assert!(matches!(promoted, Seeded::Unchanged(_)));
        assert_eq!(store.parties().unwrap().len(), 1);
        assert!(store
            .event_payloads("crm.party_promoted")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_promotion_needs_an_account_and_an_address() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        assert!(matches!(
            crm.promote_sender("  ", "Jean Fictif", "jean.fictif@exemple.test"),
            Err(CrmError::EmptyOrigin)
        ));
        assert!(matches!(
            crm.promote_sender("fictif", "Jean Fictif", "not-an-address"),
            Err(CrmError::InvalidEmail { .. })
        ));
        assert!(store.parties().unwrap().is_empty());
    }

    #[test]
    fn sync_is_an_idempotent_refresh_for_importers() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let _ = crm.create(camille()).unwrap();

        crm.sync().unwrap();
        crm.sync().unwrap();
        let records = crm_contacts(&store);
        assert_eq!(records.len(), 1, "a repeated refresh does not duplicate");
        assert!(records[0].nicknames.contains(&"Camille".to_string()));
    }
}
