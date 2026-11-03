//! A local contact index: the people the owner knows, and a recogniser that
//! masks every mention of them (slice 1f).
//!
//! Detectors that read a model miss what a model cannot know: a bare first
//! name, a lower-case name in a quoted reply, a name in a `ps:` line. The
//! index knows the people in advance, from mail headers and `<Name> <address>`
//! pairs, so [`ContactRecognizer`] masks every variant of each of them
//! deterministically: full name in either order, given or family name alone,
//! initials, hyphen and apostrophe forms, the local part of an address,
//! nicknames, declined and affixed forms (Russian cases, Hungarian suffixes,
//! Arabic prefixes, French elision), and every format of an address, a phone
//! number and an IBAN.
//!
//! The index holds personal data. It lives in memory on this machine, is never
//! sent to a cloud model, and is never written in clear: a persistent
//! [`ContactStore`] must be the encrypted local store (see that trait). Its
//! strings are kept in [`Zeroizing`] buffers, so they are wiped when dropped.
//!
//! The recogniser is linear in the text plus the number of matches: the name
//! variants compile into one Aho-Corasick automaton, and every identifier is a
//! key in a map. Seeding from mail is capped (see [`SeedLimits`]).

pub(crate) mod fold;
mod header;
mod identifiers;
pub(crate) mod inflect;
pub(crate) mod stopwords;
mod variants;

use std::borrow::Borrow;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};

use aho_corasick::{AhoCorasick, BuildError};
use zeroize::Zeroizing;

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};
use fold::{fold, lower_nfkc, plain_address, Folded};
use identifiers::{insert_key, Target};
use variants::{variants_for, Check};

/// Values one draft may hold in each list. Over it the first are kept and the
/// rest are refused, so a draft costs bounded work.
const MAX_DRAFT_VALUES: usize = 32;
/// Bytes one draft value may hold. A longer value is refused: no name, address,
/// number or IBAN is that long.
const MAX_VALUE_BYTES: usize = 256;
/// Bytes of text that the recogniser scans at once. Longer text is scanned in
/// windows, cut at a line or word break, so its working memory stays bounded.
const WINDOW_BYTES: usize = 1 << 20;
/// Bytes that consecutive windows share, so a match across a cut is whole in
/// one of them. Longer than any name, address, number or IBAN the matcher reads.
const WINDOW_OVERLAP: usize = 4 << 10;

/// Identifier of a person within one [`ContactIndex`]. Stable while the index
/// lives. Every span of one person carries it, so the anonymizer can give all
/// variants of that person the same token.
///
/// TODO(slice 1f): `Anonymizer` keys its tokens by kind and value, so the spans
/// of one person still get one token per spelling. Reading [`Span::person_id`]
/// there would unify them; that edit belongs to `anonymize.rs`, owned by
/// another open PR.
pub type PersonId = u32;

/// Confidence of a contact hit. A known person is named exactly, so the score is
/// high; it stays below `1.0` so a checksum-valid deterministic rule still
/// takes precedence on overlap.
pub const CONTACT_SCORE: f32 = 0.95;

/// Recogniser name echoed in [`Span::recognizer`].
pub const CONTACT_RECOGNIZER: &str = "contacts";

/// One known person. Strings are kept as the owner wrote them (names) or in
/// canonical form (addresses lower-case, phones and IBANs compact); matching
/// folds or normalises them again.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Person {
    /// Identifier within the index.
    pub id: PersonId,
    /// The display name as it was seen, if any.
    pub display_name: Option<Zeroizing<String>>,
    /// Given names, e.g. `Jean-Marc`.
    pub given: Vec<Zeroizing<String>>,
    /// Family names, e.g. `Van der Berg`, one entry per word.
    pub family: Vec<Zeroizing<String>>,
    /// Short forms known for this person, e.g. `Sasha`.
    pub nicknames: Vec<Zeroizing<String>>,
    /// E-mail addresses, lower-case.
    pub emails: Vec<Zeroizing<String>>,
    /// Phone numbers: `+` and digits when international, digits otherwise.
    pub phones: Vec<Zeroizing<String>>,
    /// IBANs, upper-case, without separators.
    pub ibans: Vec<Zeroizing<String>>,
}

impl fmt::Debug for Person {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only: a contact is personal data and must not reach a log.
        f.debug_struct("Person")
            .field("id", &self.id)
            .field(
                "names",
                &(self.given.len() + self.family.len() + self.nicknames.len()),
            )
            .field("emails", &self.emails.len())
            .field("phones", &self.phones.len())
            .field("ibans", &self.ibans.len())
            .finish()
    }
}

/// The data for one person, as passed to [`ContactIndex::add_person`]. Its
/// strings are wiped when the draft is dropped, as the index's own are.
#[derive(Clone, Default)]
pub struct PersonDraft {
    /// The display name, if any.
    pub display_name: Option<Zeroizing<String>>,
    /// Given names.
    pub given: Vec<Zeroizing<String>>,
    /// Family names, one entry per word.
    pub family: Vec<Zeroizing<String>>,
    /// Known short forms.
    pub nicknames: Vec<Zeroizing<String>>,
    /// E-mail addresses.
    pub emails: Vec<Zeroizing<String>>,
    /// Phone numbers, in any format.
    pub phones: Vec<Zeroizing<String>>,
    /// IBANs, with or without spaces.
    pub ibans: Vec<Zeroizing<String>>,
}

impl fmt::Debug for PersonDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonDraft")
            .field("names", &(self.given.len() + self.family.len()))
            .field("emails", &self.emails.len())
            .field("phones", &self.phones.len())
            .field("ibans", &self.ibans.len())
            .finish()
    }
}

/// Caps on what seeding reads and holds. Over one, seeding stops, what is
/// already seeded is kept, and [`ContactIndex::refused`] counts the refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedLimits {
    /// Bytes of a text that header seeding reads; the rest is not scanned.
    pub max_text_bytes: usize,
    /// Mailboxes taken from one text (or one envelope list).
    pub max_mailboxes: usize,
    /// Name variants one person may compile to.
    pub max_variants_per_person: usize,
    /// Every compiled pattern of the index: name variants plus e-mail, phone
    /// and IBAN keys. A person that would exceed it is refused whole.
    pub max_patterns: usize,
    /// People the index may hold. Counted on every draft, whether or not it
    /// compiles a pattern (given names alone compile none by default).
    pub max_contacts: usize,
    /// Bytes of envelope entries (names and addresses together) that one call
    /// to [`ContactIndex::seed_from_envelope`] reads. Over it, seeding stops.
    pub max_envelope_bytes: usize,
}

impl SeedLimits {
    /// The caps the index uses unless told otherwise.
    pub const DEFAULT: Self = Self {
        max_text_bytes: 64 * 1024,
        max_mailboxes: 500,
        max_variants_per_person: 64,
        max_patterns: 200_000,
        max_contacts: 20_000,
        max_envelope_bytes: 256 * 1024,
    };
}

impl Default for SeedLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A stored contact string used as a map key. It hashes and compares as its
/// text, so a `&str` finds it, and it is wiped when the index drops it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Key(Zeroizing<String>);

impl Key {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Borrow<str> for Key {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// The known people, reachable by e-mail address and by phone number.
///
/// Two entries that share an address or a phone number are the same person:
/// [`ContactIndex::add_person`] merges them into the oldest one.
#[derive(Clone)]
pub struct ContactIndex {
    /// One slot per person ever added; a slot is `None` once merged away.
    people: Vec<Option<Person>>,
    by_email: HashMap<Key, PersonId>,
    by_phone: HashMap<Key, PersonId>,
    limits: SeedLimits,
    /// Whether given names alone (a first name, a nickname, a spelling) are
    /// masked. Off by default: a bare first name is common, and masking it
    /// misfires. Fixed at construction, since the patterns depend on it.
    mask_first_names: bool,
    /// The live people; kept in step with every change.
    contacts: usize,
    /// Compiled patterns of the live people; kept in step with every change.
    patterns: usize,
    /// Entries and text tails that a cap refused.
    refused: usize,
}

impl Default for ContactIndex {
    fn default() -> Self {
        Self::with_limits(SeedLimits::DEFAULT)
    }
}

impl fmt::Debug for ContactIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactIndex")
            .field("people", &self.len())
            .finish()
    }
}

/// The outcome of inserting one draft.
pub(crate) enum Insert {
    /// The draft is in the index under this person.
    Added(PersonId),
    /// The draft has no usable address, phone, IBAN or name.
    Unusable,
    /// A cap refused the draft; nothing changed.
    Capped,
}

impl Insert {
    fn added(self) -> Option<PersonId> {
        match self {
            Insert::Added(id) => Some(id),
            Insert::Unusable | Insert::Capped => None,
        }
    }
}

impl ContactIndex {
    /// An empty index with the default [`SeedLimits`].
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty index with the given caps. Tests use small caps; the app uses
    /// [`SeedLimits::DEFAULT`]. First names are not masked.
    pub fn with_limits(limits: SeedLimits) -> Self {
        Self::with_options(limits, false)
    }

    /// An empty index with the given caps and the given first-name option.
    ///
    /// With `mask_first_names` set, a given name alone (`Jules`, `jules`, a
    /// nickname such as `Alex`, a declined or affixed form of a first name) is
    /// a variant too. Off by default, a first name alone is not masked; full
    /// names, family names, `J. Martin`, initials with the family name, e-mail
    /// addresses and every other identifier are masked either way.
    pub fn with_options(limits: SeedLimits, mask_first_names: bool) -> Self {
        Self {
            people: Vec::new(),
            by_email: HashMap::new(),
            by_phone: HashMap::new(),
            limits,
            mask_first_names,
            contacts: 0,
            patterns: 0,
            refused: 0,
        }
    }

    /// Whether given names alone are masked (see [`ContactIndex::with_options`]).
    pub fn mask_first_names(&self) -> bool {
        self.mask_first_names
    }

    /// The number of known people.
    pub fn len(&self) -> usize {
        self.contacts
    }

    /// Whether the index knows nobody.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every known person, in the order they were first added.
    pub fn people(&self) -> impl Iterator<Item = &Person> {
        self.people.iter().flatten()
    }

    /// The person with identifier `id`, if still known.
    pub fn person(&self, id: PersonId) -> Option<&Person> {
        self.people.get(id as usize)?.as_ref()
    }

    /// How many entries and text tails a cap has refused since the index was
    /// made. Zero means nothing was dropped.
    pub fn refused(&self) -> usize {
        self.refused
    }

    /// The number of patterns the recogniser would compile for this index: an
    /// upper bound, since equal names of different people share one pattern.
    pub fn pattern_count(&self) -> usize {
        self.patterns
    }

    /// Add one person, or merge it into the person who already has one of its
    /// e-mail addresses or phone numbers. Returns the identifier of the person
    /// the data ended up in, or `None` when the draft has no usable key or name,
    /// or a cap refused it (see [`ContactIndex::refused`]).
    pub fn add_person(&mut self, draft: PersonDraft) -> Option<PersonId> {
        self.insert(draft).added()
    }

    /// Add one person from a mail header.
    ///
    /// `display_name` is the name as written (RFC 2047 encoded words, quotes and
    /// `Last, First` order are understood), and `address` the e-mail address. If
    /// `address` is empty and `display_name` holds whole mailboxes, such as
    /// `Marie Dupont <marie.dupont83@example.invalid>`, each one is added.
    /// Returns the identifier of the last person added or merged.
    pub fn add_from_header(&mut self, display_name: &str, address: &str) -> Option<PersonId> {
        // The byte cap applies to the whole input, however many mailboxes it holds.
        let display_name = self.clip(display_name);
        let address = self.clip(address);
        if address.trim().is_empty() && display_name.contains('@') {
            let mailboxes = header::split_mailboxes(display_name);
            return self.add_mailboxes(&mailboxes).1;
        }
        self.add_mailbox(display_name, address).added()
    }

    /// Seed from the envelopes a mail sync returns: `(display name, address)`
    /// pairs. Returns how many entries were added or merged. At most
    /// [`SeedLimits::max_mailboxes`] entries are read, and at most
    /// [`SeedLimits::max_envelope_bytes`] bytes of them in all: the caps span
    /// the whole call, not each entry.
    pub fn seed_from_envelope(&mut self, envelope: &[(&str, &str)]) -> usize {
        let budget = self.limits.max_mailboxes;
        if envelope.len() > budget {
            self.refused += 1;
        }
        let mut touched = 0;
        let mut bytes = 0usize;
        for (name, address) in envelope.iter().take(budget) {
            bytes = bytes
                .saturating_add(name.len())
                .saturating_add(address.len());
            if bytes > self.limits.max_envelope_bytes {
                self.refused += 1;
                break;
            }
            let before = self.refused;
            if self.add_from_header(name, address).is_some() {
                touched += 1;
            }
            if self.refused > before {
                break;
            }
        }
        touched
    }

    /// Merge every person of `other` into this index. The variants follow this
    /// index's first-name option, not `other`'s.
    pub fn merge(&mut self, other: &ContactIndex) {
        for person in other.people() {
            self.add_person(PersonDraft {
                display_name: person.display_name.clone(),
                given: person.given.clone(),
                family: person.family.clone(),
                nicknames: person.nicknames.clone(),
                emails: person.emails.clone(),
                phones: person.phones.clone(),
                ibans: person.ibans.clone(),
            });
        }
    }

    /// Compile the recogniser for the current contents of the index.
    pub fn recognizer(&self) -> Result<ContactRecognizer, BuildError> {
        ContactRecognizer::new(self)
    }

    /// Add or merge one draft, unless a cap refuses the result. A refused draft
    /// changes nothing.
    pub(crate) fn insert(&mut self, mut draft: PersonDraft) -> Insert {
        bound_draft(&mut draft, &mut self.refused);
        let emails: Vec<Zeroizing<String>> = draft
            .emails
            .iter()
            .filter_map(|raw| normalize_email(raw))
            .map(Zeroizing::new)
            .collect();
        let phones: Vec<Zeroizing<String>> = draft
            .phones
            .iter()
            .filter_map(|raw| identifiers::normalize_phone(raw))
            .map(Zeroizing::new)
            .collect();
        let ibans: Vec<Zeroizing<String>> = draft
            .ibans
            .iter()
            .filter_map(|raw| identifiers::normalize_iban(raw))
            .map(Zeroizing::new)
            .collect();
        let has_name = draft
            .given
            .iter()
            .chain(&draft.family)
            .chain(&draft.nicknames)
            .any(|name| !name.trim().is_empty());
        if emails.is_empty() && phones.is_empty() && ibans.is_empty() && !has_name {
            return Insert::Unusable;
        }

        let mut hits: Vec<PersonId> = emails
            .iter()
            .filter_map(|email| self.by_email.get(email.as_str()).copied())
            .chain(
                phones
                    .iter()
                    .filter_map(|phone| self.by_phone.get(phone.as_str()).copied()),
            )
            .collect();
        hits.sort_unstable();
        hits.dedup();
        let survivor = match hits.first() {
            Some(&id) => id,
            None => match PersonId::try_from(self.people.len()) {
                Ok(id) => id,
                Err(_) => return Insert::Unusable,
            },
        };

        // Merge into a fresh copy first, so that a cap can refuse the whole draft.
        let mut merged = Person {
            id: survivor,
            ..Person::default()
        };
        let mut before = 0;
        for &id in &hits {
            if let Some(person) = self.person(id) {
                before += counts(person, self.mask_first_names).1;
                merge_into(&mut merged, person);
            }
        }
        if merged.display_name.is_none() {
            merged.display_name = draft
                .display_name
                .map(|name| Zeroizing::new(name.trim().to_string()))
                .filter(|name| !name.is_empty());
        }
        extend_unique(&mut merged.given, draft.given);
        extend_unique(&mut merged.family, draft.family);
        extend_unique(&mut merged.nicknames, draft.nicknames);
        extend_unique(&mut merged.emails, emails);
        extend_unique(&mut merged.phones, phones);
        extend_unique(&mut merged.ibans, ibans);

        // Merging k people into one leaves k - 1 fewer; a new person adds one.
        let contacts = (self.contacts + 1).saturating_sub(hits.len());
        let (variants, after) = counts(&merged, self.mask_first_names);
        let patterns = self.patterns.saturating_sub(before) + after;
        if variants > self.limits.max_variants_per_person
            || patterns > self.limits.max_patterns
            || contacts > self.limits.max_contacts
        {
            self.refused += 1;
            return Insert::Capped;
        }

        for &other in hits.iter().skip(1) {
            if let Some(slot) = self.people.get_mut(other as usize) {
                *slot = None;
            }
        }
        for email in &merged.emails {
            self.by_email.insert(Key(email.clone()), survivor);
        }
        for phone in &merged.phones {
            self.by_phone.insert(Key(phone.clone()), survivor);
        }
        let slot = survivor as usize;
        if slot < self.people.len() {
            self.people[slot] = Some(merged);
        } else {
            self.people.push(Some(merged));
        }
        self.patterns = patterns;
        self.contacts = contacts;
        Insert::Added(survivor)
    }

    /// Add one mailbox per entry of `mailboxes`, in order, until the mailbox cap
    /// or a cap on the index stops it. Returns how many were added or merged,
    /// and the identifier of the last person added or merged.
    fn add_mailboxes(&mut self, mailboxes: &[(String, String)]) -> (usize, Option<PersonId>) {
        let mut touched = 0;
        let mut last = None;
        for (index, (name, address)) in mailboxes.iter().enumerate() {
            if index == self.limits.max_mailboxes {
                self.refused += 1;
                break;
            }
            match self.add_mailbox(name, address) {
                Insert::Added(id) => {
                    touched += 1;
                    last = Some(id);
                }
                Insert::Unusable => {}
                Insert::Capped => break,
            }
        }
        (touched, last)
    }
}

/// Trim a draft to the value caps: an over-long display name or value is
/// dropped, and a list keeps its first [`MAX_DRAFT_VALUES`] values. Each cut
/// counts as one refusal.
fn bound_draft(draft: &mut PersonDraft, refused: &mut usize) {
    if draft
        .display_name
        .as_ref()
        .is_some_and(|name| name.len() > MAX_VALUE_BYTES)
    {
        draft.display_name = None;
        *refused += 1;
    }
    for list in [
        &mut draft.given,
        &mut draft.family,
        &mut draft.nicknames,
        &mut draft.emails,
        &mut draft.phones,
        &mut draft.ibans,
    ] {
        let before = list.len();
        list.retain(|value| value.len() <= MAX_VALUE_BYTES);
        list.truncate(MAX_DRAFT_VALUES);
        if list.len() != before {
            *refused += 1;
        }
    }
}

/// Add the values of `incoming` that `list` does not already hold, ignoring
/// case and blanks.
fn extend_unique(
    list: &mut Vec<Zeroizing<String>>,
    incoming: impl IntoIterator<Item = Zeroizing<String>>,
) {
    for value in incoming {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if list.iter().any(|known| known.to_lowercase() == lower) {
            continue;
        }
        let kept = if trimmed.len() == value.len() {
            value
        } else {
            Zeroizing::new(trimmed.to_string())
        };
        list.push(kept);
    }
}

/// Copy what `source` knows into `target`, keeping what `target` already has.
fn merge_into(target: &mut Person, source: &Person) {
    if target.display_name.is_none() {
        target.display_name = source.display_name.clone();
    }
    extend_unique(&mut target.given, source.given.iter().cloned());
    extend_unique(&mut target.family, source.family.iter().cloned());
    extend_unique(&mut target.nicknames, source.nicknames.iter().cloned());
    extend_unique(&mut target.emails, source.emails.iter().cloned());
    extend_unique(&mut target.phones, source.phones.iter().cloned());
    extend_unique(&mut target.ibans, source.ibans.iter().cloned());
}

/// The variants of one person, and every pattern the index compiles for them:
/// the variants plus the e-mail, phone and IBAN keys. Returned as
/// `(variants, all patterns)`.
fn counts(person: &Person, mask_first_names: bool) -> (usize, usize) {
    let variants = variants_for(person, mask_first_names).len();
    let identifier_keys = person.emails.len()
        + person
            .phones
            .iter()
            .map(|phone| identifiers::phone_keys(phone).len())
            .sum::<usize>()
        + person.ibans.len();
    (variants, variants + identifier_keys)
}

/// A usable e-mail address, composed and lower-cased (the form the recogniser
/// matches), or `None`.
fn normalize_email(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    // Composed, lower-cased, and with `%40` and `[at]` read as the characters
    // they stand for, so every spelling of an address stores one address.
    let plain = plain_address(&lower_nfkc(trimmed));
    let address = plain.text().trim();
    let address = address.strip_prefix("mailto:").unwrap_or(address).trim();
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || address.contains(char::is_whitespace) {
        return None;
    }
    Some(address.to_string())
}

/// Matches every variant of every known person, and every e-mail address,
/// phone number and IBAN of a known person.
///
/// Built once from a [`ContactIndex`] (see [`ContactIndex::recognizer`]) and
/// mounted with `RegistryBuilder::with_recognizer`. It never reports a span that
/// is not a whole-word or whole-identifier match in the original text.
pub struct ContactRecognizer {
    /// Folded name variants, one automaton pattern each.
    names: Option<AhoCorasick>,
    /// The people that share each name pattern, by how the match must read.
    name_groups: Vec<Vec<(Check, Target)>>,
    /// E-mail keys: `local@domain` with the local part up to a `+` tag.
    emails: HashMap<Key, Target>,
    /// Phone keys: international digits, and the national forms of a number.
    phones: HashMap<Key, Target>,
    /// IBAN keys: compact, upper-case.
    ibans: HashMap<Key, Target>,
}

impl ContactRecognizer {
    /// Compile every variant and identifier key of every person in `index`.
    pub fn new(index: &ContactIndex) -> Result<Self, BuildError> {
        let mut names: HashMap<Key, Vec<(Check, Target)>> = HashMap::new();
        let mut emails: HashMap<Key, Target> = HashMap::new();
        let mut phones: HashMap<Key, Target> = HashMap::new();
        let mut ibans: HashMap<Key, Target> = HashMap::new();
        for person in index.people() {
            for variant in variants_for(person, index.mask_first_names) {
                let groups = names.entry(Key(variant.text)).or_default();
                match groups.iter_mut().find(|(check, _)| *check == variant.check) {
                    Some((_, target)) => target.ambiguous = true,
                    None => groups.push((
                        variant.check,
                        Target {
                            person: person.id,
                            ambiguous: false,
                        },
                    )),
                }
            }
            for email in &person.emails {
                if let Some(key) = identifiers::email_key(email) {
                    insert_key(&mut emails, key, person.id);
                }
            }
            for phone in &person.phones {
                for key in identifiers::phone_keys(phone) {
                    insert_key(&mut phones, key, person.id);
                }
            }
            for iban in &person.ibans {
                insert_key(&mut ibans, iban.clone(), person.id);
            }
        }
        let (name_patterns, name_groups): (Vec<Key>, Vec<Vec<(Check, Target)>>) =
            names.into_iter().unzip();
        Ok(Self {
            names: automaton(&name_patterns)?,
            name_groups,
            emails,
            phones,
            ibans,
        })
    }

    /// The number of compiled patterns: name variants, e-mail, phone and IBAN
    /// keys. For diagnostics, never for logs of values.
    pub fn pattern_count(&self) -> usize {
        self.name_groups.len() + self.emails.len() + self.phones.len() + self.ibans.len()
    }

    /// How many compiled patterns name more than one person. Such a match masks
    /// under the oldest of them.
    pub fn ambiguous_patterns(&self) -> usize {
        let names = self
            .name_groups
            .iter()
            .flatten()
            .filter(|(_, target)| target.ambiguous)
            .count();
        let emails = self
            .emails
            .values()
            .filter(|target| target.ambiguous)
            .count();
        let phones = self
            .phones
            .values()
            .filter(|target| target.ambiguous)
            .count();
        let ibans = self
            .ibans
            .values()
            .filter(|target| target.ambiguous)
            .count();
        names + emails + phones + ibans
    }

    /// Name matches in `text`: whole words of a folded variant.
    fn names_in(&self, text: &str, spans: &mut Vec<Span>) {
        let Some(automaton) = &self.names else {
            return;
        };
        let folded = fold(text);
        let bytes = folded.text().as_bytes();
        for found in automaton.find_overlapping_iter(folded.text()) {
            let (begin, stop) = (found.start(), found.end());
            // The folded text separates words with single spaces, so a match
            // is a whole word when it sits between spaces or the text edges.
            if (begin > 0 && bytes[begin - 1] != b' ')
                || (stop < bytes.len() && bytes[stop] != b' ')
            {
                continue;
            }
            let (start, end) = folded.source(begin, stop);
            let groups = &self.name_groups[found.pattern().as_usize()];
            if let Some(target) = pick(groups, text, start, end) {
                spans.push(identifier_span(EntityKind::Person, start, end, target));
            }
        }
    }

    /// Address matches in `composed`, the composed, lower-cased text of one
    /// window: any case, composition, percent-encoding and obfuscated spelling.
    fn emails_in(&self, composed: &Folded, spans: &mut Vec<Span>) {
        if self.emails.is_empty() {
            return;
        }
        // The plain text keeps its source map, so its spans are original spans.
        let plain = plain_address(composed);
        for (start, end, target) in identifiers::email_hits(plain.text(), &self.emails) {
            let (start, end) = plain.source(start, end);
            spans.push(identifier_span(EntityKind::Email, start, end, target));
        }
    }

    /// Every match in one window of text, in any order.
    fn scan(&self, text: &str, spans: &mut Vec<Span>) {
        self.names_in(text, spans);
        let composed = lower_nfkc(text);
        self.emails_in(&composed, spans);
        for (start, end, target) in identifiers::phone_hits(composed.text(), &self.phones) {
            let (start, end) = composed.source(start, end);
            spans.push(identifier_span(EntityKind::Phone, start, end, target));
        }
        for (start, end, target) in identifiers::iban_hits(composed.text(), &self.ibans) {
            let (start, end) = composed.source(start, end);
            spans.push(identifier_span(EntityKind::Iban, start, end, target));
        }
    }
}

impl Recognizer for ContactRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Iban,
        ]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for (offset, window) in windows(text) {
            let mut found = Vec::new();
            self.scan(window, &mut found);
            spans.extend(found.into_iter().map(|mut span| {
                span.start += offset;
                span.end += offset;
                span
            }));
        }
        resolve_overlaps(text, spans)
    }

    fn name(&self) -> &'static str {
        CONTACT_RECOGNIZER
    }

    /// The index is an explicit input: the default registry does not mount it.
    fn enabled_by_default(&self) -> bool {
        false
    }
}

/// The pieces of `text` that one scan reads: the whole text when it is short,
/// else windows of [`WINDOW_BYTES`] that overlap by [`WINDOW_OVERLAP`] bytes.
/// Each window starts at the byte offset returned with it. Cuts fall after a
/// line break where one is near, and after a space otherwise, so no word is cut.
fn windows(text: &str) -> Vec<(usize, &str)> {
    if text.len() <= WINDOW_BYTES {
        return vec![(0, text)];
    }
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let limit = char_floor(text, (start + WINDOW_BYTES).min(text.len()));
        let end = if limit == text.len() {
            limit
        } else {
            break_after(text, start + WINDOW_BYTES / 2, limit).unwrap_or(limit)
        };
        out.push((start, &text[start..end]));
        if end == text.len() {
            return out;
        }
        // The next window starts at the first break inside the overlap, so a name
        // that the cut split is whole in it.
        let overlap_from = char_floor(text, end - WINDOW_OVERLAP);
        start = first_break(text, overlap_from, end).unwrap_or(overlap_from);
    }
}

/// The largest character boundary of `text` that is at most `at`.
fn char_floor(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// The byte after the last line break, or else the last whitespace, in
/// `text[from..to]`. A cut there splits no word: the byte before it is ASCII.
fn break_after(text: &str, from: usize, to: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let line = (from..to).rev().find(|&at| bytes[at] == b'\n');
    line.or_else(|| (from..to).rev().find(|&at| bytes[at].is_ascii_whitespace()))
        .map(|at| at + 1)
}

/// The byte after the first whitespace in `text[from..to]`, when there is one.
fn first_break(text: &str, from: usize, to: usize) -> Option<usize> {
    text.as_bytes()[from..to]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|at| from + at + 1)
}

/// Resolves the overlaps of the spans of one text into one match per stretch.
///
/// A span that lies inside a longer one is dropped, so that a surname inside a
/// full name, an address inside its tagged form, or a number inside its
/// international form is one match, under the outer person. Where two people's
/// names partly overlap ("Marie Dupont, Jean Dupont" reads "Dupont, Jean" too),
/// the earlier span keeps the overlap and the later one starts at its first
/// word after it, so every word is masked under one person. Spans of the same
/// person, and identifiers, may overlap. The result is sorted by start.
fn resolve_overlaps(text: &str, spans: Vec<Span>) -> Vec<Span> {
    let mut trimmed: Vec<Span> = Vec::with_capacity(spans.len());
    for mut span in prune_contained(spans) {
        if let Some(earlier) = trimmed.last() {
            let crosses = span.start < earlier.end
                && span.kind == EntityKind::Person
                && earlier.kind == EntityKind::Person
                && span.person_id != earlier.person_id;
            if crosses {
                span.start = first_word(text, earlier.end, span.end);
                if span.start >= span.end {
                    continue;
                }
            }
        }
        trimmed.push(span);
    }
    prune_contained(trimmed)
}

/// Drops every span that lies inside a longer one. The input is sorted by start
/// and the output is too.
fn prune_contained(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|span| (span.start, Reverse(span.end)));
    let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
    let mut reach = 0;
    for span in spans {
        // Sorted by start, so the span that reaches furthest so far starts first:
        // a span that ends within it lies inside it.
        if !kept.is_empty() && span.end <= reach {
            continue;
        }
        reach = reach.max(span.end);
        kept.push(span);
    }
    kept
}

/// The byte of the first letter or digit in `text[from..to]`, or `to` when there
/// is none. Both bounds are character boundaries.
fn first_word(text: &str, from: usize, to: usize) -> usize {
    text[from..to]
        .char_indices()
        .find(|(_, c)| c.is_alphanumeric())
        .map_or(to, |(at, _)| from + at)
}

/// The span of one identifier hit, carrying its person.
fn identifier_span(kind: EntityKind, start: usize, end: usize, target: Target) -> Span {
    Span::new(kind, start, end, CONTACT_SCORE, CONTACT_RECOGNIZER).with_person(target.person)
}

/// The Aho-Corasick automaton of `patterns`, or `None` when there are none.
fn automaton(patterns: &[Key]) -> Result<Option<AhoCorasick>, BuildError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    AhoCorasick::new(patterns.iter().map(Key::as_str)).map(Some)
}

/// The target of the first group whose check the matched text passes: a plain
/// match first, then an initial, then an initialism, then a titled surname, and
/// last a function word in name context.
fn pick(groups: &[(Check, Target)], text: &str, start: usize, end: usize) -> Option<Target> {
    [
        Check::Any,
        Check::FirstUpper,
        Check::AllUpper,
        Check::Titled,
        Check::Context,
    ]
    .into_iter()
    .find_map(|check| {
        groups
            .iter()
            .find(|(group, _)| *group == check && check_passes(text, start, end, check))
            .map(|(_, target)| *target)
    })
}

/// Whether the match `text[start..end]` satisfies `check`: its letters, its last
/// word, or the text around it.
fn check_passes(text: &str, start: usize, end: usize, check: Check) -> bool {
    let mut letters = text[start..end].chars().filter(|c| c.is_alphabetic());
    match check {
        Check::Any => true,
        Check::FirstUpper => letters.next().is_some_and(|c| !c.is_lowercase()),
        Check::AllUpper => letters.all(|c| !c.is_lowercase()),
        Check::Titled => {
            let surname = text[start..end]
                .rsplit(|c: char| !c.is_alphabetic())
                .next()
                .unwrap_or_default();
            surname.chars().next().is_some_and(|c| !c.is_lowercase())
        }
        Check::Context => in_name_context(text, start, end),
    }
}

/// Whether the match `text[start..end]` is name context: the only words on its
/// line (a signature, a quoted line), or the value of a mail header.
fn in_name_context(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |at| at + 1);
    let line_end = text[end..].find('\n').map_or(text.len(), |at| end + at);
    let before = &text[line_start..start];
    let after = &text[end..line_end];
    let alone = before.chars().chain(after.chars()).all(is_signature_filler);
    alone || header::is_header_value(before)
}

/// Whitespace, and the punctuation of a signature or a quote marker.
fn is_signature_filler(c: char) -> bool {
    c.is_whitespace() || "-–—|·•*_~>.,;".contains(c)
}

/// Where a contact index is kept between sessions.
///
/// **The persistent store must be the encrypted local store (SQLCipher, slice
/// 4), never plain files.** A contact index holds real names, e-mail addresses
/// and phone numbers. It never leaves this machine: it is not written to a plain
/// file, a cache, a log, or a cloud payload, and no model is ever given it.
pub trait ContactStore {
    /// Load the saved index, or an empty one when nothing was saved.
    fn load(&self) -> Result<ContactIndex, ContactStoreError>;

    /// Replace the saved index with `index`.
    fn save(&mut self, index: &ContactIndex) -> Result<(), ContactStoreError>;
}

/// A store could not be read or written. Carries no contact data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactStoreError {
    /// A fixed description of the failure.
    pub reason: &'static str,
}

impl fmt::Display for ContactStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for ContactStoreError {}

/// An in-memory store: it keeps a copy of the index for this session and writes
/// nothing to disk. It is the only implementation in this crate.
#[derive(Clone, Default)]
pub struct MemoryContactStore {
    saved: ContactIndex,
}

impl ContactStore for MemoryContactStore {
    fn load(&self) -> Result<ContactIndex, ContactStoreError> {
        Ok(self.saved.clone())
    }

    fn save(&mut self, index: &ContactIndex) -> Result<(), ContactStoreError> {
        self.saved = index.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::recognizer::Registry;

    /// Strings as a draft holds them: zeroized on drop.
    fn zs(values: &[&str]) -> Vec<Zeroizing<String>> {
        values
            .iter()
            .map(|value| Zeroizing::new(value.to_string()))
            .collect()
    }

    fn draft(given: &str, family: &str, emails: &[&str]) -> PersonDraft {
        PersonDraft {
            given: zs(&[given]),
            family: zs(&[family]),
            emails: zs(emails),
            ..PersonDraft::default()
        }
    }

    /// An index that masks first names too (the option is off by default).
    fn first_names_masked() -> ContactIndex {
        ContactIndex::with_options(SeedLimits::DEFAULT, true)
    }

    fn masked_kinds(index: &ContactIndex, text: &str) -> Vec<(EntityKind, String)> {
        index
            .recognizer()
            .expect("build")
            .analyze(text)
            .into_iter()
            .map(|span| (span.kind, text[span.start..span.end].to_string()))
            .collect()
    }

    fn masked_by_contacts(index: &ContactIndex, text: &str) -> Vec<(String, u32)> {
        let recognizer = index.recognizer().expect("build");
        recognizer
            .analyze(text)
            .into_iter()
            .filter(|span| span.kind == EntityKind::Person)
            .map(|span| {
                (
                    text[span.start..span.end].to_string(),
                    span.person_id.unwrap_or(u32::MAX),
                )
            })
            .collect()
    }

    #[test]
    fn same_address_merges_and_keeps_the_oldest_id() {
        let mut index = ContactIndex::new();
        let first = index.add_person(draft("Marie", "Dupont", &["marie@example.invalid"]));
        let second = index.add_person(PersonDraft {
            phones: zs(&["+33 1 99 00 12 34"]),
            ..draft("M.", "Dupont", &["MARIE@example.invalid"])
        });
        assert_eq!(first, second);
        assert_eq!(index.len(), 1);
        let phone_only = index.add_person(PersonDraft {
            phones: zs(&["+33 1 99 00 12 34"]),
            ..PersonDraft::default()
        });
        assert_eq!(phone_only, first);
    }

    #[test]
    fn a_bridge_entry_merges_two_people() {
        let mut index = ContactIndex::new();
        let a = index.add_person(draft("Anna", "Lind", &["anna@example.invalid"]));
        let b = index.add_person(PersonDraft {
            phones: zs(&["0033 6 99 00 11 22"]),
            ..draft("Ben", "Lind", &[])
        });
        assert_ne!(a, b);
        let bridge = index.add_person(PersonDraft {
            phones: zs(&["0033 6 99 00 11 22"]),
            ..draft("Anna", "Lind", &["anna@example.invalid"])
        });
        assert_eq!(bridge, a);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn empty_draft_is_refused() {
        let mut index = ContactIndex::new();
        assert_eq!(index.add_person(PersonDraft::default()), None);
        assert!(index.is_empty());
    }

    #[test]
    fn debug_never_prints_values() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Marie", "Dupont", &["marie@example.invalid"]));
        let rendered = format!("{index:?}");
        assert!(!rendered.contains("Marie"));
        assert!(!rendered.contains("example.invalid"));
    }

    #[test]
    fn every_variant_masks_with_offsets_on_the_source() {
        let mut index = first_names_masked();
        index.add_person(draft(
            "Marie",
            "Dupont",
            &["marie.dupont83@example.invalid"],
        ));
        let text = "Bonjour MARIE, merci à Dupont. Signé M. Dupont, Marie DUPONT, \
                    et marie dupont (marie.dupont83 aussi).";
        let found = masked_by_contacts(&index, text);
        let names: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
        for expected in [
            "MARIE",
            "Dupont",
            "M. Dupont",
            "Marie DUPONT",
            "marie dupont",
            // "(marie" closes the reversed name, which contains the bare given name.
            "dupont (marie",
        ] {
            assert!(names.contains(&expected), "missing {expected}: {names:?}");
        }
        assert!(found.iter().all(|(_, id)| *id == 0));
    }

    #[test]
    fn the_lowercase_and_accented_forms_match() {
        let mut index = first_names_masked();
        index.add_person(draft("Bálint", "Kovács", &[]));
        let found = masked_by_contacts(&index, "szia balint, kovacs úr és BÁLINT KOVÁCS");
        let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
        // "balint, kovacs" is one name; its parts lie inside it.
        assert!(values.contains(&"balint, kovacs"));
        assert!(values.contains(&"BÁLINT KOVÁCS"));
    }

    #[test]
    fn initials_need_upper_case_and_hyphens_match_both_ways() {
        let mut index = first_names_masked();
        index.add_person(draft("Jean-Marc", "Dupont", &[]));
        let found = masked_by_contacts(&index, "JM et jm, J.-M. Dupont, Jean Marc, JeanMarc.");
        let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
        assert!(values.contains(&"JM"));
        assert!(!values.contains(&"jm"));
        assert!(values.contains(&"J.-M. Dupont"));
        assert!(values.contains(&"Dupont, Jean Marc"));
        assert!(values.contains(&"JeanMarc"));
    }

    #[test]
    fn common_words_are_still_masked_for_a_known_person() {
        let mut index = first_names_masked();
        index.add_person(draft("Rose", "Will", &[]));
        let found = masked_by_contacts(&index, "Will you tell Rose? Rosemary is not her.");
        let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
        assert!(values.contains(&"Will"));
        assert!(values.contains(&"Rose"));
        assert!(!values.iter().any(|value| value.starts_with("Rosemary")));
    }

    #[test]
    fn cyrillic_and_arabic_match_in_their_own_script() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Анна", "Смирнова", &[]));
        index.add_person(draft("محمد", "علي", &[]));
        let found = masked_by_contacts(&index, "Привет, анна смирнова! و محمّد علي يرد");
        let values: Vec<&str> = found.iter().map(|(value, _)| value.as_str()).collect();
        assert!(values.contains(&"анна смирнова"));
        assert!(values.contains(&"محمّد علي"));
    }

    #[test]
    fn nicknames_and_registry_union_mask_the_short_form() {
        let mut index = first_names_masked();
        index.add_person(draft("Alexandre", "Morel", &[]));
        let registry = Registry::builder()
            .with_all()
            .with_recognizer(index.recognizer().expect("build"))
            .build();
        let text = "Salut Alex, Alexandre Morel est là.";
        let spans = registry.analyze(text);
        // Another recogniser may join the two names into one region, so check
        // that each name sits inside a masked person span.
        let covered = |needle: &str| {
            let start = text.find(needle).expect("needle is in the text");
            spans.iter().any(|span| {
                span.kind == EntityKind::Person
                    && span.start <= start
                    && start + needle.len() <= span.end
            })
        };
        assert!(covered("Alex"), "{spans:?}");
        assert!(covered("Alexandre Morel"), "{spans:?}");
    }

    #[test]
    fn a_bare_first_name_is_not_masked_by_default() {
        let mut index = ContactIndex::new();
        assert!(!index.mask_first_names());
        index.add_person(draft("Jules", "Martin", &["jules.martin@example.invalid"]));
        let text = "Jules est là. JULES, Jules Martin, Martin, J. Martin, \
                    jules.martin@example.invalid !";
        let found = masked_kinds(&index, text);
        let values: Vec<&str> = found.iter().map(|(_, value)| value.as_str()).collect();
        for expected in ["Jules Martin", "Martin", "J. Martin"] {
            assert!(values.contains(&expected), "missing {expected}: {values:?}");
        }
        assert!(found.contains(&(
            EntityKind::Email,
            "jules.martin@example.invalid".to_string()
        )));
        assert!(
            !values
                .iter()
                .any(|value| value.eq_ignore_ascii_case("jules")),
            "a bare first name was masked: {values:?}"
        );
    }

    #[test]
    fn a_bare_first_name_is_masked_when_first_names_are_on() {
        let mut index = first_names_masked();
        assert!(index.mask_first_names());
        index.add_person(draft("Jules", "Martin", &["jules.martin@example.invalid"]));
        let values: Vec<String> = masked_by_contacts(&index, "Jules est là, et JULES.")
            .into_iter()
            .map(|(value, _)| value)
            .collect();
        assert!(values.contains(&"Jules".to_string()), "{values:?}");
        assert!(values.contains(&"JULES".to_string()), "{values:?}");
    }

    #[test]
    fn spans_are_whole_words_on_char_boundaries() {
        let mut index = first_names_masked();
        index.add_person(draft("Ana", "Ruiz", &[]));
        let text = "Anaïs Ruizzo; Ana.";
        for span in index.recognizer().expect("build").analyze(text) {
            assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end));
            assert!(crate::recognizer::span_is_well_formed(text, &span));
        }
        let values: Vec<String> = masked_by_contacts(&index, text)
            .into_iter()
            .map(|(value, _)| value)
            .collect();
        assert_eq!(values, vec!["Ana".to_string()]);
    }

    #[test]
    fn many_contacts_with_one_name_emit_one_span_per_mention() {
        let mut index = first_names_masked();
        for _ in 0..10_000 {
            index.add_person(PersonDraft {
                given: zs(&["Marie"]),
                ..PersonDraft::default()
            });
        }
        assert_eq!(index.len(), 10_000);
        let recognizer = index.recognizer().expect("build");
        // "Marie" and its Hungarian suffix forms: a handful of patterns, each
        // shared by all 10,000 people.
        assert!(recognizer.pattern_count() <= 10);
        assert!(recognizer.ambiguous_patterns() >= 1);

        let mut text = String::new();
        while text.len() < 100_000 {
            text.push_str("Marie a dit bonjour à Paul. ");
        }
        let mentions = text.matches("Marie").count();
        let started = Instant::now();
        let spans = recognizer.analyze(&text);
        let elapsed = started.elapsed();
        assert_eq!(spans.len(), mentions);
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
    }

    #[test]
    fn identifiers_in_every_format_map_to_the_person() {
        let mut index = ContactIndex::new();
        index.add_person(PersonDraft {
            given: zs(&["Marie"]),
            family: zs(&["Dupont"]),
            emails: zs(&["marie.dupont83@example.invalid"]),
            phones: zs(&["+33 6 12 34 56 78"]),
            ibans: zs(&["FR76 3000 6000 0112 3456 7890 189"]),
            ..PersonDraft::default()
        });
        let text = "Écrire à MARIE.DUPONT83@EXAMPLE.INVALID ou 06.12.34.56.78, \
                    IBAN FR76 3000 6000\n0112 3456 7890 189.";
        let spans = index.recognizer().expect("build").analyze(text);
        let found: Vec<(EntityKind, &str)> = spans
            .iter()
            .map(|span| (span.kind, &text[span.start..span.end]))
            .collect();
        assert!(found.contains(&(EntityKind::Email, "MARIE.DUPONT83@EXAMPLE.INVALID")));
        assert!(found.contains(&(EntityKind::Phone, "06.12.34.56.78")));
        assert!(found.contains(&(EntityKind::Iban, "FR76 3000 6000\n0112 3456 7890 189")));
        assert!(spans.iter().all(|span| span.person_id == Some(0)));
    }

    #[test]
    fn inflected_and_affixed_forms_map_to_exact_spans() {
        let mut index = first_names_masked();
        index.add_person(draft("Анна", "Смирнова", &[]));
        index.add_person(draft("Lilla", "Kovács", &[]));
        index.add_person(draft("علي", "حسن", &[]));
        index.add_person(draft("Jean", "Artagnan", &[]));
        let text = "Письмо Анне Смирновой; Lillának és Lilla-féle; لعلي حسن؛ d'Artagnan.";
        let found: Vec<String> = masked_by_contacts(&index, text)
            .into_iter()
            .map(|(value, _)| value)
            .collect();
        for expected in [
            "Анне Смирновой",
            "Lillának",
            "Lilla-féle",
            "لعلي",
            "d'Artagnan",
        ] {
            assert!(
                found.iter().any(|value| value == expected),
                "missing {expected}: {found:?}"
            );
        }
    }

    #[test]
    fn seeding_stops_at_the_byte_cap_and_counts_it() {
        let mut index = ContactIndex::new();
        let filler = "é".repeat(SeedLimits::DEFAULT.max_text_bytes / 2 + 10);
        let late = format!("{filler}\nFrom: Marie Dupont <marie.dupont83@example.invalid>");
        assert_eq!(index.seed_from_text(&late), 0);
        assert!(index.is_empty());
        assert_eq!(index.refused(), 1);

        let early = format!(
            "From: Marie Dupont <marie.dupont83@example.invalid>\n{}",
            "é".repeat(40_000)
        );
        assert!(index.seed_from_text(&early) >= 1);
        assert_eq!(index.len(), 1);
        assert_eq!(index.refused(), 2);
    }

    #[test]
    fn seeding_stops_at_the_mailbox_cap() {
        let limits = SeedLimits {
            max_mailboxes: 5,
            ..SeedLimits::DEFAULT
        };
        let mut index = ContactIndex::with_limits(limits);
        let names = [
            "Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio", "Greta", "Hugo",
        ];
        let text: String = names
            .iter()
            .map(|name| format!("Cc: {name} <{name}.x@example.invalid>\n"))
            .collect();
        index.seed_from_text(&text);
        assert_eq!(index.len(), 5);
        assert!(index.refused() >= 1);
    }

    #[test]
    fn a_person_keeps_at_most_the_variant_cap() {
        let limits = SeedLimits {
            max_variants_per_person: 8,
            ..SeedLimits::DEFAULT
        };
        let mut index = ContactIndex::with_limits(limits);
        for name in ["Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio"] {
            index.add_person(PersonDraft {
                given: zs(&[name]),
                family: zs(&["Lind"]),
                emails: zs(&["same@example.invalid"]),
                ..PersonDraft::default()
            });
        }
        assert!(index.refused() >= 1);
        for person in index.people() {
            assert!(variants_for(person, index.mask_first_names()).len() <= 8);
        }
    }

    #[test]
    fn the_index_keeps_at_most_the_pattern_cap() {
        let limits = SeedLimits {
            max_patterns: 12,
            ..SeedLimits::DEFAULT
        };
        let mut index = ContactIndex::with_limits(limits);
        for name in ["Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio"] {
            index.add_person(PersonDraft {
                given: zs(&[name]),
                family: zs(&["Lind"]),
                ..PersonDraft::default()
            });
        }
        assert!(index.pattern_count() <= 12);
        assert!(index.refused() >= 1);
        assert!(index.len() < 6);
    }

    #[test]
    fn seeding_never_panics_on_odd_input() {
        let mut index = ContactIndex::new();
        index.seed_from_text(&"<".repeat(100_000));
        index.seed_from_text(&"=?".repeat(50_000));
        index.seed_from_text(&format!("{}From: a <b@c.d>", "é".repeat(40_000)));
        index.seed_from_text(&"\u{1F600}".repeat(20_000));
    }

    #[test]
    fn a_draft_without_patterns_still_counts_against_the_contact_cap() {
        let limits = SeedLimits {
            max_contacts: 2,
            ..SeedLimits::DEFAULT
        };
        let mut index = ContactIndex::with_limits(limits);
        let alba = index.add_person(PersonDraft {
            given: zs(&["Alba"]),
            emails: zs(&["alba@example.invalid"]),
            ..PersonDraft::default()
        });
        for name in ["Bruno", "Cora", "Dario"] {
            index.add_person(PersonDraft {
                given: zs(&[name]),
                ..PersonDraft::default()
            });
        }
        assert_eq!(index.len(), 2);
        assert_eq!(index.refused(), 2);
        // A draft that merges into a known person adds nobody, so it is kept.
        let merged = index.add_person(PersonDraft {
            given: zs(&["Alba"]),
            emails: zs(&["ALBA@example.invalid"]),
            ..PersonDraft::default()
        });
        assert_eq!(merged, alba);
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn a_header_input_keeps_the_mailbox_cap_and_the_byte_cap() {
        let limits = SeedLimits {
            max_mailboxes: 1,
            ..SeedLimits::DEFAULT
        };
        let mut index = ContactIndex::with_limits(limits);
        index.add_from_header(
            "Marie Dupont <marie@example.invalid>, Paul Martin <paul@example.invalid>",
            "",
        );
        assert_eq!(index.len(), 1);
        assert!(masked_kinds(&index, "paul@example.invalid").is_empty());
        assert!(index.refused() >= 1);

        let mut index = ContactIndex::new();
        let padding = " ".repeat(SeedLimits::DEFAULT.max_text_bytes);
        let display = format!(
            "Marie Dupont <marie@example.invalid>,{padding}Paul Martin <paul@example.invalid>"
        );
        index.add_from_header(&display, "");
        assert_eq!(index.len(), 1);
        assert_eq!(index.refused(), 1);
        assert!(masked_kinds(&index, "paul@example.invalid").is_empty());
    }

    #[test]
    fn a_surname_that_is_a_function_word_masks_only_in_name_context() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Marie", "Le", &[]));
        let values = |text: &str| -> Vec<String> {
            masked_by_contacts(&index, text)
                .into_iter()
                .map(|(value, _)| value)
                .collect()
        };
        // Running text: the article "le" is not the surname.
        assert!(values("Le chat est noir, et le meilleur.").is_empty());
        assert!(values("M. le directeur attend. Il faut le dire.").is_empty());
        // Name context: full names, titles, initials, signature and header lines.
        let found = values("Marie Le et Le Marie. M. Le, Mme Le, Mr Le et Dr Le.");
        for expected in ["Marie Le", "Le Marie", "M. Le", "Mme Le", "Mr Le", "Dr Le"] {
            assert!(found.iter().any(|value| value == expected), "{found:?}");
        }
        assert_eq!(values("Merci,\nLe\n"), ["Le"]);
        assert_eq!(values("From: Le\nCc: Paul, Le\n> Le"), ["Le", "Le", "Le"]);
    }

    #[test]
    fn e_mail_forms_match_in_any_case_and_composition() {
        let mut index = ContactIndex::new();
        index.add_person(draft(
            "Élodie",
            "Martin",
            &["élodie.martin@example.invalid"],
        ));
        let text =
            "Écrire à ÉLODIE.MARTIN%40EXAMPLE.INVALID, ou E\u{301}LODIE.MARTIN@example.invalid.";
        let emails: Vec<&str> = index
            .recognizer()
            .expect("build")
            .analyze(text)
            .iter()
            .filter(|span| span.kind == EntityKind::Email)
            .map(|span| &text[span.start..span.end])
            .collect();
        assert_eq!(
            emails,
            [
                "ÉLODIE.MARTIN%40EXAMPLE.INVALID",
                "E\u{301}LODIE.MARTIN@example.invalid"
            ]
        );
    }

    #[test]
    fn envelope_seeding_stops_at_the_total_byte_cap() {
        let names = [
            "Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio", "Greta", "Hugo",
        ];
        let entries: Vec<(String, String)> = names
            .iter()
            .map(|name| {
                (
                    format!("{name} Lind"),
                    format!("{}@example.invalid", name.to_lowercase()),
                )
            })
            .collect();
        let envelope: Vec<(&str, &str)> = entries
            .iter()
            .map(|(name, address)| (name.as_str(), address.as_str()))
            .collect();
        let limits = SeedLimits {
            max_envelope_bytes: 100,
            ..SeedLimits::DEFAULT
        };
        let mut index = ContactIndex::with_limits(limits);
        assert_eq!(index.seed_from_envelope(&envelope), 3);
        assert_eq!(index.len(), 3);
        assert!(index.refused() >= 1);

        let mut index = ContactIndex::new();
        assert_eq!(index.seed_from_envelope(&envelope), names.len());
        assert_eq!(index.refused(), 0);
    }

    #[test]
    fn a_draft_is_bounded_per_list_and_per_value() {
        let mut index = ContactIndex::new();
        let phones: Vec<String> = (0..100).map(|n| format!("+33 6 00 00 {n:04}")).collect();
        let phone_refs: Vec<&str> = phones.iter().map(String::as_str).collect();
        let long = "M".repeat(300);
        let added = index.add_person(PersonDraft {
            display_name: Some(Zeroizing::new("D".repeat(10_000))),
            given: zs(&["Marie", long.as_str()]),
            family: zs(&["Dupont"]),
            phones: zs(&phone_refs),
            ..PersonDraft::default()
        });
        assert!(added.is_some());
        let person = index.person(added.expect("id")).expect("person");
        assert_eq!(person.phones.len(), 32);
        assert!(person.display_name.is_none());
        assert_eq!(person.given.len(), 1);
        assert!(index.refused() >= 3);
    }

    #[test]
    fn a_long_text_is_scanned_in_windows_without_losing_or_doubling_a_name() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Marie", "Dupont", &[]));
        // The name's space is the last break before the window edge, so the
        // first window ends inside the name.
        let start = WINDOW_BYTES - 8;
        let words = (start - 2) / 3;
        let text = format!(
            "{}{}Marie Dupont fin.",
            "ab ".repeat(words),
            " ".repeat(start - 3 * words)
        );
        assert_eq!(text.as_bytes()[start], b'M');
        let spans = index.recognizer().expect("build").analyze(&text);
        let people: Vec<(usize, usize)> = spans
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .map(|span| (span.start, span.end))
            .collect();
        assert_eq!(people, [(start, start + "Marie Dupont".len())]);
    }

    #[test]
    fn names_split_across_a_line_break_or_in_full_width_match_once() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Jean-Luc", "Martin", &[]));
        index.add_person(draft("Marie", "Dupont", &[]));
        let text = "Jean-Luc\nMartin, signé\nＭＡＲＩＥ　ＤＵＰＯＮＴ et Marie\n  Dupont.";
        let found: Vec<String> = masked_by_contacts(&index, text)
            .into_iter()
            .map(|(value, _)| value)
            .collect();
        assert_eq!(
            found,
            [
                "Jean-Luc\nMartin",
                "ＭＡＲＩＥ　ＤＵＰＯＮＴ",
                "Marie\n  Dupont"
            ]
        );
    }

    #[test]
    fn ligatures_and_final_sigma_match_their_plain_spellings() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Νίκος", "Σάββας", &[]));
        index.add_person(draft("Ana", "Fischer", &[]));
        let text = "ΝΊΚΟΣ ΣΆΒΒΑΣ, Ana \u{FB01}scher.";
        let found: Vec<String> = masked_by_contacts(&index, text)
            .into_iter()
            .map(|(value, _)| value)
            .collect();
        assert_eq!(found, ["ΝΊΚΟΣ ΣΆΒΒΑΣ", "Ana \u{FB01}scher"]);
    }

    #[test]
    fn plus_tags_and_obfuscated_addresses_are_one_email_match() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Jules", "Martin", &["jules@example.invalid"]));
        for (text, expected) in [
            ("jules+crm@example.invalid", "jules+crm@example.invalid"),
            (
                "jules [at] example [dot] invalid",
                "jules [at] example [dot] invalid",
            ),
            (
                "jules(at)example(dot)invalid",
                "jules(at)example(dot)invalid",
            ),
            ("jules%40example%2Einvalid", "jules%40example%2Einvalid"),
            ("mailto:Jules%40Example.invalid", "Jules%40Example.invalid"),
            (
                "JULES AT EXAMPLE DOT INVALID",
                "JULES AT EXAMPLE DOT INVALID",
            ),
            ("jules＠example．invalid", "jules＠example．invalid"),
            ("jul%65s@example.invalid", "jul%65s@example.invalid"),
        ] {
            assert_eq!(
                masked_kinds(&index, text),
                [(EntityKind::Email, expected.to_string())],
                "{text}"
            );
        }
    }

    #[test]
    fn repeated_identifiers_do_not_multiply_patterns() {
        let mut index = ContactIndex::new();
        for _ in 0..1_000 {
            index.add_person(PersonDraft {
                given: zs(&["Marie"]),
                family: zs(&["Dupont"]),
                emails: zs(&["marie@example.invalid", "MARIE@example.invalid"]),
                phones: zs(&["+33 6 12 34 56 78", "0033612345678"]),
                ..PersonDraft::default()
            });
        }
        assert_eq!(index.len(), 1);
        assert_eq!(index.refused(), 0);
        assert!(index.recognizer().expect("build").pattern_count() <= 20);
    }

    #[test]
    fn an_iban_in_full_width_or_lower_case_matches() {
        let mut index = ContactIndex::new();
        index.add_person(PersonDraft {
            given: zs(&["Marie"]),
            ibans: zs(&["FR76 3000 6000 0112 3456 7890 189"]),
            ..PersonDraft::default()
        });
        let text =
            "fr76 3000 6000 0112 3456 7890 189 et ＦＲ７６ ３０００ ６０００ 0112 3456 7890 189";
        let found: Vec<String> = masked_kinds(&index, text)
            .into_iter()
            .filter(|(kind, _)| *kind == EntityKind::Iban)
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            found,
            [
                "fr76 3000 6000 0112 3456 7890 189",
                "ＦＲ７６ ３０００ ６０００ 0112 3456 7890 189",
            ]
        );
    }

    #[test]
    fn a_draft_and_an_index_debug_never_print_values() {
        let draft = PersonDraft {
            display_name: Some(Zeroizing::new("Marie Dupont".to_string())),
            given: zs(&["Marie"]),
            phones: zs(&["+33 6 12 34 56 78"]),
            ..PersonDraft::default()
        };
        let rendered = format!("{draft:?}");
        assert!(!rendered.contains("Marie") && !rendered.contains("6 12"));
        let mut index = ContactIndex::new();
        index.add_person(draft);
        let rendered = format!("{index:?} {:?}", index.people().next());
        assert!(!rendered.contains("Marie") && !rendered.contains("612"));
    }

    #[test]
    fn a_stored_address_is_read_in_every_spelling() {
        let mut index = ContactIndex::new();
        index.add_person(PersonDraft {
            given: zs(&["Jules"]),
            emails: zs(&["mailto:Jules%40Example.invalid"]),
            ..PersonDraft::default()
        });
        let found = masked_kinds(&index, "écrire à jules@example.invalid");
        assert_eq!(
            found,
            [(EntityKind::Email, "jules@example.invalid".to_string())]
        );
    }

    #[test]
    fn a_plus_tag_of_a_known_address_names_no_one() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Jules", "Martin", &["jules+crm@example.invalid"]));
        assert!(masked_kinds(&index, "Mon CRM et crm, Jules.").is_empty());
    }

    #[test]
    fn a_common_word_surname_masks_only_when_capitalised() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Marie", "Rose", &[]));
        let found: Vec<String> = masked_by_contacts(&index, "Rose est là, une rose rouge.")
            .into_iter()
            .map(|(value, _)| value)
            .collect();
        assert_eq!(found, ["Rose"]);
    }

    #[test]
    fn overlapping_contacts_sharing_a_surname_mask_consistently() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Marie", "Dupont", &[]));
        index.add_person(draft("Jean", "Dupont", &[]));
        let found = masked_by_contacts(
            &index,
            "Marie Dupont, Jean Dupont, M. Dupont, J. Dupont, puis Dupont.",
        );
        assert_eq!(
            found,
            [
                ("Marie Dupont".to_string(), 0),
                ("Jean Dupont".to_string(), 1),
                ("M. Dupont".to_string(), 0),
                ("J. Dupont".to_string(), 1),
                ("Dupont".to_string(), 0),
            ]
        );
    }

    #[test]
    fn hyphenated_and_compound_surnames_match_every_spelling() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Claire", "Martin-Dupont", &[]));
        index.add_person(draft("Jan", "van der Berg", &[]));
        let found: Vec<String> = masked_by_contacts(
            &index,
            "Claire Martin-Dupont, CLAIRE MARTIN DUPONT, Martin-Dupont. \
             Jan van der Berg, Jan Van der Berg.",
        )
        .into_iter()
        .map(|(value, _)| value)
        .collect();
        assert_eq!(
            found,
            [
                "Claire Martin-Dupont",
                "Martin-Dupont, CLAIRE",
                "CLAIRE MARTIN DUPONT",
                "Martin-Dupont",
                "Jan van der Berg",
                "van der Berg, Jan",
                "Jan Van der Berg",
            ]
        );
    }

    #[test]
    fn a_family_name_with_particles_also_comes_without_them() {
        let mut index = ContactIndex::new();
        index.add_person(draft("Jean", "de La Fontaine", &[]));
        let found: Vec<String> = masked_by_contacts(&index, "Jean de La Fontaine et La Fontaine.")
            .into_iter()
            .map(|(value, _)| value)
            .collect();
        assert_eq!(found, ["Jean de La Fontaine", "La Fontaine"]);
    }

    #[test]
    fn phones_in_every_spelling_map_to_their_contact() {
        let mut index = ContactIndex::new();
        for (given, family, phone) in [
            ("Thandi", "Nkosi", "+27 (0)82 123 4567"),
            ("Anna", "Kovacs", "+36 30 123 4567"),
            ("Li", "Wei", "+86 138 0013 8000"),
            ("Paul", "Local", "06 12 34 56 78"),
        ] {
            index.add_person(PersonDraft {
                phones: zs(&[phone]),
                ..draft(given, family, &[])
            });
        }
        let recognizer = index.recognizer().expect("build");
        let owners = |text: &str| -> Vec<(String, u32)> {
            recognizer
                .analyze(text)
                .into_iter()
                .filter(|span| span.kind == EntityKind::Phone)
                .map(|span| {
                    (
                        text[span.start..span.end].to_string(),
                        span.person_id.unwrap_or(u32::MAX),
                    )
                })
                .collect()
        };
        for (text, person) in [
            ("082 123 4567", 0),
            ("+27 82 123 4567", 0),
            ("0027 82 123 4567", 0),
            ("+36 30 123 4567", 1),
            ("+36 (0)30 123 4567", 1),
            ("06 30 123 4567", 1),
            ("+86 138 0013 8000", 2),
            ("0086 138 0013 8000", 2),
            ("138 0013 8000", 2),
            ("06 12 34 56 78", 3),
            ("06.12.34.56.78", 3),
        ] {
            assert_eq!(owners(text), [(text.to_string(), person)], "{text}");
        }
        // A local number has no country, so an international form does not match it.
        assert!(owners("+33 6 12 34 56 78").is_empty());
    }
}
