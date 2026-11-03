//! Name variants: the surface forms under which a known person may be written.
//!
//! Every variant is stored folded (see [`super::fold`]) with the check the
//! original text must pass after a match. The tables are small on purpose: a
//! name that is not listed still matches in full, and a table entry only adds
//! its forms next to the full name.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

use zeroize::Zeroizing;

use super::fold::{fold, folded_text};
use super::inflect::{self, Role};
use super::stopwords;
use super::{Key, Person};

/// What a matched span must look like in the original text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Check {
    /// Any casing is accepted.
    Any,
    /// The first letter must not be lower case: an initial such as "M. Dupont".
    FirstUpper,
    /// No letter may be lower case: an initialism such as "MD".
    AllUpper,
    /// The last word must be capitalised: a title or an initial in front of a
    /// surname that is also a function word ("M. Le", "Mme Le", not "M. le").
    Titled,
    /// Name context only: the match is the only text on its line (a signature,
    /// a quoted line), or the value of a mail header ("From: Le"). A function
    /// word such as "le" names nobody in running text.
    Context,
}

/// One folded surface form of a person.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Variant {
    pub(crate) text: Zeroizing<String>,
    pub(crate) check: Check,
}

impl fmt::Debug for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The text is a name: only its length and check are shown.
        f.debug_struct("Variant")
            .field("chars", &self.text.chars().count())
            .field("check", &self.check)
            .finish()
    }
}

/// Shortest folded variant, in characters: one letter alone is never a name.
const MIN_CHARS: usize = 2;
/// Longest folded variant, in bytes: a longer string is a sentence, not a name.
const MAX_BYTES: usize = 80;
/// Characters that join the parts of one name ("Jean-Marc", "O'Brien").
const JOINERS: &[char] = &['-', '\'', '’', 'ʼ', '`'];
/// Titles that may stand in front of a surname that is also a function word.
const TITLES: &[&str] = &[
    "M",
    "Mme",
    "Mlle",
    "Mr",
    "Mrs",
    "Ms",
    "Dr",
    "Pr",
    "Prof",
    "Monsieur",
    "Madame",
    "Mademoiselle",
    "Maître",
    "Herr",
    "Frau",
    "Sr",
    "Sra",
];

/// Short forms of a given name, keyed by the full form. Entries are grouped by
/// language; Russian keys appear in Cyrillic and in Latin transliteration.
const NICKNAMES: &[(&str, &[&str])] = &[
    // en
    ("alexander", &["alex", "al", "sandy"]),
    ("william", &["bill", "billy", "will"]),
    ("robert", &["bob", "bobby", "rob"]),
    ("richard", &["rick", "dick"]),
    ("michael", &["mike"]),
    ("elizabeth", &["liz", "beth", "betty"]),
    ("katherine", &["kate", "kathy", "katie"]),
    ("margaret", &["maggie", "meg", "peggy"]),
    ("james", &["jim", "jimmy"]),
    ("thomas", &["tom", "tommy"]),
    ("joseph", &["joe"]),
    ("daniel", &["dan"]),
    ("christopher", &["chris"]),
    ("nicholas", &["nick"]),
    // fr
    ("alexandre", &["alex"]),
    ("nicolas", &["nico"]),
    ("christophe", &["chris"]),
    ("sébastien", &["seb"]),
    ("stéphane", &["steph"]),
    ("mathieu", &["matt", "mat"]),
    // af
    ("johannes", &["hannes", "jan", "jannie"]),
    ("pieter", &["piet", "pietie"]),
    ("willem", &["wim", "willie"]),
    ("hendrik", &["hennie", "henk"]),
    ("jacobus", &["koos", "jaco"]),
    ("susanna", &["sannie", "sanna"]),
    // hu
    ("katalin", &["kati", "kata", "katica"]),
    ("erzsébet", &["erzsi", "böske"]),
    ("istván", &["pista", "istvánka"]),
    ("jános", &["jancsi", "jani"]),
    ("ferenc", &["feri"]),
    ("sándor", &["sanyi"]),
    ("zsuzsanna", &["zsuzsi", "zsuzsa"]),
    ("margit", &["margó", "margitka"]),
    // ru
    ("александр", &["саша", "саня", "шура"]),
    ("aleksandr", &["sasha", "sanya"]),
    ("дмитрий", &["дима", "митя"]),
    ("dmitrii", &["dima", "mitya"]),
    ("екатерина", &["катя", "катерина"]),
    ("ekaterina", &["katya", "katia"]),
    ("владимир", &["вова", "володя"]),
    ("vladimir", &["volodya", "vova"]),
    ("михаил", &["миша"]),
    ("mikhail", &["misha"]),
    ("мария", &["маша"]),
    ("mariya", &["masha"]),
    ("анна", &["аня"]),
    ("наталья", &["наташа"]),
    ("сергей", &["серёжа"]),
    ("sergey", &["seryozha", "serezha"]),
    // ar: Mohammed and its usual short form; Arabic script matches its own.
    ("mohammed", &["mo", "med"]),
    ("محمد", &["mo"]),
];

/// Spellings of one given name across transliterations. Every member of a
/// group also matches the others.
const SPELLING_GROUPS: &[&[&str]] = &[
    &["mohammed", "mohamed", "muhammad", "mohammad", "mohamad"],
    &["ahmed", "ahmad", "achmed"],
    &["abdullah", "abdallah"],
    &[
        "aleksandr",
        "alexandr",
        "aleksander",
        "alexander",
        "alexandru",
    ],
    &["dmitrii", "dmitriy", "dmitri", "dmitry"],
    &["mikhail", "michail"],
    &["sergey", "sergei", "sergej"],
    &["ekaterina", "yekaterina"],
    &["mariya", "marija"],
    &["pieter", "peter"],
];

/// Particles that are never a name on their own ("van", "de", "bin").
const PARTICLES: &[&str] = &[
    "de", "du", "des", "der", "den", "van", "von", "di", "da", "dos", "das", "del", "della", "le",
    "la", "les", "el", "al", "bin", "ibn", "ben", "ter", "ten", "het", "zu", "op", "ap", "abu",
];

/// Local-part words of a shared or role mailbox. They never name a person.
pub(crate) const GENERIC_WORDS: &[&str] = &[
    "info",
    "contact",
    "contacts",
    "admin",
    "administration",
    "support",
    "sales",
    "hello",
    "hallo",
    "bonjour",
    "hej",
    "team",
    "noreply",
    "reply",
    "mail",
    "office",
    "service",
    "services",
    "accounts",
    "account",
    "billing",
    "compta",
    "facturation",
    "factures",
    "invoices",
    "hr",
    "rh",
    "help",
    "news",
    "newsletter",
    "webmaster",
    "postmaster",
    "no",
    "donotreply",
    "notifications",
    "notification",
    "orders",
    "commande",
    "bureau",
    "direction",
    "secretariat",
    "secretaire",
    "legal",
    "press",
    "marketing",
    "jobs",
    "careers",
    "recrutement",
    "kontakt",
    "hilfe",
    "sekretariat",
    "mailer",
    "daemon",
    "bounce",
    "hostmaster",
    "welcome",
    "mailing",
    "list",
    "shop",
    "store",
    "web",
    "www",
    "test",
];

/// Accumulates the variants of one person, folded and de-duplicated.
#[derive(Default)]
struct Builder {
    variants: Vec<Variant>,
    seen: HashSet<Key>,
}

impl Builder {
    /// Add `raw` folded, and its compact form when it has joiners.
    fn add_name(&mut self, raw: &str, check: Check) {
        self.add(raw, check);
        if raw.contains(JOINERS) {
            let compact: String = raw.chars().filter(|c| !JOINERS.contains(c)).collect();
            self.add(&compact, check);
        }
    }

    fn add(&mut self, raw: &str, check: Check) {
        self.add_folded(folded_text(raw), check);
    }

    fn add_folded(&mut self, text: String, check: Check) {
        if text.chars().count() < MIN_CHARS || text.len() > MAX_BYTES {
            return;
        }
        match check {
            // A function word alone ("le", "the") names nobody in running text,
            // but it may be a surname: it masks in name context, and with a title.
            Check::Any if !text.contains(' ') && stopwords::is_closed_word(&text) => {
                for title in TITLES {
                    self.insert_variant(format!("{} {text}", folded_text(title)), Check::Titled);
                }
                self.insert_variant(text, Check::Context);
            }
            // A surname that is also a common word ("Rose", "Bon") masks only when
            // it is capitalised: "une rose" names no one.
            Check::Any if !text.contains(' ') && stopwords::is_common_word(&text) => {
                self.insert_variant(text, Check::FirstUpper);
            }
            // "M. le directeur" is not "M. Le": the surname must be capitalised.
            Check::FirstUpper if ends_in_function_word(&text) => {
                self.insert_variant(text, Check::Titled);
            }
            _ => self.insert_variant(text, check),
        }
    }

    /// Record `text` with `check`, unless the same text is already recorded.
    fn insert_variant(&mut self, text: String, check: Check) {
        let text = Zeroizing::new(text);
        if self.seen.insert(Key(text.clone())) {
            self.variants.push(Variant { text, check });
        }
    }
}

/// Whether the last word of the folded `text` is a function word ("M. le").
fn ends_in_function_word(text: &str) -> bool {
    stopwords::is_closed_word(text.rsplit(' ').next().unwrap_or_default())
}

/// Every surface form of `person`, folded and ready to compile.
///
/// A form built from given names alone (the names, their parts, nicknames,
/// spellings, declensions, and the initialism of the given names) is included
/// only when `mask_first_names` is set. Every other form is always included:
/// full names, family names, initials with the family name, and e-mail
/// addresses and their identifiers.
pub(crate) fn variants_for(person: &Person, mask_first_names: bool) -> Vec<Variant> {
    let given = names(&person.given);
    let family = names(&person.family);
    let nicknames = names(&person.nicknames);
    let given_phrase = given.join(" ");
    let family_phrase = family.join(" ");
    let given_keys = first_name_keys(&given, &nicknames);
    let mut out = Builder::default();

    // Full names, in both orders.
    if !given.is_empty() && !family.is_empty() {
        out.add_name(&format!("{given_phrase} {family_phrase}"), Check::Any);
        out.add_name(&format!("{family_phrase} {given_phrase}"), Check::Any);
    }

    // Given names alone, then each part of a compound given name ("Jean").
    if mask_first_names {
        for name in &given {
            out.add_name(name, Check::Any);
            for part in folded_parts(name) {
                out.add(&part, Check::Any);
            }
        }
    }

    // Family name alone, then each part that is not a particle.
    if !family.is_empty() {
        out.add_name(&family_phrase, Check::Any);
        for part in folded_parts(&family_phrase) {
            if !PARTICLES.contains(&part.as_str()) {
                out.add(&part, Check::Any);
            }
        }
        // Without its opening lower-case particles: "La Fontaine" for "de La Fontaine".
        let words: Vec<&str> = family_phrase.split_whitespace().collect();
        let opening = words
            .iter()
            .take_while(|word| is_lower_particle(word))
            .count();
        if opening > 0 && words.len() - opening >= 2 {
            out.add(&words[opening..].join(" "), Check::Any);
        }
    }

    // Declined and affixed forms of each word: Russian cases (and the case pairs
    // of the full name), Hungarian suffixes, Arabic prefixes, French elision.
    for (words, role) in [(&given, Role::Given), (&family, Role::Family)] {
        if !mask_first_names && matches!(role, Role::Given) {
            continue;
        }
        for word in words
            .iter()
            .filter(|word| !word.contains(char::is_whitespace) && !word.contains(JOINERS))
        {
            for form in inflect::word_forms(word, role) {
                out.add(&form, Check::Any);
            }
        }
    }
    if let ([given_word], [family_word]) = (given.as_slice(), family.as_slice()) {
        if let (Some(given_cases), Some(family_cases)) = (
            inflect::ru_cases(given_word, Role::Given),
            inflect::ru_cases(family_word, Role::Family),
        ) {
            for (given_case, family_case) in given_cases.iter().zip(&family_cases).skip(1) {
                out.add_name(&format!("{given_case} {family_case}"), Check::Any);
                out.add_name(&format!("{family_case} {given_case}"), Check::Any);
            }
        }
    }

    add_initials(&mut out, &given, &family_phrase, mask_first_names);
    add_related_forms(&mut out, &given, &family_phrase, mask_first_names);
    for nickname in &nicknames {
        if mask_first_names {
            out.add_name(nickname, Check::Any);
        }
        if !family_phrase.is_empty() {
            out.add(&format!("{nickname} {family_phrase}"), Check::Any);
        }
    }
    for email in &person.emails {
        add_email_variants(&mut out, email, &given_keys, mask_first_names);
    }
    out.variants
}

/// A lower-case particle, as in "de La Fontaine" or "van der Berg".
fn is_lower_particle(word: &str) -> bool {
    word.chars().next().is_some_and(char::is_lowercase)
        && PARTICLES.contains(&folded_text(word).as_str())
}

/// The folded words that a given name may be written as on its own: the name,
/// its parts, its table forms, and the nicknames. An e-mail local part that
/// holds one of them is a first name, not a surname.
fn first_name_keys(given: &[String], nicknames: &[String]) -> HashSet<String> {
    let table = lookup_table();
    let mut keys = HashSet::new();
    for name in given {
        keys.insert(folded_text(name));
        keys.extend(folded_parts(name));
        if let Some(forms) = table.get(&folded_text(name)) {
            keys.extend(forms.iter().map(|form| folded_text(form)));
        }
    }
    keys.extend(nicknames.iter().map(|nickname| folded_text(nickname)));
    keys
}

/// Initialisms ("MD", "JM", "JMD") and initial plus family name ("M. Dupont",
/// "J. M. Dupont"). Their letters must be upper case in the text.
fn add_initials(out: &mut Builder, given: &[String], family_phrase: &str, mask_first_names: bool) {
    let given_parts: Vec<String> = given.iter().flat_map(|name| folded_parts(name)).collect();
    let initials: String = given_parts
        .iter()
        .filter_map(|part| part.chars().next())
        .collect();
    let family_initial = folded_parts(family_phrase)
        .first()
        .and_then(|part| part.chars().next());
    let first_initial = given_parts.first().and_then(|part| part.chars().next());

    if mask_first_names && initials.chars().count() >= 2 {
        out.add_folded(initials.clone(), Check::AllUpper);
    }
    if let Some(family) = family_initial {
        if let Some(first) = first_initial {
            out.add_folded(format!("{first}{family}"), Check::AllUpper);
        }
        if initials.chars().count() >= 2 {
            out.add_folded(format!("{initials}{family}"), Check::AllUpper);
        }
    }
    if family_phrase.is_empty() {
        return;
    }
    if let Some(first) = first_initial {
        let initial: String = first.to_uppercase().collect();
        out.add(&format!("{initial}. {family_phrase}"), Check::FirstUpper);
    }
    if given_parts.len() >= 2 {
        let dotted: Vec<String> = given_parts
            .iter()
            .filter_map(|part| part.chars().next())
            .map(|c| format!("{}.", c.to_uppercase()))
            .collect();
        out.add(
            &format!("{} {family_phrase}", dotted.join(" ")),
            Check::FirstUpper,
        );
    }
}

/// Spelling variants and nicknames of each given name, alone and with the
/// family name.
fn add_related_forms(
    out: &mut Builder,
    given: &[String],
    family_phrase: &str,
    mask_first_names: bool,
) {
    let table = lookup_table();
    for name in given {
        let key = folded_text(name);
        let Some(forms) = table.get(&key) else {
            continue;
        };
        for form in forms {
            if mask_first_names {
                out.add_name(form, Check::Any);
            }
            if !family_phrase.is_empty() {
                out.add(&format!("{form} {family_phrase}"), Check::Any);
            }
        }
    }
}

/// The folded table of [`NICKNAMES`] and [`SPELLING_GROUPS`], built once.
fn lookup_table() -> &'static HashMap<String, Vec<String>> {
    static TABLE: OnceLock<HashMap<String, Vec<String>>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table: HashMap<String, Vec<String>> = HashMap::new();
        for (key, forms) in NICKNAMES {
            table
                .entry(folded_text(key))
                .or_default()
                .extend(forms.iter().map(|form| (*form).to_string()));
        }
        for group in SPELLING_GROUPS {
            for member in group.iter() {
                let others = group
                    .iter()
                    .filter(|other| *other != member)
                    .map(|other| (*other).to_string());
                table.entry(folded_text(member)).or_default().extend(others);
            }
        }
        table
    })
}

/// The name parts of a local part: "marie.dupont83@…" gives "marie" and
/// "dupont" alone, and "marie dupont" together. Role words never count. A part
/// that is a known given name is a first name alone, so it is skipped unless
/// first names are masked. A part the index cannot place stays masked.
fn add_email_variants(
    out: &mut Builder,
    email: &str,
    given_keys: &HashSet<String>,
    mask_first_names: bool,
) {
    let Some((local, _)) = email.rsplit_once('@') else {
        return;
    };
    // A `+tag` names a mailbox, not a person: only the part before it is a name.
    let local = local.split('+').next().unwrap_or(local);
    let tokens: Vec<String> = local
        .split(|c: char| !c.is_alphabetic())
        .filter(|token| token.chars().count() >= MIN_CHARS)
        .map(folded_text)
        .collect();
    let usable: Vec<&String> = tokens
        .iter()
        .filter(|token| !GENERIC_WORDS.contains(&token.as_str()))
        .collect();
    for token in &usable {
        if !mask_first_names && given_keys.contains(token.as_str()) {
            continue;
        }
        out.add(token, Check::Any);
    }
    if usable.len() >= 2 && usable.len() == tokens.len() {
        let joined: Vec<&str> = usable.iter().map(|token| token.as_str()).collect();
        out.add(&joined.join(" "), Check::Any);
    }
}

/// Non-empty trimmed copies of `values`.
fn names(values: &[Zeroizing<String>]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

/// The folded words of `raw`, split at the separators the folding keeps.
fn folded_parts(raw: &str) -> Vec<String> {
    fold(raw)
        .text()
        .split(' ')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(given: &[&str], family: &[&str], emails: &[&str]) -> Person {
        let wrap = |values: &[&str]| -> Vec<Zeroizing<String>> {
            values
                .iter()
                .map(|s| Zeroizing::new(s.to_string()))
                .collect()
        };
        Person {
            given: wrap(given),
            family: wrap(family),
            emails: wrap(emails),
            ..Person::default()
        }
    }

    /// The variants with first names masked; the default is covered below.
    fn texts(person: &Person) -> Vec<String> {
        variants_for(person, true)
            .into_iter()
            .map(|v| v.text.as_str().to_string())
            .collect()
    }

    fn default_texts(person: &Person) -> Vec<String> {
        variants_for(person, false)
            .into_iter()
            .map(|v| v.text.as_str().to_string())
            .collect()
    }

    #[test]
    fn full_name_in_both_orders_and_the_parts() {
        let found = texts(&person(&["Marie"], &["Dupont"], &[]));
        for expected in [
            "marie dupont",
            "dupont marie",
            "marie",
            "dupont",
            "m dupont",
        ] {
            assert!(found.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[test]
    fn compound_given_names_give_hyphen_and_joined_forms() {
        let found = texts(&person(&["Jean-Marc"], &["Dupont"], &[]));
        for expected in [
            "jean marc dupont",
            "jeanmarc dupont",
            "jean",
            "marc",
            "jm",
            "jmd",
        ] {
            assert!(found.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[test]
    fn a_variant_debug_never_prints_the_name() {
        let found = variants_for(&person(&["Marie"], &["Dupont"], &[]), false);
        let rendered = format!("{:?}", found[0]).to_lowercase();
        assert!(!rendered.contains("marie") && !rendered.contains("dupont"));
    }

    #[test]
    fn email_local_parts_skip_digits_and_role_words() {
        let found = texts(&person(&[], &[], &["marie.dupont83@example.invalid"]));
        assert!(found.contains(&"marie".to_string()));
        assert!(found.contains(&"dupont".to_string()));
        assert!(found.contains(&"marie dupont".to_string()));
        let role = texts(&person(&[], &[], &["info@example.invalid"]));
        assert!(role.is_empty());
    }

    #[test]
    fn nicknames_come_from_the_table() {
        let found = texts(&person(&["Alexandre"], &["Dupont"], &[]));
        assert!(found.contains(&"alex".to_string()));
        assert!(found.contains(&"alex dupont".to_string()));
        let arabic = texts(&person(&["محمد"], &["علي"], &[]));
        assert!(arabic.contains(&"mo".to_string()));
    }

    #[test]
    fn first_names_alone_are_not_variants_by_default() {
        let jules = person(&["Jules"], &["Martin"], &["jules.martin@example.invalid"]);
        let found = default_texts(&jules);
        for expected in ["jules martin", "martin", "j martin"] {
            assert!(found.contains(&expected.to_string()), "missing {expected}");
        }
        assert!(!found.contains(&"jules".to_string()));
        assert!(texts(&jules).contains(&"jules".to_string()));
    }

    #[test]
    fn nicknames_and_declensions_of_a_first_name_need_the_flag() {
        let alex = person(&["Alexandre"], &["Dupont"], &[]);
        assert!(!default_texts(&alex).contains(&"alex".to_string()));
        assert!(default_texts(&alex).contains(&"alex dupont".to_string()));
        let anna = person(&["Анна"], &["Смирнова"], &[]);
        assert!(!default_texts(&anna).contains(&folded_text("анной")));
        assert!(default_texts(&anna).contains(&folded_text("анну смирнову")));
    }

    #[test]
    fn family_particles_are_not_names_alone() {
        let found = texts(&person(&["Jan"], &["van", "der", "Berg"], &[]));
        assert!(found.contains(&"berg".to_string()));
        assert!(!found.contains(&"van".to_string()));
        assert!(!found.contains(&"der".to_string()));
    }

    #[test]
    fn a_function_word_surname_is_compiled_only_in_name_context() {
        let le = variants_for(&person(&[], &["Le"], &[]), false);
        let check_of = |text: &str| le.iter().find(|v| v.text.as_str() == text).map(|v| v.check);
        assert_eq!(check_of("le"), Some(Check::Context));
        assert_eq!(check_of("mme le"), Some(Check::Titled));
        assert_eq!(check_of("m le"), Some(Check::Titled));
        assert_eq!(check_of("marie le"), None);
        let marie_le = variants_for(&person(&["Marie"], &["Le"], &[]), false);
        let found: Vec<&str> = marie_le.iter().map(|v| v.text.as_str()).collect();
        assert!(found.contains(&"marie le") && found.contains(&"le marie"));
        assert!(found.contains(&"m le"));
    }

    #[test]
    fn real_names_are_compiled_as_plain_variants() {
        let found = texts(&person(&["Will"], &["Rose"], &[]));
        assert!(found.contains(&"will".to_string()));
        assert!(found.contains(&"rose".to_string()));
        assert!(texts(&person(&["Mark"], &[], &[])).contains(&"mark".to_string()));
        assert!(texts(&person(&["Pierre"], &[], &[])).contains(&"pierre".to_string()));
    }

    #[test]
    fn russian_cases_and_case_pairs_are_compiled() {
        let found = texts(&person(&["Анна"], &["Смирнова"], &[]));
        for expected in ["анне смирновой", "смирновой анне", "анну смирнову", "анной"]
        {
            assert!(found.contains(&folded_text(expected)), "missing {expected}");
        }
    }

    #[test]
    fn hungarian_suffixes_and_french_elision_are_compiled() {
        let found = texts(&person(&["Lilla"], &["Kovács"], &[]));
        for expected in ["lillának", "lillát", "kovácsnak", "kovácsot", "lilla-féle"] {
            assert!(found.contains(&folded_text(expected)), "missing {expected}");
        }
        let elided = texts(&person(&["Jean"], &["Artagnan"], &[]));
        assert!(elided.contains(&folded_text("d'Artagnan")));
    }
}
