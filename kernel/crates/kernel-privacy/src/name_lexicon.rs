//! Closed given-name and surname lexicons for the bare-first-name rule.
//!
//! The default privacy policy (`privacy.mask_first_names = false`, owner
//! decision 2026-10-09) leaves a bare given name in clear. A single-token
//! `PERSON` span is only dropped when the token is *known* to be a given
//! name and *not* known to be a surname, **and** it sits in a vocative or
//! address position outside signature context; the two closed lists below are
//! only part of that evidence. Any token the lexicons do not know stays masked.
//!
//! Both files are hand-curated and versioned ([`NAME_LEXICON_VERSION`]); a name
//! is stored folded (lowercase, marks dropped) and one language is listed per
//! line. `email_layer` has no language detector, so the lookup is over the
//! union of every supported language: a token that is a given name in any of
//! them and a surname in none is treated as a bare given name. That is the
//! conservative direction — a token that is a surname in any supported language
//! stays masked, and so does any token the lists do not carry.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::public_terms::fold;

/// Version of the bundled name lexicons. Bump it with the data files.
///
/// * `2` — strict vocative rule: adds the verified given/surname collisions the
///   earlier lists missed (`Grace`, `János` and its family forms, `Halloran`, …).
pub const NAME_LEXICON_VERSION: &str = "2";

/// Common given names (EN, FR, AF, HU, ZH-pinyin, DE, NL).
const GIVEN_NAMES: &str = include_str!("../data/given-names-v1.txt");
/// Common surnames of the same languages, plus the given/surname collisions
/// (`Martin`, `Thomas`, `Bernard`, `Laurent`, `Robert`, `Richard`, `Nagy`,
/// `Kovács`, `Botha`, …) that must never be mistaken for a bare given name.
const SURNAMES: &str = include_str!("../data/surnames-v1.txt");

static GIVEN_NAMES_SET: LazyLock<HashSet<String>> = LazyLock::new(|| load(GIVEN_NAMES));
static SURNAMES_SET: LazyLock<HashSet<String>> = LazyLock::new(|| load(SURNAMES));

/// Read one `<lang>: name name …` line per language; `#` starts a comment.
fn load(data: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for raw in data.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let names = line.split_once(':').map(|(_, rest)| rest).unwrap_or(line);
        for name in names.split_whitespace() {
            let folded = fold(name);
            if !folded.is_empty() {
                set.insert(folded);
            }
        }
    }
    set
}

/// Whether `folded` is a known given name in any supported language.
pub fn is_given_name(folded: &str) -> bool {
    GIVEN_NAMES_SET.contains(folded)
}

/// Whether `folded` is a known surname in any supported language.
pub fn is_surname(folded: &str) -> bool {
    SURNAMES_SET.contains(folded)
}

/// The number of distinct given names loaded.
pub fn given_name_count() -> usize {
    GIVEN_NAMES_SET.len()
}

/// The number of distinct surnames loaded.
pub fn surname_count() -> usize {
    SURNAMES_SET.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexicons_load_and_are_versioned() {
        assert_eq!(NAME_LEXICON_VERSION, "2");
        assert!(given_name_count() >= 600, "{}", given_name_count());
        assert!(surname_count() >= 400, "{}", surname_count());
    }

    #[test]
    fn given_names_and_surname_collisions() {
        for name in ["mila", "jules", "hugo", "yanis", "freya"] {
            assert!(is_given_name(name), "{name} should be a given name");
            assert!(!is_surname(name), "{name} should not be a surname");
        }
        for name in [
            "martin", "thomas", "bernard", "laurent", "robert", "richard", "nagy", "kovacs",
            "botha", "dupont", "wang", "grace", "morgan", "taylor", "jordan", "lee", "rose",
            "hunter", "mason", "simon", "michel", "vincent", "petit", "smit", "janos", "halloran",
        ] {
            assert!(is_surname(name), "{name} should be a surname");
        }
    }

    #[test]
    fn unknown_token_is_neither() {
        assert!(!is_given_name("zorblath"));
        assert!(!is_surname("zorblath"));
    }
}
