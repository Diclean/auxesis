//! Identifiers in the formats a mail or a note uses: e-mail addresses (any
//! case, percent-encoded, obfuscated as "name at domain dot com" or
//! "[at]"/"(dot)", with a `+tag` in the local part, and inside `mailto:`),
//! phone numbers (`+CC`, `00CC`, or a national form with its trunk prefix, with
//! any separators; stored in E.164 when the country is known) and IBANs (with or
//! without spaces or line breaks).
//!
//! The text is read as it is, never folded, so every span is an exact byte
//! range of the original.

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::{Key, PersonId};

/// Whom a key names, and whether another person shares the key. The oldest
/// person keeps the id, so an ambiguous key still masks, under one id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) person: PersonId,
    pub(crate) ambiguous: bool,
}

/// Shortest digits of a phone key, and the shortest a phone match may be.
pub(crate) const MIN_PHONE_DIGITS: usize = 6;
/// Longest digit run a phone match may cover (E.164 plus a `00` prefix).
const MAX_PHONE_DIGITS: usize = 17;
/// Most digit groups one phone match may join.
const MAX_PHONE_GROUPS: usize = 10;
/// Longest IBAN in characters (ISO 13616).
const MAX_IBAN_LEN: usize = 34;
/// Most alphanumeric tokens one IBAN match may join.
const MAX_IBAN_TOKENS: usize = 12;
/// Fewest subscriber digits a national form of a number is kept for.
const MIN_SUBSCRIBER_DIGITS: usize = MIN_PHONE_DIGITS - 1;
/// Fewest subscriber digits for the form without a trunk prefix to be kept:
/// shorter digit runs would collide with ordinary numbers in a text.
const MIN_BARE_DIGITS: usize = 8;

/// Calling codes (ITU-T E.164) of the common countries, by longest match. A
/// number whose code is not listed matches on its international form only.
const CALLING_CODES: &str = "1 7 20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 \
    54 55 56 57 58 60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98 212 213 216 218 351 352 \
    353 354 355 356 357 358 359 370 371 372 373 374 375 376 377 378 380 381 382 385 386 387 389 \
    420 421 423 961 962 963 964 965 966 967 968 970 971 972 973 974 975 976 977 992 993 994 995 \
    996 998";

/// Records `person` under `key`. A second person under the same key marks the
/// key ambiguous; the oldest keeps the id.
pub(crate) fn insert_key(
    keys: &mut HashMap<Key, Target>,
    key: Zeroizing<String>,
    person: PersonId,
) {
    keys.entry(Key(key))
        .and_modify(|target| target.ambiguous |= target.person != person)
        .or_insert(Target {
            person,
            ambiguous: false,
        });
}

/// A phone number as the index keeps it, in E.164 when its country is known
/// from the number itself: `+CC` and the subscriber digits, with the trunk `0`
/// that some writers keep after the country code (`+33 (0)6 …`) dropped. A
/// `00CC…` prefix is taken as `+CC…`. A local number with no country keeps its
/// digits as written: its country is never assumed. `None` when it has too few
/// or too many digits.
pub(crate) fn normalize_phone(raw: &str) -> Option<String> {
    let composed: String = raw.nfkc().collect();
    let digits: String = composed.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < MIN_PHONE_DIGITS || digits.len() > MAX_PHONE_DIGITS {
        return None;
    }
    if composed.trim_start().starts_with('+') {
        return Some(format!("+{}", canonical_international(&digits)));
    }
    match digits.strip_prefix("00") {
        Some(international) if international.len() >= MIN_PHONE_DIGITS => {
            Some(format!("+{}", canonical_international(international)))
        }
        _ => Some(digits),
    }
}

/// The digits of an international number with its trunk prefix removed: `0`,
/// or `06` for Hungary, whose subscribers never start with `6`.
fn canonical_international(digits: &str) -> String {
    let Some((code, subscriber)) = split_calling_code(digits) else {
        return digits.to_string();
    };
    let subscriber = match code {
        "36" => subscriber
            .strip_prefix("06")
            .or_else(|| subscriber.strip_prefix('0'))
            .unwrap_or(subscriber),
        _ => subscriber.strip_prefix('0').unwrap_or(subscriber),
    };
    format!("{code}{subscriber}")
}

/// Splits the digits of an international number into its calling code and its
/// subscriber digits, by the longest listed code. `None` when no listed code
/// fits, so an unknown country matches on its international form only.
fn split_calling_code(international: &str) -> Option<(&str, &str)> {
    (1..=3).rev().find_map(|len| {
        let code = international.get(..len)?;
        let subscriber = international.get(len..)?;
        CALLING_CODES
            .split_whitespace()
            .any(|listed| listed == code)
            .then_some((code, subscriber))
    })
}

/// An IBAN as the index keeps it: upper case, no separators. `None` unless it
/// has a two-letter country code, two check digits and a valid length.
pub(crate) fn normalize_iban(raw: &str) -> Option<String> {
    let compact: String = raw
        .nfkc()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let well_formed = (15..=MAX_IBAN_LEN).contains(&compact.len())
        && compact.chars().take(2).all(|c| c.is_ascii_uppercase())
        && compact.chars().skip(2).take(2).all(|c| c.is_ascii_digit());
    well_formed.then_some(compact)
}

/// The key of a normalised address (lower-case `local@domain`): the local part
/// up to a `+` tag, so `jules+crm@example.invalid` and `jules@example.invalid`
/// are one key. `None` when either part is empty.
pub(crate) fn email_key(email: &str) -> Option<Zeroizing<String>> {
    let (local, domain) = email.rsplit_once('@')?;
    let base = local.split('+').next().unwrap_or(local);
    (!base.is_empty() && !domain.is_empty()).then(|| Zeroizing::new(format!("{base}@{domain}")))
}

/// The keys that a canonical phone number matches: its international digits,
/// and its national forms when its calling code is known (see
/// [`national_forms`]). A number without `+` is its own key.
pub(crate) fn phone_keys(phone: &str) -> Vec<Zeroizing<String>> {
    let Some(international) = phone.strip_prefix('+') else {
        return vec![Zeroizing::new(phone.to_string())];
    };
    let mut keys = vec![Zeroizing::new(international.to_string())];
    keys.extend(
        national_forms(international)
            .into_iter()
            .map(Zeroizing::new),
    );
    keys
}

/// The national spellings of an international number, for a country whose
/// calling code is listed: the trunk prefix and the subscriber digits. The
/// trunk is `0`, except `06` in Hungary, `8` in Russia and none in the
/// North American plan. A mobile that is dialled without its trunk is also
/// kept, when it is long enough not to collide with other digits.
fn national_forms(international: &str) -> Vec<String> {
    let Some((code, subscriber)) = split_calling_code(international) else {
        return Vec::new();
    };
    if subscriber.len() < MIN_SUBSCRIBER_DIGITS {
        return Vec::new();
    }
    let trunk = match code {
        "1" => "",
        "7" => "8",
        "36" => "06",
        _ => "0",
    };
    let mut forms = vec![format!("{trunk}{subscriber}")];
    if !trunk.is_empty() && subscriber.len() >= MIN_BARE_DIGITS {
        forms.push(subscriber.to_string());
    }
    forms
}

/// Address matches in `text`, the plain address text (see `fold::plain_address`).
/// Each `@` is read with the whole address around it: the local part and the
/// domain, as far as letters, digits and address marks run. The match is the
/// whole address, and the key is its local part up to a `+` tag and its domain.
/// Returns the byte range and the target of each match.
pub(crate) fn email_hits(text: &str, keys: &HashMap<Key, Target>) -> Vec<(usize, usize, Target)> {
    let mut hits = Vec::new();
    if keys.is_empty() {
        return hits;
    }
    for (at, _) in text.match_indices('@') {
        let local_start = text[..at]
            .char_indices()
            .rev()
            .take_while(|&(_, c)| is_local_char(c))
            .last()
            .map_or(at, |(index, _)| index);
        let local = &text[local_start..at];
        let Some((last, letter)) = text[at + 1..]
            .char_indices()
            .take_while(|&(_, c)| is_domain_char(c))
            .last()
        else {
            continue;
        };
        let domain_end = at + 1 + last + letter.len_utf8();
        let domain = text[at + 1..domain_end].trim_end_matches('.');
        let base = local.split('+').next().unwrap_or(local);
        if base.is_empty() || domain.is_empty() {
            continue;
        }
        let key = Zeroizing::new(format!("{base}@{domain}"));
        if let Some(target) = keys.get(key.as_str()) {
            hits.push((local_start, at + 1 + domain.len(), *target));
        }
    }
    hits
}

/// Characters of an address's local part.
fn is_local_char(c: char) -> bool {
    c.is_alphanumeric() || "._%+-".contains(c)
}

/// Characters of an address's domain.
fn is_domain_char(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}

/// Phone matches in `text`: runs of digit groups joined by separators, read as
/// one number with or without `+`, `00` or a trunk-0 national form. A `(0)`
/// group is a trunk marker, not a digit of the number.
pub(crate) fn phone_hits(text: &str, keys: &HashMap<Key, Target>) -> Vec<(usize, usize, Target)> {
    let mut hits = Vec::new();
    if keys.is_empty() {
        return hits;
    }
    let bytes = text.as_bytes();
    let groups = runs(bytes, |byte| byte.is_ascii_digit());
    // A group inside an earlier match is part of that number, not a number of its own.
    let mut covered = 0;
    for (first, &(start, _)) in groups.iter().enumerate() {
        if start < covered
            || is_trunk_marker(bytes, groups[first])
            || (start > 0 && bytes[start - 1].is_ascii_alphabetic())
        {
            continue;
        }
        let plus = start > 0 && bytes[start - 1] == b'+';
        let mut digits = Zeroizing::new(String::new());
        for last in first..groups.len().min(first + MAX_PHONE_GROUPS) {
            let (group_start, group_end) = groups[last];
            if last > first && !separator(&text[groups[last - 1].1..group_start]) {
                break;
            }
            if !is_trunk_marker(bytes, groups[last]) {
                digits.push_str(&text[group_start..group_end]);
            }
            if digits.len() > MAX_PHONE_DIGITS {
                break;
            }
            let ends_whole = !bytes.get(group_end).is_some_and(u8::is_ascii_alphabetic);
            if digits.len() < MIN_PHONE_DIGITS
                || is_trunk_marker(bytes, groups[last])
                || !ends_whole
            {
                continue;
            }
            if let Some(target) = lookup_phone(keys, &digits, plus) {
                let from = if plus { start - 1 } else { start };
                hits.push((from, group_end, target));
                covered = group_end;
            }
        }
    }
    hits
}

/// The person of a digit run. An international run (with `+`, or a `00`
/// prefix) is canonicalised as a stored number is, so the trunk `0` after the
/// country code is ignored; any other run is looked up as it is.
fn lookup_phone(keys: &HashMap<Key, Target>, digits: &str, plus: bool) -> Option<Target> {
    let international = if plus {
        Some(digits)
    } else {
        digits
            .strip_prefix("00")
            .filter(|_| digits.len() >= MIN_PHONE_DIGITS + 2)
    };
    international
        .and_then(|run| keys.get(canonical_international(run).as_str()).copied())
        .or_else(|| keys.get(digits).copied())
}

/// Whether the group at `(start, end)` is a lone `0` between parentheses.
fn is_trunk_marker(bytes: &[u8], (start, end): (usize, usize)) -> bool {
    end - start == 1
        && bytes[start] == b'0'
        && start > 0
        && bytes[start - 1] == b'('
        && bytes.get(end) == Some(&b')')
}

/// Whether the text between two digit groups is a short run of phone
/// separators and nothing else.
fn separator(gap: &str) -> bool {
    gap.chars().count() <= 4
        && gap.chars().all(|c| {
            matches!(
                c,
                ' ' | '\t' | '\n' | '\r' | '.' | '-' | '/' | '(' | ')' | '\u{a0}' | '\u{202f}'
            )
        })
}

/// IBAN matches in `text`: runs of alphanumeric tokens joined by spaces, line
/// breaks or hyphens, read as one compact value.
pub(crate) fn iban_hits(text: &str, keys: &HashMap<Key, Target>) -> Vec<(usize, usize, Target)> {
    let mut hits = Vec::new();
    if keys.is_empty() {
        return hits;
    }
    let tokens = runs(text.as_bytes(), |byte| byte.is_ascii_alphanumeric());
    for first in 0..tokens.len() {
        let mut compact = Zeroizing::new(String::new());
        for last in first..tokens.len().min(first + MAX_IBAN_TOKENS) {
            let (start, end) = tokens[last];
            if last > first && !iban_gap(&text[tokens[last - 1].1..start]) {
                break;
            }
            compact.extend(text[start..end].chars().map(|c| c.to_ascii_uppercase()));
            if compact.len() > MAX_IBAN_LEN {
                break;
            }
            if let Some(target) = keys.get(compact.as_str()) {
                hits.push((tokens[first].0, end, *target));
            }
        }
    }
    hits
}

/// Whether the text between two IBAN tokens is a space, a line break or a
/// hyphen run.
fn iban_gap(gap: &str) -> bool {
    gap.len() <= 4
        && gap
            .chars()
            .all(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '-' | '\u{a0}'))
}

/// The byte ranges of the maximal runs of bytes that satisfy `keep`.
fn runs(bytes: &[u8], keep: impl Fn(u8) -> bool) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if keep(bytes[index]) {
            let start = index;
            while index < bytes.len() && keep(bytes[index]) {
                index += 1;
            }
            found.push((start, index));
        } else {
            index += 1;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyed(keys: Vec<Zeroizing<String>>, person: PersonId) -> HashMap<Key, Target> {
        let mut map = HashMap::new();
        for key in keys {
            insert_key(&mut map, key, person);
        }
        map
    }

    #[test]
    fn phone_forms_of_one_number_all_match() {
        let phone = normalize_phone("+33 6 12 34 56 78").expect("phone");
        let keys = keyed(phone_keys(&phone), 7);
        for text in [
            "+33 6 12 34 56 78",
            "+33.6.12.34.56.78",
            "+33-6-12-34-56-78",
            "+33 (0)6 12 34 56 78",
            "0033 6 12 34 56 78",
            "06 12 34 56 78",
            "06.12.34.56.78",
            "06/12/34/56/78",
            "(06) 12 34 56 78",
            "06 12\n34 56 78",
        ] {
            assert_eq!(phone_hits(text, &keys).len(), 1, "no match in {text:?}");
        }
        assert!(phone_hits("0612345679", &keys).is_empty());
        assert!(phone_hits("120612345678", &keys).is_empty());
    }

    #[test]
    fn north_american_national_form_has_no_trunk() {
        let keys = keyed(phone_keys("+12125551234"), 1);
        assert_eq!(phone_hits("(212) 555 1234", &keys).len(), 1);
    }

    #[test]
    fn email_forms_are_whole_and_case_free() {
        let keys = keyed(
            vec![email_key("marie.dupont83@example.invalid").expect("key")],
            3,
        );
        for text in [
            "MARIE.DUPONT83@EXAMPLE.INVALID",
            "mailto:marie.dupont83@example.invalid.",
            "marie.dupont83@example.invalid,",
        ] {
            let lower = text.to_ascii_lowercase();
            let hits = email_hits(&lower, &keys);
            assert_eq!(hits.len(), 1, "no match in {text:?}");
            let (start, end, target) = hits[0];
            assert_eq!(target.person, 3);
            assert!(lower[start..end].starts_with("marie"), "{text:?}");
        }
        for text in [
            "xmarie.dupont83@example.invalid",
            "marie.dupont83@example.invalid.fr",
            "marie.dupont8@example.invalid",
        ] {
            assert!(
                email_hits(text, &keys).is_empty(),
                "false match in {text:?}"
            );
        }
    }

    #[test]
    fn a_plus_tag_is_the_same_address_for_matching() {
        let keys = keyed(vec![email_key("jules@example.invalid").expect("key")], 1);
        let hits = email_hits("write to jules+crm@example.invalid now", &keys);
        assert_eq!(hits.len(), 1);
        let (start, end, _) = hits[0];
        assert_eq!(
            &"write to jules+crm@example.invalid now"[start..end],
            "jules+crm@example.invalid"
        );
        let key = email_key("jules+crm@example.invalid").expect("key");
        assert_eq!(key.as_str(), "jules@example.invalid");
    }

    #[test]
    fn national_forms_follow_the_country_and_stay_whole() {
        assert!(phone_keys("+36301234567").contains(&Zeroizing::new("06301234567".into())));
        assert!(phone_keys("+27821234567").contains(&Zeroizing::new("0821234567".into())));
        assert!(phone_keys("+79123456789").contains(&Zeroizing::new("89123456789".into())));
        assert!(phone_keys("+8613800138000").contains(&Zeroizing::new("13800138000".into())));
        assert!(phone_keys("+33612345678").contains(&Zeroizing::new("0612345678".into())));
        // An unlisted calling code keeps its international form only.
        assert_eq!(phone_keys("+3505551234").len(), 1);
    }

    #[test]
    fn phones_are_e164_when_the_country_is_in_the_number() {
        for raw in [
            "+33 (0)6 12 34 56 78",
            "+33 0 6 12 34 56 78",
            "0033 6 12 34 56 78",
            "＋33 6 12 34 56 78",
            "+33.6.12.34.56.78",
        ] {
            assert_eq!(
                normalize_phone(raw).as_deref(),
                Some("+33612345678"),
                "{raw}"
            );
        }
        assert_eq!(
            normalize_phone("+36 (06) 30 123 4567").as_deref(),
            Some("+36301234567")
        );
        assert_eq!(
            normalize_phone("+27 (0)82 123 4567").as_deref(),
            Some("+27821234567")
        );
        // A local number has no country: its digits are kept, nothing is assumed.
        assert_eq!(
            normalize_phone("06 12 34 56 78").as_deref(),
            Some("0612345678")
        );
    }

    #[test]
    fn hungarian_russian_and_chinese_numbers_match_every_spelling() {
        let keys = keyed(phone_keys("+36301234567"), 1);
        for text in ["+36 30 123 4567", "+36 (06) 30 123 4567", "06 30 123 4567"] {
            assert_eq!(phone_hits(text, &keys).len(), 1, "no match in {text:?}");
        }
        let keys = keyed(phone_keys("+79123456789"), 2);
        for text in ["+7 912 345 67 89", "8 (912) 345-67-89"] {
            assert_eq!(phone_hits(text, &keys).len(), 1, "no match in {text:?}");
        }
        let keys = keyed(phone_keys("+8613800138000"), 3);
        for text in ["+86 138 0013 8000", "0086 138 0013 8000", "138 0013 8000"] {
            assert_eq!(phone_hits(text, &keys).len(), 1, "no match in {text:?}");
        }
    }

    #[test]
    fn a_local_number_does_not_assume_its_country() {
        let keys = keyed(
            phone_keys(&normalize_phone("06 12 34 56 78").expect("phone")),
            4,
        );
        assert_eq!(phone_hits("06.12.34.56.78", &keys).len(), 1);
        assert!(phone_hits("+33 6 12 34 56 78", &keys).is_empty());
    }

    #[test]
    fn iban_with_and_without_spaces_matches() {
        let iban = normalize_iban("FR76 3000 6000 0112 3456 7890 189").expect("iban");
        assert_eq!(iban, "FR7630006000011234567890189");
        let keys = keyed(vec![Zeroizing::new(iban)], 2);
        for text in [
            "FR7630006000011234567890189",
            "FR76 3000 6000 0112 3456 7890 189",
            "(FR76 3000 6000\n0112 3456 7890 189)",
            "fr76-3000-6000-0112-3456-7890-189",
        ] {
            assert_eq!(iban_hits(text, &keys).len(), 1, "no match in {text:?}");
        }
        assert!(iban_hits("FR76 3000 6000 0112 3456 7890 180", &keys).is_empty());
    }
}
