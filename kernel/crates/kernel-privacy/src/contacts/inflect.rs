//! Declined and affixed forms of single name words, by rule. No dictionary:
//! each rule reads the ending of a word and writes the forms that ending takes.
//!
//! * Russian and Ukrainian (Cyrillic): the five oblique cases of given names
//!   and surnames. Female -а/-я, male consonant and soft endings, and the
//!   -ов/-ев/-ин and -ова/-ева/-ина surname families.
//! * Hungarian (Latin): -nak/-nek, -val/-vel, -t, -é, -ék, -ért, -hoz/-hez/-höz
//!   and -féle, with vowel harmony and the lengthened stem vowel (Annának).
//! * Arabic: the attached prefixes و ب ل ف ك ال لل and their common pairs.
//! * French: the elisions d' and l' before a vowel.
//!
//! The forms are lower-case and go through the usual folding, so they map back
//! to exact spans of the text like every other variant.

use super::fold::folded_text;

/// Whether a name word is a given name or a family name. Russian declension
/// differs for the two (a surname `-ова` is not a given name `-ова`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Given,
    Family,
}

/// The script of a name word, read from its first letter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    Cyrillic,
    Arabic,
    Latin,
    Other,
}

/// Attached Arabic prefixes: و (and), ب (with, in), ل (to, for), ف (then),
/// ك (like), ال (the), لل (for the), and the usual pairs with ال.
const ARABIC_PREFIXES: &[&str] = &[
    "و", "ب", "ل", "ف", "ك", "ال", "لل", "وال", "بال", "فال", "كال",
];

/// Every extra form of `word` that the rules give. The word itself is not
/// included, and an empty list means no rule covers it.
pub(crate) fn word_forms(word: &str, role: Role) -> Vec<String> {
    let lower = word.to_lowercase();
    match script_of(&lower) {
        Script::Cyrillic => ru_cases(&lower, role)
            .map(|cases| cases[1..].to_vec())
            .unwrap_or_default(),
        Script::Arabic if lower.chars().count() >= 2 => ARABIC_PREFIXES
            .iter()
            .map(|prefix| format!("{prefix}{lower}"))
            .collect(),
        Script::Arabic => Vec::new(),
        Script::Latin => {
            let mut forms = hungarian_forms(&lower);
            forms.extend(french_elisions(&lower));
            forms
        }
        Script::Other => Vec::new(),
    }
}

/// The six cases of a Russian or Ukrainian name word, nominative first, in
/// lower case. `None` when no rule covers the ending.
pub(crate) fn ru_cases(word: &str, role: Role) -> Option<[String; 6]> {
    let lower = word.to_lowercase();
    let count = lower.chars().count();
    // The word without its last `cut` characters.
    let base = |cut: usize| -> String { lower.chars().take(count - cut).collect() };
    let last = lower.chars().last()?;

    let oblique: [String; 5] = if role == Role::Family
        && ["ова", "ева", "ёва", "ина", "ына"]
            .iter()
            .any(|end| lower.ends_with(end))
    {
        let stem = base(1);
        [
            format!("{stem}ой"),
            format!("{stem}ой"),
            format!("{stem}у"),
            format!("{stem}ой"),
            format!("{stem}ой"),
        ]
    } else if role == Role::Family
        && ["ов", "ев", "ёв", "ин", "ын"]
            .iter()
            .any(|end| lower.ends_with(end))
    {
        [
            format!("{lower}а"),
            format!("{lower}у"),
            format!("{lower}а"),
            format!("{lower}ым"),
            format!("{lower}е"),
        ]
    } else if role == Role::Family && ["ий", "ый", "ой"].iter().any(|end| lower.ends_with(end))
    {
        let stem = base(2);
        let instrumental = if lower.ends_with("ий") {
            "им"
        } else {
            "ым"
        };
        [
            format!("{stem}ого"),
            format!("{stem}ому"),
            format!("{stem}ого"),
            format!("{stem}{instrumental}"),
            format!("{stem}ом"),
        ]
    } else if lower.ends_with("ия") {
        let stem = base(1);
        [
            format!("{stem}и"),
            format!("{stem}и"),
            format!("{stem}ю"),
            format!("{stem}ей"),
            format!("{stem}и"),
        ]
    } else if last == 'я' {
        let stem = base(1);
        [
            format!("{stem}и"),
            format!("{stem}е"),
            format!("{stem}ю"),
            format!("{stem}ей"),
            format!("{stem}е"),
        ]
    } else if last == 'а' {
        let stem = base(1);
        let (genitive, instrumental) = match stem.chars().last() {
            Some('ж' | 'ш' | 'ч' | 'щ' | 'ц') => ("и", "ей"),
            Some('к' | 'г' | 'х') => ("и", "ой"),
            _ => ("ы", "ой"),
        };
        [
            format!("{stem}{genitive}"),
            format!("{stem}е"),
            format!("{stem}у"),
            format!("{stem}{instrumental}"),
            format!("{stem}е"),
        ]
    } else if last == 'ь' || last == 'й' {
        let stem = base(1);
        [
            format!("{stem}я"),
            format!("{stem}ю"),
            format!("{stem}я"),
            format!("{stem}ем"),
            format!("{stem}е"),
        ]
    } else if is_ru_consonant(last) {
        let instrumental = if matches!(last, 'ж' | 'ш' | 'ч' | 'щ' | 'ц') {
            "ем"
        } else {
            "ом"
        };
        [
            format!("{lower}а"),
            format!("{lower}у"),
            format!("{lower}а"),
            format!("{lower}{instrumental}"),
            format!("{lower}е"),
        ]
    } else {
        return None;
    };
    let [genitive, dative, accusative, instrumental, prepositional] = oblique;
    Some([
        lower,
        genitive,
        dative,
        accusative,
        instrumental,
        prepositional,
    ])
}

/// Hungarian suffixes of a Latin word of at least three letters.
///
/// The stem vowel of a vowel-final word is lengthened before a suffix
/// (Anna → Annának, Annát, Annáé), and the linking vowel of the accusative
/// follows vowel harmony (-ot after back vowels, -et after front ones, -öt
/// after ö/ő/ü/ű). The accusative after a consonant is only built for words of
/// five letters or more: "Mark" + "et" would give "market".
fn hungarian_forms(word: &str) -> Vec<String> {
    let chars: Vec<char> = word.chars().collect();
    if chars.len() < 3 || !chars.iter().all(|c| c.is_alphabetic()) {
        return Vec::new();
    }
    // Vowel harmony is set by the last vowel that is not neutral (i, í, é).
    let decider = chars
        .iter()
        .rev()
        .find(|c| "aáoóuúeöőüű".contains(**c))
        .copied()
        .unwrap_or('e');
    let back = "aáoóuú".contains(decider);
    let rounded = "öőüű".contains(decider);
    let Some(&last) = chars.last() else {
        return Vec::new();
    };
    let vowel_final = "aáeéiíoóöőuúüű".contains(last);
    let stem = if vowel_final {
        let mut stem: String = chars[..chars.len() - 1].iter().collect();
        stem.push(lengthen(last));
        stem
    } else {
        word.to_string()
    };

    let nak = if back { "nak" } else { "nek" };
    let val = if back { "val" } else { "vel" };
    let hoz = if back {
        "hoz"
    } else if rounded {
        "höz"
    } else {
        "hez"
    };
    let mut forms = vec![
        format!("{stem}{nak}"),
        format!("{stem}{val}"),
        format!("{stem}{hoz}"),
        format!("{stem}ért"),
        format!("{stem}é"),
        format!("{stem}ék"),
        format!("{word}-féle"),
    ];
    if vowel_final {
        forms.push(format!("{stem}t"));
    } else if chars.len() >= 5 {
        let accusative = if back {
            "ot"
        } else if rounded {
            "öt"
        } else {
            "et"
        };
        forms.push(format!("{word}{accusative}"));
    }
    forms
}

/// The long form of a Hungarian vowel; other letters are returned unchanged.
fn lengthen(vowel: char) -> char {
    match vowel {
        'a' => 'á',
        'e' => 'é',
        'i' => 'í',
        'o' => 'ó',
        'ö' => 'ő',
        'u' => 'ú',
        'ü' => 'ű',
        other => other,
    }
}

/// `d'` and `l'` before a word that begins with a vowel (or a mute h).
fn french_elisions(word: &str) -> Vec<String> {
    if folded_text(word).starts_with(['a', 'e', 'i', 'o', 'u', 'y', 'h']) {
        vec![format!("d'{word}"), format!("l'{word}")]
    } else {
        Vec::new()
    }
}

fn script_of(word: &str) -> Script {
    match word.chars().find(|c| c.is_alphabetic()) {
        Some('\u{0400}'..='\u{04FF}') => Script::Cyrillic,
        Some('\u{0600}'..='\u{06FF}') => Script::Arabic,
        Some(c) if c.is_ascii_alphabetic() || ('\u{00C0}'..='\u{024F}').contains(&c) => {
            Script::Latin
        }
        _ => Script::Other,
    }
}

fn is_ru_consonant(c: char) -> bool {
    "бвгджзклмнпрстфхцчшщ".contains(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_cases_of_given_and_family_names() {
        let anna = ru_cases("Анна", Role::Given).expect("cases");
        assert_eq!(anna[2], "анне");
        assert_eq!(anna[3], "анну");
        let smirnova = ru_cases("Смирнова", Role::Family).expect("cases");
        assert_eq!(smirnova[1], "смирновой");
        let smirnov = ru_cases("Смирнов", Role::Family).expect("cases");
        assert_eq!(smirnov[4], "смирновым");
        let ivan = ru_cases("Иван", Role::Given).expect("cases");
        assert_eq!(ivan[4], "иваном");
        let igor = ru_cases("Игорь", Role::Given).expect("cases");
        assert_eq!(igor[1], "игоря");
        let maria = ru_cases("Мария", Role::Given).expect("cases");
        assert_eq!(maria[4], "марией");
    }

    #[test]
    fn hungarian_suffixes_follow_harmony_and_lengthening() {
        let lilla = hungarian_forms("lilla");
        assert!(lilla.contains(&"lillának".to_string()));
        assert!(lilla.contains(&"lillával".to_string()));
        assert!(lilla.contains(&"lillát".to_string()));
        assert!(lilla.contains(&"lilla-féle".to_string()));
        let ferenc = hungarian_forms("ferenc");
        assert!(ferenc.contains(&"ferencnek".to_string()));
        assert!(ferenc.contains(&"ferencet".to_string()));
        assert!(ferenc.contains(&"ferenchez".to_string()));
        let kovacs = hungarian_forms("kovács");
        assert!(kovacs.contains(&"kovácsnak".to_string()));
        assert!(kovacs.contains(&"kovácsot".to_string()));
        assert!(hungarian_forms("mark").iter().all(|form| form != "market"));
    }

    #[test]
    fn arabic_prefixes_and_french_elisions() {
        let ali = word_forms("علي", Role::Family);
        assert!(ali.contains(&"وعلي".to_string()));
        assert!(ali.contains(&"لعلي".to_string()));
        assert!(ali.contains(&"العلي".to_string()));
        let artagnan = word_forms("Artagnan", Role::Family);
        assert!(artagnan.contains(&"d'artagnan".to_string()));
        assert!(artagnan.contains(&"l'artagnan".to_string()));
        assert!(word_forms("Marie", Role::Given)
            .iter()
            .all(|form| !form.starts_with("d'")));
    }
}
