//! HEALTH-RECALL-2 fix round 1: a figurative syndrome is not a patient
//! (`Imposter syndrome`, `Stockholm syndrome`, `China syndrome`), and the
//! Afrikaans `se` form of a disease name is masked (`Down se sindroom`).
//! The guard for the idioms must never reach a real disease name.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, masked, MODES};

/// Figurative syndromes: no health value, in any mode, in any case. The first
/// two are the false positives pass A found (CHANGES c90c6df6); the rest are
/// the other idiom shapes the same rule shape would have to get right.
const IDIOMS: &[&str] = &[
    "Imposter syndrome is real, and I suffer from it daily.",
    "Impostor syndrome is real, and I suffer from it daily.",
    "imposter syndrome is real",
    "impostor syndrome is real",
    "IMPOSTER SYNDROME is real",
    "IMPOSTOR SYNDROME is real",
    "Stockholm syndrome jokes aside, the hostage ended well.",
    "Stockholm Syndrome jokes aside, the hostage ended well.",
    "stockholm syndrome jokes aside",
    "STOCKHOLM SYNDROME jokes aside",
    "Everyone in the team has a bit of China syndrome here.",
    "China syndrome is a nickname for the building, nothing more.",
    "CHINA SYNDROME is what the nickname is.",
    "Le syndrome de l'imposteur touche beaucoup de cadres.",
    "Le syndrome de Stockholm est un cliché de roman.",
    // Already clear before the guard, because the word before `syndrome` is
    // lower-case; pinned here so a case rule cannot quietly start masking them.
    "The tall poppy syndrome got him promoted.",
    "Tall poppy syndrome is a fine thing.",
    "Shiny object syndrome strikes again.",
    "The shiny object syndrome is with you.",
];

/// Real disease names that hold the same shape — a name the rules read as a
/// disease — and must stay masked in full. `Down`, `Tourette`, `Asperger`,
/// `Sjögren`, `Cushing` and `Guillain-Barré` are the ones named in the brief.
const REAL_DISEASES: &[&str] = &[
    "My son has [Down syndrome] and he is thriving.",
    "My son has [Down Syndrome] and he is thriving.",
    "She has [Tourette syndrome] and her teacher knows.",
    "Tourette [Syndrome] is hard to spell.",
    "An [Asperger syndrome] diagnosis came late.",
    "He has [Sjögren syndrome] and dry eyes.",
    "[Sjögren's syndrome] is diagnosed by blood tests.",
    "[Cushing syndrome] follows long steroid use.",
    "[Guillain-Barré syndrome] is rare and it is not genetic.",
    "[Guillain-Barre syndrome] is rare and it is not genetic.",
    // The invented names this pass exists for, in every language it covers.
    "The doctor says he has [Mist Fever].",
    "The doctor says he has [Ember Fever] and stays home.",
    "Certificate for [Grey-Wing Syndrome] attached.",
    "Ma sœur est traitée pour la [maladie de Basedow].",
    "Le diagnostic est tombé : [syndrome de Ravelle].",
    "Az orvos [Ezüst-betegséget] állapított meg.",
    "A családban öröklődik a [Hangyos-szindróma].",
    "Pieter het [Grootrivier-sindroom], hy is met siekverlof.",
    "Hy word behandel vir [Addison se siekte].",
];

/// The Afrikaans `se` form of a disease name, which a hyphen-joined rule alone
/// misses: `Down se sindroom`.
const AF_SE: &[&str] = &[
    "Down se sindroom",
    "Down se [sindroom] is 'n genetiese afwyking.",
    "My kind het [Down se sindroom].",
    "Ek het [Down se sindroom] en die kliniek bevestig dit.",
    "Hulle praat oor [Addison se siekte] in die geskiedenis.",
];

/// The three parts of a line whose health value is in brackets, or the whole
/// line as the value when it has none.
fn parts(line: &str) -> (&str, &str, &str) {
    match (line.find('['), line.rfind(']')) {
        (Some(open), Some(close)) if close > open => {
            (&line[..open], &line[open + 1..close], &line[close + 1..])
        }
        _ => ("", line, ""),
    }
}

/// No figurative syndrome is masked, in either mode.
#[test]
fn figurative_syndromes_stay_clear_in_both_modes() {
    for mode in MODES {
        let masked: Vec<_> = IDIOMS
            .iter()
            .filter(|text| masked(mode, text) != Some(vec![]))
            .copied()
            .collect();
        eprintln!("{mode:?}: {} idioms masked: {masked:#?}", masked.len());
        assert!(masked.is_empty(), "{masked:#?}");
    }
}

/// Every real disease name above is hidden in full, in both modes. This is the
/// other half of the idiom guard: it must not have swallowed a real one.
#[test]
fn real_disease_names_stay_masked_in_both_modes() {
    for line in REAL_DISEASES {
        let (pre, value, post) = parts(line);
        for mode in MODES {
            let now = masked(mode, &format!("{pre}{value}{post}")).expect("no refusal");
            assert!(
                covered(&now, pre.len(), pre.len() + value.len()),
                "{mode:?} {line}: {now:?}"
            );
        }
    }
}

/// The Afrikaans `se` form is masked in full, in both modes.
#[test]
fn afrikaans_se_sindroom_is_masked_in_both_modes() {
    for line in AF_SE {
        let (pre, value, post) = parts(line);
        for mode in MODES {
            let now = masked(mode, &format!("{pre}{value}{post}")).expect("no refusal");
            assert!(
                covered(&now, pre.len(), pre.len() + value.len()),
                "{mode:?} {line}: {now:?}"
            );
        }
    }
}
