//! HEALTH-IDIOM-SCOPE: the figurative-syndrome guard belongs to one place — a
//! lone name word right before an English `syndrome`, or right after a French
//! `de`. #202 hung it on the name itself, so it also emptied `China Fever`,
//! `Poppy disease`, `Stockholm-szindróma` and `Grey-China syndrome`, all of
//! which 2114f9e2 masked.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, masked, MODES};

/// Main as this pass found it, 6ac1dc1a with the guard in place. The header is
/// the input count and an FNV-1a hash of every input; the records are one per
/// input, the two modes joined by `|`.
const FIXTURE: &str = include_str!("data/health_idiom_main.txt");

/// Inputs 2114f9e2 masked, #202 stopped masking, and this pass masks again: the
/// guard word is the name of a disease here, and the head it follows decides.
/// Every line was probed on 2114f9e2 in both modes and masked in full. The
/// value is in brackets.
const REGRESSED: &[&str] = &[
    "The doctor says he has [China Fever].",
    "The doctor says he has [Stockholm fever].",
    "The doctor says he has [Imposter Fever].",
    "The doctor says he has [Imposter disease].",
    "The doctor says he has [China disease].",
    "Certificate for [Poppy disease] attached.",
    "Az orvos [Stockholm-szindrómát] állapított meg.",
    "Az orvos [Poppy-betegséget] állapított meg.",
    "Igazolás: [Stockholm-kór].",
    "A kezelés a [Stockholm-láz] miatt tart.",
    "Certificate for [Grey-China syndrome] attached.",
    "Certificate for [Grey-China's syndrome] attached.",
    "Die pasiënt het [Stockholm-koors] gesien.",
    "Die pasiënt het [Stockholm-siekte] gesien.",
    "Traitement pour la [maladie de Poppy].",
    "Le médecin dit qu'elle a un [syndrome de Poppy].",
];

/// The idioms the guard is for, every guard word in every case it can arrive in,
/// English and the one French shape. No other prose: a name of any other kind
/// would mask, and then the test would be measuring that instead.
fn idioms() -> Vec<String> {
    const TAIL: &str = " is a figure of speech, not a diagnosis.";
    let mut out = Vec::new();
    for word in ["imposter", "impostor", "stockholm", "china", "poppy"] {
        let mut chars = word.chars();
        let title = chars.next().unwrap().to_uppercase().to_string() + chars.as_str();
        for name in [title, word.to_uppercase(), word.to_string()] {
            out.push(format!("{name} syndrome{TAIL}"));
        }
    }
    for name in ["Stockholm", "STOCKHOLM", "stockholm"] {
        out.push(format!("Le syndrome de {name} est un cliché de roman."));
    }
    out
}

/// The 20 name forms: the five idiom words in three cases, and the compounds a
/// hyphen builds a name with. `Grey China` is here too, because the disease
/// rule resolves only `China` as the name.
const NAMES: &[&str] = &[
    "Imposter",
    "IMPOSTER",
    "imposter",
    "Impostor",
    "IMPOSTOR",
    "Stockholm",
    "STOCKHOLM",
    "stockholm",
    "China",
    "CHINA",
    "china",
    "Poppy",
    "POPPY",
    "poppy",
    "Grey-China",
    "Grey China",
    "Grey-CHINA",
    "Grey-Poppy",
    "IMPOSTER-China",
    "Stockholm-Poppy",
];

/// Every disease head the rules know — en `fever`, `disease`, `syndrome`, hu
/// `láz`, `betegség`, `szindróma`, `kór`, af `griep`, `koors`, `siekte`,
/// `sindroom`, and the three French `de` leads — each as `(health anchor, text
/// before the name, text after it)`: the English, Hungarian and Afrikaans heads
/// follow the name they mint, the French leads take it after a `de`. The Han
/// heads cannot carry a Latin name, `push_han_disease_names` never reads
/// `name_like`, so no idiom word can reach them.
const HEADS: &[(&str, &str, &str)] = &[
    ("The doctor says he has ", "", " Fever"),
    ("Certificate for ", "", "-fever"),
    ("The doctor says he has ", "", "Fever"),
    ("Certificate for ", "", " disease"),
    ("The clinic confirmed ", "", "-disease"),
    ("Diagnosis: ", "", " syndrome"),
    ("Certificate for ", "", "-syndrome"),
    ("Diagnosis: ", "", "'s syndrome"),
    ("A doktor szerint ", "", "-láz"),
    ("Kezelést kap ", "", "-lázzal"),
    ("Táppénzen van a ", "", "-lázát"),
    ("Az orvos ", "", "-betegség"),
    ("Az orvos ", "", "-szindróma"),
    ("Krónikus ", "", "-szindrómában"),
    ("Igazolás: ", "", "-kór"),
    ("Die dokter sê hy het ", "", "-griep"),
    ("Die pasiënt het ", "", "-koors"),
    ("Die dokter het ", "", "-siekte"),
    ("Die dokter sê sy het ", "", " se siekte"),
    ("Hy word behandel vir ", "", "-sindroom"),
    ("My suster het ", "", " se sindroom"),
    ("Traitement pour la ", "maladie de ", ""),
    ("Le médecin dit qu'elle a un ", "syndrome de ", ""),
    ("Le diagnostic est tombé : ", "syndrome d'", ""),
    (
        "Elle a attrapé la ",
        "fievre de ",
        ", le médecin passe ce soir",
    ),
];

/// 1,000 texts: every name above, every head above, cued and bare. The French
/// cells read as machine French, and none of them is prose: this is a grid of
/// guard words against heads, not a corpus.
fn texts() -> Vec<String> {
    let mut out = Vec::with_capacity(1_000);
    for (cue, pre, post) in HEADS {
        for name in NAMES {
            out.push(format!("{cue}{pre}{name}{post}."));
            out.push(format!("{pre}{name}{post}."));
        }
    }
    out
}

/// One record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    let join = |r: Vec<(usize, usize)>| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.map_or("!".into(), join)
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The input count and an FNV-1a hash of every input.
fn header(texts: &[String]) -> String {
    let bytes = texts.iter().flat_map(|t| t.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", texts.len())
}

#[test]
#[ignore = "freezes the fixture from main: run on 6ac1dc1a, tests only"]
fn freeze() {
    let texts = texts();
    let records: Vec<String> = texts
        .iter()
        .map(|text| MODES.map(|mode| record(masked(mode, text))).join("|"))
        .collect();
    let lines: Vec<String> = records.chunks(100).map(|c| c.join(";") + ";").collect();
    let fixture = format!("{}\n{}", header(&texts), lines.join("\n"));
    println!("IDIOM-FIXTURE-BEGIN\n{fixture}\nIDIOM-FIXTURE-END");
}

/// Every input #202 emptied is hidden in full again, in both modes.
#[test]
fn guard_words_are_masked_again_in_both_modes() {
    let mut missed = Vec::new();
    for line in REGRESSED {
        let (pre, rest) = line.split_once('[').unwrap();
        let (value, post) = rest.split_once(']').unwrap();
        for mode in MODES {
            let now = masked(mode, &format!("{pre}{value}{post}")).expect("no refusal");
            if !covered(&now, pre.len(), pre.len() + value.len()) {
                missed.push(format!("{mode:?} {line}: {now:?}"));
            }
        }
    }
    eprintln!(
        "{} of {} line-and-mode values still in clear",
        missed.len(),
        REGRESSED.len() * 2
    );
    assert!(missed.is_empty(), "{missed:#?}");
}

/// And the idioms stay clear, every guard word in every case, English and
/// French. This is the half of the guard that must not move.
#[test]
fn figurative_syndromes_stay_clear_in_both_modes() {
    let idioms = idioms();
    assert_eq!(idioms.len(), 18);
    for mode in MODES {
        let masked: Vec<_> = idioms
            .iter()
            .filter(|text| masked(mode, text) != Some(vec![]))
            .collect();
        eprintln!(
            "{mode:?}: {} of {} idioms masked: {masked:#?}",
            masked.len(),
            idioms.len()
        );
        assert!(masked.is_empty(), "{masked:#?}");
    }
}

/// The head only adds masks: of the 1,000 guard-word × disease-head texts,
/// every byte main masks is still masked in both modes, no text is newly
/// refused, and the texts that change are pinned by count so a later narrowing
/// cannot pass here.
#[test]
fn the_head_only_adds_masks_to_main() {
    let texts = texts();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&texts), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), texts.len());
    let (mut lost, mut refused, mut added) = ([0usize; 2], 0, [0usize; 2]);
    for (text, record) in texts.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += 1;
                eprintln!("{text:?}: refused");
                continue;
            };
            let main = main.unwrap_or_default();
            let gone = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                eprintln!("{text:?} {:?}: main {main:?} now {now:?}", MODES[index]);
            }
            lost[index] += gone;
            added[index] += usize::from(now != main);
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; refusals {refused}; texts with a new mask \
         Private/Open {added:?}",
        texts.len()
    );
    assert_eq!((lost, refused), ([0, 0], 0));
    // 338 of the 1,000: every guard-word name in front of every head but
    // `syndrome`, plus the hyphen-joined names in front of it. Pinned so a
    // guard that creeps back onto another head, or off `syndrome`, shows here.
    // HEALTH-CUE-RESTORE adds 41 validated frames, including lower/upper
    // name renderings; unframed case heuristics and idiom guards stay put.
    assert_eq!(
        added, [379; 2],
        "the guard must keep guarding one head only"
    );
}
