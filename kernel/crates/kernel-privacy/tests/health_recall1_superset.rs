//! HEALTH-RECALL-1 differential, as NORM-1: the 1,132 NORM-1 inputs plus the
//! repros and guards below against `data/health_recall1_main.txt`, frozen from
//! origin/main (`-- --ignored freeze --nocapture`). All values are invented.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
#[allow(dead_code)]
mod tail4 {
    include!("data/secret_tail4_cases.rs");

    pub fn texts() -> Vec<String> {
        let fixed = [CASES, PR1B_CASES, PR2_CASES].into_iter().flatten();
        let fixed = fixed.map(|case| case.1.to_string());
        fixed
            .chain(built_cases().into_iter().map(|case| case.1))
            .collect()
    }
}
use cases::{covered, masked, repros, CYRILLIC_PROSE, MODES, ZH_PROSE};
use kernel_core::privacy::PrivacyMode;

const FIXTURE: &str = include_str!("data/health_recall1_main.txt");
/// The same inputs plus this pass's negatives, frozen from main after
/// HEALTH-RECALL-1.
const FIXTURE_2: &str = include_str!("data/health_recall2_main.txt");

/// Invented health values the cue rules must hide in full, each in a frame.
const REPROS: &[(&str, &str)] = &[
    ("Nia is under treatment for ", "Mist Fever"),
    ("Condition: ", "Ashen Disease"),
    ("His doctor says he has ", "Brume's disease"),
    ("Certificate for ", "Grey-Wing Syndrome"),
    ("Traitement pour la ", "maladie de Brume"),
    ("Traitement : ", "maladie d'Ombrelune"),
    ("Le médecin dit qu'elle a un ", "syndrome de Valbrume"),
    ("Kezelést kap ", "Köd-lázzal"),
    // `igazolás` and `toestand` are no longer cues (HEALTH-RECALL-2): a fever
    // name still needs a real health word around it.
    ("Kezelés: ", "Köd-lázról"),
    ("Betegség: ", "Szürke-betegség"),
    ("Die dokter sê hy het ", "Mis-griep"),
    ("Pasiënt: ", "Grys-koors"),
    ("Ek is ", "op siek verlof"),
    ("Sy is ", "met siek verlof"),
    ("苏珞言最近在治疗", "晨雾热"),
    ("医生确诊她有", "灰羽病"),
    ("我请病假，因为", "晨雾症"),
];

/// Texts that must come out exactly as main: a name next to a health word, a
/// capitalised word that is no head, insurance, an era, Chinese weather.
const GUARDS: &[&str] = &[
    "Dr Brume called this morning about the invoice.",
    "Dr Brume has a fever, so the call moves to Friday.",
    "The Fever Tree tonic is in the fridge.",
    "This disease is not the topic; the slides are.",
    "Le Dr Brume arrive demain avec la maladie du lundi matin.",
    "La caisse d'assurance maladie de Lyon a répondu.",
    "Az Árpád-kor története érdekes.",
    "Dr. Köd holnap jön.",
    "Die Grys-familie kom Dinsdag.",
    "今天天气很热，大家多喝水。",
    "这个功能有点毛病，明天修。",
];

/// Idioms with a disease word and no health sense (pass A, CHANGES 251b9123).
const IDIOMS: &[&str] = &[
    "Cabin fever sets in after a week of rain.",
    "Gold fever drove thousands west.",
    "Spring fever hit the office this week.",
    "We watched Saturday Night Fever last night.",
    "Night Fever played on the radio.",
    "Disco Fever is the theme of the party.",
    "World Cup Fever: the bars are full.",
    "Bieber Fever is back in town.",
    "Football Fever weekend starts on Friday.",
    "Monday fever: nobody wants to work.",
    "Yesterday fever ran high at the market.",
    "Election fever grips the capital.",
    "La Fièvre du Samedi Soir passe à la télé ce soir.",
    "C'est la fièvre de Noël dans les magasins.",
    "La fièvre du Mondial gagne les bars.",
    "Le syndrome de l'imposteur touche beaucoup de cadres.",
    "Elkapott a VB-láz.",
    "Az EB-láz miatt mindenki a tévé előtt ül.",
    "Kitört a Black Friday-láz.",
    "A Balaton-láz minden nyáron visszatér.",
    "Die Bok-koors is terug.",
    "Rugby-koors het die dorp getref.",
    "Kersfees-koors in die winkels.",
    "气温升高天气热，医生提醒防中暑。",
    // The 16 negatives pass A found masked on HEALTH-RECALL-1 by its new cues
    // (CHANGES 02fc91a1): clear on main, and clear here again.
    "Terms and conditions apply, Gold Fever sale ends Sunday.",
    "Certificate of Cabin Fever screening at the cinema on Friday.",
    "The car is in good condition, Saturday Night Fever is on TV tonight.",
    "Weather conditions delayed the Valley Fever concert.",
    "Upload your gift certificate before Spring Fever weekend ends.",
    "Market conditions: Crypto Fever is cooling off.",
    "SSL certificate expired, Holiday Fever landing page is down.",
    "Under these conditions the Gold Rush Fever exhibit will open late.",
    "Stock condition report: Disco Fever tickets are on sale.",
    "The weather condition index shows Heat Wave Fever in retail.",
    "Certificate of completion for the Tiger Fever coding bootcamp.",
    "Football fever and perfect pitch conditions at the stadium today.",
    "La fièvre du Mondial gagne Paris, certificat de garantie en poche.",
    "Az iskolai igazolás kell a Balaton-láz fesztiválra.",
    "Igazolás: Kovács Péter részt vett a Tavasz-láz versenyen.",
    "Die motor is in goeie toestand, Kersfees-koors in die winkels.",
];

/// Names and titles next to a disease word: no mask, in either mode.
const NAMES: &[&str] = &[
    "Dr Teller syndrome and Dr Morrow said nothing more.",
    "Mr Morrow's disease of choice is silence.",
    "Le Dr Ravelle parle du syndrome de fatigue.",
    "Mnr Teller het die Grys-koors opgedoen.",
    "Teller úr betegsége nem ismert.",
    "Morrow doktor sprak oor die siekte.",
    "Marcus Fever will collect the parcel.",
    "Le syndrome de M. Basedow est publié.",
    "泰勒先生今天没有来。",
    "莫罗医生今天休息。",
];

/// Held-out health sentences, written before the r1 rules were run on them;
/// the value is in brackets.
const HELD_OUT: &[&str] = &[
    "My doctor confirmed it is [Lyme disease].",
    "She has been in treatment for [Crohn's disease] since May.",
    "The clinic diagnosed [Kawasaki disease] in her son.",
    "He takes medication for [hay fever] every spring.",
    "After the trip she was treated in hospital for [dengue fever].",
    "Patient notes: [Q fever], follow-up in two weeks.",
    "His symptoms point to [Huntington's disease].",
    "The doctor says the rash is [Ember Fever].",
    "Sick note: [Tallow Syndrome], three days off.",
    "She was prescribed rest for [Grey Lantern Fever].",
    "Le médecin a confirmé une [maladie de Lyme].",
    "Elle est suivie à l'hôpital pour la [maladie de Crohn].",
    "Traitement en cours contre la [maladie de Gilbert].",
    "Mon fils a la [fièvre de Brumeval], le médecin passe ce soir.",
    "Il est en [arrêt maladie] jusqu'à lundi.",
    "Diagnostic : [syndrome de Ventelune].",
    "Elle prend un traitement pour la [fièvre jaune].",
    "Le patient souffre de la [maladie d'Ombreval].",
    "Certificat médical : [maladie de Brisecœur].",
    "Les symptômes de la [maladie de Kawasaki] ont disparu.",
    "Az orvos szerint [Lyme-kórral] fertőződött.",
    "[Crohn-betegséggel] kezelik a kórházban.",
    "[Parkinson-kórban] szenved, gyógyszert szed.",
    "A kezelés a [Hamu-láz] miatt tart.",
    "Igazolás: [Basedow-kór], két hét pihenő.",
    "Az orvos [Szürke-betegséget] diagnosztizált.",
    "Táppénzen van a [Fagy-láz] miatt.",
    "Krónikus [Hamu-szindrómával] él.",
    "A beteg [Ezüst-lázban] szenved.",
    "Die dokter sê sy het [Lyme-siekte].",
    "Hy word behandel vir [Crohn se siekte].",
    "Sy is in die hospitaal met [Mis-koors].",
    "Die pasiënt het [Parkinson-siekte].",
    "Hy is [op siek verlof] tot Vrydag.",
    "Die kliniek het [Grys-griep] gediagnoseer.",
    "Sy neem medisyne vir [hooikoors].",
    "Toestand: [As-koors], stabiel.",
    "医生确诊他得了[莱姆病]。",
    "她因为[银霜热]请了病假。",
    "[风铃病]复发了，正在治疗。",
    "[寒雾热]已经好转，医生说下周复查。",
    "孩子在住院治疗[灰雾症]。",
    "他患有[晨霜病]，需要长期服药。",
    "診斷結果是[晨霧熱]。",
    "病历上写着[灰羽病]。",
    "她在医院接受[冰雨热]的治疗。",
];

/// The health sentences pass A found missed on HEALTH-RECALL-1 (CHANGES
/// 02fc91a1): a disease word now stands on its own, a fever word needs the
/// anchor the sentence gives it. `Teller-szindrómája` stands for the adjectival
/// `Teller-szindrómás`, an inflection gap on main too; the last two name a
/// fever with no health word at all and are the standing allowance.
const HELD_OUT_2: &[&str] = &[
    "My brother has [Teller's syndrome] and gets tired fast.",
    "Our neighbour lives with [Hadley's disease].",
    "Anna has [Brackwater syndrome].",
    "It ended in a flare-up of [Quillon's disease].",
    "My son's [Pellwick syndrome] means a lot of appointments.",
    "Since the biopsy we know it's [Fennick-Orr syndrome].",
    "Mon père a le [syndrome de Gilbert], rien de grave.",
    "Ma sœur est traitée pour la [maladie de Basedow].",
    "Le diagnostic est tombé : [syndrome de Ravelle].",
    "A bátyám [Teller-szindrómája] miatt nem dolgozik.",
    "My suster het [Teller-sindroom].",
    "Hy word behandel vir [Addison se siekte].",
    "Pieter het [Grootrivier-sindroom], hy is met siekverlof.",
    "我弟弟得了[灰霜症]。",
    // A Han name is the two characters before the head, so `综合征` is the
    // span; the prefix stays clear (P3, as on main).
    "妈妈的银铃[综合征]又复发了。",
    "奶奶有吉尔伯特[综合征]，要定期复查。",
    "她因为[谷热病]请假了。",
    "Tom is recovering from [Lassa fever] this week.",
    "Kim tested positive for [Harrow fever], the clinic called.",
    "A doktor szerint [Völgy-láza] van.",
    "She's off with [Valley fever] this week.",
    "Il a attrapé la [fièvre de Saint-Brume] en voyage.",
];

/// The NORM-1 inputs in their order, then the repros and guards.
fn inputs() -> Vec<(&'static str, String)> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    let read = |path: String| std::fs::read_to_string(path).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(format!("{root}/cases"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let text = read(file.display().to_string());
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            out.push(("eval", case["text"].as_str().unwrap().to_string()));
        }
    }
    for lang in ["af", "hu", "sl"] {
        let prose = read(format!("{root}/prose/{lang}.txt"));
        let lines = prose.lines().filter(|l| !l.trim().is_empty());
        out.extend(lines.map(|l| ("prose", l.into())));
    }
    out.extend(tail4::texts().into_iter().map(|text| ("tail4", text)));
    for (text, _, _) in repros() {
        for (pre, post) in [("", ""), ("Hi,\n", " thanks."), ("« ", " »\r\n")] {
            out.push(("repro", format!("{pre}{text}{post}")));
        }
    }
    let prose = ZH_PROSE.iter().chain(CYRILLIC_PROSE);
    out.extend(prose.map(|t| ("prose", t.to_string())));
    let health = REPROS
        .iter()
        .map(|(pre, v)| ("health", format!("{pre}{v}.")));
    out.extend(health);
    out.extend(GUARDS.iter().map(|t| ("prose", t.to_string())));
    out
}

/// The same inputs plus the negatives of this pass and the names: they come out
/// of main and of the head, and the negatives come out with nothing at all.
fn inputs_2() -> Vec<(&'static str, String)> {
    let mut out = inputs();
    for t in &IDIOMS[24..] {
        out.push(("idiom", (*t).to_string()));
    }
    for t in NAMES {
        out.push(("prose", (*t).to_string()));
    }
    out
}

/// Every mask this pass gives back from main, and nothing else: the line it is
/// given back on, and on that line the exact text of the one value given back.
/// The allowance is closed — the bytes named here may go, and every other byte
/// main masks on that line must still be masked, in Private and in Open alike.
/// The 16 idiom lines hold one fever name and nothing else.
const GIVEN_BACK: &[(&str, &str)] = &[
    // The 16 negatives pass A found masked on HEALTH-RECALL-1 by its new cues
    // (CHANGES 02fc91a1), and clear on main: `IDIOMS[24..]`.
    (
        "Terms and conditions apply, Gold Fever sale ends Sunday.",
        "Gold Fever",
    ),
    (
        "Certificate of Cabin Fever screening at the cinema on Friday.",
        "Cabin Fever",
    ),
    (
        "The car is in good condition, Saturday Night Fever is on TV tonight.",
        "Night Fever",
    ),
    (
        "Weather conditions delayed the Valley Fever concert.",
        "Valley Fever",
    ),
    (
        "Upload your gift certificate before Spring Fever weekend ends.",
        "Spring Fever",
    ),
    (
        "Market conditions: Crypto Fever is cooling off.",
        "Crypto Fever",
    ),
    (
        "SSL certificate expired, Holiday Fever landing page is down.",
        "Holiday Fever",
    ),
    (
        "Under these conditions the Gold Rush Fever exhibit will open late.",
        "Rush Fever",
    ),
    (
        "Stock condition report: Disco Fever tickets are on sale.",
        "Disco Fever",
    ),
    (
        "The weather condition index shows Heat Wave Fever in retail.",
        "Wave Fever",
    ),
    (
        "Certificate of completion for the Tiger Fever coding bootcamp.",
        "Tiger Fever",
    ),
    (
        "Football fever and perfect pitch conditions at the stadium today.",
        "Football fever",
    ),
    (
        "La fièvre du Mondial gagne Paris, certificat de garantie en poche.",
        "fièvre du Mondial",
    ),
    (
        "Az iskolai igazolás kell a Balaton-láz fesztiválra.",
        "Balaton-láz",
    ),
    (
        "Igazolás: Kovács Péter részt vett a Tavasz-láz versenyen.",
        "Tavasz-láz",
    ),
    (
        "Die motor is in goeie toestand, Kersfees-koors in die winkels.",
        "Kersfees-koors",
    ),
    // The three eval values #202 gave back with its five cues (`certificate
    // for Mist Fever`, `Condition: Mist Fever`, `igazolást kér a Köd-láz
    // miatt`) are masked again by the cue frames of HEALTH-CUE-RESTORE: no
    // allowance, every byte of main stays.
];

/// The byte range of the one value given back on this line, when the line is
/// one of [`GIVEN_BACK`]: the value at its first occurrence inside its context.
fn given_back(text: &str) -> Option<(usize, usize)> {
    let (context, value) = GIVEN_BACK
        .iter()
        .find(|(context, _)| text.contains(context))?;
    let start = text.find(context)? + context.find(value)?;
    Some((start, start + value.len()))
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
fn header(inputs: &[(&str, String)]) -> String {
    let bytes = inputs.iter().flat_map(|(_, text)| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

/// The frozen fixture of one input list: its header, then its records.
fn fixture_text(inputs: &[(&str, String)]) -> String {
    let record = |text: &String| MODES.map(|mode| record(masked(mode, text))).join("|");
    let records: Vec<String> = inputs.iter().map(|(_, text)| record(text)).collect();
    let lines: Vec<String> = records.chunks(100).map(|c| c.join(";") + ";").collect();
    format!("{}\n{}", header(inputs), lines.join("\n"))
}

#[test]
#[ignore = "freezes the main fixtures: run on origin/main only"]
fn freeze() {
    for inputs in [inputs(), inputs_2()] {
        println!("FIXTURE-BEGIN\n{}\nFIXTURE-END", fixture_text(&inputs));
    }
}

/// The bytes of `main` a closed-allowance line may drop: none of them, or
/// exactly the bytes of the one named value. Panics on anything else, so a loss
/// of an address, an ID or any Open-mode mask on a given-back line fails here
/// rather than passing as part of the allowance.
fn assert_closed_allowance(
    text: &str,
    mode: PrivacyMode,
    main: &[(usize, usize)],
    now: &[(usize, usize)],
    allowance: (usize, usize),
) {
    assert!(
        now.iter().all(|r| main.contains(r)),
        "{text:?} {mode:?}: a mask main did not have, {now:?} against {main:?}"
    );
    let in_main = |byte: &usize| main.iter().any(|&(s, e)| *byte >= s && *byte < e);
    let gone: Vec<usize> = main
        .iter()
        .flat_map(|&(s, e)| s..e)
        .filter(|&b| !covered(now, b, b + 1))
        .collect();
    let named: Vec<usize> = (allowance.0..allowance.1).filter(in_main).collect();
    assert_eq!(
        gone,
        named,
        "{text:?} {mode:?}: main {main:?} now {now:?}; only {:?} may go",
        &text[allowance.0..allowance.1]
    );
}

/// A strict byte superset of `fixture` in both modes, no new refusal, and no new
/// mask on a prose line or a guard. The masks main has and the head drops are
/// the ones this pass exists to remove, and only on the lines [`GIVEN_BACK`]
/// names: an idiom HEALTH-RECALL-1 over-masked (`idiom` inputs) and an eval
/// value whose only anchor was a removed cue. On such a line the closed
/// allowance of [`given_back`] is all that may go, in either mode; every other
/// byte main masked must still be masked. `expect` is how many of the named
/// lines this fixture really gives something back, counted in each mode.
fn strict_superset(inputs: &[(&str, String)], fixture: &str, expect: usize) {
    let (head, body) = fixture.split_once('\n').unwrap();
    assert_eq!(head, header(inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut prose, mut dropped) = ([0usize; 2], 0, 0, [0usize; 2]);
    for ((kind, text), record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += 1;
                continue;
            };
            let main = main.unwrap_or_default();
            let gone = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if let Some(allowance) = given_back(text) {
                assert_closed_allowance(text, MODES[index], &main, &now, allowance);
                dropped[index] += usize::from(gone > 0);
                continue;
            }
            lost[index] += gone;
            let new = *kind == "prose" && now != main;
            prose += usize::from(new);
            if gone > 0 || new {
                eprintln!(
                    "{kind} {:?} {text:?}: main {main:?} now {now:?}",
                    MODES[index]
                );
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; refusals {refused}; prose or guard \
         lines changed {prose}; masks reclaimed from main Private/Open {dropped:?}",
        inputs.len()
    );
    assert_eq!((lost, refused, prose), ([0, 0], 0, 0));
    assert_eq!(
        dropped, [expect; 2],
        "every given-back line must give back its named value, in both modes"
    );
}

/// Both differentials: the HEALTH-RECALL-1 fixture is frozen from the main
/// before it, which masked none of the values named in [`GIVEN_BACK`] and so
/// has nothing to give back; the second is frozen from main after it, and gives
/// back the 16 negatives of this pass.
#[test]
fn strict_superset_of_main_in_both_modes() {
    strict_superset(&inputs(), FIXTURE, 0);
    strict_superset(&inputs_2(), FIXTURE_2, GIVEN_BACK.len());
}

/// The allowance names exactly the lines it exempts, once each: every `idiom`
/// input and no other line, and no line twice. Without this a typo in
/// [`GIVEN_BACK`] would quietly shrink the exemption.
#[test]
fn the_allowance_names_exactly_the_reclaimed_lines() {
    let inputs = inputs_2();
    let reclaimed: Vec<&String> = inputs
        .iter()
        .filter(|(kind, text)| *kind == "idiom" || given_back(text).is_some())
        .map(|(_, text)| text)
        .collect();
    assert_eq!(reclaimed.len(), GIVEN_BACK.len());
    for text in reclaimed {
        assert_eq!(
            GIVEN_BACK.iter().filter(|(c, _)| text.contains(c)).count(),
            1,
            "{text:?} is named by more than one allowance entry"
        );
    }
    assert_eq!(
        GIVEN_BACK.len(),
        IDIOMS[24..].len(),
        "the sixteen idioms and no eval value"
    );
}

/// The closed allowance has teeth: a given-back line that also loses its
/// national ID is not the allowance, and says so instead of passing.
#[test]
#[should_panic(expected = "only \"Mist Fever\" may go")]
fn the_allowance_catches_a_second_value_going_missing() {
    let inputs = inputs_2();
    let (_, body) = FIXTURE_2.split_once('\n').unwrap();
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    let at = inputs
        .iter()
        .position(|(_, text)| text.contains("Condition: Mist Fever"))
        .expect("the Condition line is an input");
    let text = &inputs[at].1;
    let main = parse(records[at].split('|').next().unwrap())
        .expect("no refusal")
        .to_vec();
    // The line is no longer an allowance (HEALTH-CUE-RESTORE): name the fever
    // here to test the check itself.
    let start = text.find("Mist Fever").expect("the fever is on the line");
    let allowance = (start, start + "Mist Fever".len());
    // The head keeps the fever masked and drops the ID too: thirteen bytes too
    // many, none of them named.
    let now: Vec<(usize, usize)> = main
        .iter()
        .copied()
        .filter(|(s, e)| (*s, *e) != (59, 72))
        .collect();
    assert_ne!(main, now, "the doctored head must really differ");
    assert_closed_allowance(text, MODES[0], &main, &now, allowance);
}

/// Every invented health value is hidden in full in both modes.
#[test]
fn invented_health_values_are_hidden_in_both_modes() {
    for (pre, value) in REPROS {
        let text = format!("{pre}{value}.");
        let (start, end) = (pre.len(), pre.len() + value.len());
        for mode in MODES {
            let now = masked(mode, &text).expect("no refusal");
            assert!(covered(&now, start, end), "{mode:?} {text:?}: {now:?}");
        }
    }
}

/// At most 5 of the 40 idioms and negatives are masked in Private.
#[test]
fn idioms_stay_clear() {
    let masked: Vec<_> = IDIOMS
        .iter()
        .filter(|t| masked(MODES[0], t) != Some(vec![]))
        .collect();
    eprintln!(
        "idioms masked: {} of {}: {masked:?}",
        masked.len(),
        IDIOMS.len()
    );
    assert!(masked.len() <= 5, "{masked:?}");
}

/// At least 70 % of the held-out health values are hidden in full in Private.
#[test]
fn held_out_health_recall_is_at_least_seventy_percent() {
    let mut missed = Vec::new();
    for line in HELD_OUT {
        let (pre, rest) = line.split_once('[').unwrap();
        let (value, post) = rest.split_once(']').unwrap();
        let now = masked(MODES[0], &format!("{pre}{value}{post}")).expect("no refusal");
        if !covered(&now, pre.len(), pre.len() + value.len()) {
            missed.push(*line);
        }
    }
    let hit = HELD_OUT.len() - missed.len();
    eprintln!(
        "held-out recall {hit}/{}; missed {missed:#?}",
        HELD_OUT.len()
    );
    assert!(hit * 10 >= HELD_OUT.len() * 7, "{missed:#?}");
}

/// Twenty of the twenty-two are hidden in full in both modes; the two fever
/// lines that carry no health word are the named allowance.
#[test]
fn held_out_2_health_is_hidden_in_both_modes() {
    let mut missed = Vec::new();
    for line in HELD_OUT_2 {
        let (pre, rest) = line.split_once('[').unwrap();
        let (value, post) = rest.split_once(']').unwrap();
        for mode in MODES {
            let now = masked(mode, &format!("{pre}{value}{post}")).expect("no refusal");
            if !covered(&now, pre.len(), pre.len() + value.len()) {
                missed.push(format!("{mode:?} {line}"));
            }
        }
    }
    eprintln!("held-out 2: {} lines, missed {missed:#?}", HELD_OUT_2.len());
    assert_eq!(missed.len(), 4, "{missed:#?}");
    let allowance = ["Valley fever", "fièvre de Saint-Brume"];
    assert!(
        missed
            .iter()
            .all(|m| allowance.iter().any(|a| m.contains(a))),
        "{missed:#?}"
    );
}
