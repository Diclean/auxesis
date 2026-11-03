//! HEALTH-RECALL-2 fresh set, written before any rule of this pass ran on it:
//! 40 health sentences and 60 negative prose lines (en, fr, hu, af, zh), none of
//! them in the repo and none tuned on. Bars: 60 % of the health values hidden
//! in full in Private, at most 5 of the negatives masked in either mode.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, masked, MODES};

/// Fresh health sentences; the value is in brackets.
const FRESH_HEALTH: &[&str] = &[
    "The clinic confirmed [Thornfield disease] this morning.",
    "My father is in hospital with [Ashgrove syndrome].",
    "She has been taking tablets for [Kestrel Bay disease] for a year.",
    "[Marlowe fever] kept her in bed all week.",
    "The doctor prescribed rest after my [Vandermeer syndrome].",
    "He was diagnosed with [Coldharbour disease] last winter.",
    "[Pemberly fever] is going round the office.",
    "Her treatment for [Underhill disease] starts on Monday.",
    "The specialist said the [Ravensworth disease] is manageable.",
    "My brother-in-law has [Hartsmere syndrome] since the accident.",
    "Blood tests show [Grimshaw disease].",
    "The nurse changed the dressing on my [Winterbourne fever] leg.",
    "Le diagnostic est tombé : [syndrome de Beaulieu].",
    "Elle suit un traitement pour une [maladie de Courcelle].",
    "Mon père souffre d'un [syndrome de Vaulais] depuis l'enfance.",
    "Il a la [fièvre de Montclair] depuis trois jours.",
    "Le médecin parle d'une [maladie de Trécy] à surveiller.",
    "On parle beaucoup du [syndrome de Vaudelnay] en ce moment.",
    "Sa [maladie d'Aubrac] reste sans traitement connu.",
    "Elle a attrapé la [fièvre du Perthus] pendant les vacances.",
    "Un nouveau protocole contre le [syndrome de Janval] arrive.",
    "Az orvos [Ezüst-betegséget] állapított meg.",
    "A családban öröklődik a [Hangyos-szindróma].",
    "Hónapok óta kezelik a [Kőszikla-lázát].",
    "A diagnózis egy [Vörösföld-betegség].",
    "A [Borsszék-szindróma] miatt nem tud dolgozni.",
    "A doktor [Vas-kórt] mondott ki.",
    "Hétköznap kórházban volt a [Fogas-láza] miatt.",
    "Die dokter het [Rooivalk-siekte] by hom gesien.",
    "Hy herstel van [Kameel-siekte] in die hospitaal.",
    "Sy het [Vuurberg-koors] en moet binnemoes.",
    "[Renoster-siekte] is baie seldeam in hierdie land.",
    "Dieet het geskiedenis van [Wolwekrans-koors] nagegaan.",
    "[Kameel se siekte] is al vir drie maande aan die gang.",
    "医院确诊他患有[霜叶病]。",
    "她因为[蓝铃热]请了病假。",
    "妈妈最近在治疗[灰石症]。",
    "医生说是[赤松病]，需要定期复查。",
    "[晨河病]已经痊愈，可以出院了。",
    "他得了[雾杉综合征]，正在治疗。",
];

/// Fresh negative prose: names, honorifics, finance, weather, shop names and
/// idioms that hold a disease word without a health value.
const FRESH_NEGATIVES: &[&str] = &[
    "Dr Teller will see the client on Tuesday morning.",
    "Mr Morrow said the invoice had already been paid.",
    "Mrs Valley signed the lease this afternoon.",
    "Professor Grey-Wing retired at the end of term.",
    "Marcus Fever will collect the parcel on Friday.",
    "Teller signed the lease without reading the small print.",
    "Dr. Köd arrives tomorrow morning for the handover.",
    "Terms and conditions apply to every Gold Fever weekend ticket.",
    "The car is in good condition after the service.",
    "Spring fever hit the office and everyone forgot the deadline.",
    "Gold fever drove the town hall to build a new museum.",
    "The Fever Tree tonic is in the fridge.",
    "The Hemlock Fever brewery in Ghent won an award.",
    "Le Dr Ravelle a signé le certificat de travail.",
    "Mme Grisel arrive demain pour le dossier.",
    "La fièvre du Mondial gagne Paris, les bars sont pleins.",
    "Le certificat de garantie est dans la boîte à gants.",
    "C'est la fièvre de Noël dans les magasins.",
    "Le syndrome de l'imposteur touche beaucoup de cadres.",
    "La caisse d'assurance maladie de Lyon a répondu.",
    "Winter fever kept the office closed on Monday.",
    "Pierre Malouin will send the figures before Friday.",
    "Assurance maladie: le tarif change en janvier.",
    "Le Mondial joue à domicile samedi soir.",
    "Teller úr megállította a taxit a kikötőben.",
    "Morrow doktor megnézte a leletet.",
    "Az iskolai igazolás kell a fesztiválra.",
    "A vezetőség a Black Friday-láz miatt döntött a halasztásról.",
    "A Balaton-láz minden nyáron visszatér.",
    "Az EB-láz miatt mindenki a tévé előtt ül.",
    "A meccs láza a szurkolókat is elkapta.",
    "Nagyon meleg volt, a termosz kifosztott.",
    "A pályázatok határideje ma este lejár.",
    "A felújítás után a tető nem szivárog.",
    "A tárgyalás holnap reggel kezdődik.",
    "Kedd reggel korán felkelt, hogy utazzon.",
    "Mnr Teller het die brief gepos.",
    "Dr Morrow het die uitslag van die bloedproef bespreek.",
    "Die motor is in goeie toestand, hy ry nie.",
    "Die Bok-koors is terug na die rugbywedstryd.",
    "Rugby-koors het die dorp getref.",
    "Kersfees-koors in die winkels begin Maandag.",
    "Die Smit-familie woon al twintig jaar in die dorp.",
    "Die vergadering is Dinsdag om nege-uur in die groot saal.",
    "Ons het 'n goeie tyd gehad op die plaas.",
    "Die kos wat die bank kos, maar die teller het reg gekry.",
    "Die bydrae van die werknemers het die fonds laat groot.",
    "Die blomme in die tuin het pragtig geblom.",
    "这个月天气热得厉害，空调都不够用。",
    "气温升高，天气预报说会有雷雨。",
    "他最近很忙，没时间休息。",
    "会议上讨论了下季度的预算安排。",
    "这台机器出了毛病，需要换零件。",
    "病历已经整理好了，请医生过目。",
    "请把这份材料打印两份给我。",
    "老王昨天出差回来了，辛苦了。",
    "时间过得真快，一转眼又到年底。",
    "这本书我看了一半，还剩两百页。",
    "会后我们分组讨论，再统一汇总。",
    "他说完就走了，会议室里剩下几个人。",
];

/// The two bars of the fresh set: 60 % of the health values hidden in full in
/// Private, at most 5 of the 60 negatives masked in either mode.
#[test]
fn fresh_probe_holds_its_bars() {
    let mut missed = Vec::new();
    for line in FRESH_HEALTH {
        let (pre, rest) = line.split_once('[').unwrap();
        let (value, post) = rest.split_once(']').unwrap();
        let now = masked(MODES[0], &format!("{pre}{value}{post}")).expect("no refusal");
        if !covered(&now, pre.len(), pre.len() + value.len()) {
            missed.push(*line);
        }
    }
    let hit = FRESH_HEALTH.len() - missed.len();
    eprintln!(
        "fresh health recall {hit}/{}; missed {missed:#?}",
        FRESH_HEALTH.len()
    );
    assert!(hit * 10 >= FRESH_HEALTH.len() * 6, "{missed:#?}");
    for mode in MODES {
        let masked: Vec<_> = FRESH_NEGATIVES
            .iter()
            .filter(|text| masked(mode, text) != Some(vec![]))
            .copied()
            .collect();
        eprintln!(
            "{mode:?}: {} of {} masked: {masked:#?}",
            masked.len(),
            FRESH_NEGATIVES.len()
        );
        assert!(masked.len() <= 5, "{masked:#?}");
    }
}
