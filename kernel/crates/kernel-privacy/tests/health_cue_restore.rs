//! HEALTH-CUE-RESTORE acceptance: #202 took `condition`, `certificate`,
//! `certificat`, `igazolás` and `toestand` off the cue list, and with them the
//! masks on a fever name those words introduce (`Condition: Mist Fever`). The
//! words come back as frames that touch the name — a line label, `certificate
//! for`, `igazolás … miatt` — never as sentence-wide cues, so the idioms #202
//! cleared stay clear. All values are invented.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, issue, masked, MODES};

/// A cue frame and the disease name it introduces, in brackets: hidden in full,
/// in both modes.
const FRAMED: &[&str] = &[
    "[Condition: Mist Fever]",
    "[Condition: Mist Fever].",
    "Patient record (scan, OCR)\nName: Mara Ellison\n[Condition: Mist Fever]\nStatus: stable",
    "[Condition : Mist Fever]",
    "\t* [cOnDiTiOn： Mist Fever]",
    "An unrelated introduction longer than the frame window ends here. [Condition: Mist Fever]",
    "[Condition: Ashen Disease]",
    "[Certificate for Grey-China syndrome] attached.",
    "[Medical condition: Ash Fever], stable.",
    "- [Condition: Grey-Wing Fever]",
    "[Medical certificate: Valley fever]",
    "[Certificate: Ember Fever], three days off.",
    "Owen Calder needs a [certificate for Mist Fever]. Do not forward the form.",
    "Please send the [certificate for his Ember Fever] today.",
    "[Certificat médical : fièvre de Brume].",
    "Il demande un [certificat pour la fièvre de Brume].",
    "[Toestand: As-koors], stabiel.",
    "[Toestand: Mis-griep]",
    "[Mediese toestand: Grys-koors]",
    "[Igazolás: Köd-láz], két hét pihenő.",
    "[Orvosi igazolás: Hamu-láz]",
    "Fekete Áron [igazolást kér a Köd-láz] miatt.",
    "Tárgy: orvosi távollét\nFekete Áron (1984. március 12.) [igazolást kér a Köd-láz] miatt.",
];

/// The negatives #202 cleared (CHANGES 02fc91a1), and the frame lookalikes this
/// pass must not reach: no mask at all, in either mode.
const CLEAR: &[&str] = &[
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
    // Lookalikes of the frames themselves.
    "Conditions: Gold Fever sale ends Sunday.",
    "Weather conditions: Gold Fever sale ends Sunday.",
    "Upload your gift certificate for Spring Fever weekend.",
    "The SSL certificate for Holiday Fever expired.",
    "Az EB-láz miatt mindenki a tévé előtt ül.",
    "A vezetőség a Black Friday-láz miatt döntött a halasztásról.",
    "Toestand van die pad: Kersfees-koors in die winkels.",
    "The car is in good condition after the service.",
    "Le certificat de garantie est dans la boîte à gants.",
];

#[test]
fn cue_framed_fever_names_are_hidden_in_both_modes() {
    let mut missed = Vec::new();
    for line in FRAMED {
        let (pre, rest) = line.split_once('[').unwrap();
        let (value, post) = rest.split_once(']').unwrap();
        for mode in MODES {
            let now = masked(mode, &format!("{pre}{value}{post}")).expect("no refusal");
            if !covered(&now, pre.len(), pre.len() + value.len()) {
                missed.push(format!("{mode:?} {line}: {now:?}"));
            }
        }
    }
    assert!(missed.is_empty(), "{missed:#?}");
}

#[test]
fn the_negatives_202_cleared_stay_clear_in_both_modes() {
    for mode in MODES {
        let hit: Vec<_> = CLEAR
            .iter()
            .filter(|text| masked(mode, text) != Some(vec![]))
            .collect();
        assert!(hit.is_empty(), "{mode:?}: {hit:#?}");
    }
}

const FIXED_FRAMES: &[&str] = &[
    "Condition: Larch Fever",
    "Certificate: Larch Fever",
    "Toestand: Doring-koors",
    "Igazolás: Fenyő-láz",
    "Condition:\nLarch Fever",
    "**Condition:** Larch Fever",
    "**Condition**: Larch Fever",
    "Medical condition - Larch Fever",
    "Toestand:\nDoring-koors",
    "Igazolás:\nFenyő-láz",
    "Condition: larch fever",
    "Condition: LARCH FEVER",
    "condition: larch fever",
    "CONDITION: LARCH FEVER",
    "Toestand: doring-koors",
    "TOESTAND: DORING-KOORS",
    "Igazolás: fenyő-láz",
    "IGAZOLÁS: FENYŐ-LÁZ",
    "Certificat: fièvre de brume",
    "CERTIFICAT: FIÈVRE DE BRUME",
    "Condition:\n  Larch Fever",
    "**Condition:**\n\tLarch Fever",
];
/// Seal A: complete frames, with no promotion of the next field in either mode.
#[test]
fn restored_frames_mask_completely_and_keep_following_fields_clear() {
    let mut failed = Vec::new();
    for &frame in FIXED_FRAMES {
        for tail in [
            "",
            " | Film: Saturday Night Fever",
            ", event: Gold Fever sale.",
            ", film: Vakansie-koors.",
            ", esemény: Duna-láz fesztivál.",
            ". Film: Saturday Night Fever",
            "; Film: Saturday Night Fever",
            "\nFilm: Saturday Night Fever",
        ] {
            let text = format!("{frame}{tail}");
            for mode in MODES {
                let now = masked(mode, &text).expect("no refusal");
                if !covered(&now, 0, frame.len()) || now.iter().any(|&(_, e)| e > frame.len()) {
                    failed.push(format!("{mode:?} {text:?}: {now:?}"));
                }
            }
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
    for text in [
        "larch fever",
        "LARCH FEVER",
        "doring-koors",
        "DORING-KOORS",
        "fenyő-láz",
        "FENYŐ-LÁZ",
        "fièvre de brume",
        "FIÈVRE DE BRUME",
        "**Conditions:** Larch Fever",
        "**Condition: Larch Fever",
        "Condition:** Larch Fever",
        "**Condition** Larch Fever",
    ] {
        for mode in MODES {
            assert_eq!(masked(mode, text), Some(vec![]), "{mode:?} {text:?}");
        }
    }
}

/// Linear time: 4x the framed lines costs less than 6x the time.
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn cue_frames_scale_linearly() {
    let unit: String = FRAMED
        .iter()
        .chain(CLEAR)
        .chain(FIXED_FRAMES)
        .map(|line| line.replace(['[', ']'], "") + "\n")
        .collect();
    for mode in MODES {
        // Time the gate itself; exact-mask alignment is correctness-test work.
        let time = |n: usize| {
            let text = unit.repeat(n);
            let mut samples = [0.0; 3];
            for sample in &mut samples {
                let started = std::time::Instant::now();
                std::hint::black_box(issue(mode, &text).expect("no refusal"));
                *sample = started.elapsed().as_secs_f64();
            }
            samples.sort_by(f64::total_cmp);
            samples[1]
        };
        time(1);
        let times = [time(10), time(40), time(160)];
        for pair in times.windows(2) {
            let ratio = pair[1] / pair[0];
            eprintln!("{mode:?}: {:.3}s -> {:.3}s ({ratio:.2}x)", pair[0], pair[1]);
            assert!(ratio <= 6.0, "{mode:?}: {ratio:.2}x for 4x input");
        }
    }
}
