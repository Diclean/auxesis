//! FIN-6: separator, glue and case variants of covered IDs and keys. A UK NI
//! number with glued letters or `/`, `.` or double-space separators, a
//! lower-case AWS key, and a NIR, card or SSN with double spaces, `/` or `.` are
//! masked in Private and removed in Open; the traps stay clear. All values are
//! invented (the AWS key is the AWS documentation example).

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, masked, MODES};
use kernel_privacy::{EntityKind, Registry};

/// The UK NI numbers in every shape of the spec, glue included.
fn nino_probes() -> Vec<String> {
    let mut out = Vec::new();
    for (letters, digits, suffix) in [
        ("PN", ["48", "15", "16"], "C"),
        ("QQ", ["12", "34", "56"], "A"),
    ] {
        for sep in ["/", "  ", "."] {
            out.push(format!("{letters}{sep}{}{sep}{suffix}", digits.join(sep)));
        }
        let spaced = format!("{letters} {} {suffix}", digits.join(" "));
        out.push(format!("{spaced}ok"));
        out.push(format!("ref{spaced}"));
    }
    out
}

/// Every probe: the value alone, and where the gate must still hide it.
fn probes() -> Vec<String> {
    let mut values = nino_probes();
    values.push("akiaiosfodnn7example".into());
    values.push(["AKIA", "IOSFODNN7EXAMPLE"].concat());
    for sep in ["  ", "/", "."] {
        values.push(["1", "84", "12", "76", "451", "089", "46"].join(sep));
        values.push(["4539", "1488", "0343", "6467"].join(sep));
    }
    values
}

/// The value `value` inside `frame` (`{}`), and its byte range there.
fn framed(frame: &str, value: &str) -> (String, usize, usize) {
    let start = frame.find("{}").unwrap();
    (frame.replace("{}", value), start, start + value.len())
}

#[test]
fn every_probe_is_masked_in_private_and_removed_in_open() {
    let frames = [
        "{}",
        "my NI is {}, thanks",
        "{} is the one",
        "please use {}",
    ];
    let ssn_frames = [
        "| SSN | {} |",
        "The SSN was {}.",
        "SSN:{}",
        "my SSN is {}, thanks",
        "SSN {} is the one",
        "SSN: {}",
    ];
    let cases = probes().into_iter().map(|value| (value, &frames[..]));
    let cases = cases.chain(["512/45/8873", "512.45.8873"].map(|v| (v.into(), &ssn_frames[..])));
    let mut missed = Vec::new();
    for (value, frames) in cases {
        for frame in frames {
            let (text, start, end) = framed(frame, &value);
            // A glued probe hides its NI number; the glue letters are no part of it.
            let (start, end) = match value.strip_prefix("ref") {
                Some(_) => (start + 3, end),
                None => (start, end - usize::from(value.ends_with("ok")) * 2),
            };
            for mode in MODES {
                let now = masked(mode, &text);
                if !now.as_deref().is_some_and(|now| covered(now, start, end)) {
                    missed.push(format!("{mode:?} {text:?}: {now:?}"));
                }
            }
        }
    }
    assert!(
        missed.is_empty(),
        "{} missed:\n{}",
        missed.len(),
        missed.join("\n")
    );
}

/// FIN-6 r1: an SSN whose groups two or three spaces join reads like the slash
/// and dot shapes do — a national id in Private, removed in Open — where it used
/// to go out in clear in Open behind a phone shape, which Open keeps by design.
#[test]
fn a_double_spaced_ssn_is_masked_and_removed() {
    let frames = [
        "SSN {}",
        "SSN:{}",
        "my SSN is {}, thanks",
        "Social Security Number: {}",
    ];
    let mut missed = Vec::new();
    for frame in frames {
        let (text, start, end) = framed(frame, "512  45  8873");
        let spans = Registry::new().analyze(&text);
        let is_id = spans.iter().any(|span| {
            span.kind == EntityKind::NationalId && span.start <= start && end <= span.end
        });
        missed.extend((!is_id).then(|| format!("no national id in {text:?}")));
        for mode in MODES {
            let now = masked(mode, &text);
            if !now.as_deref().is_some_and(|now| covered(now, start, end)) {
                missed.push(format!("{mode:?} {text:?}: {now:?}"));
            }
        }
    }
    let report = missed.join("\n");
    assert!(missed.is_empty(), "{} missed:\n{report}", missed.len());
}

/// Dates, versions, refs, short or prefix-less words and hashes stay clear, and
/// a double-spaced 16-digit run that fails Luhn is not removed in Open. The two
/// groups of a split SSN are no SSN either (FIN-6 r1).
#[test]
fn the_traps_stay_clear_in_both_modes() {
    let traps = "12/34/56|2026/10/22|v1.48.15.16|PN 48 pages|Section 48.15.16|ref 4539 1488|akia|\
        internationalization|the akia word stays|3f9a1c7e5b2d8f40a6c4|512  45|\
        commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b";
    let mut hit = Vec::new();
    for trap in traps.split('|') {
        for frame in ["{}", "see {} today"] {
            let text = frame.replace("{}", trap);
            for mode in MODES {
                let now = masked(mode, &text);
                if now != Some(vec![]) {
                    hit.push(format!("{mode:?} {text:?}: {now:?}"));
                }
            }
        }
    }
    let non_luhn = "4539  1488  0343  6468";
    let open = masked(MODES[1], &format!("card {non_luhn}"));
    if open != Some(vec![]) {
        hit.push(format!("Open non-Luhn {non_luhn:?}: {open:?}"));
    }
    assert!(hit.is_empty(), "{}", hit.join("\n"));
}
