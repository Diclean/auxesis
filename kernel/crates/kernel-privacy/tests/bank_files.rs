//! FIN-5: bank files (SWIFT MT940/MT103, EDIFACT FINSTA/PAYMUL, BAI2) are
//! tokenised in Private, never refused. Masking a value puts a stand-in and a line
//! break in the residue view, so a number glued to it (`…567+4930123456789`,
//! `…Ov/USD123456`) starts a line there and reads as a phone or an MRZ line.
//! Main refused the text; the gate now masks that residue as its own class.
//!
//! Every IBAN passes its checksum; every IBAN and BIC is invented. A value in
//! `«…»` must be a minted token in Private, never in clear; text in `‹…›`
//! (amounts) must pass unchanged. BICs are not a classed value and stay clear.

use std::sync::Arc;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, NameDictionary};

/// `(format, marked text)`: `«…»` must be tokenised in Private, `‹…›` must stay clear.
const BANK_FILES: &[(&str, &str)] = &[
    (
        "MT940 statement, value glued to an IBAN",
        ":20:STMT2610210001\n:25:«DE89500105170001234567»\n:28C:00042/001\n\
         :60F:C261020EUR‹12500,00›\n\
         :61:261021USD‹123456.78›NTRF//«NL80AUXB0417164300»/USD123456.78\n\
         /261021-010022USD123456.78/USD123456.78\n\
         :86:166?00SEPA TRANSFER?20INVOICE 2026-117?30AUXBNL2AXXX?31«NL80AUXB0417164300»\n\
         :62F:C261021EUR‹11000,00›\n",
    ),
    (
        "MT103 customer transfer",
        "{1:F01AUXBDEFFAXXX0000000000}{2:I103AUXBNL2AXXXXN}{4:\n:20:REF2610210042\n:23B:CRED\n\
         :32A:261021EUR‹4250,00›\n:50K:/«DE89500105170001234567»\nEXAMPLE TRADING GMBH\n\
         :52A:AUXBDEFFXXX\n:57A:AUXBNL2AXXX\n:59:/«NL80AUXB0417164300»+31201234567\nEXAMPLE BV\n\
         :70:INVOICE 2026-117\n:71A:SHA\n-}",
    ),
    (
        "EDIFACT FINSTA statement",
        "UNB+UNOC:3+AUXBDEFF:25+EXAMPLECORP:ZZZ+261021:0930+0042'\nUNH+1+FINSTA:D:96A:UN'\n\
         BGM+‹4250›+STMT0042+9'\nFII+AO+«DE89500105170001234567»+4930123456789:25:5'\n\
         FII+BF+«NL80AUXB0417164300»+31201234567:25:5'\nMOA+343:‹12500.00›:EUR'\nMOA+315:‹11000.00›:EUR'\nUNT+6+1'\nUNZ+1+0042'",
    ),
    (
        "EDIFACT PAYMUL payment order",
        "UNB+UNOC:3+EXAMPLECORP:ZZZ+AUXBNL2A:25+261021:1015+0043'\nUNH+1+PAYMUL:D:96A:UN'\n\
         BGM+452+PAY0043+9'\nMOA+9:‹1500.00›:EUR'\nFII+OR+«DE89500105170001234567»+4930123456789:25:5'\n\
         FII+BF+«NL80AUXB0417164300»+31201234567:25:5'\nUNT+7+1'\nUNZ+1+0043'",
    ),
    (
        "BAI2 balance report",
        "01,AUXBANK,EXAMPLECORP,261021,0930,1,,,2/\n02,EXAMPLECORP,AUXBANK,1,261020,,USD,2/\n\
         03,«GB23AUXB40512398765432»FR015000,USD,010,‹1250000›,,,040,‹1180000›,,/\n\
         16,195,‹150000›,0,REF0001,,WIRE IN/\n49,‹2580000›,4/\n98,‹2580000›,1,6/\n99,‹2580000›,1,8/",
    ),
];

/// The plain text of a fixture, its tokenised values and its clear parts.
fn parse(marked: &str) -> (String, Vec<String>, Vec<String>) {
    let (mut text, mut hidden, mut clear) = (String::new(), Vec::new(), Vec::new());
    let mut open = None;
    for ch in marked.chars() {
        match (ch, open) {
            ('«' | '‹', None) => open = Some(text.len()),
            ('»', Some(at)) => hidden.push(text[at..].to_string()),
            ('›', Some(at)) => clear.push(text[at..].to_string()),
            _ => text.push(ch),
        }
        if matches!(ch, '»' | '›') {
            open = None;
        }
    }
    (text, hidden, clear)
}

fn gate(mode: PrivacyMode) -> Gate {
    let ctx = Context {
        destination: Destination::Vendor("bank-files".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be admitted in {mode:?}");
    };
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).expect("dictionary"));
    Gate::for_grant_with_dictionary(&grant, [5; 32], names)
}

#[test]
fn private_issues_every_bank_file_with_its_values_tokenised() {
    let mut wrong = Vec::new();
    for &(name, marked) in BANK_FILES {
        let (text, hidden, clear) = parse(marked);
        let mut gate = gate(PrivacyMode::Private);
        let out = match gate.text(&text) {
            Ok((safe, _)) => safe.as_str().to_string(),
            Err(error) => {
                wrong.push(format!("{name}: refused {error:?}"));
                continue;
            }
        };
        let minted = gate.take_minted();
        for value in &hidden {
            if out.contains(value.as_str()) {
                wrong.push(format!("{name}: {value:?} in clear"));
            }
            if !minted
                .iter()
                .any(|(_, minted)| minted.contains(value.as_str()))
            {
                wrong.push(format!("{name}: {value:?} not tokenised"));
            }
        }
        for part in clear.iter().filter(|part| !out.contains(part.as_str())) {
            wrong.push(format!("{name}: {part:?} masked"));
        }
        // No residue: the issued text, read again by a fresh Private gate that
        // keeps this one's tokens, comes back unchanged.
        let tokens = minted.iter().map(|(token, _)| token.clone()).collect();
        let mut again =
            Gate::for_session_tokens(&grant_private(), Arc::new(tokens)).expect("session gate");
        match again.text(&out) {
            Ok((safe, _)) if safe.as_str() == out => {}
            other => wrong.push(format!("{name}: residue on a second read: {other:?}")),
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

fn grant_private() -> kernel_core::privacy::Grant {
    let ctx = Context {
        destination: Destination::Vendor("bank-files".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &ctx) else {
        panic!("A1 must be admitted");
    };
    grant
}

#[test]
fn open_issues_every_bank_file_without_its_ibans() {
    for &(name, marked) in BANK_FILES {
        let (text, hidden, clear) = parse(marked);
        let (safe, _) = gate(PrivacyMode::Open).text(&text).expect(name);
        let iban = |value: &&String| {
            value.len() > 14 && value.as_bytes()[..2].iter().all(u8::is_ascii_uppercase)
        };
        for value in hidden.iter().filter(iban) {
            assert!(!safe.as_str().contains(value.as_str()), "{name}: {value}");
        }
        for part in &clear {
            assert!(safe.as_str().contains(part.as_str()), "{name}: {part}");
        }
    }
}

/// Linear time: 4x the bank lines costs less than 6x the time (quadratic is 16x).
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn bank_files_scale_linearly() {
    let unit: String = BANK_FILES
        .iter()
        .map(|(_, marked)| parse(marked).0 + "\n")
        .collect();
    let time = |n: usize| {
        let text = unit.repeat(n);
        let started = std::time::Instant::now();
        gate(PrivacyMode::Private).text(&text).expect("issued");
        started.elapsed().as_secs_f64()
    };
    time(25);
    let (small, large) = (time(100), time(400));
    assert!(large / small < 6.0, "{small:.3}s -> {large:.3}s");
}
