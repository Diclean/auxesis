//! TEST-FITS-EXACT: the gate-output alignment must be exact, so a text that
//! cannot be aligned fails instead of passing under some reading that happens
//! to keep the value hidden.
//!
//! Main's reader (`norm1_cases::ranges`, and `health_label::fits` beside it)
//! split an output into clear pieces and dropped each piece at the **first**
//! place it appeared in the input, then asked whether *some* reading kept the
//! bytes hidden. With two masks side by side that passes a real leak: the
//! clear piece slides onto the second copy of the text and the first mask grows
//! over a value that is in the clear in the output.
//!
//! The outputs below are that leak in its shapes. Each one is read by the main
//! helper (both variants, verbatim below, so the hole stays reproducible) and
//! by the exact reader every test in this crate now uses
//! (`data/exact_mask.rs`). The exact reader rejects all of them: either the
//! output does not read back onto the input at all, or the one reading it has
//! leaves the value in the clear. Nothing here runs the gate: these are outputs
//! the gate could have written and must not, so the reader is the thing under
//! test.
//!
//! The pins at the end go the other way: one case per source `exact_ranges` can
//! use, and one per mode, so an honest output keeps reading back.
//!
//! Values are invented and belong to no one.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod cases {
    include!("data/exact_mask.rs");
}
use cases::exact_ranges;

/// Whether every byte of `(start, end)` is inside one of `ranges`.
fn covered(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    (start..end).all(|byte| ranges.iter().any(|&(s, e)| s <= byte && byte < e))
}

/// Main's greedy reader, verbatim: each clear piece at the first place it
/// appears in `input`. Kept here so the leaks it passes stay reproducible.
fn greedy(input: &str, output: &str) -> Vec<(usize, usize)> {
    let (mut pieces, mut rest) = (vec![String::new()], output);
    while let Some(ch) = rest.chars().next() {
        let token = rest.strip_prefix('⟦').and_then(|r| Some(r.find('⟧')? + 6));
        let marker = (ch == '[').then(|| rest.find(" removed]")).flatten();
        let marker = marker.filter(|&e| !rest[1..e].contains(['[', ']']));
        if let Some(len) = token.or(marker.map(|e| e + 9)) {
            rest = &rest[len..];
            pieces.push(String::new());
        } else {
            pieces.last_mut().unwrap().push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    let (first, last) = (&pieces[0], &pieces[pieces.len() - 1]);
    if pieces.len() == 1 {
        assert_eq!(first, input, "unaligned");
        return Vec::new();
    }
    let fail = || -> usize { panic!("unaligned: {input:?} -> {output:?}") };
    if !input.starts_with(first.as_str()) || !input.ends_with(last.as_str()) {
        fail();
    }
    let (mut out, mut at) = (Vec::new(), first.len());
    for piece in &pieces[1..pieces.len() - 1] {
        let from = at + input[at..].chars().next().map_or(1, char::len_utf8);
        let found = input[from..].find(piece.as_str()).unwrap_or_else(fail) + from;
        out.push((at, found));
        at = found + piece.len();
    }
    out.push((at, input.len() - last.len()));
    out
}

/// The clear pieces of a gate output, between its tokens and markers (main's
/// `health_label::pieces`, verbatim).
fn pieces(output: &str) -> Vec<String> {
    let (mut pieces, mut rest) = (vec![String::new()], output);
    while let Some(ch) = rest.chars().next() {
        let token = rest.strip_prefix('⟦').and_then(|r| Some(r.find('⟧')? + 6));
        let marker = (ch == '[').then(|| rest.find(" removed]")).flatten();
        let marker = marker.filter(|&e| !rest[1..e].contains(['[', ']']));
        if let Some(len) = token.or(marker.map(|e| e + 9)) {
            rest = &rest[len..];
            pieces.push(String::new());
        } else {
            pieces.last_mut().unwrap().push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    pieces
}

/// Main's `health_label::fits`, verbatim: whether *some* reading of the output
/// keeps `hidden` masked, each clear piece placed at the earliest place that
/// shows none of those bytes.
fn fits(input: &str, output: &str, hidden: &[(usize, usize)]) -> bool {
    let pieces = pieces(output);
    let clear = |s: usize, e: usize| hidden.iter().all(|&(hs, he)| he <= s || e <= hs);
    let (first, last) = (&pieces[0], &pieces[pieces.len() - 1]);
    if pieces.len() == 1 {
        return first == input && hidden.iter().all(|&(s, e)| s == e);
    }
    let tail = input.len() - last.len().min(input.len());
    if !input.starts_with(first.as_str()) || !input.ends_with(last.as_str()) {
        return false;
    }
    if !clear(0, first.len()) || !clear(tail, input.len()) {
        return false;
    }
    let mut at = first.len();
    for piece in &pieces[1..pieces.len() - 1] {
        let Some(c) = input[at..].chars().next() else {
            return false;
        };
        let from = at + c.len_utf8();
        let place = (from..=input.len().saturating_sub(piece.len())).find(|&p| {
            input.is_char_boundary(p)
                && input[p..].starts_with(piece.as_str())
                && clear(p, p + piece.len())
        });
        let Some(place) = place else {
            return false;
        };
        at = place + piece.len();
    }
    at < tail
}

/// One adversarial output: what the gate must never write, the tokens it claims
/// to have minted, and the bytes the old test recorded as hidden (the first
/// copy of the value, which is all `inputs()` ever records).
#[derive(Debug)]
struct Leak {
    what: &'static str,
    mode: PrivacyMode,
    input: &'static str,
    output: &'static str,
    minted: &'static [(&'static str, &'static str)],
    hidden: &'static [(usize, usize)],
}

fn minted(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(token, surface)| (token.to_string(), surface.to_string()))
        .collect()
}

/// The seal's counterexample on PR #207, three more shapes of the same hole, and
/// the four an unminted token name or a marker of any body slips through:
/// `⟦HEALTH_4412⟧` and `[health 4412 removed]` hide the value by *spelling* it,
/// so both read as fully masked while the value sits in the output.
fn leaks() -> Vec<Leak> {
    vec![
        Leak {
            what: "two masks side by side, the second value in the clear",
            mode: PrivacyMode::Private,
            input: "zz MRN 4412 qq MRN 4412 ww",
            output: "⟦HEALTH_a⟧ MRN 4412 ⟦HEALTH_b⟧",
            minted: &[("HEALTH_a", "4412"), ("HEALTH_b", "4412")],
            hidden: &[(7, 11)],
        },
        Leak {
            what: "the two tokens swapped, so each hides the wrong value",
            mode: PrivacyMode::Private,
            input: "aa 1111 bb 2222 cc",
            output: "aa ⟦HEALTH_b⟧ bb ⟦HEALTH_a⟧ cc",
            minted: &[("HEALTH_a", "1111"), ("HEALTH_b", "2222")],
            hidden: &[(3, 7), (11, 15)],
        },
        Leak {
            what: "a value in the clear between two identical tokens",
            mode: PrivacyMode::Private,
            input: "aa 1111 bb 1111 cc 1111 dd",
            output: "aa ⟦H⟧ bb 1111 ⟦H⟧ cc 1111 dd",
            minted: &[("H", "1111")],
            hidden: &[(3, 7)],
        },
        Leak {
            what: "a token covering half the value",
            mode: PrivacyMode::Private,
            input: "aa 1111 bb 1111 cc 1111 dd",
            output: "aa ⟦H⟧ bb 11⟦H⟧11 cc 1111 dd",
            minted: &[("H", "1111")],
            hidden: &[(3, 7)],
        },
        Leak {
            what: "the value spelled in the token name, first copy",
            mode: PrivacyMode::Private,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN ⟦HEALTH_4412⟧ and MRN ⟦HEALTH_4412⟧ end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "the value spelled in the token name, second copy",
            mode: PrivacyMode::Private,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN ⟦HEALTH_removed⟧ and MRN ⟦HEALTH_4412⟧ end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "the value spelled in the marker body, first copy",
            mode: PrivacyMode::Open,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN [health 4412 removed] and MRN [health removed] end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "the value spelled in the marker body, second copy",
            mode: PrivacyMode::Open,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN [health removed] and MRN [health 4412 removed] end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "the value spelled as the class inside the marker, first copy",
            mode: PrivacyMode::Open,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN [MRN 4412 removed] and MRN [MRN removed] end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "the value spelled as the class inside the marker, second copy",
            mode: PrivacyMode::Open,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN [MRN removed] and MRN [MRN 4412 removed] end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
    ]
}

/// The remaining shapes the old reader and the first exact reader had no case
/// for. Main's reader is not asserted here: it already rejected these, so they
/// pin the exact reader alone.
fn rejected() -> Vec<Leak> {
    vec![
        Leak {
            what: "the value left in the clear and the marker put on the second copy",
            mode: PrivacyMode::Open,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN 4412 and MRN [health removed] end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "both markers real, the value shifted between them",
            mode: PrivacyMode::Open,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN [health removed] and MRN 4412 [health removed] end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "a marker of another class over a health span",
            mode: PrivacyMode::Open,
            input: "MRN 4412 and MRN 4412 end",
            output: "MRN [iban removed] and MRN [iban removed] end",
            minted: &[],
            hidden: &[(4, 8), (17, 21)],
        },
        Leak {
            what: "a token name no gate minted, over a detector span it never read",
            mode: PrivacyMode::Private,
            input: "aa MRN 4412 bb MRN 4412 cc",
            output: "aa ⟦HEALTH_a⟧ bb MRN ⟦HEALTH_b⟧ cc",
            minted: &[],
            hidden: &[(7, 11), (19, 23)],
        },
        Leak {
            what: "an unclosed token, so the rest of the output is a name",
            mode: PrivacyMode::Private,
            input: "aa MRN 4412 bb",
            output: "aa ⟦HEALTH_a",
            minted: &[("HEALTH_a", "4412")],
            hidden: &[(7, 11)],
        },
        Leak {
            what: "a closer with no opener, hiding a value in the clear",
            mode: PrivacyMode::Private,
            input: "aa MRN 4412 bb",
            output: "aa 4412⟧ bb",
            minted: &[],
            hidden: &[(7, 11)],
        },
    ]
}

/// The two shapes of a split run the gate itself writes (TEST-FITS-EXACT-2):
/// one detector span, one name, several tokens, the pieces read by the gate's
/// own residue round. The reader has to line them up — and has to keep refusing
/// the two mutations of that line-up below, where a value ends up in the clear
/// between the pieces or the pieces are claimed out of order.
///
/// The input is a real corpus text of `nino_newline` (its seeded differential
/// is the red this reader change fixes): `StandardDetector::detect` reads one
/// `UkNino` span over both spellings and the break between them, while the
/// residue view — the view `Gate::apply_spans` masks when a first-round span is
/// not one whole maskable value — reads the two spellings as two pieces of it,
/// and the gate writes one token for each under one name. The token names are
/// the gate's own, so the case does not depend on a digest of its own.
fn nino_split() -> (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
) {
    (
        "4539-1488-0343-6467 \u{2029} \u{2028}AB \u{2028}  12 34 56 C\u{2028}AB123456C \u{2029} \u{2028}Dear customer,",
        "\u{27E6}CREDIT_CARD_4D66576F98FC\u{27E7} \u{2029} \u{2028}\u{27E6}UK_NINO_7ACDCEB03044\u{27E7}\u{2028}\u{27E6}UK_NINO_7ACDCEB03044\u{27E7} \u{2029} \u{2028}Dear customer,",
        &[
            ("CREDIT_CARD_4D66576F98FC", "4539-1488-0343-6467"),
            ("UK_NINO_7ACDCEB03044", "AB \u{2028}  12 34 56 C"),
        ],
    )
}

/// The run reads back: one token per piece, the break between them clear, and
/// the card, the long spelling and the second spelling all masked.
#[test]
fn a_split_run_reads_back_one_token_per_piece() {
    let (input, output, pairs) = nino_split();
    assert_eq!(
        exact_ranges(PrivacyMode::Private, input, output, &minted(pairs)),
        Some(vec![(0, 19), (27, 45), (48, 57)]),
        "the card, the first spelling (the minted surface) and the second \
         (the residue piece)"
    );
    // The minted surface is the first spelling only: `take_minted` keeps one
    // entry per name, and the second token has no surface at its cursor, so
    // this is the case the residue piece exists for.
    assert!(
        !input[48..].starts_with(pairs[1].1),
        "the second spelling must not be the minted surface"
    );
}

/// One mutation of a split run: what it is, the output the gate must never
/// write, and the one reading the reader has of it (`None` for none at all).
type Mutation = (&'static str, &'static str, Option<Vec<(usize, usize)>>);

/// The three mutations of that run, each one the gate must never write: the
/// value left in the clear where the break is, the pieces claimed out of order,
/// and the gate's own two tokens with the value beside them. Each outcome is
/// pinned, because there are two ways to refuse and only one of them is a
/// clean reading: the first reads back and leaves the number in the clear, the
/// other two have no exact reading at all.
#[test]
fn a_split_run_never_hides_a_value_left_in_the_clear() {
    let (input, _, pairs) = nino_split();
    let cases: Vec<Mutation> = vec![
        (
            "split pieces with the value left in the clear between them",
            "⟦CREDIT_CARD_4D66576F98FC⟧ \u{2029} \u{2028}⟦UK_NINO_7ACDCEB03044⟧\u{2028}\
             AB123456C \u{2029} \u{2028}Dear customer,",
            Some(vec![(0, 19), (27, 45)]),
        ),
        (
            "split pieces out of order: the tokens bracket the value, not the break",
            "⟦CREDIT_CARD_4D66576F98FC⟧ \u{2029} \u{2028}⟦UK_NINO_7ACDCEB03044⟧\
             AB123456C\u{2028}⟦UK_NINO_7ACDCEB03044⟧ \u{2029} \u{2028}Dear customer,",
            None,
        ),
        (
            "the gate's two tokens, and the second spelling in the clear after them",
            "⟦CREDIT_CARD_4D66576F98FC⟧ \u{2029} \u{2028}⟦UK_NINO_7ACDCEB03044⟧\u{2028}\
             ⟦UK_NINO_7ACDCEB03044⟧AB123456C \u{2029} \u{2028}Dear customer,",
            None,
        ),
    ];
    let second = input.find("AB123456C").unwrap();
    let hidden = [(second, second + "AB123456C".len())];
    for (what, output, expected) in cases {
        let ranges = exact_ranges(PrivacyMode::Private, input, output, &minted(pairs));
        assert_eq!(ranges, expected, "{what}: {output:?}");
        assert!(
            !ranges
                .as_ref()
                .is_some_and(|ranges| hidden.iter().all(|&(s, e)| covered(ranges, s, e))),
            "{what}: {output:?} reads back as {ranges:?} and still calls the \
             second spelling masked"
        );
    }
}

/// The exact reader leaves no reading a leak can pass: each output either does
/// not read back onto the input, or the one reading it has leaves at least one
/// recorded byte in the clear.
#[test]
fn the_exact_reader_rejects_every_leak_the_old_reader_passed() {
    let mut passed = Vec::new();
    for leak in leaks().into_iter().chain(rejected()) {
        let minted = minted(leak.minted);
        let ranges = exact_ranges(leak.mode, leak.input, leak.output, &minted);
        let hidden = ranges
            .as_ref()
            .is_some_and(|ranges| leak.hidden.iter().all(|&(s, e)| covered(ranges, s, e)));
        assert!(
            !hidden,
            "{}: {:?} reads back as {:?} and still calls {:?} masked",
            leak.what, leak, ranges, leak.hidden
        );
        passed.push((leak.what, ranges.is_some()));
    }
    assert_eq!(
        passed.iter().filter(|(_, reads_back)| !reads_back).count(),
        passed.len(),
        "every output here must fail to read back: {passed:?}"
    );
}

/// The other half of the fix: main's reader really did pass these outputs. Kept
/// as a test, not a comment, so the hole cannot be reintroduced unnoticed — if
/// main's reader ever stops accepting a leak, this fails and says which one.
#[test]
fn the_old_reader_passed_every_leak() {
    for leak in leaks() {
        let greedy_hidden = leak
            .hidden
            .iter()
            .all(|&(s, e)| covered(&greedy(leak.input, leak.output), s, e));
        let any_reading = fits(leak.input, leak.output, leak.hidden);
        assert!(
            greedy_hidden || any_reading,
            "{}: {:?} — main's reader now rejects it, drop the case",
            leak.what,
            leak
        );
        eprintln!(
            "{}: greedy {}, any-reading {}",
            leak.what,
            if greedy_hidden { "pass" } else { "fail" },
            if any_reading { "pass" } else { "fail" }
        );
    }
}

/// The exact reader reads an honest output the old one also read: the ranges
/// are the gate's own, byte for byte, in both modes of the same text.
#[test]
fn an_exact_output_still_reads_exactly() {
    let (input, minted) = (
        "IBAN FR76 3000 6000 0112 3456 7890 189 and FR76 3000 6000 0112 3456 7890 189.",
        vec![(
            "IBAN_0123456789AB".to_string(),
            "FR76 3000 6000 0112 3456 7890 189".to_string(),
        )],
    );
    let output = "IBAN ⟦IBAN_0123456789AB⟧ and ⟦IBAN_0123456789AB⟧.";
    let ranges = exact_ranges(PrivacyMode::Private, input, output, &minted)
        .expect("the gate's own output reads back");
    assert_eq!(ranges, vec![(5, 38), (43, 76)]);
    assert_eq!(greedy(input, output), ranges);
}

/// The same text in Open mode: one fixed marker per removed range, and the
/// reader takes only that marker's own class for the range it stands in.
#[test]
fn an_exact_open_output_still_reads_exactly() {
    let input = "MRN 4412 and MRN 4412 end";
    let output = "MRN [health removed] and MRN [health removed] end";
    let ranges = exact_ranges(PrivacyMode::Open, input, output, &[])
        .expect("the gate's own Open output reads back");
    assert_eq!(ranges, vec![(4, 8), (17, 21)]);
}

/// One case per source [`exact_ranges`] can use, so none of them rots: the
/// minted surface, the detector span for a second spelling, and a token the
/// gate minted nothing for. All three are the gate's own outputs; the token
/// names are invented so the cases do not depend on a digest.
#[test]
fn every_source_of_a_token_reads_back() {
    // Source 2: one phone token over two spellings. `normalize_value` keys a
    // phone on its digits, so `+33 6 12 34 56 78` and `+33612345678` share one
    // token and `take_minted` keeps only the first surface — the second one has
    // no minted surface at the cursor, so the detector's own phone span is what
    // stands there.
    let (input, minted) = (
        "call +33 6 12 34 56 78 and +33612345678.",
        vec![(
            "PHONE_0123456789AB".to_string(),
            "+33 6 12 34 56 78".to_string(),
        )],
    );
    let output = "call ⟦PHONE_0123456789AB⟧ and ⟦PHONE_0123456789AB⟧.";
    assert_eq!(
        exact_ranges(PrivacyMode::Private, input, output, &minted),
        Some(vec![(5, 22), (27, 39)]),
        "the detector span of the second spelling"
    );

    // Source 3: the text the gate leaves clear holds its own `⟦x⟧`, with the
    // opener doubled by the gate's escaping and the closer untouched. The token
    // over the value is read from the minted surface; the literal marker text is
    // clear on both sides, so no byte of it may be claimed.
    let input = "aa ⟦x⟧ bb MRN 4412 cc";
    let output = "aa ⟦⟦x⟧ bb MRN ⟦HEALTH_a⟧ cc";
    let minted = vec![("HEALTH_a".to_string(), "4412".to_string())];
    let ranges = exact_ranges(PrivacyMode::Private, input, output, &minted)
        .expect("an escaped literal marker and a token over the value read back");
    let at = input.find("4412").unwrap();
    assert!(covered(&ranges, at, at + 4), "{ranges:?}");
    let marker = input.find('⟦').unwrap();
    assert!(
        !covered(&ranges, marker, marker + '⟦'.len_utf8()),
        "the literal marker text is clear, not masked: {ranges:?}"
    );
}

/// The span a token of a class can cover is that class's own whole-span cap: a
/// secret stays one token up to `MAX_KEY_SPAN_BYTES`, every other kind splits at
/// `MAX_SPAN_BYTES`. Filtering on the smaller cap dropped a secret of 129–512
/// bytes, so a long secret with a second spelling had no exact reading at all.
///
/// The gate mints one token per exact surface for a secret, so this is the
/// reader's model of `Anonymizer::restore` — a token shared by two spellings —
/// rather than a shape it writes today. What it pins is the candidate rule: a
/// detector span the gate could hand to one token must never be filtered out.
#[test]
fn a_secret_span_of_129_to_512_bytes_is_still_a_candidate() {
    let long = format!("glpat-{}", "AbCdEf0123456789".repeat(13));
    let spelled = long.replacen("AbCdEf01", "AbCdEf0\u{A0}1", 1);
    let (input, minted) = (
        format!("key {long} and {spelled} end"),
        vec![("SECRET_0123456789AB".to_string(), long.clone())],
    );
    let output = "key ⟦SECRET_0123456789AB⟧ and ⟦SECRET_0123456789AB⟧ end";
    assert!(
        long.len() > 128 && long.len() <= 512,
        "the case must sit in the 129-512 byte band, got {}",
        long.len()
    );
    let ranges = exact_ranges(PrivacyMode::Private, &input, output, &minted)
        .expect("a secret the gate keeps whole is a candidate");
    let second = 4 + long.len() + " and ".len();
    assert_eq!(
        ranges,
        vec![(4, 4 + long.len()), (second, second + spelled.len())]
    );
}
