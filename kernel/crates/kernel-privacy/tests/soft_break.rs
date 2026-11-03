//! Quoted-printable soft-break regression tests (PR #170, round 8). A value a
//! mail client wrapped with `=` plus a line break is one value: it is masked
//! whole, the break included, and no part of it survives. Fake data only.

use kernel_privacy::{Anonymizer, Registry};

/// Mask `text` and assert the span covering `value` is found and that the output
/// is the text around `value` with `value` replaced by exactly one placeholder.
fn assert_masked_whole(text: &str, value: &str) {
    let registry = Registry::new();
    let spans = registry.analyze(text);
    assert!(
        spans
            .iter()
            .any(|span| &text[span.start..span.end] == value),
        "no span is {value:?} in {text:?}: {spans:?}"
    );
    let mut anonymizer = Anonymizer::new([0x7Eu8; 32]);
    let (masked, _) = anonymizer.anonymize(text, &spans);
    let start = text.find(value).expect("value is in the text");
    let (prefix, suffix) = (&text[..start], &text[start + value.len()..]);
    let placeholder = masked
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .unwrap_or_else(|| panic!("residue around {value:?} in {text:?}: {masked:?}"));
    assert!(
        placeholder.starts_with('\u{27E6}')
            && placeholder.ends_with('\u{27E7}')
            && placeholder.matches('\u{27E6}').count() == 1,
        "{value:?} is not one placeholder in {text:?}: {masked:?}"
    );
}

#[test]
fn soft_wrapped_email_is_masked_whole() {
    for text in [
        "name=\r\n@example.invalid",
        "name=\n@example.invalid",
        "name=\r@example.invalid",
        "na=\r\nme@example.invalid",
        "name=  \r\n@example.invalid",
    ] {
        assert_masked_whole(text, text);
    }
}

#[test]
fn soft_wrapped_phone_is_masked_whole() {
    // FAKE: a number in the 555 fiction range, wrapped mid-group.
    assert_masked_whole("+1 (202) 555=\r\n-0142", "+1 (202) 555=\r\n-0142");
    // FAKE: a French mobile in the 06 range, wrapped mid-group.
    assert_masked_whole("+33 6 12 3=\r\n4 56 78", "+33 6 12 3=\r\n4 56 78");
}

#[test]
fn soft_wrapped_iban_is_masked_whole() {
    // FAKE: the checksum-valid specimen FR IBAN, wrapped before its last group.
    let text = "FR76 3000 6000 0112 3456 7890 1=\r\n89";
    assert_masked_whole(text, text);
}

#[test]
fn soft_wrapped_nir_is_masked_whole() {
    // FAKE: a NIR wrapped after the commune digits, contiguous and spaced.
    let contiguous = "184030099900=\r\n123";
    assert_masked_whole(&format!("NIR {contiguous} fin"), contiguous);
    let spaced = "1 84 03 00 99=\r\n9 001 23";
    assert_masked_whole(&format!("NIR {spaced} fin"), spaced);
}

#[test]
fn plain_equals_signs_are_left_alone() {
    let registry = Registry::new();
    for text in ["a=b", "x = 1", "id=123"] {
        let mut anonymizer = Anonymizer::new([0x7Eu8; 32]);
        let spans = registry.analyze(text);
        let (masked, _) = anonymizer.anonymize(text, &spans);
        assert_eq!(masked, text, "{text:?} changed");
    }
}

#[test]
fn soft_break_edges_never_panic() {
    // The char-boundary and end-of-text edges of the soft-break removal. The
    // exact normalised views are pinned in `normalize.rs`; here the whole
    // pipeline must scan and mask them without a panic.
    let registry = Registry::new();
    for text in [
        "=",
        "name=",
        "name=\r",
        "=\r\n",
        "=  ",
        "caf=C3=\r\n=A9 ok",
        "café=\r\n@example.invalid",
        "é=\r\né=\n",
        "a=\u{00A0}\r\nb",
    ] {
        let spans = registry.analyze(text);
        let mut anonymizer = Anonymizer::new([0x7Eu8; 32]);
        let _ = anonymizer.anonymize(text, &spans);
    }
}
