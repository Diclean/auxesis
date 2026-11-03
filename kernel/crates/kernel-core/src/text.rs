//! Shared text hygiene: sanitising untrusted text, one-line cleaning, and
//! character-budgeted truncation.
//!
//! Tool output, provider errors, model text and store rows are all *external*
//! input: they can contain ANSI escapes, bidi overrides and zero-width
//! characters that spoof what a human or model sees, and they can be
//! arbitrarily large. These primitives are the single implementation used by
//! `kernel-broker`, the daemon API, the CLI and the UI.

/// Noncharacters: reserved code points that never render (U+FDD0-FDEF and
/// the last two points of every plane).
fn is_noncharacter(c: char) -> bool {
    if matches!(c, '\u{FDD0}'..='\u{FDEF}') {
        return true;
    }
    let cp = c as u32;
    cp >= 0xFFFE && (cp & 0xFFFE) == 0xFFFE
}

/// Characters that are invisible, format-only, or terminal control, and can
/// be used to spoof what a human or model sees.
fn is_invisible(c: char) -> bool {
    c.is_control()
        || is_noncharacter(c)
        || matches!(
            c,
            '\u{00A0}' // no-break space
            | '\u{00AD}' // soft hyphen
            | '\u{034F}' // combining grapheme joiner
            | '\u{0600}'..='\u{0605}' // Arabic number signs
            | '\u{061C}' // Arabic letter mark
            | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}' | '\u{08E2}'
            | '\u{115F}'..='\u{1160}' // Hangul fillers
            | '\u{1680}' // Ogham space mark
            | '\u{17B4}'..='\u{17B5}' // Khmer inherent vowels
            | '\u{180B}'..='\u{180F}' // Mongolian selectors + vowel separator
            | '\u{2000}'..='\u{200F}' // exotic spaces + zero-width joiners/bidi
            | '\u{2028}'..='\u{202E}' // line/paragraph separators + bidi overrides
            | '\u{202F}' | '\u{205F}' // narrow/no-break spaces
            | '\u{2060}'..='\u{206F}' // word joiner, invisible operators, bidi isolates
            | '\u{2800}' // blank braille pattern
            | '\u{3000}' // ideographic space
            | '\u{3164}' // Hangul filler
            | '\u{FE00}'..='\u{FE0F}' // variation selectors
            | '\u{FEFF}' // BOM / zero-width no-break space
            | '\u{FFA0}' // halfwidth Hangul filler
            | '\u{FFF0}'..='\u{FFF8}' // unassigned/DI
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotations
            | '\u{110BD}' | '\u{110CD}' // Kaithi number signs
            | '\u{13430}'..='\u{1343F}' // Egyptian format controls
            | '\u{1BCA0}'..='\u{1BCA3}' // shorthand format controls
            | '\u{1D173}'..='\u{1D17A}' // musical format controls
            | '\u{E0000}'..='\u{E0FFF}' // tags, VS supplement, DI reserved
        )
}

/// Strip control and invisible characters, keeping only `\n` and `\t`.
pub fn sanitize_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| !is_invisible(*c) || *c == '\n' || *c == '\t')
        .collect()
}

/// The bidi *isolate* controls U+2066–U+2069. Unlike the embedding/override
/// controls around them, isolates wrap a run instead of overriding the whole
/// rest of the line, so they are legitimate mixed-direction content.
fn is_bidi_isolate(c: char) -> bool {
    matches!(c, '\u{2066}'..='\u{2069}')
}

/// Like [`sanitize_text`], but keeps the four bidi isolate controls
/// (U+2066–U+2069) while still dropping every other control/invisible
/// character. Used by the scrub preview path so text that hides no secret
/// keeps those codepoints byte-for-byte (dh-1 fidelity note).
pub fn sanitize_text_keep_bidi_isolates(input: &str) -> String {
    input
        .chars()
        .filter(|c| !is_invisible(*c) || *c == '\n' || *c == '\t' || is_bidi_isolate(*c))
        .collect()
}

/// Sanitize external text and collapse it to one line.
///
/// The canonical `clean_field` every transport (daemon, CLI, app) shares; two
/// copies of a security-relevant sanitiser can drift, one cannot.
pub fn clean_field(raw: &str) -> String {
    sanitize_text(raw)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Cap by characters (never splits UTF-8) and mark the cut.
///
/// `max == 0` yields just the truncation marker; `max == 1` yields `…`.
pub fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_and_invisible_characters() {
        let raw = "safe\u{1b}[31mred\u{0}\u{202e}reversed\u{200b}\u{feff}end";
        let clean = sanitize_text(raw);
        assert!(!clean.contains('\u{1b}'));
        assert!(!clean.contains('\u{202e}'));
        assert!(!clean.contains('\u{200b}'));
        assert!(!clean.contains('\u{feff}'));
        assert_eq!(clean, "safe[31mredreversedend");
    }

    #[test]
    fn strips_extended_invisible_set() {
        let raw = "a\u{00A0}b\u{034F}c\u{0600}d\u{061C}e\u{115F}f\u{1680}g\u{180E}h\u{2003}i\u{2060}j\u{2800}k\u{3000}l\u{3164}m\u{FE0F}n\u{FDD0}o\u{FFA0}p\u{FFF1}q\u{13430}r\u{1BCA0}s\u{1D173}t\u{E0041}u\u{E0090}v\u{E0100}w";
        let clean = sanitize_text(raw);
        assert_eq!(clean, "abcdefghijklmnopqrstuvw");
    }

    #[test]
    fn strips_noncharacters_and_di_reserved() {
        let raw = "a\u{FDD0}b\u{FDEF}c\u{FFFF}d\u{1FFFE}e\u{10FFFF}f\u{E01F0}g\u{E0F00}h";
        let clean = sanitize_text(raw);
        assert_eq!(clean, "abcdefgh");
    }

    #[test]
    fn keeps_newlines_and_tabs() {
        assert_eq!(sanitize_text("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn keeps_bidi_isolates_and_strips_the_other_invisibles() {
        let raw = "a\u{2066}b\u{2067}c\u{2068}d\u{2069}e\u{202e}f\u{200b}g\u{1b}h";
        assert_eq!(
            sanitize_text_keep_bidi_isolates(raw),
            "a\u{2066}b\u{2067}c\u{2068}d\u{2069}efgh"
        );
        // The plain sanitizer still drops the isolates (terminal path).
        assert_eq!(sanitize_text("a\u{2066}b\u{2069}c"), "abc");
    }

    #[test]
    fn strips_carriage_returns() {
        assert_eq!(sanitize_text("a\r\nb"), "a\nb");
    }

    #[test]
    fn clean_field_collapses_to_one_sanitized_line() {
        let raw = "  two\nlines\u{200b}\tand   spaces\u{1b}[0m  ";
        assert_eq!(clean_field(raw), "two lines and spaces[0m");
        assert_eq!(clean_field("   "), "");
    }

    #[test]
    fn truncate_chars_never_splits_and_marks_the_cut() {
        assert_eq!(truncate_chars("short", 10), "short");
        assert_eq!(truncate_chars("abcdef", 4), "abc…");
        assert_eq!(truncate_chars("éééé", 2), "é…");
        assert_eq!(truncate_chars("abcdef", 0), "…");
    }

    #[test]
    fn every_named_invisible_codepoint_is_stripped() {
        for cp in 0u32..=0x10FFFF {
            if let Some(c) = char::from_u32(cp) {
                if is_invisible(c) && c != '\n' && c != '\t' {
                    assert!(
                        sanitize_text(&c.to_string()).is_empty(),
                        "U+{cp:04X} survived sanitize_text"
                    );
                }
            }
        }
    }

    #[test]
    fn sanitizes_a_megabyte_within_budget() {
        let raw = "abc\u{200B}def\n".repeat(100_000); // ~1 MB
        let started = std::time::Instant::now();
        let clean = sanitize_text(&raw);
        let elapsed = started.elapsed();
        assert!(!clean.contains('\u{200B}'));
        assert!(
            elapsed.as_millis() < 2_000,
            "sanitizing ~1 MB took {elapsed:?}"
        );
    }

    #[test]
    fn injection_corpus_files_are_sanitized() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../qa/attacks/prompt-injection");
        // The attack corpus is private and left out of the public export;
        // a tree without it skips this test (the private tree always has it).
        if !dir.exists() {
            eprintln!("skipped: no attack corpus at {}", dir.display());
            return;
        }
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("corpus dir {}: {err}", dir.display()));
        let mut checked = 0;
        for entry in entries {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("txt") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap();
            let clean = sanitize_text(&raw);
            assert!(
                !clean
                    .chars()
                    .any(|c| is_invisible(c) && c != '\n' && c != '\t'),
                "{} still contains invisible characters",
                path.display()
            );
            checked += 1;
        }
        assert!(
            checked >= 5,
            "expected seeded corpus files, found {checked}"
        );
    }
}
