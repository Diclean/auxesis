//! IPv4 recogniser built on `std::net`, so no custom range arithmetic.

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// A parsed address is certain, so it scores 1.0.
pub const SCORE: f32 = 1.0;

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("ipv4 regex compiles")
});

/// Finds IPv4 addresses. IPv6 is intentionally out of slice 1b.
#[derive(Clone, Copy, Debug, Default)]
pub struct IpV4Recognizer;

impl IpV4Recognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for IpV4Recognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::IpV4]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        // Fullwidth letters and digits are folded before the scan.
        let normalized = NormalizedText::new(text, false);
        let body = normalized.text();
        IPV4_RE
            .find_iter(body)
            .filter(|found| !part_of_dotted_run(body, found.start(), found.end()))
            .filter(|found| !version_context(body, found.start()))
            .filter(|found| found.as_str().parse::<Ipv4Addr>().is_ok())
            .filter_map(|found| {
                normalized
                    .to_original(found.start(), found.end())
                    .map(|(start, end)| Span::new(EntityKind::IpV4, start, end, SCORE, "ipv4"))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "ipv4"
    }
}

/// Whether an adjacent `.` continues the dotted run, so `1.2.3.4.5` is rejected.
///
/// A trailing sentence period is not part of a run: `192.168.0.1.` still masks
/// (P2-5) because the dot is not followed by a digit, while `.5` after the
/// address is.
fn part_of_dotted_run(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    let before_dot_digit = before == Some('.')
        && text[..start]
            .chars()
            .rev()
            .nth(1)
            .is_some_and(|ch| ch.is_ascii_digit());
    let after_dot_digit = after == Some('.')
        && text[end..]
            .chars()
            .nth(1)
            .is_some_and(|ch| ch.is_ascii_digit());
    before_dot_digit || after_dot_digit
}

/// Whether the token immediately before the address marks a version string, so
/// `build 1.2.3.4`, `version 10.12.0.1`, `release v 10.12.0.1` are not read as
/// IP addresses, while `app 10.0.0.5` is (P3-3). Only the nearest token counts,
/// and its length is capped so a very long run before an address stays linear.
fn version_context(text: &str, start: usize) -> bool {
    let before = text[..start].trim_end_matches(char::is_whitespace);
    let Some(token) = before.rsplit(|ch: char| !ch.is_alphanumeric()).next() else {
        return false;
    };
    if token.len() > 16 {
        return false;
    }
    matches!(
        token.to_ascii_lowercase().as_str(),
        "version" | "v" | "build" | "release"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        IpV4Recognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn accepts_valid_addresses() {
        assert_eq!(hits("host 192.168.0.1 up"), vec!["192.168.0.1"]);
        assert_eq!(hits("8.8.8.8"), vec!["8.8.8.8"]);
        assert_eq!(hits("0.0.0.0"), vec!["0.0.0.0"]);
    }

    #[test]
    fn rejects_out_of_range_and_partial_runs() {
        assert!(hits("999.1.1.1").is_empty());
        assert!(hits("1.2.3").is_empty());
        assert!(hits("1.2.3.4.5").is_empty());
        assert!(hits("version 1.2.3.4.5").is_empty());
    }

    #[test]
    fn rejects_version_strings() {
        assert!(hits("build 1.2.3.4").is_empty());
        assert!(hits("version 10.12.0.1").is_empty());
        assert!(hits("release v 10.12.0.1").is_empty());
        // `app` is not a version cue: an app address must be masked (P3-3).
        assert_eq!(hits("app 10.0.0.5"), vec!["10.0.0.5"]);
    }

    #[test]
    fn masks_an_address_before_a_sentence_period() {
        assert_eq!(hits("host 192.168.0.1."), vec!["192.168.0.1"]);
        assert!(hits("1.2.3.4.5").is_empty());
        assert!(hits("192.168.0.1.5").is_empty());
    }

    #[test]
    fn fullwidth_address_is_folded() {
        assert_eq!(
            hits("ｈｏｓｔ １９２.１６８.０.１"),
            vec!["１９２.１６８.０.１"]
        );
    }

    #[test]
    fn does_not_match_inside_a_longer_number() {
        assert!(hits("x1.2.3.4").is_empty());
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = IpV4Recognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::IpV4]);
        assert_eq!(recognizer.name(), "ipv4");
        assert!(recognizer.verified());
    }
}
