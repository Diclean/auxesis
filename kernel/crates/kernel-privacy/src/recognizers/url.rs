//! URL recogniser: scheme plus a structurally validated dotted host.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// A structurally valid URL scores 0.6; a nearby cue word raises it.
pub const SCORE: f32 = 0.6;

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s<>"')]+"#).expect("url regex compiles")
});

/// Finds URLs with a scheme and a plausible host.
#[derive(Clone, Copy, Debug, Default)]
pub struct UrlRecognizer;

impl UrlRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for UrlRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Url]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        URL_RE
            .find_iter(text)
            .filter_map(|found| {
                let trimmed = trim_trailing_punctuation(text, found.start(), found.end());
                let value = &text[trimmed.0..trimmed.1];
                if valid_url(value) {
                    Some(Span::new(
                        EntityKind::Url,
                        trimmed.0,
                        trimmed.1,
                        SCORE,
                        "url",
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "url"
    }
}

fn trim_trailing_punctuation(text: &str, start: usize, mut end: usize) -> (usize, usize) {
    while end > start {
        let Some(last) = text[start..end].chars().next_back() else {
            break;
        };
        if matches!(last, '.' | ',' | ';' | ':' | '!' | '?') {
            end -= last.len_utf8();
            continue;
        }
        break;
    }
    (start, end)
}

/// Whether a candidate URL has a scheme and a valid host.
pub(crate) fn valid_url(value: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let scheme = &value[..scheme_end];
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ftp"
    ) {
        return false;
    }
    let rest = &value[scheme_end + 3..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return false;
    }
    // Strip userinfo, then validate the host.
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if let Some(stripped) = host_port.strip_prefix('[') {
        let Some(close) = stripped.find(']') else {
            return false;
        };
        return stripped[..close].parse::<Ipv6Addr>().is_ok();
    }
    let host = host_port.split(':').next().unwrap_or("");
    if host.is_empty() {
        return false;
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    if !host.contains('.') || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return false;
        }
    }
    let tld = labels.last().copied().unwrap_or("");
    tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        UrlRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn accepts_valid_urls() {
        assert_eq!(
            hits("voir https://example.com/page?q=1"),
            vec!["https://example.com/page?q=1"]
        );
        assert_eq!(
            hits("http://sub.example.co.uk"),
            vec!["http://sub.example.co.uk"]
        );
        assert_eq!(
            hits("ftp://files.example.org/x"),
            vec!["ftp://files.example.org/x"]
        );
        assert_eq!(
            hits("http://192.168.0.1/admin"),
            vec!["http://192.168.0.1/admin"]
        );
    }

    #[test]
    fn trims_sentence_punctuation() {
        assert_eq!(
            hits("lien https://example.com."),
            vec!["https://example.com"]
        );
        assert_eq!(
            hits("(https://example.com/a)"),
            vec!["https://example.com/a"]
        );
    }

    #[test]
    fn rejects_bare_hosts_and_bad_hosts() {
        assert!(hits("example.com").is_empty());
        assert!(hits("http://localhost/x").is_empty());
        assert!(hits("http://-bad.example.com").is_empty());
        assert!(hits("htp://example.com").is_empty());
    }

    #[test]
    fn validity_vectors() {
        assert!(valid_url("https://example.com"));
        assert!(valid_url("https://user:pass@example.com:8443/x"));
        assert!(valid_url("http://[::1]:8080/x"));
        assert!(!valid_url("https://example"));
        assert!(!valid_url("https://.com"));
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = UrlRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::Url]);
        assert_eq!(recognizer.name(), "url");
        assert!(recognizer.verified());
    }
}
