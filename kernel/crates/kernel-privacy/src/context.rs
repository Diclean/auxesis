//! Context-word score enhancer, ported from Presidio's `LemmaContextAwareEnhancer`.
//!
//! A recogniser's base score can be low when the value alone is ambiguous (a
//! bare card number, a national phone number). A cue word in a short window
//! *before* the span raises the score, which is how Presidio's low-base-score
//! recognisers stay useful. The window is measured backwards from the span in
//! characters, so it is UTF-8 safe.

use crate::span::{EntityKind, Span};

/// Default number of characters inspected before a span.
pub const DEFAULT_WINDOW: usize = 40;
/// Default score added when a cue is present.
pub const DEFAULT_BOOST: f32 = 0.35;

/// Raises a span's score when a per-kind cue word appears just before it.
#[derive(Clone, Debug)]
pub struct ContextEnhancer {
    window: usize,
    boost: f32,
    cues: Vec<(EntityKind, &'static [&'static str])>,
}

impl ContextEnhancer {
    /// The enhancer with the built-in FR/EN/AF/HU cue lists.
    pub fn new() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            boost: DEFAULT_BOOST,
            cues: default_cues(),
        }
    }

    /// Override the look-back window (in characters).
    pub fn with_window(mut self, window: usize) -> Self {
        self.window = window;
        self
    }

    /// Override the score boost.
    pub fn with_boost(mut self, boost: f32) -> Self {
        self.boost = boost;
        self
    }

    /// Replace the cue list for one kind.
    pub fn with_cues(mut self, kind: EntityKind, cues: &'static [&'static str]) -> Self {
        self.cues.retain(|(existing, _)| *existing != kind);
        self.cues.push((kind, cues));
        self
    }

    /// The cue lists currently installed.
    pub fn cues(&self) -> &[(EntityKind, &'static [&'static str])] {
        &self.cues
    }

    /// Boost `span` in place when a cue for its kind precedes it.
    pub fn enhance(&self, text: &str, span: &mut Span) {
        if span.start > text.len() || !text.is_char_boundary(span.start) {
            return;
        }
        let window = self.window_before(text, span.start);
        if window.is_empty() {
            return;
        }
        let lowered = window.to_lowercase();
        let Some((_, cues)) = self.cues.iter().find(|(kind, _)| *kind == span.kind) else {
            return;
        };
        if cues
            .iter()
            .any(|cue| contains_cue(&lowered, &cue.to_lowercase()))
        {
            span.score = (span.score + self.boost).min(1.0);
        }
    }

    fn window_before<'a>(&self, text: &'a str, start: usize) -> &'a str {
        let before = &text[..start];
        if self.window == 0 {
            return "";
        }
        let window_start = before
            .char_indices()
            .rev()
            .nth(self.window)
            .map(|(index, _)| index)
            .unwrap_or(0);
        &before[window_start..]
    }
}

impl Default for ContextEnhancer {
    fn default() -> Self {
        Self::new()
    }
}

/// Find `cue` in `haystack` at a token start (the preceding character is not
/// alphanumeric), so `phone` does not fire inside `telephone` while `tél`
/// still fires inside `téléphone`.
fn contains_cue(haystack: &str, cue: &str) -> bool {
    if cue.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(offset) = haystack[from..].find(cue) {
        let absolute = from + offset;
        let at_token_start = haystack[..absolute]
            .chars()
            .next_back()
            .is_none_or(|ch| !ch.is_alphanumeric());
        if at_token_start {
            return true;
        }
        from = absolute + cue.len();
        if from >= haystack.len() {
            break;
        }
    }
    false
}

fn default_cues() -> Vec<(EntityKind, &'static [&'static str])> {
    vec![
        (
            EntityKind::Email,
            &["email", "e-mail", "mail", "courriel", "adresse"],
        ),
        (
            EntityKind::Phone,
            &[
                "tél",
                "tel",
                "téléphone",
                "phone",
                "telefoon",
                "telefonszám",
                "mobile",
                "portable",
                "gsm",
                "cell",
                "call",
                "numéro",
            ],
        ),
        (
            EntityKind::Iban,
            &["iban", "rib", "account", "compte", "bankszámla", "bank"],
        ),
        (
            EntityKind::CreditCard,
            &[
                "carte",
                "card",
                "credit",
                "visa",
                "mastercard",
                "cb",
                "kártya",
            ],
        ),
        (EntityKind::Url, &["url", "lien", "link", "site", "web"]),
        (
            EntityKind::FrNir,
            &["nir", "sécurité sociale", "social security", "secu"],
        ),
        (EntityKind::FrSiren, &["siren", "entreprise", "company"]),
        (
            EntityKind::FrSiret,
            &["siret", "établissement", "etablissement"],
        ),
        (EntityKind::FrVat, &["tva", "vat", "áfa"]),
        (EntityKind::HuTaj, &["taj", "társadalombiztosítási"]),
        (EntityKind::HuTaxId, &["adóazonosító", "adószám", "tax"]),
        (EntityKind::ZaId, &["id", "identity", "south african id"]),
        (
            EntityKind::PassportMrz,
            &["passeport", "passport", "útlevél"],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(kind: EntityKind, start: usize, end: usize) -> Span {
        Span::new(kind, start, end, 0.5, "test")
    }

    #[test]
    fn cue_raises_score_and_no_cue_leaves_it() {
        let enhancer = ContextEnhancer::new();
        let text = "appelez le tél 06 12 34 56 78";
        let start = text.find("06").unwrap();
        let mut boosted = span(EntityKind::Phone, start, text.len());
        enhancer.enhance(text, &mut boosted);
        assert!(boosted.score > 0.5);

        let mut plain = span(EntityKind::Phone, start, text.len());
        enhance_without_cue(&enhancer, "valeur 06 12 34 56 78", &mut plain);
        assert_eq!(plain.score, 0.5);
    }

    fn enhance_without_cue(enhancer: &ContextEnhancer, text: &str, span: &mut Span) {
        let start = text.find("06").unwrap();
        span.start = start;
        span.end = text.len();
        enhancer.enhance(text, span);
    }

    #[test]
    fn cue_does_not_fire_inside_a_word() {
        let enhancer = ContextEnhancer::new().with_cues(EntityKind::Phone, &["phone"]);
        // "telephone" contains "phone" but not at a token start.
        let text = "mon telephone 06 12 34 56 78";
        let start = text.find("06").unwrap();
        let mut value = span(EntityKind::Phone, start, text.len());
        enhancer.enhance(text, &mut value);
        assert_eq!(value.score, 0.5);
    }

    #[test]
    fn accented_cue_is_found() {
        let enhancer = ContextEnhancer::new();
        let text = "téléphone : 06 12 34 56 78";
        let start = text.find("06").unwrap();
        let mut value = span(EntityKind::Phone, start, text.len());
        enhancer.enhance(text, &mut value);
        assert!(value.score > 0.5);
    }

    #[test]
    fn window_is_char_safe_at_the_edge() {
        let enhancer = ContextEnhancer::new().with_window(3);
        let text = "tél 06";
        let start = text.find("06").unwrap();
        let mut value = span(EntityKind::Phone, start, text.len());
        enhancer.enhance(text, &mut value);
        assert!(value.score > 0.5);
    }
}
