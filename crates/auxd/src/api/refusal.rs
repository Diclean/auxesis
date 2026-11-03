//! A typed refusal while an approval card waits (CANCEL-AT-CARD).
//!
//! Only a bare refusal counts: every word is a refusal, a filler ("that",
//! "it") or the action it forbids ("send"). A named object, a bare "wait"
//! and "yes" never touch the card; "wait no" does (CARD-NEVER-BLOCKS). The
//! check fails closed: a false positive can only withdraw a card, never
//! approve one.

const MAX_WORDS: usize = 6;

#[rustfmt::skip]
const REFUSAL: &[&str] = &[
    "no", "non", "nope", "nah", "nan", "nvm", "not", "pas", "stop", "cancel", "cancelled",
    "canceled", "annule", "annuler", "annulez", "laisse", "tomber", "arrete", "arreter",
    "oublie", "oublier", "abandonne", "abandonner", "dont", "don", "never", "nevermind",
    "forget", "scratch", "refuse", "refuser", "halte",
];

#[rustfmt::skip]
const FILLER: &[&str] = &[
    "that", "it", "this", "the", "a", "an", "please", "pls", "plz", "stp", "svp", "merci",
    "thanks", "thank", "you", "ok", "okay", "bon", "ben", "en", "fait", "actually", "really",
    "just", "now", "maintenant", "tout", "de", "du", "des", "le", "la", "les", "l", "un",
    "une", "ce", "cette", "ca", "so", "and", "then", "well", "mind", "ne", "n", "t", "s",
    "c", "j", "d", "qu", "il", "te", "plait", "fais", "do", "go", "wait", "attends",
    "hold", "on",
];

#[rustfmt::skip]
const ACTION: &[&str] = &[
    "send", "sending", "envoyer", "envoie", "mail", "email", "call", "appeler", "book",
    "reserver", "pay", "payer", "delete", "supprimer", "post", "publier", "write", "ecrire",
    "run", "execute", "continue", "continuer", "move", "deplacer", "reply", "repondre",
    "share", "partager", "invite", "buy",
];

/// Lowercase (full Unicode) then accent-folded words; an apostrophe
/// separates them.
fn normalize(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    for character in text.chars().flat_map(char::to_lowercase) {
        let character = match character {
            '\'' | '\u{2019}' | '\u{2018}' | '\u{02bc}' => ' ',
            'à' | 'â' | 'ä' | 'á' | 'ã' | 'å' => 'a',
            'ç' => 'c',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' | 'í' | 'ì' => 'i',
            'ô' | 'ö' | 'ó' | 'ò' | 'õ' => 'o',
            'ù' | 'û' | 'ü' | 'ú' => 'u',
            'ÿ' => 'y',
            'ñ' => 'n',
            other => other,
        };
        #[rustfmt::skip]
        normalized.push(if character.is_alphanumeric() { character } else { ' ' });
    }
    normalized
}

/// True when `text` is a short, bare refusal of the waiting card.
pub(crate) fn is_bare_refusal(text: &str) -> bool {
    let normalized = normalize(text);
    let words: Vec<&str> = normalized.split_whitespace().collect();
    if words.is_empty() || words.len() > MAX_WORDS {
        return false;
    }
    let mut refused = false;
    for word in words {
        if REFUSAL.contains(&word) {
            refused = true;
        } else if !FILLER.contains(&word) && !ACTION.contains(&word) {
            return false;
        }
    }
    refused
}

#[cfg(test)]
mod tests {
    use super::is_bare_refusal;

    #[test]
    fn an_owner_retraction_is_a_refusal_and_an_assent_never_is() {
        for text in [
            "wait no",
            "no wait",
            "Wait, no!",
            "never mind",
            "forget it",
            "non attends",
            "attends non",
            "oublie",
            "oublie ça",
            "hold on, cancel that",
        ] {
            assert!(is_bare_refusal(text), "{text}");
        }
        for text in [
            "wait",
            "attends",
            "yes",
            "ok",
            "send it",
            "wait, send it",
            "hold on",
            "what's on fri",
            "no wait, move it to 5pm",
        ] {
            assert!(!is_bare_refusal(text), "{text}");
        }
    }
}
