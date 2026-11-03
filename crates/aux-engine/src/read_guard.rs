//! CAL-NO-TOOL-GUESS: an agent never states a calendar, mail, client or
//! reminder fact it did not read with a tool in the same turn.
//!
//! A question about a domain whose read tools (or `delegate`) the session
//! offers, answered with no tool call, is retried once with a nudge; a second
//! such answer that states a fact becomes a fixed honest line. Detection needs
//! a domain word, a question, and the owner's data (EN + FR); a greeting, a
//! "thanks" or a how-to question never triggers it.

use kernel_core::Lang;

/// The data domains the guard covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Domain {
    Calendar,
    Mail,
    Clients,
    Reminders,
}

const ALL: [Domain; 4] = [
    Domain::Calendar,
    Domain::Mail,
    Domain::Clients,
    Domain::Reminders,
];

/// The one system nudge of the retry round. Static text: nothing from the
/// owner or a tool is in it.
pub(crate) const NUDGE: &str = "Check with your tools before answering; never guess counts, \
dates or names. Earlier answers in this conversation may be out of date: read again.";

impl Domain {
    /// Value-free label for receipts.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Domain::Calendar => "calendar",
            Domain::Mail => "mail",
            Domain::Clients => "clients",
            Domain::Reminders => "reminders",
        }
    }

    /// The answer when the agent still did not check.
    pub(crate) fn honest_line(self, lang: Lang) -> String {
        let (en, fr) = match self {
            Domain::Calendar => ("calendar", "votre agenda"),
            Domain::Mail => ("mail", "vos mails"),
            Domain::Clients => ("client records", "vos fiches clients"),
            Domain::Reminders => ("reminders", "vos rappels"),
        };
        match lang {
            Lang::En => format!("I didn't check your {en}, so I can't say."),
            Lang::Fr => format!("Je n'ai pas vérifié {fr}, je ne peux donc pas répondre."),
        }
    }

    /// Wire names of the read tools that answer this domain, space-separated.
    fn read_tools(self) -> &'static str {
        match self {
            Domain::Calendar => {
                "apple_calendar_list_events calendar_list_events google_calendar_list_events \
                 google_calendar_get_event"
            }
            Domain::Mail => {
                "mail_list mail_read mail_search mail_thread google_gmail_search \
                 google_gmail_read_message"
            }
            Domain::Clients => "crm_get crm_list crm_search crm_today",
            Domain::Reminders => "apple_reminders_list",
        }
    }

    /// Whole lowercase words (EN + FR) that name this domain's data.
    fn keywords(self) -> &'static str {
        match self {
            Domain::Calendar => {
                "calendar calendars agenda schedule scheduled meeting meetings event events \
                 appointment appointments call calls busy available availability booked \
                 calendrier réunion réunions rendez-vous rdv événement événements evenement \
                 evenements appel appels dispo disponible occupé"
            }
            Domain::Mail => {
                "mail mails email emails e-mails inbox unread wrote écrit courriel courriels boîte"
            }
            Domain::Clients => {
                "client clients customer customers crm follow-up follow-ups relance relances \
                 prospect prospects"
            }
            Domain::Reminders => {
                "reminder reminders to-do todo todos task tasks rappel rappels tâche tâches"
            }
        }
    }
}

/// Phrases that ask for a count, a date or a sender: a request for data.
const DATA_CUES: &str = "how many|how much|what's on|what is on|when is|when's|when are|who wrote|\
who sent|who emailed|next meeting|next call|next event|any new|anything new|unread|non lus|combien|quand|qui m'a|\
prochain|prochaine";

/// Words that make a turn a request rather than a remark.
const ASK_CUES: &str = "list|show|tell|check|find|count|any|liste|montre|dis-moi|vérifie|cherche";

/// Phrases that point at the owner's own data.
const OWNER_REFS: &str =
    "my|mine|me|i have|do i have|am i|i'm|have i|did i|today|tomorrow|tonight|\
this week|next week|mon|ma|mes|moi|j'ai|ai-je|est-ce que j'ai|m'a|suis-je|aujourd'hui|demain|\
cette semaine";

/// Phrases of a how-to or advice request: never a read of the owner's data.
const ADVICE: &str = "how do i|how should i|how can i|how to|how would|what should|should i|\
tip|tips|advice|best way|best practice|best practices|good way|polite|politely|write a|draft a|\
what is a|what's a|what does|explain|comment faire|comment puis-je|comment dois-je|comment je|\
comment écrire|comment rédiger|conseil|conseils|astuce|astuces|dois-je|faut-il|qu'est-ce qu'un|\
qu'est-ce qu'une|c'est quoi|rédige|écris|should a|should an|should you|best time|good time|\
ideal|usually|typically|in general|generally|on average|en général|généralement|meilleur moment";

/// French words that do not occur in English questions.
const FRENCH: &str = "je j'ai ai-je est-ce mon ma mes moi combien quand quel quelle quels \
quelles qui m'a les des du une cette semaine demain aujourd'hui avec pour sur dans prochain \
prochaine rendez-vous réunion réunions courriels rappels";

/// Words that state a calendar, mail, client or reminder fact.
const FACT_WORDS: &str = "monday tuesday wednesday thursday friday saturday sunday january \
february april june july august september october november december today tomorrow tonight \
yesterday zero none two three four five six seven eight nine ten eleven twelve lundi mardi \
mercredi jeudi vendredi samedi dimanche janvier février avril mai juin juillet août septembre \
octobre novembre décembre aujourd'hui demain hier aucun aucune deux trois quatre cinq sept huit \
neuf dix onze douze yes no free busy morning afternoon evening week oui non libre occupé matin \
après-midi soir semaine";

/// The input as lowercase words joined by single spaces, padded with a
/// space at each end so a phrase match is a whole-word match.
fn padded_words(text: &str) -> String {
    let lower = text.to_lowercase().replace('\u{2019}', "'");
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '\''))
        .filter(|word| !word.is_empty())
        .collect();
    format!(" {} ", words.join(" "))
}

fn has_phrase(padded: &str, list: &str) -> bool {
    list.split('|')
        .map(str::trim)
        .any(|phrase| padded.contains(&format!(" {phrase} ")))
}

/// The domains whose read tools (or `delegate`) the session offers.
pub(crate) fn offered_domains<'n>(names: impl IntoIterator<Item = &'n str>) -> Vec<Domain> {
    let names: Vec<&str> = names.into_iter().collect();
    if names.contains(&"delegate") {
        return ALL.to_vec();
    }
    ALL.into_iter()
        .filter(|domain| {
            domain
                .read_tools()
                .split_whitespace()
                .any(|tool| names.contains(&tool))
        })
        .collect()
}

/// The first offered domain whose data the OWNER asks about, or `None`.
/// A how-to or advice question ("how do I call a client?") is never one; a
/// data question names a domain, asks, and points at the owner's data or
/// asks for a count, a date or a sender.
pub(crate) fn asked_domain(input: &str, offered: &[Domain]) -> Option<Domain> {
    if offered.is_empty() {
        return None;
    }
    let padded = padded_words(input);
    if has_phrase(&padded, ADVICE) {
        return None;
    }
    let data = has_phrase(&padded, DATA_CUES);
    let asks = data || input.contains('?') || has_phrase(&padded, ASK_CUES);
    let owned = data || has_phrase(&padded, OWNER_REFS);
    if !(asks && owned) {
        return None;
    }
    offered.iter().copied().find(|domain| {
        domain
            .keywords()
            .split_whitespace()
            .any(|key| padded.contains(&format!(" {key} ")))
    })
}

/// The owner's language for the honest line: French when the question reads
/// French (and does not ask for English), else English.
pub(crate) fn question_lang(input: &str) -> Lang {
    let padded = padded_words(input);
    if has_phrase(&padded, "in english|en anglais") {
        return Lang::En;
    }
    let french = FRENCH
        .split_whitespace()
        .any(|word| padded.contains(&format!(" {word} ")));
    if french || input.chars().any(|c| "éèêàâçùûôîœ".contains(c)) {
        Lang::Fr
    } else {
        Lang::En
    }
}

/// True when `answer` states a domain fact: a number (list markers aside),
/// a day or month, a count word, or an address. Advice states none, so a
/// second no-tool answer that states none is kept, not replaced.
pub(crate) fn states_fact(answer: &str) -> bool {
    let body: String = answer
        .lines()
        .map(|line| {
            let line = line.trim_start();
            let digits = line.chars().take_while(char::is_ascii_digit).count();
            match line[digits..].chars().next() {
                Some('.' | ')') if digits > 0 => &line[digits + 1..],
                _ => line,
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if body.chars().any(|c| c.is_ascii_digit()) || body.contains('@') {
        return true;
    }
    let padded = padded_words(&body);
    FACT_WORDS
        .split_whitespace()
        .any(|word| padded.contains(&format!(" {word} ")))
}

/// MEM-FORGET-HANG: the one nudge when an answer says something was saved
/// but no memory write ran this turn. Static text.
pub(crate) const SAVE_NUDGE: &str = "No memory item was saved this turn. Call `remember` only when the owner asked you to save it; use `suggest_memory` only to propose a stable fact the owner stated or confirmed here, and say it awaits owner review.";

/// Words that say something went into memory (EN + FR).
const SAVE_WORDS: &str = "saved|stored|noted|remembered|memorized|memorised|i'll remember|\
i will remember|enregistré|enregistrée|noté|notée|mémorisé|mémorisée|retenu|retenue|sauvegardé|\
sauvegardée|je m'en souviendrai|je retiens";

/// Words of an owner message that asks to keep something (EN + FR).
const SAVE_ASKS: &str = "remember|keep in mind|save this|save it|save that|note this|note that|\
note it|note down|retiens|retenir|souviens|souviens-toi|mémorise|mémoriser|enregistre|prends note|\
garde en mémoire|garde en tête";

/// Phrases that say nothing was saved.
const NOT_SAVED: &str = "not saved|didn't save|did not save|couldn't save|could not save|\
wasn't saved|was not saved|nothing was saved|never saved|not stored|isn't stored|wasn't stored|\
never stored|pas enregistré|rien n'a été|n'ai pas|n'est pas";

/// True when the owner's message asks to keep something in memory. A
/// question ("do you remember…?") asks to recall, not to save.
pub(crate) fn asks_to_save(input: &str) -> bool {
    !input.trim_end().ends_with('?') && has_phrase(&padded_words(input), SAVE_ASKS)
}

/// True when `answer` says something was saved and the owner's `input`
/// asked to keep it.
pub(crate) fn claims_save(input: &str, answer: &str) -> bool {
    let said = padded_words(answer);
    asks_to_save(input) && has_phrase(&said, SAVE_WORDS) && !has_phrase(&said, NOT_SAVED)
}

/// The answer when the agent still claims a save that never ran.
pub(crate) fn not_saved_line(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "I did not save that: nothing was written to memory in this turn.",
        Lang::Fr => "Je ne l'ai pas enregistré : rien n'a été écrit en mémoire pendant ce tour.",
    }
}

/// The turn's last line when an approval card got no answer in time.
pub(crate) fn card_expired_line(lang: Lang, tool: &str) -> String {
    match lang {
        Lang::En => format!(
            "The approval card for `{tool}` got no answer in time, so it did not run. Ask \
             again when you are at the Mac."
        ),
        Lang::Fr => format!(
            "La demande d'accord pour `{tool}` n'a pas eu de réponse à temps : elle n'a pas \
             été exécutée. Redemandez quand vous serez devant le Mac."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Domain::{Calendar, Clients, Mail, Reminders};

    #[test]
    fn the_memory_nudge_keeps_suggestions_reviewable() {
        assert!(SAVE_NUDGE.contains("suggest_memory"));
        assert!(SAVE_NUDGE.contains("owner review"));
    }

    #[test]
    fn a_save_claim_needs_memory_in_the_turn_and_no_denial() {
        let ask = "Remember the code word KIWI-7731 for later.";
        assert!(claims_save(ask, "Saved it to my memory."));
        assert!(claims_save("Retiens le code KIWI-7731.", "C'est noté."));
        assert!(claims_save(
            "Note this",
            "I saved it directly in my memory."
        ));
        assert!(!claims_save(ask, "OK"));
        let question = "Do you remember my code word?";
        assert!(!claims_save(question, "Yes, I have it stored: KIWI."));
        assert!(!claims_save(ask, "I did not save that."));
        assert!(!claims_save(
            "Book the room",
            "The event is saved in your calendar."
        ));
        let forget = "Please delete it from your memory completely.";
        assert!(!claims_save(forget, "Saved items: none. It isn't stored."));
    }

    #[test]
    fn general_advice_and_remarks_never_trigger() {
        let advice = [
            "how do I call a client for the first time?",
            "How should I write a follow-up to a client?",
            "how to run a good meeting?",
            "What's a polite way to decline a meeting?",
            "Any tips for a first call with a customer?",
            "what is a CRM?",
            "how can I keep my inbox clean?",
            "Should I send a reminder after a quote?",
            "Draft a short email to thank a client",
            "What does a good agenda for a kickoff call look like?",
            "explain how calendar invites work",
            "Best way to schedule a meeting across time zones?",
            "comment faire une bonne relance client ?",
            "Comment rédiger un mail de relance ?",
            "des conseils pour un premier rendez-vous client ?",
            "c'est quoi un CRM ?",
            "Dois-je appeler un prospect avant de lui écrire ?",
            "Comment puis-je organiser mes réunions ?",
            "Écris un mail pour remercier un client",
            "faut-il confirmer un rendez-vous la veille ?",
            "hello",
            "thanks!",
            "Thanks for the meeting notes",
            "merci",
            "What is her email again?",
            // General "how many / when is" questions.
            "how many clients should a freelancer have?",
            "when is the best time to send an email?",
            "how many meetings is too many in a week, usually?",
            "Quel est le meilleur moment pour relancer un client ?",
        ];
        for input in advice {
            assert_eq!(asked_domain(input, &ALL), None, "{input}");
        }
        assert!(advice.len() >= 20);
    }

    #[test]
    fn questions_about_the_owners_data_trigger_their_domain() {
        let data = [
            (
                "Ask the Calendar agent: how many events this week?",
                Calendar,
            ),
            ("What meetings do I have today?", Calendar),
            ("when is my next meeting?", Calendar),
            ("am I busy tomorrow afternoon?", Calendar),
            ("what's on my calendar?", Calendar),
            ("Do I have a call with Ines Fictive?", Calendar),
            ("Combien de réunions cette semaine ?", Calendar),
            ("quand est mon prochain rendez-vous ?", Calendar),
            ("Quels mails non lus ?", Mail),
            ("who wrote my last email?", Mail),
            ("any unread mails?", Mail),
            ("Qui m'a envoyé un courriel ce matin ?", Mail),
            ("show my clients waiting on a follow-up", Clients),
            ("which clients do I have in Lyon?", Clients),
            ("mes relances clients de demain ?", Clients),
            ("what reminders do I have?", Reminders),
            ("ai-je des tâches pour aujourd'hui ?", Reminders),
            ("who wrote to me last?", Mail),
        ];
        for (input, expected) in data {
            assert_eq!(asked_domain(input, &ALL), Some(expected), "{input}");
        }
        assert!(data.len() >= 15);
    }

    #[test]
    fn only_offered_domains_count_and_delegate_reaches_them_all() {
        assert_eq!(asked_domain("how many unread mails?", &[Calendar]), None);
        assert_eq!(asked_domain("how many meetings?", &[]), None);
        assert_eq!(offered_domains(["delegate"]), ALL.to_vec());
        assert_eq!(
            offered_domains(["read_file", "apple_calendar_list_events"]),
            vec![Calendar]
        );
        assert!(offered_domains(["read_file", "apple_calendar_create_event"]).is_empty());
    }

    #[test]
    fn the_honest_line_speaks_the_question_language() {
        assert_eq!(question_lang("how many events this week?"), Lang::En);
        assert_eq!(
            question_lang("Combien de réunions cette semaine ?"),
            Lang::Fr
        );
        assert_eq!(question_lang("quels rdv demain"), Lang::Fr);
        assert_eq!(
            question_lang("Quel est le dernier mail ? Reponds en anglais."),
            Lang::En
        );
        assert_eq!(
            Mail.honest_line(Lang::Fr),
            "Je n'ai pas vérifié vos mails, je ne peux donc pas répondre."
        );
    }

    #[test]
    fn only_an_answer_that_states_a_fact_counts_as_a_guess() {
        for guess in [
            "3",
            "You have two meetings.",
            "Next one is on Tuesday.",
            "Aucun.",
            // Yes/no and time-of-day guesses.
            "Yes, Camille wrote this morning.",
            "No.",
            "You're free all week.",
        ] {
            assert!(states_fact(guess), "{guess}");
        }
        for kept in [
            "Introduce yourself and ask about their goals.",
            "1. Be brief\n2) Listen first",
            "I can look that up for you if you like.",
        ] {
            assert!(!states_fact(kept), "{kept}");
        }
    }
}
