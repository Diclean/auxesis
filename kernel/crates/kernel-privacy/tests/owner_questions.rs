//! AGENT-REAL-1: the owner's own questions reach a hosted model intact in
//! Private mode. Only real names, and nothing about the question, are masked.
//! The assistant's own names (`Aux`, `Auxesis`) are never a person.

use std::sync::Arc;

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{Gate, NameDictionary};

fn grant() -> Grant {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, PrivacyMode::Private, &context) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow, got {other:?}"),
    }
}

/// What a private session sends for `text`, with an empty contacts dictionary.
fn sent(text: &str) -> String {
    let names = Arc::new(NameDictionary::new::<[&str; 0], &str>([]).expect("dictionary"));
    let mut gate = Gate::for_grant_with_dictionary(&grant(), [7u8; 32], names);
    let (safe, _) = gate.text(text).expect("private chat is issued");
    safe.as_str().to_string()
}

#[test]
fn owner_questions_stay_intact() {
    for text in [
        "How many unread mails do I have, and who sent the newest one?",
        "What is on my calendar tomorrow?",
        "How many unread mails do I have, Aux?",
        "Aux, what is on my calendar tomorrow?",
        "Hey Aux, check my mail, please.",
        "Thanks Auxesis, that is all.",
        "You are Aux, an Auxesis agent: a personal always-on agent running on this Mac.",
        "Can you check my calendar, please?",
        "Do I have any meetings tomorrow, or is the day free?",
        "Which invoices are still unpaid, and for how long?",
        "Is there anything urgent in my inbox, from this week?",
        "Quels mails non lus, et de qui ?",
        "Combien de mails non lus ai-je, et qui a envoyé le dernier ?",
        "Peux-tu vérifier mon agenda, s'il te plaît ?",
    ] {
        assert_eq!(sent(text), text, "{text:?} was altered");
    }
}

#[test]
fn the_assistant_names_are_never_a_person() {
    for text in [
        "Hi Aux,\nwhat is on my calendar?",
        "Aux said the meeting moved.",
        "Merci Aux,\nc'est parfait.",
        "Regards,\nAux",
        "Salut Aux, tu peux regarder mes mails ?",
        "Aux a dit que le dossier suit.",
        "Hello Auxesis,\nplease check my mail.",
    ] {
        let out = sent(text);
        assert!(!out.contains("⟦PERSON"), "{text:?} -> {out:?}");
    }
}
