//! A private chat turn through the daemon's turn runner: `EngineTurnRunner::run_turn`
//! is the path the API and Telegram take. The owner's contact is Camille Exemple.
//! The turn must complete, the provider must see no raw name or address, and the
//! next turn of the same thread must still see the first.

use std::path::PathBuf;
use std::sync::Arc;

use aux_providers::{ChatProvider, FakeProvider};
use auxd::api::{EngineTurnRunner, TurnRunner};
use kernel_privacy::ContactIndex;

const MESSAGE: &str = "Dis bonjour à Camille Exemple, camille@exemple.fr.";

/// A home whose owner has chosen private mode.
fn private_home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"private\"\n",
    )
    .unwrap();
    (dir, home)
}

/// The owner's contacts: Camille Exemple, with one address.
fn camille() -> aux_runtime::known_names::Contacts {
    let mut contacts = ContactIndex::new();
    assert!(contacts
        .add_from_header("Camille Exemple", "camille@exemple.fr")
        .is_some());
    Arc::new(contacts)
}

/// The messages of every provider request, as JSON, in order.
fn bodies(provider: &FakeProvider) -> Vec<String> {
    provider
        .requests()
        .iter()
        .map(|request| serde_json::to_string(&request.messages).unwrap())
        .collect()
}

/// The first `⟦EMAIL_…⟧` token in a request body.
fn email_token(body: &str) -> String {
    let start = body.find("⟦EMAIL_").expect("an e-mail token in the body");
    let end = body[start..].find('⟧').unwrap() + start + '⟧'.len_utf8();
    body[start..end].to_string()
}

#[test]
fn a_private_turn_completes_without_raw_text_and_the_next_turn_sees_it() {
    let (_dir, home) = private_home();
    let provider = Arc::new(FakeProvider::echo("fake"));
    let runner = EngineTurnRunner::new(&home)
        .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>)
        .with_contacts(camille());

    let first = runner
        .run_turn("main", None, MESSAGE, None)
        .expect("a private turn completes");
    let reply = first.messages.last().expect("the turn's reply");
    assert_eq!(reply.role, "assistant");
    assert!(!reply.content.is_empty(), "the reply has content");

    let first_bodies = bodies(&provider);
    assert_eq!(first_bodies.len(), 1, "one provider call");
    for body in &first_bodies {
        // The name passes as written (NAMES-OFF, owner 2026-10-19).
        assert!(
            !body.contains("camille@exemple.fr"),
            "raw contact text reached the provider: {body}"
        );
    }
    let token = email_token(&first_bodies[0]);

    runner
        .run_turn("main", Some(first.thread.id), "Et demain ?", None)
        .expect("the next private turn completes");
    let second = bodies(&provider);
    assert_eq!(second.len(), 2);
    assert!(
        second[1].contains(&token),
        "the next turn lost the first turn's token"
    );
}

/// The sensitive values of a turn
/// (a CN resident ID, an EN health term, a bare CN mobile, an API key and a
/// `name=value` secret) before the provider sees it.
#[test]
fn a_private_turn_keeps_sensitive_values_from_the_provider() {
    const SENSITIVE: [&str; 6] = [
        "11010519491231002X",
        "chemotherapy",
        "13800138000",
        "sk-proj-Q7vL2mX9pR4tY8wZ1nB6cD3f",
        "DB_PASSWORD=Xk9&mP2q!z",
        "Xk9&mP2q!z",
    ];
    let (_dir, home) = private_home();
    let provider = Arc::new(FakeProvider::echo("fake"));
    let runner = EngineTurnRunner::new(&home)
        .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>)
        .with_contacts(camille());
    let message = format!(
        "Camille Exemple, résident {}, traitement de chemotherapy, mobile {}, clé {}, {}",
        SENSITIVE[0], SENSITIVE[2], SENSITIVE[3], SENSITIVE[4]
    );

    let turn = runner
        .run_turn("main", None, &message, None)
        .expect("a private turn completes");
    assert_eq!(
        turn.messages.last().expect("the turn's reply").role,
        "assistant"
    );

    let sent = bodies(&provider);
    assert_eq!(sent.len(), 1, "one provider call");
    assert!(
        sent[0].contains("⟦"),
        "the turn was masked into placeholders"
    );
    for value in SENSITIVE {
        for body in &sent {
            assert!(
                !body.contains(value),
                "a sensitive value reached the provider: {value}"
            );
        }
    }
}

/// English health inflections,
/// secrets written in prose and UK National Insurance numbers before the
/// provider sees them.
#[test]
fn a_private_turn_keeps_english_prose_secrets_and_health_from_the_provider() {
    const SENSITIVE: [&str; 9] = [
        "chemotherapies",
        "hospitalized",
        "Tr0ubProse42",
        "Tr0ubCliP42",
        "Q7vL2mX9pR4tY8wZ1nB6cD3fGhJkLmNp",
        "Xk9mP2q",
        "QQ123456C",
        "AB 12 34 56 C",
        "AB\u{a0}123456\u{a0}C",
    ];
    let (_dir, home) = private_home();
    let provider = Arc::new(FakeProvider::echo("fake"));
    let runner = EngineTurnRunner::new(&home)
        .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>)
        .with_contacts(camille());
    let message = format!(
        "Camille Exemple finished two {} and was {} last May. My password is {}; \
         mysql -u root -p{}; api key: {}; the wifi password is {}. \
         NI number {}, national insurance {}, NI {}.",
        SENSITIVE[0],
        SENSITIVE[1],
        SENSITIVE[2],
        SENSITIVE[3],
        SENSITIVE[4],
        SENSITIVE[5],
        SENSITIVE[6],
        SENSITIVE[7],
        SENSITIVE[8]
    );

    runner
        .run_turn("main", None, &message, None)
        .expect("a private turn completes");

    let sent = bodies(&provider);
    assert_eq!(sent.len(), 1, "one provider call");
    for value in SENSITIVE {
        assert!(
            !sent[0].contains(value),
            "a sensitive value reached the provider: {value}"
        );
    }
}

/// A passport machine-readable zone is masked
/// whole, a Markdown-decorated password key and a singular health term.
#[test]
fn a_private_turn_keeps_mrz_lines_decorated_secrets_and_singular_health_from_the_provider() {
    const SENSITIVE: [&str; 6] = [
        "ERIKSSON",
        "L898902C36",
        "7408122F1204159",
        "Zq7Lm2Xr",
        "Wd4Np8Ks",
        "kidney stone",
    ];
    let (_dir, home) = private_home();
    let provider = Arc::new(FakeProvider::echo("fake"));
    let runner = EngineTurnRunner::new(&home)
        .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>)
        .with_contacts(camille());
    let message = "Camille Exemple sent her scan:\n\
                   P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n\
                   L898902C36UTO7408122F1204159ZE184226B<<<<<10\n\
                   **password**: Zq7Lm2Xr and `password` is Wd4Np8Ks. \
                   She mentioned a kidney stone.";

    runner
        .run_turn("main", None, message, None)
        .expect("a private turn completes");

    let sent = bodies(&provider);
    assert_eq!(sent.len(), 1, "one provider call");
    for value in SENSITIVE {
        assert!(
            !sent[0].contains(value),
            "a sensitive value reached the provider: {value}"
        );
    }
}

/// The values of decorated and
/// curly-quoted secret keys.
#[test]
fn a_private_turn_keeps_decorated_and_curly_quoted_secrets_from_the_provider() {
    const SENSITIVE: [&str; 5] = ["Tk7Qm2Wx", "Ak9Lp3Zr", "Cs4Vn8Hd", "Pw6Jr1Bt", "Gt5Xe9Mu"];
    let (_dir, home) = private_home();
    let provider = Arc::new(FakeProvider::echo("fake"));
    let runner = EngineTurnRunner::new(&home)
        .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>)
        .with_contacts(camille());
    let message = format!(
        "Camille Exemple pasted her notes: `token`: {}, **api_key**: {}, \
         `clientSecret` is {}, \u{201c}password\u{201d} is {}, `GITHUB_TOKEN` is {}.",
        SENSITIVE[0], SENSITIVE[1], SENSITIVE[2], SENSITIVE[3], SENSITIVE[4]
    );

    runner
        .run_turn("main", None, &message, None)
        .expect("a private turn completes");

    let sent = bodies(&provider);
    assert_eq!(sent.len(), 1, "one provider call");
    for value in SENSITIVE {
        assert!(
            !sent[0].contains(value),
            "a sensitive value reached the provider: {value}"
        );
    }
}
