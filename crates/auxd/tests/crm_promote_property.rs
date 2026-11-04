//! B2 acceptance (`docs/phase1.md` §2): a mail sender promoted to a party is
//! tokenised in the next provider request, and promoting the same sender twice
//! leaves one party.
//!
//! Each case promotes a generated sender through [`aux_crm::Crm::promote_sender`] twice,
//! into a temp home's store, then runs one private turn whose message carries the
//! sender's name and address. The fake provider records the request bodies; none may
//! hold a cleartext name or address, and the masked text must carry the token marker.

use std::sync::Arc;

use aux_crm::{Crm, Seeded};
use aux_providers::{ChatProvider, FakeProvider};
use auxd::api::{EngineTurnRunner, TurnRunner};
use proptest::prelude::*;

/// A given or family name: Latin letters with the accents, cedillas and hyphens
/// the kernel normalises, at least three letters so a bare token is a real name.
fn name_word() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-ZÉÈÊËÀÂÄÎÏÔÖÙÛÜÇ][a-zéèêëàâäîïôöùûüç]{2,7}(-[A-Z][a-z]{2,7})?")
        .unwrap()
}

/// A lower-case local part for a `.test` address.
fn email_local() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z]{4,10}").unwrap()
}

prop_compose! {
    // One generated sender: its display name and its address.
    fn sender_case()(
        given in name_word(),
        family in name_word(),
        local in email_local(),
    ) -> (String, String) {
        (format!("{given} {family}"), format!("{local}@exemple.test"))
    }
}

fn assert_address_is_one_token(body: &str, email: &str) {
    let tail = body
        .split_once("please reply to ")
        .map(|(_, tail)| tail)
        .expect("reply prompt reaches provider");
    assert!(tail.starts_with('⟦'), "address has no token: {body}");
    let token_end = tail.find('⟧').expect("complete address token");
    assert!(
        tail[token_end + '⟧'.len_utf8()..].starts_with('.'),
        "token does not cover the whole address: {body}"
    );
    assert!(
        !body.contains(email),
        "cleartext `{email}` reached provider: {body}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn every_promoted_senders_address_is_tokenised_in_the_next_provider_call(
        (display, email) in sender_case(),
    ) {
        // A private home: the turn is gated, so the address must become a token.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            kernel_core::config_path(&home),
            "version = 1\n\n[privacy]\nmode = \"private\"\n",
        )
        .unwrap();

        // Promote twice through the CRM API only: the second call must change nothing.
        {
            let store = aux_store::Store::open(&home.join("store.db")).unwrap();
            let crm = Crm::new(&store);
            let first = crm.promote_sender("fictif", &display, &email).unwrap();
            let second = crm.promote_sender("fictif", &display, &email).unwrap();
            prop_assert!(matches!(first, Seeded::Created(_)));
            prop_assert!(matches!(second, Seeded::Unchanged(_)));
            prop_assert_eq!(second.party().id, first.party().id);
            prop_assert_eq!(store.parties().unwrap().len(), 1);
        }

        let message = format!("Hello {display}, please reply to {email}.");
        let provider = Arc::new(FakeProvider::echo("fake"));
        let runner = EngineTurnRunner::new(&home)
            .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>);
        runner
            .run_turn("main", None, &message, None)
            .expect("a private turn completes over the synced index");

        let bodies: Vec<String> = provider
            .requests()
            .iter()
            .map(|request| serde_json::to_string(&request.messages).unwrap())
            .collect();
        prop_assert_eq!(bodies.len(), 1, "one provider call");
        let body = &bodies[0];
        prop_assert!(
            body.contains('⟦'),
            "the turn was not masked into placeholders: {body}"
        );
        // Names stay clear. A prohibited substring
        // inside the address may label its one whole token HEALTH or SECRET.
        prop_assert!(!body.contains("⟦PERSON_"), "{body}");
        assert_address_is_one_token(body, &email);
    }
}

#[test]
fn promoted_sensitive_address_parts_are_tokenised_whole() {
    let display = "Äçô Ùôa";
    for email in [
        "ptsd@exemple.test",
        "diabetes@exemple.test",
        "hiv.clinic@exemple.test",
        "sk-test@exemple.test",
        "AB123456C@exemple.test",
        "owner@ptsd.exemple.test",
        "owner@diabetes.exemple.test",
        "owner@hiv.clinic.test",
        "owner@sk-test.exemple.test",
        "owner@AB123456C.exemple.test",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            kernel_core::config_path(&home),
            "version = 1\n\n[privacy]\nmode = \"private\"\n",
        )
        .unwrap();
        {
            let store = aux_store::Store::open(&home.join("store.db")).unwrap();
            Crm::new(&store)
                .promote_sender("fictif", display, email)
                .unwrap();
        }

        let provider = Arc::new(FakeProvider::echo("fake"));
        EngineTurnRunner::new(&home)
            .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>)
            .run_turn(
                "main",
                None,
                &format!("Hello {display}, please reply to {email}."),
                None,
            )
            .unwrap();
        let body = serde_json::to_string(&provider.requests()[0].messages).unwrap();
        assert_address_is_one_token(&body, email);
    }
}
