//! B1 acceptance (`docs/phase1.md` §2): every party write is tokenised in the
//! next provider request.
//!
//! Each case writes generated parties into a temp home's store through
//! [`aux_crm::Crm`] and runs the real turn runner over that home (the contacts
//! are **not** injected: the runner reads the store). One private turn follows
//! each write: create, update (a name change), merge and archive. The fake
//! provider records the request bodies; none may hold a cleartext variant, the
//! `.test` address or the E.164 phone, and the masked text must carry the token
//! marker. Archive is checked on the store's `crm` source, because an archived
//! name is *supposed* to be gone from the index.
//!
//! The property fails if a CRM write stops refreshing the contacts index: the
//! written name reaches the provider cleartext, or the archived name is still
//! mounted.

use std::sync::Arc;

use aux_crm::{Crm, NewParty, PartyKind, CRM_CONTACT_SOURCE};
use aux_providers::{ChatProvider, FakeProvider};
use auxd::api::{EngineTurnRunner, TurnRunner};
use proptest::prelude::*;
use serde_json::{json, Value};
use unicode_normalization::UnicodeNormalization;

/// One generated party: display name, name variants, `.test` address, E.164 phone.
type PartyCase = (String, Vec<String>, String, String);

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

/// The nine national digits of a fictional `+33` number.
fn phone_tail() -> impl Strategy<Value = String> {
    prop::string::string_regex("[1-9][0-9]{8}").unwrap()
}

prop_compose! {
    // One generated party.
    fn party_case()(
        given in name_word(),
        family in name_word(),
        local in email_local(),
        tail in phone_tail(),
    ) -> PartyCase {
        let display = format!("{given} {family}");
        let variants = vec![display.clone(), given.clone(), family.clone()];
        (display, variants, format!("{local}@exemple.test"), format!("+33{tail}"))
    }
}

/// A case: the create party `a`, `a`'s update, a merge target `b`, and `c`.
fn scenario() -> impl Strategy<Value = (PartyCase, PartyCase, PartyCase, PartyCase)> {
    (party_case(), party_case(), party_case(), party_case())
}

/// A private person party from one generated case.
fn person(case: &PartyCase) -> NewParty {
    let (display, variants, email, phone) = case;
    NewParty {
        kind: PartyKind::Person,
        display_name: display.clone(),
        name_variants: variants.clone(),
        emails: vec![email.clone()],
        phones: vec![phone.clone()],
        origin: "owner".to_string(),
        ..NewParty::default()
    }
}

/// A message that writes every secret out, so the gate must mask each.
fn message_with(secrets: &[String]) -> String {
    format!("Bonjour {}.", secrets.join(", "))
}

/// A party case's name variants plus its address and number.
fn secrets(case: &PartyCase) -> Vec<String> {
    let (_, variants, email, phone) = case;
    let mut secrets = variants.clone();
    secrets.push(email.clone());
    secrets.push(phone.clone());
    secrets
}

/// The values of `case` a private turn still hides: names pass as written.
fn hidden(case: &PartyCase) -> Vec<String> {
    vec![case.2.clone(), case.3.clone()]
}

/// Run one private turn and return the request the fake provider saw, as the
/// JSON it would put on the wire.
fn run_request(runner: &EngineTurnRunner, provider: &FakeProvider, message: &str) -> Value {
    runner
        .run_turn("main", None, message, None)
        .expect("a private turn completes over the synced index");
    let requests = provider.requests();
    serde_json::to_value(requests.last().expect("a recorded request")).unwrap()
}

/// Every text of `request` a name must not stand in: message contents,
/// tool-call ids and arguments, tool results and reasoning, plus the tool
/// specs. Only trusted fields byte-identical to `baseline`'s (a turn taken
/// before any party existed) are exempt: its system messages and its tool
/// specs. A trusted field that changed is scanned in full.
fn scanned(request: &Value, baseline: &Value) -> Vec<String> {
    let trusted: Vec<&Value> = baseline["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|message| message["role"] == "system")
        .collect();
    let mut texts = Vec::new();
    for message in request["messages"].as_array().into_iter().flatten() {
        if !(message["role"] == "system" && trusted.contains(&message)) {
            strings(message, &mut texts);
        }
    }
    if request["tools"] != baseline["tools"] {
        strings(&request["tools"], &mut texts);
    }
    texts
}

/// The string values under `value`, but the wire's schema words (`role`,
/// `type`): a name may be "User" or "Function".
fn strings(value: &Value, texts: &mut Vec<String>) {
    match value {
        Value::String(text) => texts.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| strings(item, texts)),
        Value::Object(fields) => fields
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "role" | "type"))
            .for_each(|(_, item)| strings(item, texts)),
        _ => {}
    }
}

/// Whether `secret` stands in `text`: matched without case after NFKC on both
/// sides, with no letter right before or after it. Digits, `@`, `/`, `.`,
/// `_`, punctuation and the ends of the text all bound a name; only a longer
/// word ("Sav" in "Save") hides one.
fn occurs(text: &str, secret: &str) -> bool {
    let fold = |s: &str| s.nfkc().collect::<String>().to_lowercase();
    let (text, secret) = (fold(text), fold(secret));
    text.match_indices(&secret).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + secret.len()..].chars().next();
        !before.is_some_and(char::is_alphabetic) && !after.is_some_and(char::is_alphabetic)
    })
}

/// The secrets that stand in any scanned text. No count against the
/// baseline: a name said once is a leak, whatever the prompt holds.
fn leaked(texts: &[String], secrets: &[String]) -> Vec<String> {
    secrets
        .iter()
        .filter(|secret| texts.iter().any(|text| occurs(text, secret)))
        .cloned()
        .collect()
}

/// The fixed prompt of the deterministic cases below.
const PROMPT: &str = "- `remember` (risk: medium): Save a fact.\nUse tools.";

/// A request with one system message and the given later messages.
fn request_with(system: &str, rest: Value) -> Value {
    let mut messages = vec![json!({"role": "system", "content": system})];
    messages.extend(rest.as_array().unwrap().iter().cloned());
    json!({"model": "fake", "messages": messages, "tools": []})
}

/// The shrunk seed's name "Sav" is a prefix of the prompt's
/// "Save"; a masked turn over the unchanged prompt holds no leak.
#[test]
fn a_name_inside_an_unchanged_prompt_word_is_not_a_leak() {
    let baseline = request_with(PROMPT, json!([]));
    let turn = request_with(
        PROMPT,
        json!([{"role": "user", "content": "Bonjour ⟦PERSON_F94B4EA04199⟧."}]),
    );
    let secrets = ["Sav".to_string(), "Use".to_string()];
    assert!(leaked(&scanned(&turn, &baseline), &secrets).is_empty());
    // The prompt is exempt only while unchanged; changed, "Save" still bounds
    // "Sav" but the bare "Use" is scanned.
    let changed = request_with(&format!("{PROMPT} "), json!([]));
    assert_eq!(leaked(&scanned(&changed, &baseline), &secrets), ["Use"]);
}

/// The prompt's "Use" becomes a token while the user content says
/// "Use". The counts tie, so baseline subtraction must not hide the leak.
#[test]
fn a_replaced_prompt_word_does_not_hide_a_leak() {
    let baseline = request_with(PROMPT, json!([]));
    let user = json!([{"role": "user", "content": "Use"}]);
    let replaced = PROMPT.replace("Use", "⟦PERSON_F94B4EA04199⟧");
    let secrets = ["Use".to_string()];
    for system in [replaced.as_str(), PROMPT] {
        let turn = request_with(system, user.clone());
        assert_eq!(
            leaked(&scanned(&turn, &baseline), &secrets),
            ["Use"],
            "{system:?}"
        );
    }
}

/// A name inside an identifier still counts. Digits, `@`, `/`,
/// `_` and `.` bound it; case and NFKC width do not hide it.
#[test]
fn a_name_inside_an_identifier_is_a_leak() {
    let baseline = request_with(PROMPT, json!([]));
    for content in [
        "Sav123@example.test",
        "see /Sav123",
        "id_sav.",
        "SAV",
        "\u{ff33}\u{ff41}\u{ff56}",
    ] {
        let turn = request_with(PROMPT, json!([{"role": "user", "content": content}]));
        assert_eq!(
            leaked(&scanned(&turn, &baseline), &["Sav".to_string()]),
            ["Sav"],
            "{content:?}"
        );
    }
}

/// Tool-call arguments and ids, tool results and reasoning are
/// scanned too, not only message contents.
#[test]
fn a_name_outside_message_content_is_a_leak() {
    let baseline = request_with(PROMPT, json!([]));
    let call = |id: &str, arguments: &str| {
        json!([{"role": "assistant", "content": "", "tool_calls": [{"id": id,
            "type": "function", "function": {"name": "remember", "arguments": arguments}}]}])
    };
    for rest in [
        call("call_1", r#"{"fact":"Sav likes tea"}"#),
        call("call_Sav", "{}"),
        json!([{"role": "tool", "content": "ok", "tool_call_id": "Sav-1"}]),
        json!([{"role": "assistant", "content": "", "reasoning_content": "ask Sav"}]),
    ] {
        let turn = request_with(PROMPT, rest.clone());
        assert_eq!(
            leaked(&scanned(&turn, &baseline), &["Sav".to_string()]),
            ["Sav"],
            "{rest}"
        );
    }
    let mut turn = request_with(PROMPT, json!([]));
    turn["tools"] = json!([{"type": "function", "function": {"name": "Sav", "description": "",
        "parameters": {}}}]);
    assert_eq!(
        leaked(&scanned(&turn, &baseline), &["Sav".to_string()]),
        ["Sav"]
    );
}

/// The total case count, spread over [`SHARDS`] test functions so the test
/// runner takes them in parallel: every shard draws its own random cases from
/// the same generator, and all of them run the one property below.
const CASES: u32 = 200;
/// How many test functions share [`CASES`].
const SHARDS: u32 = 4;
// The shards add up to exactly `CASES`.
const _: () = assert!(CASES.is_multiple_of(SHARDS));

/// A private home with its store already created: the master key minted and
/// the schema migrated (about a second per open in a debug build). Built once
/// per shard; each case gets a byte copy, so it still starts from a fresh,
/// empty store of its own.
fn template_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    // A private home: the turn is gated, so an address must become a token.
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"private\"\n",
    )
    .unwrap();
    drop(aux_store::Store::open(&home.join("store.db")).unwrap());
    dir
}

/// Copy `from` to `to` recursively, keeping each entry's permissions.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        assert!(
            !kind.is_symlink(),
            "unexpected symlink in the template home"
        );
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
    std::fs::set_permissions(to, std::fs::metadata(from).unwrap().permissions()).unwrap();
}

/// Run [`CASES`] / [`SHARDS`] cases of the property. A failure is shrunk and
/// saved to `crm_property.proptest-regressions` like the macro form, and the
/// saved seeds replay first in every shard.
fn run_shard() {
    let template = template_home();
    let config = ProptestConfig {
        source_file: Some(file!()),
        ..ProptestConfig::with_cases(CASES / SHARDS)
    };
    let mut runner = proptest::test_runner::TestRunner::new(config);
    let outcome = runner.run(&scenario(), |(a, a2, b, c)| {
        // A fresh home per case, copied from the template before any write.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        copy_tree(&template.path().join("home"), &home);
        crm_writes_are_tokenised(&home, &a, &a2, &b, &c)
    });
    if let Err(failure) = outcome {
        panic!("{failure}\n{runner}");
    }
}

#[test]
fn every_crm_writes_address_and_phone_are_tokenised_in_the_next_provider_call_1() {
    run_shard();
}

#[test]
fn every_crm_writes_address_and_phone_are_tokenised_in_the_next_provider_call_2() {
    run_shard();
}

#[test]
fn every_crm_writes_address_and_phone_are_tokenised_in_the_next_provider_call_3() {
    run_shard();
}

#[test]
fn every_crm_writes_address_and_phone_are_tokenised_in_the_next_provider_call_4() {
    run_shard();
}

/// The property for one case over the private `home`.
fn crm_writes_are_tokenised(
    home: &std::path::Path,
    a: &PartyCase,
    a2: &PartyCase,
    b: &PartyCase,
    c: &PartyCase,
) -> Result<(), TestCaseError> {
    // The store stays open across the writes; the runner reads it fresh.
    let store = aux_store::Store::open(&home.join("store.db")).unwrap();
    let crm = Crm::new(&store);
    let provider = Arc::new(FakeProvider::echo("fake"));
    let runner =
        EngineTurnRunner::new(home).with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>);
    // The fixed prompt before any party exists: what a name may match
    // without being a leak.
    let baseline = run_request(&runner, &provider, "Bonjour.");
    let turn = |message: &str| scanned(&run_request(&runner, &provider, message), &baseline);

    // Create `a`, then a turn over its names and identifiers.
    let a_party = crm.create(person(a)).unwrap();
    let body = turn(&message_with(&secrets(a)));
    prop_assert!(
        body.iter().any(|text| text.contains('⟦')),
        "not masked: {body:?}"
    );
    prop_assert!(
        leaked(&body, &hidden(a)).is_empty(),
        "create leaked {:?}: {body:?}",
        leaked(&body, &hidden(a))
    );

    // Update `a`'s names (the same address and number), then a turn.
    let updated = NewParty {
        display_name: a2.0.clone(),
        name_variants: a2.1.clone(),
        ..person(a)
    };
    crm.update(a_party.id, updated).unwrap();
    let body = turn(&message_with(&secrets(a2)));
    prop_assert!(
        leaked(&body, &hidden(a2)).is_empty(),
        "update leaked {:?}: {body:?}",
        leaked(&body, &hidden(a2))
    );

    // Create `b` and merge `a` into it: the target absorbs `a`'s names and
    // identifiers, so both must be masked.
    let b_party = crm.create(person(b)).unwrap();
    crm.merge(a_party.id, b_party.id).unwrap();
    let mut merged = secrets(a2);
    merged.extend(secrets(b));
    let body = turn(&message_with(&merged));
    let merged = [hidden(a2), hidden(b)].concat();
    prop_assert!(
        leaked(&body, &merged).is_empty(),
        "merge leaked {:?}: {body:?}",
        leaked(&body, &merged)
    );

    // Create `c` and archive it: its names leave the index. The store's
    // `crm` source must no longer hold `c`'s address, while a turn over the
    // live `b` is still masked.
    let c_party = crm.create(person(c)).unwrap();
    crm.archive(c_party.id).unwrap();
    let crm_emails: Vec<String> = store
        .contacts()
        .unwrap()
        .into_iter()
        .filter(|record| record.source == CRM_CONTACT_SOURCE)
        .flat_map(|record| record.emails)
        .collect();
    prop_assert!(
        !crm_emails.contains(&c.2),
        "an archived party is still in the index: {crm_emails:?}"
    );
    let body = turn(&message_with(&secrets(b)));
    prop_assert!(
        leaked(&body, &hidden(b)).is_empty(),
        "archive broke the live index: {body:?}"
    );
    Ok(())
}
