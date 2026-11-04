//! Probe floor: every known evasion input, on the
//! real path of a delegated tool result: owner → chief gate → handed token →
//! Mail's search → sanitizer → gate → carry (retokenize) → gate → provider.
//! - `no_worse_than_main::*`: no raw run of a marked value (card, IBAN, ID, key,
//!   address, health term, phone) is in any serialised provider request.
//! - `atomic_goal::*` (ignored, the target): in Mail's view each value is one
//!   placeholder of its own, exact on restore; the owner reads the result whole.
//!
//! Values are marked `«…»`, all fictional; key-shaped ones are built at run time.

mod common;

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, ProviderError, ToolCall,
};
use aux_runtime::executor::TokenResolver;
use auxd::api::{self, ApiOptions, ToolRegistryHook};
use common::post;
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::config_path;
use serde_json::json;

const THREAD: &str = "/v1/threads/aux/messages";
/// Built here so the source holds no key-shaped literal.
fn token() -> String {
    "0123456789abcdef".repeat(4)
}
const CONFIG: &str = "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"private\"\n\n\
[[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"\n\n[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
model = \"fake-model\"\nkind = \"fake\"\n\n[ui]\nlanguage = \"en\"\n\n[connectors.mail]\n\n\
[[connectors.mail.accounts]]\nid = \"sim\"\nemail = \"owner@mailsim.test\"\n\n\
[connectors.mail.accounts.imap]\nhost = \"127.0.0.1\"\nport = 9\nsecurity = \"tls\"\n";
/// Shortest raw run of a value that counts as a leak.
const RUN: usize = 7;

/// Chief or not, the messages, every string of the serialised request.
type Body = (bool, Vec<(ChatRole, String)>, Vec<String>);

/// The string leaves of `value` (tool-call arguments are JSON values too).
fn leaves(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => out.push(text.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|v| leaves(v, out)),
        serde_json::Value::Object(map) => map.values().for_each(|v| leaves(v, out)),
        _ => {}
    }
}

/// The first `⟦…⟧` of `text`.
fn first_token(text: &str) -> Option<String> {
    let start = text.find('⟦')?;
    let end = start + text[start..].find('⟧')? + '⟧'.len_utf8();
    Some(text[start..end].to_string())
}

/// Chief: delegate the owner's first token (or nothing) to Mail, then repeat
/// Mail. Mail: search the task's token, then answer what it found.
#[derive(Default)]
struct Script {
    bodies: StdMutex<Vec<Body>>,
}

#[async_trait]
impl ChatProvider for Script {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let chief = request
            .tools
            .iter()
            .any(|t| t.name().as_str() == "delegate");
        let messages: Vec<(ChatRole, String)> = request
            .messages
            .iter()
            .map(|m| (m.role(), m.content().as_str().to_string()))
            .collect();
        let mut strings = Vec::new();
        leaves(&serde_json::to_value(request).unwrap(), &mut strings);
        (self.bodies.lock().unwrap()).push((chief, messages.clone(), strings));
        let at = messages.iter().rposition(|(r, _)| *r == ChatRole::User);
        let handed = at.and_then(|at| first_token(&messages[at].1));
        let tool: Vec<&str> = messages[at.map_or(0, |at| at + 1)..]
            .iter()
            .filter(|(r, _)| *r == ChatRole::Tool)
            .map(|(_, text)| text.as_str())
            .collect();
        let call = |name: &str, args: serde_json::Value| {
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new("call-1", name, args)],
            ))
        };
        Ok(match (chief, tool.is_empty()) {
            (true, true) => {
                let task = match handed {
                    Some(token) => format!("Find the mail about {token}."),
                    None => "Find my newest mail.".to_string(),
                };
                call("delegate", json!({ "agent": "mail", "task": task }))
            }
            (false, true) => call("mail_search", json!({ "from": handed })),
            (false, false) => ChatResponse::assistant(format!("Found: {}", tool.join("\n"))),
            (true, false) => ChatResponse::assistant(format!("Mail says: {}", tool.join("\n"))),
        })
    }

    fn name(&self) -> &str {
        "script"
    }
}

/// Mail's search: always returns the probe.
struct FakeMailSearch(String);

#[async_trait]
impl Tool for FakeMailSearch {
    fn name(&self) -> &str {
        "mail_search"
    }
    fn schema(&self) -> serde_json::Value {
        json!({"type": "object", "properties": {"from": {"type": "string"}}})
    }
    async fn run(&self, _: &serde_json::Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(self.0.clone()))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B19
    }
    fn class(&self) -> ToolClass {
        ToolClass::default()
    }
}

/// `text` without its `«…»` marks, and the ranges of the values they mark.
fn marked(text: &str) -> (String, Vec<Range<usize>>) {
    let (mut out, mut values) = (String::new(), Vec::new());
    for (at, part) in text.split(['«', '»']).enumerate() {
        if at % 2 == 1 {
            values.push(out.len()..out.len() + part.len());
        }
        out.push_str(part);
    }
    (out, values)
}

/// One owner turn on a fresh private home: every provider request and the
/// answer as the app shows it.
fn run(owner: &str, found: &str) -> (Vec<Body>, String) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), CONFIG).unwrap();
    std::fs::write(api::token_path(&home), format!("{}\n", token())).unwrap();
    let found = found.to_string();
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register(Box::new(FakeMailSearch(found.clone())));
        registry.mark_read_only("mail_search");
    });
    let brain = Arc::new(Script::default());
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::clone(&brain) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(30)),
        tools: Some(tools),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    let body = json!({ "content": owner }).to_string();
    let response = post(handle.addr(), THREAD, Some(&token()), &body);
    assert_eq!(response.status, 200, "{}", response.body);
    let json: serde_json::Value = response.json();
    let last = json["messages"].as_array().unwrap().last().unwrap();
    let answer = last["content"].as_str().unwrap_or_default().to_string();
    let bodies = brain.bodies.lock().unwrap().clone();
    // Each request's agent and its last message: a short chain shows where it stopped.
    let steps: Vec<String> = bodies
        .iter()
        .map(|(chief, messages, _)| {
            let (role, text) = messages
                .last()
                .cloned()
                .unwrap_or((ChatRole::User, String::new()));
            let text: String = text.chars().take(120).collect();
            format!("{} {role:?}: {text}", if *chief { "chief" } else { "Mail" })
        })
        .collect();
    assert!(
        bodies.len() >= 4,
        "chief, Mail, Mail, chief: {}\n{}",
        bodies.len(),
        steps.join("\n")
    );
    handle.shutdown();
    drop(dir);
    (bodies, answer)
}

/// Lower-case letters, digits and `@` of `text`, every `⟦…⟧` dropped: a value
/// split by blanks, dots, slashes or dashes reads as one run.
fn compact(text: &str) -> String {
    let (mut out, mut inside) = (String::new(), false);
    for c in text.chars() {
        match c {
            '⟦' => inside = true,
            '⟧' => inside = false,
            c if !inside && (c.is_alphanumeric() || c == '@') => out.extend(c.to_lowercase()),
            _ => {}
        }
    }
    out
}

/// Group A: no provider request holds a raw run of [`RUN`] characters of a
/// marked value, in the owner's text or the search result.
fn floor(owner: &str, found: &str) {
    let (owner_text, owner_values) = marked(owner);
    let (found_text, found_values) = marked(found);
    let (bodies, _) = run(&owner_text, &found_text);
    let values = owner_values.iter().map(|r| &owner_text[r.clone()]);
    let values = values.chain(found_values.iter().map(|r| &found_text[r.clone()]));
    for value in values {
        let core = compact(value);
        let chars: Vec<char> = core.chars().collect();
        for text in bodies.iter().flat_map(|body| &body.2) {
            let seen = compact(text);
            for run in chars.windows(RUN.min(chars.len())) {
                let run: String = run.iter().collect();
                assert!(!seen.contains(&run), "{value:?} left raw: {text}");
            }
        }
    }
}

/// Every pair a session of this process minted (one home per process).
fn minted() -> BTreeMap<String, String> {
    let stores = (1..=32).map(aux_engine::skill_runtime::session_tokens);
    stores
        .flat_map(|s| kernel_core::sync::lock_recover(&s).pairs())
        .collect()
}

/// Group B: in Mail's view of the result each value is one placeholder of its
/// own that restores its exact bytes, and the owner reads it back whole.
fn goal(owner: &str, found: &str) {
    let (found_text, values) = marked(found);
    let source = kernel_broker::sanitize_external_text(&found_text, 128 * 1024);
    assert_eq!(source, found_text, "the sanitizer keeps the probe");
    let (bodies, answer) = run(&marked(owner).0, &found_text);
    let mail = bodies.iter().filter(|b| !b.0).flat_map(|b| b.1.iter());
    let mut tool = mail.filter(|(r, _)| *r == ChatRole::Tool);
    let (_, view) = tool.next_back().expect("Mail read the result");
    let pairs = minted();
    let (mut found, mut at, mut rest) = (Vec::new(), 0, view.as_str());
    while let Some(c) = rest.chars().next() {
        let (step, skip) = if rest.starts_with("⟦⟦") {
            ('⟦'.len_utf8(), 2 * '⟦'.len_utf8())
        } else if let Some(body) = rest.strip_prefix('⟦') {
            let token = &body[..body.find('⟧').expect("a placeholder closes")];
            let value = &pairs[token];
            let shown = source.get(at..at + value.len());
            assert_eq!(shown, Some(value.as_str()), "{token}: {view}");
            found.push((token, at..at + value.len()));
            (value.len(), token.len() + 2 * '⟦'.len_utf8())
        } else {
            assert!(source[at..].starts_with(c), "{view:?} is not {source:?}");
            (c.len_utf8(), c.len_utf8())
        };
        at += step;
        rest = &rest[skip..];
    }
    assert_eq!(at, source.len(), "{view}");
    let overlap = |a: &Range<usize>, b: &Range<usize>| a.start < b.end && b.start < a.end;
    for value in &values {
        let shown = &source[value.clone()];
        let hits: Vec<_> = found.iter().filter(|(_, r)| overlap(r, value)).collect();
        assert_eq!(hits.len(), 1, "{shown:?} split into {hits:?}: {view}");
        let (token, range) = hits[0];
        let inside = range.start <= value.start && value.end <= range.end;
        assert!(inside, "{shown:?}: {view}");
        let held = values.iter().filter(|other| overlap(range, other)).count();
        assert_eq!(held, 1, "{token} holds {held} values: {view}");
    }
    let whole = format!("Mail says: Found: {source}");
    assert_eq!(answer, whole, "the owner's copy");
}

/// A long URL right before a value.
fn p() -> String {
    format!("https://e.test/{}/", "x".repeat(110))
}

/// A fictional key, built here so the source holds no key-shaped literal.
fn key() -> String {
    let letters: String = ('A'..='Z').collect();
    format!("{}-{letters}0123456789", "sk")
}

const CARD: &str = "Find the mail about card «4111 1111 1111 1111»";
const DIGITS: &str = "4111111111111111";

/// The sweep of values (its IP address left out: not a covered class).
const VALUES: &str = concat!(
    "4111111111111111|4111 1111 1111 1111|4111-1111-1111-1111|4111.1111.1111.1111|",
    "4111/1111/1111/1111|4012888888881881|5555 5555 5555 4444|FR7630006000011234567890189|",
    "FR76 3000 6000 0112 3456 7890 189|DE89370400440532013000|DE89 3704 0044 0532 0130 00|",
    "+33 6 12 34 56 78|+33612345678|06 12 34 56 78|06.12.34.56.78",
);

/// Each sweep value beside the next one (often its other spelling), in one of
/// four wrappers.
fn sweep() -> Vec<(String, String)> {
    let values = VALUES.split('|');
    let wrappers = [
        (p(), String::new()),
        ("Mara Quell ".repeat(8), String::new()),
        (" ".repeat(150), " ".repeat(150)),
        (format!("mara.{}+", "q".repeat(150)), "@e.test".to_string()),
    ];
    let pairs = values.clone().zip(values.cycle().skip(1));
    let cases = pairs
        .zip(wrappers.iter().cycle())
        .map(|((a, b), (before, after))| {
            let found = format!("{before}«{a}»{after} and {before}«{b}»{after}");
            (NEWEST.to_string(), found)
        });
    cases.collect()
}

fn one(owner: &str, found: String) -> Vec<(String, String)> {
    vec![(owner.to_string(), found)]
}

/// Each case in a process of its own: gate keys and session token stores are
/// process-wide, keyed by session id, so two homes in one process share them
/// (a test artifact: one daemon has one home). The child runs case `KAT2_CASE`.
fn isolated(test: &str, cases: Vec<(String, String)>, check: fn(&str, &str)) {
    if let Ok(at) = std::env::var("KAT2_CASE") {
        let (owner, found) = &cases[at.parse::<usize>().unwrap()];
        return tokio::task::block_in_place(|| check(owner, found));
    }
    for at in 0..cases.len() {
        if let Err(log) = child(test, at) {
            panic!("case {at} of {test}: {log}");
        }
    }
}

/// Run case `at` of `test` in a sandboxed child, killed after two minutes: it
/// passes only when exactly that one test ran and passed.
fn child(test: &str, at: usize) -> Result<(), String> {
    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let log_path = dir.path().join("child.log");
    let home = dir.path().join(".auxesis");
    let mut command = common::sandbox_command(exe.to_str().unwrap(), dir.path(), &home);
    command
        .args([test, "--exact", "--include-ignored", "--test-threads=1"])
        .env("KAT2_CASE", at.to_string())
        .stdout(std::fs::File::create(&log_path).unwrap())
        .stderr(std::process::Stdio::null());
    let mut child = common::KillOnDrop::new(command.spawn().unwrap());
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break status,
            None if std::time::Instant::now() > deadline => return Err("killed at 120 s".into()),
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let one = log.contains("test result: ok. 1 passed; 0 failed;");
    (status.success() && one).then_some(()).ok_or(log)
}

/// A child whose filter matches no test fails: a renamed probe never greens.
#[test]
fn a_child_that_runs_no_test_fails() {
    let log = child("no_worse_than_main::no_such_probe", 0).unwrap_err();
    assert!(log.contains("0 passed"), "{log}");
}

macro_rules! probes {
    ($($name:ident: $cases:expr;)*) => {
        mod no_worse_than_main {
            use super::*;
            $(#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $name() {
                isolated(concat!("no_worse_than_main::", stringify!($name)), $cases, floor);
            })*
        }
        mod atomic_goal {
            use super::*;
            $(#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[ignore = "KERNEL-ATOMIC-2 target"]
            async fn $name() {
                isolated(concat!("atomic_goal::", stringify!($name)), $cases, goal);
            })*
        }
    };
}

const NEWEST: &str = "Find my newest mail.";

probes! {
    // One placeholder for two values behind a long URL.
    r1_slashed_and_plain_card: one(NEWEST, format!("{0}«4222222222222/006» and {0}«4222222222222006»", p()));
    r1_two_passport_spellings: one(NEWEST, format!("{0}Q/«QXZ1234567» and {0}QQ/«XZ1234567»", p()));
    r1_two_cards_one_slash: one(NEWEST, format!("{}«4123456789012349»/«4532015112830366»", p()));
    // Each split before.
    url_then_card_twice: one(NEWEST, format!("https://e.test/{0}«4111111111111111» and https://e.test/{0}«4012888888881881»", "x".repeat(98)));
    names_then_iban: one(NEWEST, format!("{}«FR7630006000011234567890189»", "Mara Quell ".repeat(8)));
    card_pairs_126_spaces_apart: one(NEWEST, format!("pay «{}» now", ["41", "23", "45", "67", "89", "01", "23", "49"].join(&" ".repeat(126))));
    health_term_in_a_url: one(NEWEST, format!("see {}«chemotherapy»/notes", p()));
    two_cards_a_blank_apart: one(NEWEST, "«4111111111111111» «4012888888881881»".into());
    phone_two_spellings_one_slash: one(NEWEST, "«06.12.34.56.78»/«06 12 34 56 78»".into());
    values_in_wrappers: sweep();
    // A handed card or key met in another spelling.
    r2_handed_card_spaced_and_plain: one(CARD, format!("«4111 1111 1111 1111» and «{DIGITS}»"));
    r2_handed_key_and_its_lowercase: one(&format!("Find the mail with key «{}»", key()), format!("«{}» and «{}»", key(), key().to_lowercase()));
    // A handed address as two passwords; a key with a tail.
    r3_handed_address_as_two_passwords: one("Find the mail from «Mara@Quell.test»", "password=«Mara@Quell.test»\npassword=«mara@quell.test»".into());
    r3_handed_key_and_key_with_tail: one(&format!("Find the mail with key «{}»", key()), format!("«{0}» and «{0}-extra»", key()));
    r3_unlisted_suffix_token_beside_an_address: one("Find the mail from «mara@quell.test»", "⟦EMAIL_SECRET_012345678901⟧ wrote from «mara@quell.test»".into());
    // A card before slash or dot digits.
    r4_card_then_slash_digits: one(NEWEST, format!("«{DIGITS}»/1/2/3/4/5"));
    r4_card_then_dot_digits: one(NEWEST, format!("«{DIGITS}».1.2.3.4.5"));
    r4_dotted_digit_run: one(NEWEST, "«4.2.2.2-222.22.22.22»".into());
    // The handed card in odd whitespace, or between digits.
    r5_handed_card_double_spaced: one(CARD, format!("«{}»", DIGITS.chars().map(String::from).collect::<Vec<_>>().join("  ")));
    r5_handed_card_triple_newlines: one(CARD, "«4111\n\n\n1111\n\n\n1111\n\n\n1111»".into());
    r5_spaced_card_between_digits: one(NEWEST, "7/«4111 1111 1111 1111»/9".into());
    // A handed ID or IBAN met lower-cased in odd whitespace.
    r6_handed_id_lowercase_spaced: one("Find the mail about passport «QXZ1234567»", "«qxz  1234567»".into());
    r6_handed_iban_lowercase_newlines: one("Find the mail about IBAN «FR76 3000 6000 0112 3456 7890 189»", format!("«{}»", "fr76 3000 6000 0112 3456 7890 189".replace(' ', "\n\n\n")));
}
