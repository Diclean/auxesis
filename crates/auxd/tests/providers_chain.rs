//! The daemon resolves its provider through `providers.toml`.
//!
//! Every upstream is a loopback `TcpListener` fake: no real key, no real HOME,
//! no network. The tests drive `EngineTurnRunner::run_turn`, the same path the
//! API and the scheduler take.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aux_providers::{FallbackAdmission, ProviderError};
use aux_runtime::skills::SkillBrain;
use auxd::api::{EngineTurnRunner, TurnError, TurnRunner};
use auxd::brains::TurnChain;
use kernel_core::privacy::{admit_call, Destination, Grant, PathId, PrivacyMode};

const KEY_NAME: &str = "AUX_KEY_A4_CHAIN";

/// A loopback fake upstream that records each request and answers `responder`.
struct Upstream {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
    hits: Arc<AtomicUsize>,
}

impl Upstream {
    fn spawn<F>(responder: F) -> Self
    where
        F: Fn(&str) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback upstream");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (records, counts) = (Arc::clone(&requests), Arc::clone(&hits));
        let responder = Arc::new(responder);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let request = read_request(&mut stream);
                counts.fetch_add(1, Ordering::SeqCst);
                records.lock().unwrap().push(request.clone());
                let (status, body) = responder(&request);
                let reason = if status == 200 { "OK" } else { "Error" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            base,
            requests,
            hits,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let len = content_length(&head);
            while buf.len() < pos + 4 + len {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn request_line(raw: &str) -> &str {
    raw.lines().next().unwrap_or("")
}

fn request_body(raw: &str) -> &str {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

fn ok_answer(content: &str) -> (u16, String) {
    (
        200,
        format!(r#"{{"choices":[{{"message":{{"role":"assistant","content":"{content}"}}}}]}}"#),
    )
}

/// A home with `providers.toml`: `primary` then `fallback`, `[brain]` wiring
/// them, and optionally a key in the protected `.env`.
fn write_home(
    dir: &Path,
    primary: &Upstream,
    fallback: &Upstream,
    mode: &str,
    key: Option<&str>,
) -> PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join("agents/main")).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n"),
    )
    .unwrap();
    let key_line = key
        .map(|_| format!("key = \"env:{KEY_NAME}\"\n"))
        .unwrap_or_default();
    let providers = format!(
        "[[provider]]\nid = \"primary\"\nkind = \"openai\"\nbase_url = \"{}/v1\"\nmodels = [\"m\"]\n{key_line}\n\
         [[provider]]\nid = \"fallback\"\nkind = \"openai\"\nbase_url = \"{}/v1\"\nmodels = [\"m\"]\n{key_line}\n\
         [brain]\ndefault = \"primary/m\"\nfallback = [\"fallback/m\"]\n",
        primary.base, fallback.base
    );
    std::fs::write(home.join("providers.toml"), providers).unwrap();
    if let Some(key) = key {
        std::fs::write(home.join(".env"), format!("{KEY_NAME}={key}\n")).unwrap();
    }
    home
}

fn fallback_rows(home: &Path) -> Vec<String> {
    let store = aux_store::Store::open(&kernel_core::store_path(home)).expect("open the store");
    store.event_payloads("provider.fallback").unwrap()
}

#[test]
fn a_503_from_the_primary_falls_back_and_writes_the_ledger_hop_row() {
    let primary = Upstream::spawn(|_| (503, r#"{"error":{"message":"overloaded"}}"#.into()));
    let fallback = Upstream::spawn(|_| ok_answer("from fallback"));
    let dir = tempfile::tempdir().unwrap();
    let home = write_home(dir.path(), &primary, &fallback, "open", None);

    let turn = EngineTurnRunner::new(&home)
        .run_turn("main", None, "hello", None)
        .expect("the fallback answers");

    assert_eq!(turn.messages.last().unwrap().content, "from fallback");
    assert_eq!(primary.hits(), 1);
    assert_eq!(fallback.hits(), 1);
    let rows = fallback_rows(&home);
    assert_eq!(rows.len(), 1, "one provider.fallback row");
    assert!(
        rows[0].contains("\"from\":\"primary\"") && rows[0].contains("\"to\":\"fallback\""),
        "hop row: {}",
        rows[0]
    );
}

/// A real kernel admission on `A3`, which is `Disabled` in Private: a fallback
/// destination that must be refused without a send.
struct RefusingAdmission;

impl FallbackAdmission for RefusingAdmission {
    fn admit(&self, provider: &str, _path: PathId) -> Result<Option<Grant>, ProviderError> {
        admit_call(
            PathId::A3,
            PrivacyMode::Private,
            Destination::Vendor(provider.to_string()),
        )
        .map(Some)
        .map_err(|refused| ProviderError::PrivacyDisabled {
            provider: provider.to_string(),
            path: refused.path.as_str(),
        })
    }
}

#[test]
fn a_private_turn_with_a_non_admitted_fallback_sends_it_no_request() {
    let primary = Upstream::spawn(|_| (503, r#"{"error":{"message":"down"}}"#.into()));
    let fallback = Upstream::spawn(|_| ok_answer("must not run"));
    let dir = tempfile::tempdir().unwrap();
    let home = write_home(dir.path(), &primary, &fallback, "private", None);

    let err = EngineTurnRunner::new(&home)
        .with_fallback_admission(Arc::new(RefusingAdmission))
        .run_turn("main", None, "hello", None)
        .expect_err("the fallback is not admitted");

    let debug = format!("{err:?}");
    assert!(
        matches!(
            err,
            TurnError::PrivacyDisabled { .. } | TurnError::PrivacyWithheld { .. }
        ),
        "expected the admission refusal, got {debug}"
    );
    assert!(
        debug.contains("A3") || debug.to_lowercase().contains("private"),
        "the refusal must be the fallback admission: {debug}"
    );
    assert_eq!(
        fallback.hits(),
        0,
        "a refused fallback destination got a request"
    );
    assert!(
        fallback_rows(&home).is_empty(),
        "a refused hop writes no provider.fallback row"
    );
}

#[test]
fn a_canary_key_never_reaches_a_request_body_url_or_the_error() {
    const KEY: &str = "sk-a4-canary-daemon-0001";
    let primary =
        Upstream::spawn(|_| (400, format!(r#"{{"error":{{"message":"bad key {KEY}"}}}}"#)));
    let fallback = Upstream::spawn(|_| ok_answer("must not run"));
    let dir = tempfile::tempdir().unwrap();
    let home = write_home(dir.path(), &primary, &fallback, "open", Some(KEY));

    let err = EngineTurnRunner::new(&home)
        .run_turn("main", None, "hello", None)
        .expect_err("a 400 is an error");

    assert!(
        !err.to_string().contains(KEY),
        "the key leaked into the error: {err}"
    );
    assert!(
        !format!("{err:?}").contains(KEY),
        "the key leaked into Debug: {err:?}"
    );
    for raw in primary.requests() {
        assert!(
            !request_body(&raw).contains(KEY),
            "the key leaked into a request body"
        );
        assert!(
            !request_line(&raw).contains(KEY),
            "the key leaked into a request URL"
        );
    }
    // The key travels only in the Authorization header.
    let first = &primary.requests()[0];
    assert!(
        first
            .to_lowercase()
            .contains(&format!("authorization: bearer {}", KEY.to_lowercase())),
        "the key must be carried by the Authorization header"
    );
}

#[test]
fn a_chat_only_model_on_a_tool_turn_is_refused_with_chat_only() {
    let primary = Upstream::spawn(|_| ok_answer("must not run"));
    let fallback = Upstream::spawn(|_| ok_answer("must not run"));
    let dir = tempfile::tempdir().unwrap();
    let home = write_home(dir.path(), &primary, &fallback, "open", None);
    // The agent declares a tool, so the turn needs a tool-capable model. The
    // catalog does not list `primary/m`, so it is `tools = false`.
    std::fs::write(
        home.join("agents/main/agent.toml"),
        "tools = [\"google.gmail.search\"]\n",
    )
    .unwrap();

    let err = EngineTurnRunner::new(&home)
        .run_turn("main", None, "hello", None)
        .expect_err("a chat-only model is refused");

    match &err {
        TurnError::ProviderConfig { detail } => {
            assert!(detail.contains("chat only"), "detail: {detail}")
        }
        other => panic!("expected a chat-only refusal, got {other:?}"),
    }
    assert_eq!(primary.hits(), 0, "the gate runs before any request");
    assert_eq!(fallback.hits(), 0);
}

#[test]
fn without_providers_toml_the_legacy_single_provider_path_still_works() {
    let server = Upstream::spawn(|_| ok_answer("legacy"));
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        format!(
            "version = 1\n\n[privacy]\nmode = \"open\"\n\n\
             [[providers]]\nid = \"legacy\"\nbase_url = \"{}/v1\"\nmodel = \"m\"\nkind = \"openai-compat\"\n",
            server.base
        ),
    )
    .unwrap();

    let turn = EngineTurnRunner::new(&home)
        .run_turn("main", None, "hello", None)
        .expect("the legacy path answers");

    assert_eq!(turn.messages.last().unwrap().content, "legacy");
    assert_eq!(server.hits(), 1);
    assert!(
        !home.join("providers.toml").exists(),
        "no providers.toml is written"
    );
    if let Ok(store) = aux_store::Store::open(&kernel_core::store_path(&home)) {
        assert_eq!(
            store.event_count("provider.fallback").unwrap(),
            0,
            "the legacy path has no fallback hop"
        );
    }
}

/// Write an `agent.md` and one skill file so `load_runtime_skills` finds it.
fn write_agent_skill(home: &Path, file: &str, text: &str) {
    let dir = home.join("agents/main");
    std::fs::create_dir_all(dir.join("skills")).unwrap();
    std::fs::write(
        dir.join("agent.md"),
        "---\nname: main\nbrain: cloud\ntools: [docs.ingest]\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nBody.\n",
    )
    .unwrap();
    std::fs::write(dir.join("skills").join(file), text).unwrap();
}

const NONE_SKILL: &str = r#"---
name: collect-receipts
version: 1
command: collect-receipts
brain: none
trigger:
  manual: true
tools: [docs.ingest]
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Collect.
"#;

const FAKE_SKILL: &str = r#"---
name: fake-skill
version: 1
command: fakeskill
brain: fake
trigger:
  manual: true
tools: [docs.ingest]
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Body.
"#;

/// C1's `brain: none`: no model, so the chain builds no provider at all.
#[test]
fn a_skill_with_brain_none_builds_no_provider_and_makes_no_request() {
    let primary = Upstream::spawn(|_| ok_answer("must not run"));
    let fallback = Upstream::spawn(|_| ok_answer("must not run"));
    let dir = tempfile::tempdir().unwrap();
    let home = write_home(dir.path(), &primary, &fallback, "open", None);
    write_agent_skill(&home, "collect-receipts.md", NONE_SKILL);

    let dir = home.join("agents/main");
    let agent = aux_runtime::skills::agent::load_agent(&dir).expect("agent.md loads");
    let load = aux_runtime::skills::load_skills(&dir, &agent, None);
    assert!(load.errors.is_empty(), "skill errors: {:?}", load.errors);
    assert_eq!(load.skills.len(), 1, "the skill loads");
    assert_eq!(load.skills[0].brain, SkillBrain::None);
    let skill_brain = auxd::brains::skill_brain(load.skills[0].brain);
    assert_eq!(skill_brain, Some("none"));

    let store = Arc::new(Mutex::new(
        aux_store::Store::open(&kernel_core::store_path(&home)).unwrap(),
    ));
    let chain = auxd::brains::build_turn_chain(
        &home,
        None,
        skill_brain,
        true,
        &store,
        Arc::new(|| PrivacyMode::Open),
        None,
    )
    .expect("the chain resolves");

    assert!(
        matches!(chain, TurnChain::NoModel),
        "brain: none must build no provider"
    );
    assert_eq!(primary.hits(), 0, "no model, so no request");
    assert_eq!(fallback.hits(), 0);
}

/// C1's per-skill `brain:` mapped by `[brain.hints]` to a providers.toml entry.
#[test]
fn a_skill_brain_mapped_by_a_hint_uses_the_mapped_entry() {
    let primary = Upstream::spawn(|_| ok_answer("primary"));
    let fallback = Upstream::spawn(|_| ok_answer("fallback"));
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("agents/main")).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    std::fs::write(
        home.join("providers.toml"),
        format!(
            "[[provider]]\nid = \"primary\"\nkind = \"openai\"\nbase_url = \"{}/v1\"\nmodels = [\"m\"]\n\n\
             [[provider]]\nid = \"fallback\"\nkind = \"openai\"\nbase_url = \"{}/v1\"\nmodels = [\"m\"]\n\n\
             [brain]\ndefault = \"primary/m\"\nhints = {{ fake = \"fallback/m\" }}\n",
            primary.base, fallback.base
        ),
    )
    .unwrap();
    write_agent_skill(&home, "fake-skill.md", FAKE_SKILL);

    let dir = home.join("agents/main");
    let agent = aux_runtime::skills::agent::load_agent(&dir).expect("agent.md loads");
    let load = aux_runtime::skills::load_skills(&dir, &agent, None);
    assert!(load.errors.is_empty(), "skill errors: {:?}", load.errors);
    assert_eq!(load.skills.len(), 1, "the skill loads");
    assert_eq!(load.skills[0].brain, SkillBrain::Fake);
    let skill_brain = auxd::brains::skill_brain(load.skills[0].brain);
    assert_eq!(skill_brain, Some("fake"));

    let store = Arc::new(Mutex::new(
        aux_store::Store::open(&kernel_core::store_path(&home)).unwrap(),
    ));
    let chain = auxd::brains::build_turn_chain(
        &home,
        None,
        skill_brain,
        false,
        &store,
        Arc::new(|| PrivacyMode::Open),
        None,
    )
    .expect("the chain resolves");

    let TurnChain::Ready(provider) = chain else {
        panic!("expected the mapped provider entry");
    };
    assert_eq!(provider.name(), "fallback");
}
