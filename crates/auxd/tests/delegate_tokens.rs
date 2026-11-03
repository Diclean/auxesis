//! TOK-DELEGATE acceptance: in private mode the chief hands Mail a task with
//! its own tokens. Mail keeps them whole for its model, its local mail search
//! gets the real value, and Mail's own tokens reach the owner as values.
//!
//! Names pass as written since NAMES-OFF (owner, 2026-10-19): the handed value
//! is an e-mail address.
//! (a) the mail search argument is the real address; no request body holds it.
//! (b) an address only Mail tokenised is shown to the owner as the address.
//! (c) a forged token (well-formed, never minted) is never rehydrated and
//!     never re-read as another kind.
//!
//! A real server on a loopback port, a scripted brain that records every
//! request, and fake mail tools. No network, Keychain or real home.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, ProviderError, ToolCall,
};
use auxd::api::{self, ApiHandle, ApiOptions, ToolRegistryHook};
use common::post;
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::config_path;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OPEN: char = '⟦';
const CLOSE: char = '⟧';

/// Well-formed, never minted by any session.
const FORGED: &str = "⟦PERSON_0123456789AB⟧";

/// The owner's ask: the address is the value a private turn hides.
const ASK: &str = "Find the mail from camille@exemple.fr";

const EXTRA: &str = "\n[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
model = \"fake-model\"\nkind = \"fake\"\n\n[ui]\nlanguage = \"en\"\n\n[connectors.mail]\n\n\
[[connectors.mail.accounts]]\nid = \"sim\"\nemail = \"owner@mailsim.test\"\n\n\
[connectors.mail.accounts.imap]\nhost = \"127.0.0.1\"\nport = 9\nsecurity = \"tls\"\n";

/// The first `⟦<kind>…⟧` reference of `text`.
fn first_token(text: &str, kind: &str) -> Option<String> {
    let start = text.find(&format!("{OPEN}{kind}"))?;
    let end = start + text[start..].find(CLOSE)? + CLOSE.len_utf8();
    Some(text[start..end].to_string())
}

/// The chief delegates the owner's first token (or `forge`, or nothing) to
/// Mail; Mail searches it and answers what it found; the chief repeats Mail's
/// answer. Each step reads only the messages after the last owner or task
/// text. A Mail task with no token replays the last token Mail was handed.
#[derive(Default)]
struct Script {
    forge: bool,
    bodies: StdMutex<Vec<String>>,
    handed: StdMutex<Option<String>>,
}

#[async_trait]
impl ChatProvider for Script {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        self.bodies
            .lock()
            .unwrap()
            .push(serde_json::to_string(&request.messages).unwrap());
        let chief = request
            .tools
            .iter()
            .any(|t| t.name().as_str() == "delegate");
        let messages = &request.messages;
        let last_user = messages.iter().rposition(|m| m.role() == ChatRole::User);
        let user = last_user.map_or(String::new(), |at| {
            messages[at].content().as_str().to_string()
        });
        let tool = messages[last_user.map_or(0, |at| at + 1)..]
            .iter()
            .filter(|m| m.role() == ChatRole::Tool)
            .map(|m| m.content().as_str().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let call = |name: &str, args: serde_json::Value| {
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new("call-1", name, args)],
            ))
        };
        let replay = if chief {
            None
        } else {
            match first_token(&user, "") {
                Some(token) => {
                    *self.handed.lock().unwrap() = Some(token);
                    None
                }
                None => self.handed.lock().unwrap().clone(),
            }
        };
        Ok(match (chief, tool.is_empty()) {
            (true, true) => {
                let who = match self.forge {
                    true => Some(FORGED.to_string()),
                    false => first_token(&user, "EMAIL_"),
                };
                let task = match who {
                    Some(who) => format!("Find the mail from {who}."),
                    None => "Find my newest mail.".to_string(),
                };
                call(
                    "delegate",
                    serde_json::json!({ "agent": "mail", "task": task }),
                )
            }
            (false, true) => {
                let who = first_token(&user, "").or(replay).unwrap_or("nobody".into());
                call("mail_search", serde_json::json!({ "from": who }))
            }
            (false, false) => match replay {
                Some(token) => ChatResponse::assistant(format!("Found: {tool} re {token}")),
                None => ChatResponse::assistant(format!("Found: {tool}")),
            },
            (true, false) => ChatResponse::assistant(format!("Mail says: {tool}")),
        })
    }

    fn name(&self) -> &str {
        "script"
    }
}

/// What every `mail_search` call actually received, per rig.
type Seen = Arc<StdMutex<Vec<serde_json::Value>>>;

/// Mail's search: records its arguments; its result names `found`.
struct FakeMailSearch {
    seen: Seen,
    found: &'static str,
}

#[async_trait]
impl Tool for FakeMailSearch {
    fn name(&self) -> &str {
        "mail_search"
    }
    fn schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": {"from": {"type": "string"}}})
    }
    async fn run(&self, args: &serde_json::Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
        self.seen.lock().unwrap().push(args.clone());
        Ok(ToolOutput::ok(self.found))
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

struct Rig {
    _dir: tempfile::TempDir,
    home: PathBuf,
    brain: Arc<Script>,
    seen: Seen,
    handle: ApiHandle,
}

impl Rig {
    fn start(forge: bool, found: &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home: PathBuf = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config = "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"private\"\n\n\
                      [[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"\n";
        std::fs::write(config_path(&home), config).unwrap();
        kernel_core::Config::load_or_create(&config_path(&home)).unwrap();
        let text = std::fs::read_to_string(config_path(&home)).unwrap() + EXTRA;
        std::fs::write(config_path(&home), text).unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        let seen: Seen = Arc::default();
        let hook_seen = Arc::clone(&seen);
        let tools: ToolRegistryHook = Arc::new(move |registry| {
            registry.register(Box::new(FakeMailSearch {
                seen: Arc::clone(&hook_seen),
                found,
            }));
            registry.mark_read_only("mail_search");
        });
        let brain = Arc::new(Script {
            forge,
            ..Script::default()
        });
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(Arc::clone(&brain) as Arc<dyn ChatProvider>),
            approval_timeout: Some(Duration::from_secs(30)),
            tools: Some(tools),
            ..ApiOptions::default()
        };
        let handle = api::spawn(&home, options).unwrap();
        let vcf = dir.path().join("contacts.vcf");
        let cards =
            "BEGIN:VCARD\nVERSION:3.0\nFN:Camille Exemple\nEMAIL:camille@exemple.fr\nEND:VCARD\n\
                     BEGIN:VCARD\nVERSION:3.0\nFN:Lena Muster\nEMAIL:lena@muster.test\nEND:VCARD\n";
        std::fs::write(&vcf, cards).unwrap();
        let body = serde_json::json!({ "path": vcf, "dry_run": false }).to_string();
        let imported = post(handle.addr(), "/v1/contacts/import", Some(TOKEN), &body);
        assert_eq!(imported.status, 200, "{}", imported.body);
        Self {
            _dir: dir,
            home,
            brain,
            seen,
            handle,
        }
    }

    /// The owner asks the chief; the answer as the app shows it.
    fn ask(&self, content: &str) -> String {
        let body = serde_json::json!({ "content": content }).to_string();
        let response = post(
            self.handle.addr(),
            "/v1/threads/aux/messages",
            Some(TOKEN),
            &body,
        );
        assert_eq!(response.status, 200, "{}", response.body);
        let json: serde_json::Value = response.json();
        let last = json["messages"].as_array().unwrap().last().unwrap().clone();
        last["content"].as_str().unwrap().to_string()
    }

    fn bodies(&self) -> Vec<String> {
        self.brain.bodies.lock().unwrap().clone()
    }

    fn assert_never_sent(&self, values: &[&str]) {
        let bodies = self.bodies();
        assert!(bodies.len() >= 4, "chief, Mail, Mail, chief: {bodies:#?}");
        for body in &bodies {
            for value in values {
                assert!(!body.contains(value), "{value:?} left the Mac: {body}");
            }
        }
    }
}

const FOUND: &str =
    "uid 7 · Invoice · from: Camille Exemple <camille@exemple.fr> · cc: Lena Muster";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mail_search_uses_the_real_address_and_hides_the_owner_mail_link() {
    let rig = Rig::start(false, FOUND);
    let answer = tokio::task::block_in_place(|| rig.ask(ASK));

    // (a) The local search ran on the value; Mail's model read the chief's
    // token verbatim, and no body holds an address.
    let seen = rig.seen.lock().unwrap().clone();
    assert_eq!(seen, [serde_json::json!({ "from": "camille@exemple.fr" })]);
    rig.assert_never_sent(&["camille@exemple.fr", "lena@"]);
    let bodies = rig.bodies();
    let owner_line = bodies[0]
        .split("Find the mail from ")
        .nth(1)
        .unwrap_or_default();
    let chief_token = first_token(owner_line, "EMAIL_").expect("the chief tokenised the address");
    assert!(
        bodies[1].contains(&format!("Find the mail from {chief_token}.")),
        "{}",
        bodies[1]
    );
    // The search result names the same address with the chief's token, so
    // Mail's model can match it to the task; the name stays as written.
    assert!(
        bodies[2].contains(&format!("from: Camille Exemple <{chief_token}>")),
        "{}",
        bodies[2]
    );
    // Every model is told to pass references on whole.
    assert!(bodies
        .iter()
        .all(|body| body.contains("# Private references")));

    // (b) Mail's own tokens come back as values.
    assert!(
        answer.contains("[camille@exemple.fr](mailto:[hidden])"),
        "{answer}"
    );
    assert!(
        !answer.contains(OPEN) && !answer.contains("[name"),
        "{answer}"
    );
}

/// LANG-DRIFT-1: the chief and the agent it delegates to are both told the
/// reply language, through the private gate, on every request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chief_and_the_delegated_agent_are_told_the_reply_language() {
    let rig = Rig::start(false, FOUND);
    tokio::task::block_in_place(|| rig.ask(ASK));
    let bodies = rig.bodies();
    assert!(bodies.len() >= 4, "chief, Mail, Mail, chief: {bodies:#?}");
    for body in &bodies {
        assert!(
            body.contains("Reply in the language of the message you are answering")
                && body.contains("if unsure, reply in English"),
            "{body}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_token_is_never_rehydrated_nor_read_as_another_kind() {
    let rig = Rig::start(true, FOUND);
    let answer = tokio::task::block_in_place(|| rig.ask(ASK));
    // The search never ran: an unknown token refuses the local call.
    assert!(
        rig.seen.lock().unwrap().is_empty(),
        "{:?}",
        rig.seen.lock().unwrap()
    );
    // Mail's model read the forged text whole, not masked into a new token.
    let bodies = rig.bodies();
    assert!(
        bodies[1].contains(&format!("Find the mail from {FORGED}.")),
        "{}",
        bodies[1]
    );
    rig.assert_never_sent(&["camille@exemple.fr"]);
    assert!(!answer.contains("camille@"), "{answer}");
}

/// Seal r1 P1: a handoff is one run's. The chief hands Mail its token in one
/// session; a token-free delegation from ANOTHER chief session, where Mail
/// replays that token, gets no value from it: the search refuses and the
/// second chief's owner never sees the name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handed_token_is_never_honoured_in_a_later_delegation() {
    let rig = Rig::start(false, FOUND);
    // The seal's seed: an Open-mode Mail chat, so every delegation reuses it.
    let config = config_path(&rig.home);
    let private = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        private.replace("mode = \"private\"", "mode = \"open\""),
    )
    .unwrap();
    let body = r#"{"content":"hello"}"#;
    let seeded = post(
        rig.handle.addr(),
        "/v1/threads/mail/messages",
        Some(TOKEN),
        body,
    );
    assert_eq!(seeded.status, 200, "{}", seeded.body);
    std::fs::write(&config, private).unwrap();
    let before = rig.seen.lock().unwrap().len();
    // The Open seed sent its text in clear, as Open does; Private starts here.
    let open_bodies = rig.bodies().len();
    tokio::task::block_in_place(|| rig.ask(ASK));
    assert_eq!(
        rig.seen.lock().unwrap().len(),
        before + 1,
        "the first search ran"
    );

    let store = aux_store::Store::open(&kernel_core::store_path(&rig.home)).unwrap();
    let other = store
        .create_session_of_kind("aux", Some("iMessage"), "chat")
        .unwrap()
        .id;
    let channel = rig.handle.channel_access();
    let record =
        tokio::task::block_in_place(|| channel.run_turn(other, "What is new in my mail?")).unwrap();
    let raw = record
        .messages
        .iter()
        .rfind(|m| m.role == "assistant")
        .unwrap()
        .content
        .clone();
    let shown = auxd::privacy_wiring::rehydrate_local(other, &raw);

    let seen = rig.seen.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        before + 1,
        "the replayed token reached the search: {seen:?}"
    );
    assert!(shown.starts_with("Mail says: Found: "), "{shown}");
    assert!(
        !shown.contains("camille@"),
        "the second chief adopted it: {shown}"
    );
    for body in &rig.bodies()[open_bodies..] {
        assert!(
            !body.contains("camille@"),
            "a Private request holds the address: {body}"
        );
    }
}
