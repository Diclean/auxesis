//! AGENT-HISTORY-BLEED acceptance: a delegated agent's history belongs to the
//! chief thread that asked. Two turns in chief thread A: Mail's second request
//! still holds the first task. A new chief thread B: Mail's request holds
//! nothing from A.
//!
//! A real server on a loopback port and a scripted brain that records every
//! request. No network, Keychain or real home.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, ProviderError, ToolCall,
};
use auxd::api::{self, ApiHandle, ApiOptions};
use common::post;
use kernel_core::config_path;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const EXTRA: &str = "\n[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
model = \"fake-model\"\nkind = \"fake\"\n\n[ui]\nlanguage = \"en\"\n";

/// The chief hands the owner's text to Mail as the task, then repeats Mail's
/// answer; Mail answers the task. Mail's requests are recorded.
#[derive(Default)]
struct Script {
    mail: StdMutex<Vec<String>>,
}

#[async_trait]
impl ChatProvider for Script {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let chief = request
            .tools
            .iter()
            .any(|t| t.name().as_str() == "delegate");
        let messages = &request.messages;
        let last_user = messages.iter().rposition(|m| m.role() == ChatRole::User);
        let user = last_user.map_or(String::new(), |at| {
            messages[at].content().as_str().to_string()
        });
        if !chief {
            self.mail
                .lock()
                .unwrap()
                .push(serde_json::to_string(messages).unwrap());
            return Ok(ChatResponse::assistant(format!("Mail did: {user}")));
        }
        let tool = messages[last_user.map_or(0, |at| at + 1)..]
            .iter()
            .filter(|m| m.role() == ChatRole::Tool)
            .map(|m| m.content().as_str().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(match tool.is_empty() {
            true => ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new(
                    "call-1",
                    "delegate",
                    serde_json::json!({ "agent": "mail", "task": user }),
                )],
            )),
            false => ChatResponse::assistant(format!("Mail says: {tool}")),
        })
    }

    fn name(&self) -> &str {
        "script"
    }
}

struct Rig {
    _dir: tempfile::TempDir,
    brain: Arc<Script>,
    handle: ApiHandle,
}

impl Rig {
    fn start(mode: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home: PathBuf = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config = format!(
            "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"{mode}\"\n\n\
             [[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"\n"
        );
        std::fs::write(config_path(&home), config).unwrap();
        aux_engine::config::load_or_create(&config_path(&home)).unwrap();
        let text = std::fs::read_to_string(config_path(&home)).unwrap() + EXTRA;
        std::fs::write(config_path(&home), text).unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        let brain = Arc::new(Script::default());
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(Arc::clone(&brain) as Arc<dyn ChatProvider>),
            approval_timeout: Some(Duration::from_secs(30)),
            ..ApiOptions::default()
        };
        let handle = api::spawn(&home, options).unwrap();
        Self {
            _dir: dir,
            brain,
            handle,
        }
    }

    /// The owner asks the chief in its current thread.
    fn ask(&self, content: &str) {
        let body = serde_json::json!({ "content": content }).to_string();
        let response = post(
            self.handle.addr(),
            "/v1/threads/aux/messages",
            Some(TOKEN),
            &body,
        );
        assert_eq!(response.status, 200, "{}", response.body);
    }

    /// The owner starts a new chief thread.
    fn new_chat(&self) {
        let response = post(self.handle.addr(), "/v1/threads/aux/new", Some(TOKEN), "{}");
        assert_eq!(response.status, 200, "{}", response.body);
    }

    fn mail_requests(&self) -> Vec<String> {
        self.brain.mail.lock().unwrap().clone()
    }
}

fn a_new_chief_thread_starts_mail_fresh(mode: &str) {
    let rig = Rig::start(mode);
    rig.ask("Latest mail from Pineapple Alpha");
    rig.ask("And the one before from Quince Alpha");
    rig.new_chat();
    rig.ask("Same question as before?");

    let mail = rig.mail_requests();
    assert_eq!(mail.len(), 3, "one Mail request per chief turn: {mail:#?}");
    // Same chief thread: Mail's second turn still sees its first.
    assert!(mail[1].contains("Pineapple Alpha"), "{}", mail[1]);
    // New chief thread: nothing from thread A reaches Mail's brain.
    for marker in ["Pineapple", "Quince", "Alpha", "Mail did"] {
        assert!(
            !mail[2].contains(marker),
            "{marker:?} bled into B: {}",
            mail[2]
        );
    }
    assert!(mail[2].contains("Same question as before?"), "{}", mail[2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_mode_new_chief_thread_starts_mail_fresh() {
    tokio::task::block_in_place(|| a_new_chief_thread_starts_mail_fresh("open"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_mode_new_chief_thread_starts_mail_fresh() {
    tokio::task::block_in_place(|| a_new_chief_thread_starts_mail_fresh("private"));
}
