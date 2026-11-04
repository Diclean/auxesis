//! In Private only the owner-account tools named in the engine's allowlist get
//! real values. An MCP tool, a web tool and a known owner-account name mounted
//! on another path keep the tokens.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aux_engine::{ChatSession, ChatSetup};
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, ProviderError, ToolCall,
};
use aux_store::{Store, StoreHandle};
use kernel_broker::{
    Action, Risk, Rule, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, ToolRegistry,
};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::{ModeFn, PathId, PrivacyMode};
use kernel_core::ContextConfig;
use kernel_privacy::ContactIndex;
use serde_json::{json, Value};

const NAME: &str = "Camille Exemple";
/// Names pass in Private; the address is the value.
const ADDRESS: &str = "camille@exemple.fr";

type Seen = Arc<Mutex<Vec<(String, Value)>>>;

/// Records what it was called with.
struct Probe {
    name: &'static str,
    path: PathId,
    seen: Seen,
}

#[async_trait]
impl Tool for Probe {
    fn name(&self) -> &str {
        self.name
    }
    fn schema(&self) -> Value {
        json!({"type": "object", "properties": {"q": {"type": "string"}}})
    }
    async fn run(&self, args: &Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
        self.seen
            .lock()
            .unwrap()
            .push((self.name.to_string(), args.clone()));
        Ok(ToolOutput::ok("nothing found"))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn path_id(&self) -> PathId {
        self.path
    }
    fn class(&self) -> ToolClass {
        ToolClass::default()
    }
}

/// Calls every probe once with the owner's first token, then answers.
struct Script(&'static [&'static str]);

#[async_trait]
impl ChatProvider for Script {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        if req.messages.iter().any(|m| m.role() == ChatRole::Tool) {
            return Ok(ChatResponse::assistant("done"));
        }
        let user = req
            .messages
            .iter()
            .rfind(|m| m.role() == ChatRole::User)
            .map(|m| m.content().as_str().to_string())
            .unwrap_or_default();
        let start = user.find("⟦EMAIL_").expect("the address is a token");
        let end = start + user[start..].find('⟧').unwrap() + '⟧'.len_utf8();
        let token = &user[start..end];
        let calls = self
            .0
            .iter()
            .enumerate()
            .map(|(i, name)| ToolCall::new(format!("call-{i}"), *name, json!({ "q": token })))
            .collect();
        Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
            "", calls,
        )))
    }
    fn name(&self) -> &str {
        "script"
    }
}

struct ApproveAll;

#[async_trait]
impl kernel_broker::Approver for ApproveAll {
    async fn approve(
        &self,
        _: &kernel_broker::ApprovalRequest,
    ) -> Result<bool, kernel_broker::ApproverError> {
        Ok(true)
    }
}

#[tokio::test]
async fn mcp_and_web_tools_keep_tokens_and_only_allowlisted_tools_get_the_value() {
    const PROBES: &[(&str, PathId)] = &[
        ("mcp_probe", PathId::B13),
        ("web_probe", PathId::B6),
        // A known owner-account name on another path is not on the allowlist.
        ("mail_search", PathId::B14),
        ("mail_read", PathId::B19),
    ];
    let dir = tempfile::tempdir().unwrap();
    let home: PathBuf = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let seen: Seen = Arc::default();
    let mut registry = ToolRegistry::new();
    let mut rules = Vec::new();
    for (name, path) in PROBES {
        registry.register(Box::new(Probe {
            name,
            path: *path,
            seen: Arc::clone(&seen),
        }));
        registry.mark_read_only(*name);
        rules.push(Rule::new("main", *name, Action::Allow));
    }
    let mut contacts = ContactIndex::new();
    assert!(contacts.add_from_header(NAME, ADDRESS).is_some());
    let names: Vec<&str> = PROBES.iter().map(|(name, _)| *name).collect();
    let provider = Script(Box::leak(names.into_boxed_slice()));
    let mode: ModeFn = Arc::new(|| PrivacyMode::Private);
    let (budgets, prices) = (Budgets::default(), PriceTable::default());
    let mut session = ChatSession::start(ChatSetup {
        store: StoreHandle::Shared(Arc::clone(&store)),
        provider: &provider,
        registry: Arc::new(std::sync::RwLock::new(registry)),
        rules,
        approver: Arc::new(ApproveAll),
        agent: "main".to_string(),
        home,
        mode,
        contacts: Arc::new(contacts),
        skills: Vec::new(),
        budgets: &budgets,
        prices: &prices,
        context: ContextConfig::default(),
        title: None,
        stop: None,
        cancel: None,
        session_id: None,
        events: None,
        run_id: None,
    })
    .unwrap();
    session
        .send(&format!("Look up {ADDRESS} everywhere."))
        .await
        .unwrap();

    let seen = seen.lock().unwrap().clone();
    let got = |name: &str| -> String {
        let (_, args) = seen.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
            panic!("{name} never ran: {seen:?}");
        });
        args["q"].as_str().unwrap().to_string()
    };
    for name in ["mcp_probe", "web_probe", "mail_search"] {
        let arg = got(name);
        assert!(arg.starts_with("⟦EMAIL_"), "{name} got {arg:?}");
        assert!(!arg.contains("camille@"), "{name} got the value");
    }
    assert_eq!(got("mail_read"), ADDRESS);
}
