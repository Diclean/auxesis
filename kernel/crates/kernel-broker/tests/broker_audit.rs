//! End-to-end broker test: every decision lands in the store's
//! `tool.decision` stream with the expected JSON payload.

use async_trait::async_trait;
use kernel_broker::{
    Action, ApprovalDecision, ApprovalRequest, Approver, ApproverError, Authorization,
    AuthorizeRequest, Broker, ExecutionMode, MemoryAuditSink, Risk, Rule, SkillOnlyLookup, Taint,
    TaintSource, ANY, MAX_EDITED_ARGUMENTS_BYTES,
};
use serde_json::Value;
use std::sync::Arc;

/// This file's tests do not exercise the skill floor, but [`Broker::new`] has
/// no optional argument: a broker cannot be built without an answer to "is this
/// tool skill-only?". Here the answer is always no, so only a request's own
/// `skill_only` declaration raises the floor.
struct NoSkillOnlyTools;

impl SkillOnlyLookup for NoSkillOnlyTools {
    fn is_skill_only(&self, _tool: &str) -> bool {
        false
    }
}

/// The mandatory [`Broker::new`] argument for this file.
fn no_skill_only() -> Arc<dyn SkillOnlyLookup> {
    Arc::new(NoSkillOnlyTools)
}

/// A clean taint state with a `'static` lifetime, so the request helper below
/// can borrow it.
static CLEAN: Taint = Taint::Clean;

/// A clean, sandboxed request with no explicit-rule or skill context.
fn request<'a>(
    agent: &'a str,
    tool: &'a str,
    risk: Risk,
    arguments: Value,
) -> AuthorizeRequest<'a> {
    request_with(
        agent,
        tool,
        risk,
        arguments,
        &CLEAN,
        false,
        ExecutionMode::Sandboxed,
        false,
        false,
        None,
    )
}

/// The full request, in the order the old entry points took their arguments.
#[allow(clippy::too_many_arguments)]
fn request_with<'a>(
    agent: &'a str,
    tool: &'a str,
    risk: Risk,
    arguments: Value,
    taint: &'a Taint,
    read_only: bool,
    mode: ExecutionMode,
    requires_explicit_rule: bool,
    skill_only: bool,
    skill: Option<&'a kernel_broker::SkillRef>,
) -> AuthorizeRequest<'a> {
    AuthorizeRequest {
        agent,
        tool,
        risk,
        arguments,
        taint,
        read_only,
        mode,
        requires_explicit_rule,
        skill,
        skill_only,
    }
}

struct FixedApprover {
    answer: bool,
}

#[async_trait]
impl Approver for FixedApprover {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(self.answer)
    }
}

struct FailingApprover;

#[async_trait]
impl Approver for FailingApprover {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Err(ApproverError("no approval UI attached".to_string()))
    }
}

#[tokio::test]
async fn decisions_are_audited_with_json_payloads() {
    let sink = Arc::new(MemoryAuditSink::new());

    let rules = vec![
        Rule::new(ANY, ANY, Action::Deny),
        Rule::new("main", "shell", Action::Allow),
        Rule::new("main", "read_file", Action::Ask),
        Rule::new("main", "write_file", Action::Ask),
    ];
    let approving = Broker::new(
        sink.clone(),
        rules.clone(),
        Arc::new(FixedApprover { answer: true }),
        no_skill_only(),
    );
    let denying = Broker::new(
        sink.clone(),
        rules,
        Arc::new(FixedApprover { answer: false }),
        no_skill_only(),
    );

    // 1. allow rule.
    assert!(approving
        .authorize(request(
            "main",
            "shell",
            Risk::High,
            serde_json::Value::Null
        ))
        .await
        .unwrap()
        .is_allowed());
    // 2. ask, approved.
    assert!(approving
        .authorize(request(
            "main",
            "read_file",
            Risk::Low,
            serde_json::Value::Null
        ))
        .await
        .unwrap()
        .is_allowed());
    // 3. ask, denied.
    assert!(!denying
        .authorize(request(
            "main",
            "write_file",
            Risk::Medium,
            serde_json::Value::Null
        ))
        .await
        .unwrap()
        .is_allowed());
    // 4. deny rule for any agent/tool.
    assert!(matches!(
        denying
            .authorize(request(
                "work",
                "shell",
                Risk::High,
                serde_json::Value::Null
            ))
            .await
            .unwrap(),
        Authorization::Denied { .. }
    ));
    // 5. no matching rule: default ask, denied.
    let defaulting = Broker::new(
        sink.clone(),
        vec![],
        Arc::new(FixedApprover { answer: false }),
        no_skill_only(),
    );
    assert!(!defaulting
        .authorize(request(
            "scout",
            "shell",
            Risk::High,
            serde_json::Value::Null
        ))
        .await
        .unwrap()
        .is_allowed());
    // 6. ask whose approval channel fails: denied (fail closed).
    let failing = Broker::new(
        sink.clone(),
        vec![Rule::new("main", "read_file", Action::Ask)],
        Arc::new(FailingApprover),
        no_skill_only(),
    );
    assert!(!failing
        .authorize(request(
            "main",
            "read_file",
            Risk::Low,
            serde_json::Value::Null
        ))
        .await
        .unwrap()
        .is_allowed());

    assert_eq!(sink.count("tool.decision"), 6);

    let payloads = sink.payloads("tool.decision");
    assert_eq!(payloads.len(), 6);

    let allow = &payloads[0];
    assert_eq!(allow["agent"], "main");
    assert_eq!(allow["tool"], "shell");
    assert_eq!(allow["risk"], "high");
    assert_eq!(allow["action"], "allow");
    assert_eq!(allow["outcome"], "allowed");
    assert_eq!(allow["rule"], 1);
    assert!(allow.get("approved").is_none());
    assert!(allow.get("error").is_none());

    let approved = &payloads[1];
    assert_eq!(approved["action"], "ask");
    assert_eq!(approved["outcome"], "allowed");
    assert_eq!(approved["approved"], true);
    assert_eq!(approved["rule"], 2);
    assert!(approved["reason"].as_str().unwrap().contains("approved"));

    let denied = &payloads[2];
    assert_eq!(denied["action"], "ask");
    assert_eq!(denied["outcome"], "denied");
    assert_eq!(denied["approved"], false);
    assert_eq!(denied["rule"], 3);

    let rule_deny = &payloads[3];
    assert_eq!(rule_deny["agent"], "work");
    assert_eq!(rule_deny["action"], "deny");
    assert_eq!(rule_deny["outcome"], "denied");
    assert_eq!(rule_deny["rule"], 0);
    assert!(rule_deny.get("approved").is_none());

    let default_ask = &payloads[4];
    assert_eq!(default_ask["agent"], "scout");
    assert_eq!(default_ask["action"], "ask");
    assert_eq!(default_ask["outcome"], "denied");
    assert!(default_ask.get("rule").is_none());
    assert_eq!(default_ask["approved"], false);
    assert!(default_ask["reason"]
        .as_str()
        .unwrap()
        .contains("no matching rule"));

    let failed = &payloads[5];
    assert_eq!(failed["outcome"], "denied");
    assert_eq!(failed["approved"], false);
    assert!(failed["error"]
        .as_str()
        .unwrap()
        .contains("no approval UI attached"));
    assert!(failed["reason"].as_str().unwrap().contains("fail closed"));
}

#[tokio::test]
async fn edited_payload_hashes_are_stable_across_object_key_order() {
    let sink = Arc::new(MemoryAuditSink::new());
    let edited_first: Value =
        serde_json::from_str(r#"{"z":0,"nested":{"b":2,"a":1},"ratio":1.0,"a":9}"#).unwrap();
    let edited_second: Value =
        serde_json::from_str(r#"{"a":9,"ratio":1e0,"nested":{"a":1,"b":2},"z":0}"#).unwrap();
    let first = Broker::new(
        sink.clone(),
        vec![Rule::new("main", "write_file", Action::Ask)],
        Arc::new(EditingApprover {
            edited: edited_first,
        }),
        no_skill_only(),
    );
    let second = Broker::new(
        sink.clone(),
        vec![Rule::new("main", "write_file", Action::Ask)],
        Arc::new(EditingApprover {
            edited: edited_second,
        }),
        no_skill_only(),
    );

    for broker in [&first, &second] {
        assert!(broker
            .authorize(request_with(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::json!({"path":"out.txt"}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None
            ))
            .await
            .unwrap()
            .is_allowed());
    }

    let payloads = sink.payloads("tool.decision");
    assert_eq!(payloads.len(), 2);
    assert_eq!(
        payloads[0]["executed_args_sha256"], payloads[1]["executed_args_sha256"],
        "object order and equivalent numeric spellings must not change the digest"
    );
}

#[tokio::test]
async fn tainted_decisions_record_the_taint_and_its_source() {
    let sink = Arc::new(MemoryAuditSink::new());
    let broker = Broker::new(
        sink.clone(),
        vec![Rule::new("main", "shell", Action::Allow)],
        Arc::new(FixedApprover { answer: true }),
        no_skill_only(),
    );

    // Tainted: the allow rule is raised to ask, and the row carries it.
    let taint = Taint::Tainted(TaintSource::new(
        "http_fetch",
        Some("https://evil.example/page".to_string()),
    ));
    assert!(broker
        .authorize(request_with(
            "main",
            "shell",
            Risk::High,
            Value::Null,
            &taint,
            false,
            ExecutionMode::Sandboxed,
            false,
            false,
            None
        ))
        .await
        .unwrap()
        .is_allowed());

    let payloads = sink.payloads("tool.decision");
    assert_eq!(payloads.len(), 1);

    let tainted = &payloads[0];
    assert_eq!(tainted["action"], "ask", "an allow rule cannot auto-run");
    assert_eq!(tainted["rule"], 0);
    assert_eq!(tainted["outcome"], "allowed");
    assert_eq!(tainted["approved"], true);
    assert_eq!(tainted["tainted"], true);
    assert_eq!(tainted["mode"], "sandboxed");
    assert_eq!(
        tainted["taint_source"],
        "http_fetch: https://evil.example/page"
    );
    assert!(
        tainted["reason"].as_str().unwrap().contains("tainted"),
        "{}",
        tainted["reason"]
    );
}

#[tokio::test]
async fn unsandboxed_decisions_record_the_mode_and_force_the_ask() {
    // WS-C round 7: the mode is a first-class input. With a clean
    // conversation and an allow rule, an unsandboxed call must still be
    // raised to an ask on the first call, and the audit row must say so.
    let sink = Arc::new(MemoryAuditSink::new());
    let broker = Broker::new(
        sink.clone(),
        vec![Rule::new("main", "shell", Action::Allow)],
        Arc::new(FixedApprover { answer: false }),
        no_skill_only(),
    );

    assert!(!broker
        .authorize(request_with(
            "main",
            "shell",
            Risk::High,
            Value::Null,
            &Taint::Clean,
            false,
            ExecutionMode::Unsandboxed,
            false,
            false,
            None
        ))
        .await
        .unwrap()
        .is_allowed());

    let payloads = sink.payloads("tool.decision");
    assert_eq!(payloads.len(), 1);
    let row = &payloads[0];
    assert_eq!(
        row["action"], "ask",
        "an allow rule cannot auto-run an unsandboxed call"
    );
    assert_eq!(row["rule"], 0);
    assert_eq!(row["mode"], "unsandboxed");
    assert_eq!(row["outcome"], "denied");
    assert_eq!(row["tainted"], false);
    assert!(
        row["reason"].as_str().unwrap().contains("unsandboxed"),
        "{}",
        row["reason"]
    );
}

#[tokio::test]
async fn arguments_reach_the_approver_but_never_the_audit() {
    struct CapturingApprover {
        seen: std::sync::Mutex<Option<Value>>,
    }

    #[async_trait]
    impl Approver for CapturingApprover {
        async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
            *self.seen.lock().unwrap() = Some(request.arguments.clone());
            Ok(true)
        }
    }

    let sink = Arc::new(MemoryAuditSink::new());

    let approver = Arc::new(CapturingApprover {
        seen: std::sync::Mutex::new(None),
    });
    let broker = Broker::new(
        sink.clone(),
        vec![Rule::new("main", ANY, Action::Ask)],
        approver.clone(),
        no_skill_only(),
    );

    let secret = "TOP-SECRET-CANARY-9271";
    let arguments = serde_json::json!({"command": format!("echo {secret}")});
    assert!(broker
        .authorize(request("main", "shell", Risk::High, arguments.clone()))
        .await
        .unwrap()
        .is_allowed());

    // The approver saw the real arguments…
    assert_eq!(approver.seen.lock().unwrap().clone(), Some(arguments));

    // …but the audit trail stays metadata-only: the canary must not leak.
    let payloads = sink.payloads("tool.decision");
    assert_eq!(payloads.len(), 1);
    let raw = serde_json::to_string(&payloads).unwrap();
    assert!(!raw.contains(secret), "audit leaked arguments: {raw}");
}

/// An approver that answers every ask with an edited draft (the app's `edit`).
struct EditingApprover {
    edited: Value,
}

#[async_trait]
impl Approver for EditingApprover {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }

    async fn decide(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision, ApproverError> {
        Ok(ApprovalDecision::edited(self.edited.clone()))
    }
}

#[tokio::test]
async fn an_edited_draft_is_what_runs_and_both_payloads_are_hashed() {
    // An `edit` answer substitutes the payload: the broker authorizes the
    // draft, not the original request, and the audit names both payloads by
    // SHA-256 without ever storing either.
    let sink = Arc::new(MemoryAuditSink::new());

    let requested = serde_json::json!({"path": "out.txt", "content": "original"});
    let edited = serde_json::json!({"path": "edited.txt", "content": "edited body"});
    let broker = Broker::new(
        sink.clone(),
        vec![Rule::new("main", "write_file", Action::Ask)],
        Arc::new(EditingApprover {
            edited: edited.clone(),
        }),
        no_skill_only(),
    );

    let auth = broker
        .authorize(request_with(
            "main",
            "write_file",
            Risk::Medium,
            requested.clone(),
            &Taint::Clean,
            false,
            ExecutionMode::Sandboxed,
            false,
            false,
            None,
        ))
        .await
        .unwrap();
    assert!(auth.is_allowed());
    assert_eq!(
        auth.arguments(),
        Some(&edited),
        "the executed arguments must be the edited draft"
    );
    assert_ne!(
        auth.arguments(),
        Some(&requested),
        "the original request must not be what runs"
    );

    let payloads = sink.payloads("tool.decision");
    assert_eq!(payloads.len(), 1);
    let row = &payloads[0];
    assert_eq!(row["action"], "ask");
    assert_eq!(row["outcome"], "allowed");
    assert_eq!(row["approved"], true);
    let original_hash = row["original_args_sha256"].as_str().unwrap();
    let executed_hash = row["executed_args_sha256"].as_str().unwrap();
    assert_eq!(original_hash.len(), 64, "SHA-256 hex: {original_hash}");
    assert_eq!(executed_hash.len(), 64, "SHA-256 hex: {executed_hash}");
    assert_ne!(original_hash, executed_hash);
    // Metadata-only: neither payload leaks into the journal.
    let raw = serde_json::to_string(row).unwrap();
    assert!(!raw.contains("out.txt"), "audit leaked the request: {raw}");
    assert!(!raw.contains("edited.txt"), "audit leaked the draft: {raw}");
}

#[tokio::test]
async fn an_oversized_edited_draft_is_denied_and_traced() {
    // The same 4 KiB cap as a tool preview is a hard floor on an edit.
    let sink = Arc::new(MemoryAuditSink::new());

    let requested = serde_json::json!({"command": "echo original"});
    let edited = serde_json::json!({"command": "x".repeat(MAX_EDITED_ARGUMENTS_BYTES + 1)});
    let broker = Broker::new(
        sink.clone(),
        vec![Rule::new("main", "shell", Action::Ask)],
        Arc::new(EditingApprover {
            edited: edited.clone(),
        }),
        no_skill_only(),
    );

    let auth = broker
        .authorize(request_with(
            "main",
            "shell",
            Risk::High,
            requested.clone(),
            &Taint::Clean,
            false,
            ExecutionMode::Sandboxed,
            false,
            false,
            None,
        ))
        .await
        .unwrap();
    assert!(!auth.is_allowed(), "an oversized edit must be refused");

    let payloads = sink.payloads("tool.decision");
    assert_eq!(payloads.len(), 1);
    let row = &payloads[0];
    assert_eq!(row["outcome"], "denied");
    assert_eq!(row["approved"], true);
    assert_eq!(row["error"], "edited_arguments_too_large");
    assert!(row["original_args_sha256"].is_string());
    assert!(row["executed_args_sha256"].is_string());
}

#[test]
fn legacy_dot_rule_key_still_loads_as_agent() {
    // Rules saved before the rename say `"dot"`; they must still load.
    let rule = Rule::new("main", "shell", Action::Allow);
    let mut json = serde_json::to_value(&rule).unwrap();
    let object = json.as_object_mut().unwrap();
    let agent = object.remove("agent").unwrap();
    object.insert("dot".to_owned(), agent);
    let loaded: Rule = serde_json::from_value(json).unwrap();
    assert_eq!(loaded, rule);
}
