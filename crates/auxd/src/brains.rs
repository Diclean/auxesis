//! The `providers.toml` chain for a turn: brain choice, fallbacks and the
//! real Ledger sink.
//!
//! When `~/.auxesis/providers.toml` exists the turn resolves its provider
//! through [`aux_providers::build_chain`]: per-skill brain, else the agent's
//! brain, else `[brain] default`, with `[brain] fallback` hops admitted live.
//! When the file is absent the caller keeps the legacy `config.toml` path.

use std::path::Path;
use std::sync::{Arc, Mutex};

use aux_providers::{
    build_chain, find_entry, load_providers_for_home, resolve_brain, Catalog, ChatProvider,
    EntryKind, FallbackAdmission, FallbackLedger, ProviderEntry, PROVIDERS_FILE,
};
use aux_runtime::skills::{LoadedSkill, SkillBrain};
use aux_store::Store;
use kernel_core::privacy::ModeFn;

/// Why the `providers.toml` chain could not produce a provider.
#[derive(Debug, thiserror::Error)]
pub enum BrainError {
    /// The resolved model cannot use tools but the turn needs them, so the turn
    /// is refused with the `chat only` label before any request.
    #[error("{0}")]
    ChatOnly(String),
    /// The configuration or the adapter could not be built.
    #[error("{0}")]
    Provider(String),
}

/// The real Ledger sink: one `provider.fallback` event row per hop. Payloads
/// carry the hop only, never content.
pub struct StoreFallbackLedger {
    store: Arc<Mutex<Store>>,
}

impl StoreFallbackLedger {
    /// Write hop rows to `store`.
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }
}

impl FallbackLedger for StoreFallbackLedger {
    fn provider_fallback(&self, from: &str, to: &str, reason: &str) {
        let payload = serde_json::json!({
            "from": from,
            "to": to,
            "reason": reason,
        })
        .to_string();
        if let Err(err) =
            kernel_core::lock_recover(&self.store).log_event("provider.fallback", &payload)
        {
            tracing::warn!(error = %err, "provider.fallback ledger write failed");
        }
    }
}

/// True when anything is at this home's `providers.toml`: a link (dangling
/// too), a FIFO or a folder counts, and the load then refuses it. Only a
/// missing name is absent, so it never falls back to the legacy provider.
pub fn providers_toml_present(home: &Path) -> bool {
    let there = std::fs::symlink_metadata(home.join(PROVIDERS_FILE));
    !matches!(there, Err(err) if err.kind() == std::io::ErrorKind::NotFound)
}

/// The agent's own brain reference: the `<provider>` or `<provider>/<model>`
/// it pinned in `agent.toml`.
pub fn agent_brain(provider: Option<&str>, model: Option<&str>) -> Option<String> {
    match (provider, model) {
        (Some(provider), Some(model)) => Some(format!("{provider}/{model}")),
        (Some(provider), None) => Some(provider.to_string()),
        _ => None,
    }
}

/// The brain reference a skill's `brain:` field resolves to.
///
/// `Agent` inherits (the chain falls to the agent then the default); `none`
/// means no model runs; `cloud`/`local`/`fake` are hint names the
/// `[brain.hints]` table may map to a provider entry (`docs/providers.md` §3).
pub fn skill_brain(brain: SkillBrain) -> Option<&'static str> {
    match brain {
        SkillBrain::Agent => None,
        SkillBrain::None => Some("none"),
        SkillBrain::Cloud => Some("cloud"),
        SkillBrain::Local => Some("local"),
        SkillBrain::Fake => Some("fake"),
    }
}

/// The brain reference of the forced `/command` skill, when the turn names one.
pub fn forced_skill_brain(home: &Path, agent: &str, content: &str) -> Option<&'static str> {
    let runtime = aux_engine::skill_runtime::load_runtime_skills(home, agent, None);
    let skill = aux_engine::skill_runtime::command_skill(content, &runtime.skills)?;
    skill_brain(skill.brain)
}

/// The provider entry the brain resolves to, when `providers.toml` exists.
///
/// `None` means the file is absent or the brain is `none`. The caller reads the
/// kind to route an `acp` entry to the turn-level ACP path instead of building
/// a [`ChatProvider`].
pub fn resolved_entry(
    home: &Path,
    agent_brain: Option<&str>,
    skill_brain: Option<&str>,
) -> Result<Option<ProviderEntry>, BrainError> {
    if !providers_toml_present(home) {
        return Ok(None);
    }
    let file =
        load_providers_for_home(home).map_err(|err| BrainError::Provider(err.to_string()))?;
    let catalog = Catalog::bundled();
    match resolve_brain(&file, &catalog, agent_brain, skill_brain) {
        Ok(aux_providers::ResolvedBrain::Model { provider, .. }) => {
            Ok(find_entry(&file, &provider).cloned())
        }
        Ok(aux_providers::ResolvedBrain::None) => Ok(None),
        Err(err) => Err(BrainError::Provider(err.to_string())),
    }
}

/// The provider and model selected for the agent's default chat turn.
pub fn resolved_label(
    home: &Path,
    agent_brain: Option<&str>,
) -> Result<Option<(String, String)>, BrainError> {
    if !providers_toml_present(home) {
        return Ok(None);
    }
    let file =
        load_providers_for_home(home).map_err(|err| BrainError::Provider(err.to_string()))?;
    match resolve_brain(&file, &Catalog::bundled(), agent_brain, None) {
        Ok(aux_providers::ResolvedBrain::Model { provider, model }) => Ok(Some((provider, model))),
        Ok(aux_providers::ResolvedBrain::None) => Ok(None),
        Err(err) => Err(BrainError::Provider(err.to_string())),
    }
}

/// True when `entry` is an ACP agent, which is a turn-level backend.
pub fn is_acp(entry: &ProviderEntry) -> bool {
    entry.kind == EntryKind::Acp
}

/// True when the skill declares any tool that is not read-only.
///
/// An ACP brain cannot gate its tool calls per call, so it may run read-only
/// skills only (`docs/providers.md` §7). An unknown tool counts as a write.
pub fn skill_needs_write(skill: &LoadedSkill) -> bool {
    skill.tools.iter().any(|tool| {
        aux_runtime::skills::tool_map::lookup(tool)
            .map(|info| !info.is_read_only())
            .unwrap_or(true)
    })
}

/// What the `providers.toml` chain produced for a turn.
pub enum TurnChain {
    /// `providers.toml` is absent: the caller keeps the legacy path.
    Legacy,
    /// The resolved brain is `none`: no model runs, so no provider is built
    /// and no request is made.
    NoModel,
    /// A ready provider: one entry, or a fallback chain.
    Ready(Box<dyn ChatProvider>),
}

/// Build the turn's provider chain.
///
/// `Legacy` means `providers.toml` is absent (the caller keeps the
/// `config.toml` path). The primary provider is still wrapped in `GatedChat`
/// by the caller; this chain admits each fallback destination before its hop.
/// `admission` overrides the kernel admission (a test seam); `None` uses the
/// live kernel mode.
#[allow(clippy::too_many_arguments)] // the turn's full context, documented.
pub fn build_turn_chain(
    home: &Path,
    agent_brain: Option<&str>,
    skill_brain: Option<&str>,
    needs_tools: bool,
    store: &Arc<Mutex<Store>>,
    live: ModeFn,
    admission: Option<Arc<dyn FallbackAdmission>>,
) -> Result<TurnChain, BrainError> {
    if !providers_toml_present(home) {
        return Ok(TurnChain::Legacy);
    }
    let file =
        load_providers_for_home(home).map_err(|err| BrainError::Provider(err.to_string()))?;
    let catalog = Catalog::bundled();
    let ledger = Arc::new(StoreFallbackLedger::new(Arc::clone(store)));
    let admission: Arc<dyn FallbackAdmission> = match admission {
        Some(admission) => admission,
        None => Arc::new(aux_providers::KernelFallbackAdmission::new(live)),
    };
    match build_chain(
        &file,
        &catalog,
        home,
        ledger,
        Some(admission),
        agent_brain,
        skill_brain,
        needs_tools,
    ) {
        Ok(Some(provider)) => Ok(TurnChain::Ready(provider)),
        Ok(None) => Ok(TurnChain::NoModel),
        Err(aux_providers::BrainError::ChatOnly(chat)) => Err(BrainError::ChatOnly(format!(
            "{}: {chat}",
            aux_providers::ChatOnly::LABEL
        ))),
        Err(err) => Err(BrainError::Provider(err.to_string())),
    }
}

/// What a forced `brain: none` skill says when it cannot reach a mailbox.
pub const NO_MAILBOX: &str = "No mailbox is configured to collect receipts from.";

/// The chat path's stand-in for a forced `brain: none` skill. No model
/// runs and nothing leaves the Mac: the first round calls the skill with its
/// fixed fill, the next one reports the run's counts. The turn keeps its
/// executor, broker, Ledger rows and stored thread.
pub struct NoModelSkill {
    /// The skill call, or `None` when the skill cannot run (no mailbox).
    call: Option<aux_providers::ToolCall>,
}

impl NoModelSkill {
    /// The no-model run of the turn's forced `/command`, or `None` when the turn
    /// names no `brain: none` skill. `has_mailbox` answers whether this Mac has
    /// a mailbox to read; the collector reads every configured one.
    pub fn for_turn(
        home: &Path,
        agent: &str,
        content: &str,
        has_mailbox: impl FnOnce() -> bool,
    ) -> Option<Self> {
        let runtime = aux_engine::skill_runtime::load_runtime_skills(home, agent, None);
        let skill = aux_engine::skill_runtime::command_skill(content, &runtime.skills)?;
        if skill.brain != SkillBrain::None {
            return None;
        }
        let mut mailbox = Some(has_mailbox);
        let mut calls = Vec::new();
        for logical in &skill.effective_tools {
            let wire = aux_runtime::skills::tool_map::lookup(logical)?.wire;
            // The collector names no account: it reads every configured
            // mailbox, one after another.
            if logical == "docs.ingest" && !mailbox.take().map(|ask| ask()).unwrap_or(false) {
                return Some(Self { call: None });
            }
            let arguments = serde_json::json!({});
            calls.push(serde_json::json!({ "tool": wire, "arguments": arguments }));
        }
        let fill = serde_json::json!({ "slots": {}, "calls": calls });
        Some(Self {
            call: Some(aux_providers::ToolCall::new(
                "no-model-1",
                aux_runtime::skills::skill_tool_name(&skill.name),
                fill,
            )),
        })
    }
}

/// The owner's line for a finished run, from the skill tool's JSON result.
fn run_summary(result: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(result).unwrap_or_default();
    let text = |key: &str| value[key].as_str().unwrap_or("unknown").to_string();
    match value["outcome"].as_str() {
        Some("done") => {
            let (mut new, mut stored, mut skipped) = (0, 0, 0);
            for action in value["actions"].as_array().into_iter().flatten() {
                let report = &action["result"];
                new += report["new"].as_u64().unwrap_or(0);
                stored += report["deduplicated"].as_u64().unwrap_or(0);
                skipped += report["skipped"].as_array().map_or(0, Vec::len);
            }
            format!("Receipts collected: {new} new, {stored} already stored, {skipped} skipped.")
        }
        Some("refused") => format!("The collect did not run: {}.", text("reason")),
        Some("failed") => format!("The collect failed: {}.", text("error")),
        _ => "The collect did not finish.".to_string(),
    }
}

#[async_trait::async_trait]
impl ChatProvider for NoModelSkill {
    async fn complete(
        &self,
        req: &aux_providers::ChatRequest,
    ) -> Result<aux_providers::ChatResponse, aux_providers::ProviderError> {
        use aux_providers::{ChatMessage, ChatResponse, ChatRole};
        let Some(call) = &self.call else {
            return Ok(ChatResponse::assistant(NO_MAILBOX));
        };
        let turn = req
            .messages
            .iter()
            .rposition(|message| message.role() == ChatRole::User)
            .map_or(&req.messages[..], |at| &req.messages[at..]);
        match turn
            .iter()
            .rev()
            .find(|message| message.role() == ChatRole::Tool)
        {
            Some(result) => Ok(ChatResponse::assistant(run_summary(
                result.content().as_str(),
            ))),
            None => Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![call.clone()],
            ))),
        }
    }

    fn name(&self) -> &str {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A FIFO nobody writes to, a link or a dangling link at providers.toml
    /// refuses the provider at once, every reader alike, and never falls back
    /// to the legacy `config.toml` entry, which names another host.
    #[cfg(unix)]
    #[test]
    fn an_unusable_providers_toml_is_refused_and_never_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let (path, other) = (home.join(PROVIDERS_FILE), home.join("o.toml"));
        let entry = "[[provider]]\nid = \"p\"\nkind = \"openai\"\nmodels = [\"m\"]\n";
        let entry = format!("{entry}base_url = \"http://127.0.0.1:9/v1\"\n");
        std::fs::write(&other, format!("{entry}[brain]\ndefault = \"p/m\"\n")).unwrap();
        let legacy = "[[providers]]\nid = \"old\"\nkind = \"openai-compat\"\nmodel = \"m\"\n";
        let legacy = format!("{legacy}base_url = \"http://127.0.0.2:9/v1\"\n");
        std::fs::write(kernel_core::config_path(&home), legacy).unwrap();
        for kind in ["fifo", "link", "dangling"] {
            match kind {
                "fifo" => {
                    let made = std::process::Command::new("mkfifo").arg(&path).status();
                    assert!(made.unwrap().success());
                }
                "link" => std::os::unix::fs::symlink(&other, &path).unwrap(),
                _ => std::os::unix::fs::symlink(home.join("gone"), &path).unwrap(),
            }
            assert!(providers_toml_present(&home), "{kind}");
            let (moved, (sent, got)) = (home.clone(), std::sync::mpsc::channel());
            std::thread::spawn(move || {
                let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
                let live: ModeFn = Arc::new(|| kernel_core::privacy::PrivacyMode::Open);
                let chain = build_turn_chain(&moved, None, None, false, &store, live, None);
                let refused = matches!(chain, Err(BrainError::Provider(_)));
                let entry = resolved_entry(&moved, None, None).is_err();
                sent.send([refused, entry, resolved_label(&moved, None).is_err()])
            });
            let wait = std::time::Duration::from_secs(10);
            let got = got.recv_timeout(wait).expect("blocked");
            assert_eq!(got, [true; 3], "{kind}: refused, no fallback");
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::rename(&other, &path).unwrap();
        let brain = resolved_label(&home, None).unwrap();
        assert_eq!(brain, Some(("p".to_string(), "m".to_string())));
    }
}
