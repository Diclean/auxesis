//! Starting one chat session: the store session, the soul, the privacy
//! gate and the broker. Everything a turn needs is set up here, once,
//! before the first provider call.

use super::approvals::PreApproved;
use super::context::{bounded_window, hydrate_message, is_state_line};
use super::privacy::{report_minted, withheld_marker, withhold_history};
use super::taint::private_history_tool;
use super::{validate_agent, ChatError, ChatSession, ChatSetup, ToolGate, MAX_TOOL_ROUNDS};
use crate::outbound::session_gate;
use crate::prompt::{build_system_prompt_with_skills, issue_system_prompt, issue_tool_specs};
use crate::soul::{self, SoulStatus};
use aux_providers::{ChatMessage, ChatRole, ProviderError, SafeMessage};
use aux_runtime::executor::{RecipientDirectory, SkillConnector};
use aux_store::{Message, Session, StoreHandle};
use kernel_broker::{Broker, Taint, TaintSource, ToolCtx, ToolRegistry};
use kernel_core::privacy::{admit_call, Destination, ModeFn, PathId, PrivacyMode};
use kernel_core::Lang;
use kernel_net::{WebBudget, WebGate};
use kernel_privacy::safetext::{Gate, GateError};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex, PoisonError, RwLockReadGuard};

/// The ids of the agents under `<home>/agents`, plus `agent`, for the gate's
/// non-person terms. Bounded: at most 64 directory entries are read.
fn configured_agent_ids(home: &std::path::Path, agent: &str) -> Vec<String> {
    let mut ids = vec![agent.to_string()];
    if let Ok(entries) = std::fs::read_dir(crate::soul::agents_dir(home)) {
        ids.extend(
            entries
                .flatten()
                .take(64)
                .filter_map(|entry| entry.file_name().into_string().ok()),
        );
    }
    ids
}

/// hook recognizes even when the tool is no longer registered. A row without
/// a readable tool name is not classified here; its taint stays fail-closed.
/// The broker's audit sink: the turn's shared store. A borrowed store cannot
/// back it, because the kernel sink must be `Send + Sync`.
fn audit_sink(store: &StoreHandle<'_>) -> Result<Arc<dyn kernel_broker::AuditSink>, ChatError> {
    store.audit_sink().ok_or(ChatError::SharedStoreRequired)
}

impl<'a> ChatSession<'a> {
    /// The turn's tools, read live. A poisoned lock is recovered: the registry
    /// is only read here, never left half-written.
    pub(super) fn registry(&self) -> RwLockReadGuard<'_, ToolRegistry> {
        self.registry.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Create the store session, load (or create) the soul, make sure the
    /// workspace exists, and persist the system prompt.
    ///
    /// With [`ChatSetup::session_id`] set, the turn appends to that existing
    /// session instead: a **bounded** page of its history is hydrated into
    /// the conversation (E-13 — persisted history is never deleted) and the
    /// system prompt is only (re)persisted when the session has none.
    pub fn start(setup: ChatSetup<'a>) -> Result<Self, ChatError> {
        validate_agent(&setup.agent)?;
        // Before any store access: past the stop no session starts, so none of
        // its rows (session, system prompt, private marks) is written. A start
        // already in flight is waited for by the stop.
        let _in_flight = super::budget::admitted()?;
        // The mode and the names are read once, here. With no contacts the
        // private gate still tokenises every pattern value; it never refuses.
        let mode = (setup.mode)();
        let home = setup.home.clone();
        let names =
            aux_runtime::known_names::names_for(&setup.contacts).map_err(GateError::from)?;

        let soul = soul::load_or_create(&setup.home, &setup.agent);
        let workspace = soul::workspace_dir(&setup.home, &setup.agent);
        // SANDBOX-GATEWAY-EXEMPT: legacy engine agent workspace, path-based by design; tracked for the gateway follow-up.
        std::fs::create_dir_all(&workspace)?;
        let workspace_key = crate::workspace::workspace_key(&workspace);
        let registry = setup
            .registry
            .read()
            .unwrap_or_else(PoisonError::into_inner);

        // Today's date is part of the turn's context: the model needs it to turn
        // "tomorrow 10:00" into an RFC 3339 time, and to know which days
        // "this week" names (CAL-THIS-WEEK). Read once per session start.
        let today = aux_runtime::today::date_context_now();
        let system_prompt =
            build_system_prompt_with_skills(&soul.content, &setup.skills, &registry, &today);
        // The tool context carries the turn's cancellation token so a tool
        // whose future may be dropped (the shell process tree) can clean up
        // cooperatively as well as through its own Drop guard.
        // It also carries the mode the turn's gate runs under, for a tool that
        // starts another turn: the mode read here is its floor, and the live
        // handle may only tighten it.
        let live_mode = Arc::clone(&setup.mode);
        let turn_mode: ModeFn = Arc::new(move || mode.max(live_mode()));
        let ctx = ToolCtx::new(&setup.agent, workspace)
            .with_cancel(setup.cancel.clone())
            .with_run_id(setup.run_id.clone())
            .with_turn_mode(turn_mode);

        // The bounded context: the newest `max_messages` rows (never the whole
        // session), the one system prompt, and every tool row's *metadata*
        // (taint reconstruction never needs content, and a bounded window must
        // not launder an old untrusted call away).
        let max_messages = setup.context.max_messages.max(1);
        let raw_text = crate::private::raw_text_allowed(mode);
        let keep_history = crate::private::history_allowed(mode);
        let (session, window, system_row, tool_rows, remembered) = match setup.session_id {
            Some(id) => {
                let session = setup
                    .store
                    .with(|store| store.session(id))?
                    .ok_or(ChatError::SessionMissing { id })?;
                let (window, _has_more) = setup
                    .store
                    .with(|store| store.list_messages_limited(id, None, max_messages))?;
                let system_row = setup.store.with(|store| store.session_system_message(id))?;
                let tool_rows = setup.store.with(|store| store.list_tool_rows(id))?;
                // A private conversation's history is in memory, not in the store.
                let remembered = if raw_text {
                    None
                } else {
                    crate::private::recall(&home, session.id)
                };
                (session, window, system_row, tool_rows, remembered)
            }
            None => {
                let title = if raw_text {
                    setup.title.as_deref()
                } else {
                    None
                };
                (
                    setup
                        .store
                        .with(|store| store.create_session(&setup.agent, title))?,
                    Vec::new(),
                    None,
                    Vec::new(),
                    None,
                )
            }
        };

        // CONV-PRIVATE-MIX: a chat that ever ran a Private turn is never
        // listed in Conversations. The mark is written **before** the turn
        // runs and is never cleared, so a cancelled or crashed Private turn
        // still hides the chat; switching back to Open later does not bring
        // it back. `raw_text` is false exactly in Private mode (C7 is
        // disabled there), so this is the one place the turn's mode is known.
        if !raw_text {
            setup
                .store
                .with(|store| store.mark_session_ever_private(session.id))?;
        }

        // Taint is the one-way ratchet of this conversation, rebuilt from
        // three persisted sources:
        // - completed tool rows (text is never inspected);
        // - a write-ahead mark for an untrusted call that never completed
        //   (cancelled, timed out or crashed mid-run);
        // - the workspace mark: outside content touched this workspace, so
        //   every conversation starting here is tainted until the owner
        //   clears it.
        let mut taint = match &remembered {
            Some(conversation) => conversation.taint.clone(),
            None => crate::taint::from_history(&tool_rows, &registry),
        };
        if let Some(mark) = setup.store.with(|store| store.session_taint(session.id))? {
            taint.record(TaintSource::new(mark.tool, mark.detail));
        }
        if let Some(source) = setup
            .store
            .with(|store| store.workspace_taint(&workspace_key))?
        {
            taint.record(TaintSource::new("workspace", Some(source)));
        }

        // The private-data egress rule is sticky like taint: once a turn of
        // this conversation read mail, calendar, memory or notes, every later
        // turn of the same `session_id` restores the flag from the store, so
        // an `http_fetch` cannot silently carry private text in a URL the
        // model composed. The flag used to live only in the session struct
        // and reset on each inbound turn.
        let stored_mark = setup
            .store
            .with(|store| store.session_private_data(session.id))?;
        let remembered_mark = remembered
            .as_ref()
            .is_some_and(|conversation| conversation.carries_private_data);
        let carries_private_data = remembered_mark
            || match stored_mark {
                Some(_) => true,
                // Legacy backfill: a conversation that read private owner data
                // before the marker covered that tool (for example Apple Calendar
                // or Reminders) has its tool rows but no marker row. Derive the
                // marker from the history now, persist it, and only then accept
                // egress. Unknown names never clear it: they simply do not set it.
                None => match tool_rows
                    .iter()
                    .find_map(|row| private_history_tool(row, &registry))
                {
                    Some(tool) => {
                        setup
                            .store
                            .with(|store| store.mark_session_private_data(session.id, &tool))?;
                        true
                    }
                    None => false,
                },
            };

        // Exactly one system prompt per session, tracked separately from the
        // bounded window. A marked state line is the exception and reaches the
        // model: Resume lifts a stop the model has already acknowledged.
        let window: Vec<Message> = window
            .into_iter()
            .filter(|message| message.role != "system" || is_state_line(message))
            .collect();
        if system_row.is_none() && raw_text {
            setup
                .store
                .with(|store| store.append_message(session.id, "system", &system_prompt, None))?;
        }
        // Every outbound value is issued by this session's gate. The provider's
        // system prompt is composed from the current soul, skills and tools, piece
        // by piece: application text is trusted, owner text is gated. The stored
        // system row is one string that cannot be split, so it is never sent. A
        // stored message the gate refuses becomes a fixed marker in the
        // provider-bound copy only: the start goes on, and the stored row is left
        // as it is.
        // The gate runs under the provider path the turn admits, in the mode read
        // at the start: a path closed in that mode stops the turn here.
        let provider_name = setup.provider.name().to_string();
        let grant = admit_call(PathId::A2, mode, Destination::Vendor(provider_name.clone()))
            .map_err(|refused| ProviderError::PrivacyDisabled {
                provider: provider_name.clone(),
                path: refused.path.as_str(),
            })?;
        // The assistant's own names are never a person: `Aux`, `Auxesis` (the
        // kernel's built-ins) and the ids of the agents this home configures.
        let mut gate = session_gate(session.id, &grant, names)?
            .with_non_person_terms(configured_agent_ids(&setup.home, &setup.agent))
            .with_non_person_terms(aux_runtime::grants::DOMAIN_AGENTS);
        // Application-authored text — the fixed system-prompt sentences and a
        // native tool's declaration — is `'static` and carries no private data,
        // so it is issued under the kernel's passthrough policy: the detector
        // still runs (a secret-shaped constant is removed) but the person
        // tokeniser never mints a name in it. The owner's and a server's bytes
        // stay on the session gate above, under the live mode. `for_passthrough`
        // refuses a tokenising grant, so this cannot silently become a masking
        // path if the admission below changes.
        let app_grant = admit_call(
            PathId::A2,
            PrivacyMode::Open,
            Destination::Vendor(provider_name.clone()),
        )
        .map_err(|refused| ProviderError::PrivacyDisabled {
            provider: provider_name,
            path: refused.path.as_str(),
        })?;
        let mut app_gate = Gate::for_passthrough(&app_grant)?;
        let sink = audit_sink(&setup.store)?;
        // The agent's runtime skills: advertised as `skill__<name>` tools and
        // routed to the executor. A load error is logged through the store's
        // sink and the skill is not offered.
        let runtime = crate::skill_runtime::load_runtime_skills(
            &setup.home,
            &setup.agent,
            Some(sink.as_ref()),
        );
        let tool_specs = issue_tool_specs(&mut gate, &mut app_gate, &registry)?;
        // Every part of a skill spec is built from the skill file, never from a
        // `'static` constant, so it stays on the tokenising session gate.
        let skill_specs = crate::skill_runtime::skill_specs(&mut gate, &runtime.skills)?;
        // The session's token map outlives the turn: a later turn of the same
        // session can still rehydrate what an earlier turn minted.
        let skill_tokens = crate::skill_runtime::session_tokens(session.id);
        let system = match issue_system_prompt(
            &mut gate,
            &mut app_gate,
            &soul.content,
            &setup.skills,
            &registry,
            &today,
        ) {
            Ok(message) => message,
            Err(_) => SafeMessage::from_text(
                ChatRole::System,
                gate.text(withheld_marker(Lang::from_env()))?.0,
            ),
        };
        let (issued, withheld) = match &remembered {
            Some(conversation) => (
                conversation
                    .messages
                    .iter()
                    .filter(|message| message.role() != ChatRole::System)
                    .cloned()
                    .collect::<Vec<SafeMessage>>(),
                0,
            ),
            None => {
                let stored = bounded_window(window, &setup.context);
                let history: Vec<ChatMessage> = stored.iter().filter_map(hydrate_message).collect();
                // PRIVATE-TRANSCRIPT: a private thread read back from the store
                // holds the tokenised copy the provider saw. Its token table
                // comes back with it, and those tokens stay whole, so the rows
                // go out as they did; a value in clear is still masked.
                let kept = if raw_text {
                    Vec::new()
                } else {
                    setup.store.with(|store| store.session_tokens(session.id))?
                };
                kernel_core::sync::lock_recover(&skill_tokens).record(&kept);
                if let (false, Some(events)) = (kept.is_empty(), setup.events.as_deref()) {
                    events.session_tokens(session.id, &kept);
                }
                let tokens = kernel_core::sync::lock_recover(&skill_tokens).tokens();
                gate.keep_session_tokens((!kept.is_empty()).then(|| Arc::new(tokens)));
                let issued = withhold_history(&mut gate, &history);
                gate.keep_session_tokens(None);
                issued?
            }
        };
        let minted = report_minted(&mut gate, setup.events.as_deref(), session.id);
        kernel_core::sync::lock_recover(&skill_tokens).record(&minted);
        if withheld > 0 {
            tracing::warn!(withheld, "stored messages replaced by the privacy marker");
        }
        let messages: Vec<SafeMessage> = std::iter::once(system).chain(issued).collect();

        // H-02 (calibration) deliberately does **not** seed an `allow` rule
        // for read-only tools here. The broker's no-rule default is already
        // "allow a declared read-only tool", but only while the turn is
        // untainted ([`Broker::authorize_call_with_taint`]); seeding a rule
        // would match *before* that guard and let a tainted turn read
        // without a card, weakening the taint bar. The operator's `[[rules]]`
        // are passed through untouched, so an explicit deny/ask still wins.

        let approver = Arc::clone(&setup.approver);
        let rules = setup.rules.clone();
        Ok(Self {
            agent: setup.agent,
            session,
            messages: Arc::new(messages),
            gate,
            tool_specs,
            provider: setup.provider,
            store: setup.store.clone(),
            registry: Arc::clone(&setup.registry),
            broker: Broker::new(
                Arc::clone(&sink),
                setup.rules,
                setup.approver,
                setup.registry.clone(),
            ),
            taint,
            web: WebGate::new(registry.web_config().clone()),
            web_budget: Arc::new(Mutex::new(WebBudget::new())),
            web_seen_origins: BTreeSet::new(),
            carries_private_data,
            raw_text,
            keep_history,
            gate_mode: mode,
            home,
            window_limit: max_messages,
            current_owner_input: None,
            current_owner_row_id: None,
            inherited_owner_words: None,
            input_source: None,
            local_rows: std::sync::atomic::AtomicI64::new(0),
            workspace_key,
            ctx,
            max_rounds: MAX_TOOL_ROUNDS,
            soul_status: soul.status,
            budgets: setup.budgets,
            prices: setup.prices,
            stop: setup.stop,
            cancel: setup.cancel,
            events: setup.events,
            run_id: setup.run_id,
            runtime_skills: runtime.skills,
            skill_specs,
            skill_allowlist: runtime.allowlist,
            sink: Arc::clone(&sink),
            skill_broker: Broker::new(
                Arc::clone(&sink),
                rules,
                Arc::new(PreApproved),
                setup.registry.clone(),
            ),
            approver,
            skill_connector: None,
            skill_ran_this_turn: AtomicBool::new(false),
            read_nudge_at: None,
            save_nudge_at: None,
            tool_gates: Vec::new(),
            card_expiries: None,
            card_expired: None,
            skill_recipients: None,
            skill_tokens,
            inherited: None,
            handoff: crate::handoff::Handoff::default(),
            #[cfg(test)]
            day_source: None,
            #[cfg(test)]
            budget: None,
        })
    }

    /// TOK-DELEGATE: take the caller's handoff for this run (`crate::handoff`).
    /// The pairs live in this run only, never in the session's table or
    /// display. An open session takes none: its task is in clear.
    pub fn inherit_tokens(&mut self, handoff: &crate::handoff::Handoff) {
        if !handoff.is_private() || self.gate_mode != kernel_core::privacy::PrivacyMode::Private {
            return;
        }
        self.inherited = Some(Arc::new(handoff.kept.clone()));
        self.handoff = handoff.clone();
    }

    /// Inject the connector that runs a skill's write calls.
    pub fn with_skill_connector(mut self, connector: Arc<dyn SkillConnector>) -> Self {
        self.skill_connector = Some(connector);
        self
    }

    /// Count this turn's expired approval cards with `counter` (auxd's approver
    /// increments it): a card nobody answers ends the turn with an honest line.
    pub fn with_card_expiries(mut self, counter: Arc<AtomicUsize>) -> Self {
        self.card_expiries = Some(counter);
        self
    }

    /// Offer `tool` only in rounds where `gate` says yes. The tool refuses a
    /// call itself; this keeps a switched-off tool out of later rounds.
    pub fn with_tool_gate(mut self, tool: &str, gate: ToolGate) -> Self {
        self.tool_gates.push((tool.to_string(), gate));
        self
    }

    /// DELEGATION-SOURCE-1: stamp this turn's own input row with the source
    /// that says who wrote it (`delegation` for a task the chief handed to an
    /// agent). The row keeps its role; the source rides in its metadata, so
    /// an old reader still sees the same thread.
    pub fn with_input_source(mut self, source: &str) -> Self {
        self.input_source = Some(source.to_string());
        self
    }

    /// Give a non-owner turn the live owner's words for local checks only.
    pub fn with_owner_words(mut self, words: Option<String>) -> Self {
        self.inherited_owner_words = words;
        self
    }

    /// Inject the directory the `known-contacts` recipient policy reads.
    pub fn with_skill_recipients(mut self, directory: Arc<dyn RecipientDirectory>) -> Self {
        self.skill_recipients = Some(directory);
        self
    }

    /// The store session this run reads and writes.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Address of the shared conversation buffer (test seam for E-13: every
    /// round must reuse one allocation, never deep-copy it).
    #[cfg(test)]
    pub(crate) fn context_arc_ptr(&self) -> usize {
        Arc::as_ptr(&self.messages) as usize
    }

    /// Current conversation taint state.
    ///
    /// The model can never change this; only running an untrusted-output
    /// tool (or resuming a session that already did, or starting in a
    /// touched workspace) can move it, and only a new conversation in a
    /// trusted workspace resets it.
    pub fn taint(&self) -> &Taint {
        &self.taint
    }

    /// True once the conversation read private owner data (mail, calendar,
    /// memory, notes). Sticky for the conversation: reading is silent, but an
    /// unseen web host asks from then on.
    pub fn carries_private_data(&self) -> bool {
        self.carries_private_data
    }

    /// Origins (`scheme://host:port`) already fetched in this conversation
    /// (tests and diagnostics).
    pub fn web_seen_origins(&self) -> &BTreeSet<String> {
        &self.web_seen_origins
    }

    /// The per-turn and per-day fetch counters (tests only).
    #[cfg(test)]
    pub(super) fn web_budget_counts(&self) -> (u32, u32) {
        let budget = match self.web_budget.lock() {
            Ok(budget) => budget,
            Err(poisoned) => poisoned.into_inner(),
        };
        (budget.turn_count(), budget.day_count())
    }

    /// Where the agent's soul text came from.
    pub fn soul_status(&self) -> &SoulStatus {
        &self.soul_status
    }

    /// The privacy mode the session's gate was built under.
    pub fn gate_mode(&self) -> kernel_core::privacy::PrivacyMode {
        self.gate_mode
    }
}

#[cfg(test)]
mod tests {
    use super::super::testsupport::*;
    use super::super::turn::{with_unerased_document_result, DOCUMENT_RESULT_LOOKUP_PAUSE};
    use super::super::{ChatError, ChatSession, ChatSetup};
    use super::*;
    use crate::soul::{default_soul, soul_path, SoulStatus};
    use aux_providers::{ChatResponse, FakeProvider};
    use aux_store::{Store, StoreHandle};
    use kernel_core::ContextConfig;
    use std::sync::{Arc, Mutex};

    #[test]
    fn configured_agent_ids_list_the_agent_and_every_agent_directory() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(crate::soul::agents_dir(home.path()).join("mail")).unwrap();
        std::fs::create_dir_all(crate::soul::agents_dir(home.path()).join("clients")).unwrap();
        let mut ids = configured_agent_ids(home.path(), "main");
        ids.sort();
        assert_eq!(ids, ["clients", "mail", "main"]);
        assert_eq!(configured_agent_ids(&home.path().join("none"), "x"), ["x"]);
    }

    #[tokio::test]
    async fn soul_default_is_created_and_sent_as_system_prompt() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        assert_eq!(session.soul_status(), &SoulStatus::Created);
        let on_disk = std::fs::read_to_string(soul_path(&harness.home, "main")).unwrap();
        assert_eq!(on_disk, default_soul("main"));

        session.send("hello").await.unwrap();
        let system = &provider.requests()[0].messages[0];
        assert_eq!(system.role(), aux_providers::ChatRole::System);
        assert!(system.content().as_str().contains("You are main"));
        assert!(system.content().as_str().contains("# main"));
    }

    #[tokio::test]
    async fn existing_soul_is_used_verbatim() {
        let harness = Harness::new();
        let path = soul_path(&harness.home, "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# custom\nanswer in haiku\n").unwrap();

        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
        assert_eq!(session.soul_status(), &SoulStatus::Loaded);

        session.send("hello").await.unwrap();
        let system = &provider.requests()[0].messages[0];
        assert!(system
            .content()
            .as_str()
            .starts_with("# custom\nanswer in haiku"));
    }

    #[tokio::test]
    async fn corrupt_soul_falls_back_without_being_overwritten() {
        let harness = Harness::new();
        let path = soul_path(&harness.home, "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let garbage = [0xff, 0xfe, 0x00, 0x42];
        std::fs::write(&path, garbage).unwrap();

        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
        assert!(matches!(session.soul_status(), SoulStatus::FellBack { .. }));

        session.send("still works?").await.unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            garbage,
            "the corrupt file must be preserved"
        );
        let system = &provider.requests()[0].messages[0];
        assert!(system.content().as_str().contains("You are main"));
    }

    #[tokio::test]
    async fn resumed_session_rehydrates_history_and_skips_erased_document_text() {
        use aux_providers::ChatRole;
        const OCR: &str = "ERASE-PROBE-OCR-501";
        const HASH_OCR: &str = "ERASE-HASH-PROBE-OCR-503";

        let harness = Harness::new();
        let provider = FakeProvider::echo("fake");
        let session_id = {
            let mut first = harness.start(&provider, vec![], RecordingApprover::new(false));
            first.send("one").await.unwrap();
            first.session().id
        };
        {
            let store = harness.store();
            let hash = "c".repeat(64);
            let document_id = append_test_document(&store, &hash, "erased.txt");
            let retained_hash = "d".repeat(64);
            let retained_id = append_test_document(&store, &retained_hash, "retained.txt");
            let hash_only = "f".repeat(64);
            append_test_document(&store, &hash_only, "hash-only.txt");
            let content = format!(
                "[untrusted document content]\n{}",
                serde_json::json!({"matches":[
                    {"document_id":document_id,"excerpt":OCR},
                    {"content_hash":hash_only,"excerpt":HASH_OCR},
                    {"document_id":retained_id,"excerpt":"KEEP-OTHER-DOCUMENT"}
                ]})
            );
            let meta = r#"{"tool":"docs_ingest"}"#;
            store
                .append_message(session_id, "tool", &content, Some(meta))
                .unwrap();
            store.erase_document_by_hash_prefix(&hash[..12]).unwrap();
            store.finish_evidence_erasure(&hash).unwrap();
            store
                .erase_document_by_hash_prefix(&hash_only[..12])
                .unwrap();
            store.finish_evidence_erasure(&hash_only).unwrap();
            let messages = store.list_messages(session_id).unwrap();
            let saved = messages.last().unwrap().content.split_once('\n').unwrap().1;
            let saved: serde_json::Value = serde_json::from_str(saved).unwrap();
            assert_eq!(saved["matches"][0], aux_store::DOCUMENT_UNAVAILABLE_TEXT);
            assert_eq!(saved["matches"][1], aux_store::DOCUMENT_UNAVAILABLE_TEXT);
            assert_eq!(saved["matches"][2]["excerpt"], "KEEP-OTHER-DOCUMENT");
        }
        let mut second =
            harness.start_resumed(&provider, RecordingApprover::new(false), session_id);
        second.send("two").await.unwrap();

        let roles = harness.roles(session_id);
        assert_eq!(
            roles,
            vec!["system", "user", "assistant", "tool", "user", "assistant"],
            "two turns in one session, one system prompt"
        );

        let requests = provider.requests();
        assert_eq!(requests.len(), 2);
        let second_request = &requests[1];
        assert_eq!(
            second_request
                .messages
                .iter()
                .filter(|message| message.role() == ChatRole::System)
                .count(),
            1,
            "the resumed prompt carries exactly one system message"
        );
        assert!(
            second_request
                .messages
                .iter()
                .any(|message| message.content().as_str() == "one"),
            "the first turn is replayed to the provider"
        );
        assert!(second_request.messages.iter().all(|message| !message
            .content()
            .as_str()
            .contains(OCR)
            && !message.content().as_str().contains(HASH_OCR)));
    }

    /// RESUME-AFTER-STOP: the resume state row reaches the model, but the
    /// session's one stored prompt row stays out of the bounded window.
    #[tokio::test]
    async fn a_marked_state_line_reaches_the_resumed_model_but_the_prompt_row_does_not() {
        let harness = Harness::new();
        let provider = FakeProvider::echo("fake");
        let session_id = {
            let mut first = harness.start(&provider, vec![], RecordingApprover::new(false));
            first.send("one").await.unwrap();
            first.session().id
        };
        let note = "You resumed all agents. The stop is lifted; nothing was replayed.";
        harness
            .store()
            .append_message(
                session_id,
                "system",
                note,
                Some(r#"{"kind":"state","state":"resume"}"#),
            )
            .unwrap();
        let mut second =
            harness.start_resumed(&provider, RecordingApprover::new(false), session_id);
        second.send("two").await.unwrap();

        let requests = provider.requests();
        let request = &requests[1];
        let systems: Vec<&str> = request
            .messages
            .iter()
            .filter(|message| message.role() == aux_providers::ChatRole::System)
            .map(|message| message.content().as_str())
            .collect();
        assert_eq!(
            systems.get(1),
            Some(&note),
            "the resume line follows the fresh prompt; the stored prompt row stays out: {systems:?}"
        );
        let at = |text: &str| {
            request
                .messages
                .iter()
                .position(|message| message.content().as_str() == text)
        };
        assert!(at(note) < at("two"), "the lift is read before the new ask");
    }

    #[test]
    fn an_in_flight_document_result_saved_after_erase_is_marked_before_resume() {
        const OCR: &str = "ERASE-RACE-OCR-502";
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let session_id = store
            .lock()
            .unwrap()
            .create_session("main", None)
            .unwrap()
            .id;
        let hash = "e".repeat(64);
        let document_id = append_test_document(&store.lock().unwrap(), &hash, "race.txt");
        let content = format!(
            "[untrusted document content]\n{}",
            serde_json::json!({"matches":[{"document_id":document_id,"excerpt":OCR}]})
        );
        let worker_store = Arc::clone(&store);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            DOCUMENT_RESULT_LOOKUP_PAUSE.with(|slot| {
                *slot.borrow_mut() = Some((ready_tx, resume_rx));
            });
            let handle = StoreHandle::Shared(Arc::clone(&worker_store));
            with_unerased_document_result(&handle, &content, |safe| {
                kernel_core::sync::lock_recover(&worker_store)
                    .append_message(session_id, "tool", safe, Some(r#"{"tool":"docs_ingest"}"#))
                    .map_err(ChatError::from)
            })
        });
        ready_rx.recv().unwrap();
        let lifecycle = aux_store::evidence_lifecycle_lock(&hash);
        {
            let _guard = kernel_core::lock_recover(&lifecycle);
            let store = kernel_core::sync::lock_recover(&store);
            assert!(matches!(
                store.erase_document_by_hash_prefix(&hash[..12]).unwrap(),
                aux_store::DocumentEraseResult::Erased(_)
            ));
            store.finish_evidence_erasure(&hash).unwrap();
        }
        resume_tx.send(()).unwrap();
        let saved = worker.join().unwrap().unwrap().content;
        assert!(!saved.contains(OCR), "late result retained OCR: {saved}");
        assert!(
            saved.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
            "{saved}"
        );
        assert!(!saved.contains("[document erased]"), "{saved}");
    }

    /// DOCS-ERASED-MARKER: the raw store marker is internal, never owner text.
    /// A model that quotes it, or an old row replayed on resume, still gives
    /// the owner the plain sentence, and the stored assistant row says the same.
    #[tokio::test]
    async fn the_owner_facing_reply_never_carries_the_raw_erased_document_marker() {
        const RAW: &str = "[document erased]";
        let harness = Harness::new();
        let provider = FakeProvider::repeating(
            "fake",
            ChatResponse::assistant(format!("That search came back as \"{RAW}\".")),
        );
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        let outcome = session.send("what's in that pdf").await.unwrap();

        assert!(!outcome.text.contains(RAW), "{}", outcome.text);
        assert!(
            outcome.text.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
            "{}",
            outcome.text
        );
    }

    #[tokio::test]
    async fn resumed_session_context_is_bounded_and_keeps_recent_messages() {
        use aux_providers::ChatRole;

        // E-13 regression: 5,000 stored messages, a bounded context.
        let harness = Harness::new();
        let session = harness
            .store()
            .create_session("main", Some("long"))
            .unwrap();
        harness
            .store()
            .append_message(session.id, "system", "the soul", None)
            .unwrap();
        for index in 0..4_998 {
            let role = if index % 2 == 0 { "user" } else { "assistant" };
            harness
                .store()
                .append_message(session.id, role, &format!("old message {index}"), None)
                .unwrap();
        }

        let provider = FakeProvider::echo("fake");
        let mut resumed =
            harness.start_resumed(&provider, RecordingApprover::new(false), session.id);
        let outcome = resumed.send("recent question").await.unwrap();

        let requests = provider.requests();
        assert_eq!(requests.len(), 1);
        let context = &requests[0].messages;
        let max = ContextConfig::default().max_messages;
        assert!(
            context.len() <= max + 2,
            "context must stay bounded ({} > {max} + system/user)",
            context.len()
        );
        assert_eq!(context[0].role(), ChatRole::System, "system prompt kept");
        assert!(
            context
                .iter()
                .any(|message| message.content().as_str() == "recent question"),
            "the newest turn is in context"
        );
        assert!(
            context
                .iter()
                .any(|message| message.content().as_str() == "old message 4997"),
            "the newest history is visible"
        );
        assert!(
            !context
                .iter()
                .any(|message| message.content().as_str() == "old message 0"),
            "the oldest history is not re-sent"
        );
        assert!(
            outcome.text.contains("recent question"),
            "the answer still sees the recent messages: {}",
            outcome.text
        );
        // Bounding the context never deletes persisted history.
        assert_eq!(
            harness.store().list_messages(session.id).unwrap().len(),
            5_001,
            "system + 4,998 + user + assistant"
        );
    }

    #[test]
    fn resuming_a_missing_session_is_a_typed_error() {
        let harness = Harness::new();
        let provider = FakeProvider::echo("fake");
        let result = ChatSession::start(ChatSetup {
            mode: std::sync::Arc::new(|| kernel_core::privacy::PrivacyMode::Open),
            contacts: aux_runtime::known_names::owner_contacts(),
            store: StoreHandle::Shared(Arc::clone(&harness.store)),
            provider: &provider,
            registry: Arc::clone(&harness.registry),
            rules: Vec::new(),
            approver: RecordingApprover::new(false),
            agent: "main".to_string(),
            home: harness.home.clone(),
            skills: Vec::new(),
            budgets: &harness.budgets,
            prices: &harness.prices,
            context: ContextConfig::default(),
            title: None,
            stop: None,
            cancel: None,
            session_id: Some(4242),
            events: None,
            run_id: None,
        });
        let err = match result {
            Ok(_) => panic!("resuming a missing session must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ChatError::SessionMissing { id: 4242 }));
    }
}
