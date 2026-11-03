//! The privacy gate: issuing the outbound copy of every message,
//! withholding what the gate refuses, and keeping the session's token
//! pairs consistent across turns.

use super::ChatSession;
use crate::events::TurnEvents;
use crate::skill_runtime::SessionTokenStore;
use aux_providers::{ChatMessage, ChatRole, SafeMessage};
use aux_runtime::executor::TokenResolver;
use kernel_core::privacy::PrivacyMode;
use kernel_core::Lang;
use kernel_privacy::safetext::{Gate, GateError};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

pub(super) fn report_minted(
    gate: &mut Gate,
    events: Option<&dyn TurnEvents>,
    session_id: i64,
) -> Vec<(String, String)> {
    let pairs = gate.take_minted();
    if let Some(events) = events {
        if !pairs.is_empty() {
            events.session_tokens(session_id, &pairs);
        }
    }
    pairs
}

fn issue_and_report(
    gate: &mut Gate,
    events: Option<&dyn TurnEvents>,
    session_id: i64,
    tokens: &Mutex<SessionTokenStore>,
    message: &ChatMessage,
) -> Result<SafeMessage, GateError> {
    match SafeMessage::issue(gate, message) {
        Ok(issued) => {
            let pairs = report_minted(gate, events, session_id);
            kernel_core::sync::lock_recover(tokens).record(&pairs);
            Ok(issued)
        }
        Err(err) => {
            gate.take_minted();
            Err(err)
        }
    }
}

pub(super) fn withhold_history(
    gate: &mut Gate,
    history: &[ChatMessage],
) -> Result<(Vec<SafeMessage>, usize), GateError> {
    let marker = withheld_marker(Lang::from_env());
    let mut issued = Vec::with_capacity(history.len());
    let mut withheld = 0usize;
    // Call ids whose request was replaced: their tool answers can no longer pair.
    let mut dropped_calls: BTreeSet<&str> = BTreeSet::new();
    for message in history {
        let orphaned = message.role == ChatRole::Tool
            && message
                .tool_call_id
                .as_deref()
                .is_some_and(|id| dropped_calls.contains(id));
        let kept = if orphaned {
            None
        } else {
            SafeMessage::issue(gate, message).ok()
        };
        if let Some(safe) = kept {
            issued.push(safe);
            continue;
        }
        withheld += 1;
        dropped_calls.extend(message.tool_calls.iter().map(|call| call.id.as_str()));
        let replacement = match SafeMessage::issue(gate, &stand_in(message, orphaned, marker)) {
            Ok(safe) => safe,
            // A tool answer whose own id was refused is replaced as a plain note.
            Err(_) => SafeMessage::issue(gate, &ChatMessage::user(marker))?,
        };
        issued.push(replacement);
    }
    Ok((issued, withheld))
}

fn stand_in(message: &ChatMessage, orphaned: bool, marker: &str) -> ChatMessage {
    match message.role {
        ChatRole::Tool if !orphaned => ChatMessage {
            role: ChatRole::Tool,
            content: marker.to_string(),
            tool_calls: Vec::new(),
            tool_call_id: message.tool_call_id.clone(),
            reasoning_content: None,
            reasoning_provider: None,
        },
        ChatRole::Tool => ChatMessage::user(marker),
        role => ChatMessage {
            role,
            content: marker.to_string(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            reasoning_content: None,
            reasoning_provider: None,
        },
    }
}

fn bounded_conversation(messages: &[SafeMessage], limit: usize) -> Vec<SafeMessage> {
    let (system, rest): (Vec<&SafeMessage>, Vec<&SafeMessage>) = messages
        .iter()
        .partition(|message| message.role() == ChatRole::System);
    let skip = rest.len().saturating_sub(limit);
    system
        .into_iter()
        .chain(rest.into_iter().skip(skip))
        .cloned()
        .collect()
}

pub(super) fn withheld_marker(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "[message withheld for privacy]",
        Lang::Fr => "[message retiré pour confidentialité]",
    }
}

impl<'a> ChatSession<'a> {
    /// Keep this conversation in memory when its text is not stored, so the
    /// next turn of the same session sees it.
    pub(super) fn remember_private(&self) {
        if self.raw_text {
            return;
        }
        let messages = bounded_conversation(&self.messages, self.window_limit);
        crate::private::remember(
            &self.home,
            self.session.id,
            crate::private::Conversation {
                messages,
                taint: self.taint.clone(),
                carries_private_data: self.carries_private_data,
            },
        );
    }

    /// Issue the outbound copy of `message`, then report the tokens it minted
    /// so the local display can resolve them.
    pub(super) fn issue_outbound(
        &mut self,
        message: &ChatMessage,
    ) -> Result<SafeMessage, GateError> {
        let issued = issue_and_report(
            &mut self.gate,
            self.events.as_deref(),
            self.session.id,
            &self.skill_tokens,
            message,
        )?;
        self.handoff.note_issued(issued.content().as_str());
        Ok(issued)
    }

    /// Issue `message` keeping the handed task tokens whole (TOK-DELEGATE).
    /// TOK-CONSISTENT-1: the detectors read it as written (seal r2 P1); then a
    /// value the conversation has a token for is put back as that token and the
    /// text issued again, keeping it: one value, one token across turns,
    /// spellings, detector kinds and the sessions of chief and agent.
    pub(super) fn issue_keeping_handed(
        &mut self,
        message: &ChatMessage,
    ) -> Result<SafeMessage, GateError> {
        let known = self.known_pairs();
        self.gate.keep_session_tokens(self.inherited.clone());
        let first = SafeMessage::issue(&mut self.gate, message);
        let minted = self.gate.take_minted();
        let carried = first.as_ref().ok().and_then(|first| {
            let mut own = kernel_core::sync::lock_recover(&self.skill_tokens);
            own.record(&minted);
            let text = first.content().as_str();
            crate::handoff::carry(text, &minted, &mut own, &self.handoff.pairs, &known)
        });
        let issued = match carried {
            Some((text, mut keep)) => {
                keep.extend(self.inherited.iter().flat_map(|kept| kept.iter().cloned()));
                let mut named = message.clone();
                named.content = text;
                self.gate.keep_session_tokens(Some(Arc::new(keep)));
                self.issue_outbound(&named)
            }
            None => first.inspect(|first| self.handoff.note_issued(first.content().as_str())),
        };
        self.gate.keep_session_tokens(None);
        if let Ok(issued) = &issued {
            self.handoff.note_read(issued.content().as_str());
        }
        if let (Ok(issued), Some(events)) = (&issued, self.events.as_deref()) {
            // Minted or put back: report it as a fresh gate would.
            let text = issued.content().as_str();
            let own = kernel_core::sync::lock_recover(&self.skill_tokens).pairs();
            let shown: Vec<_> = own
                .into_iter()
                .filter(|(t, _)| text.contains(t.as_str()))
                .collect();
            if !shown.is_empty() {
                events.session_tokens(self.session.id, &shown);
            }
        }
        issued
    }

    /// The caller's and this session's addresses and multi-word names (one
    /// word, `Mail`, would rename the plain word). Private only.
    fn known_pairs(&self) -> Vec<(String, String)> {
        if self.gate_mode != PrivacyMode::Private {
            return Vec::new();
        }
        let named = |(t, v): &(String, String)| {
            t.starts_with("EMAIL_")
                || (t.starts_with("PERSON_") || t.starts_with("ORGANIZATION_"))
                    && v.trim().contains(char::is_whitespace)
        };
        let known = self.handoff.known.iter().filter(|p| named(p)).cloned();
        let mut pairs: Vec<_> = known.collect();
        let own = kernel_core::sync::lock_recover(&self.skill_tokens).carried();
        pairs.extend(own.into_iter().filter(named));
        pairs
    }

    /// Issue what the model wrote. It read only this session's tokens, so its
    /// references to them stay references in the stored, shown and re-sent copy
    /// (else the gate reads them as literal `⟦` text and every display shows
    /// them raw); a value it wrote in clear is still masked.
    /// TOK-CONSISTENT-1: so do the caller's; an unknown one is the display marker.
    pub(super) fn issue_model_output(
        &mut self,
        message: &ChatMessage,
    ) -> Result<SafeMessage, GateError> {
        let mut minted = self.token_snapshot().tokens();
        minted.extend(self.known_pairs().into_iter().map(|(token, _)| token));
        let mut named = message.clone();
        if self.gate_mode == PrivacyMode::Private {
            let marker = match Lang::from_env() {
                Lang::En => "[name hidden]",
                Lang::Fr => "[nom masqué]",
            };
            named.content = crate::handoff::hide_unknown(&message.content, &minted, marker);
        }
        self.gate.keep_session_tokens(Some(Arc::new(minted)));
        let issued = self.issue_outbound(&named);
        self.gate.keep_session_tokens(None);
        issued
    }
}

#[cfg(test)]
mod tests {
    use super::super::testsupport::*;
    use super::super::ChatError;
    use super::*;
    use crate::skill_runtime::SessionTokenStore;
    use aux_providers::{ChatMessage, ChatRole, FakeProvider};
    use aux_runtime::executor::TokenResolver;
    use kernel_broker::ShellSandbox;
    use std::sync::{Arc, Mutex};

    /// A detector that cannot decide: every call errors.
    struct BrokenDetector;

    impl kernel_privacy::safetext::Detector for BrokenDetector {
        fn detect(
            &self,
            _text: &str,
        ) -> Result<Vec<kernel_privacy::Span>, kernel_privacy::safetext::DetectError> {
            Err(kernel_privacy::safetext::DetectError::Panicked)
        }
    }

    #[tokio::test]
    async fn a_withheld_stored_message_is_replaced_only_in_the_provider_copy() {
        let harness = Harness::new();
        let provider = FakeProvider::echo("fake");
        let session_id = {
            let mut first = harness.start(&provider, vec![], RecordingApprover::new(false));
            first.send("un").await.unwrap();
            first.session().id
        };
        let stored = harness
            .store()
            .append_message(session_id, "user", "REFUSE-ME 06 12 34 56 78", None)
            .unwrap();

        // The next start meets a stored row the gate refuses: it must still start.
        crate::outbound::test_seam::refuse_text_containing("REFUSE-ME");
        let mut second =
            harness.start_resumed(&provider, RecordingApprover::new(false), session_id);
        second.send("deux").await.unwrap();
        crate::outbound::test_seam::clear();

        let rows = harness.store().list_messages(session_id).unwrap();
        let kept = rows.iter().find(|row| row.id == stored.id).unwrap();
        assert_eq!(
            kept.content, "REFUSE-ME 06 12 34 56 78",
            "the stored row is untouched"
        );

        let requests = provider.requests();
        let sent = serde_json::to_string(&requests.last().unwrap().messages).unwrap();
        assert!(
            !sent.contains("REFUSE-ME"),
            "the refused text was sent: {sent}"
        );
        let marker_en = super::withheld_marker(kernel_core::Lang::En);
        let marker_fr = super::withheld_marker(kernel_core::Lang::Fr);
        assert!(
            sent.contains(marker_en) || sent.contains(marker_fr),
            "no withheld marker in {sent}"
        );
    }

    #[tokio::test]
    async fn the_values_a_turn_masks_reach_the_local_sink_and_never_the_provider() {
        const CANARY: &str = "anne.dupont@example.org";
        let mut harness = Harness::new();
        harness.private(known_contacts());
        let provider = FakeProvider::echo("fake");
        let events = RecordingEvents::new();
        let mut session = harness.start_with_events(
            &provider,
            vec![],
            RecordingApprover::new(false),
            events.clone(),
        );

        session
            .send(&format!("écris à {CANARY} demain"))
            .await
            .unwrap();

        let minted = events.minted.lock().unwrap().clone();
        assert!(
            minted
                .iter()
                .any(|(token, value)| token.starts_with("EMAIL_") && value == CANARY),
            "the local sink must learn the token: {minted:?}"
        );
        let requests = provider.requests();
        for request in &requests {
            let sent = serde_json::to_string(&request.messages).unwrap();
            assert!(!sent.contains(CANARY), "the provider saw a value: {sent}");
        }
    }

    #[tokio::test]
    async fn a_refused_user_message_stays_local_and_sends_nothing() {
        let harness = Harness::new();
        let provider = FakeProvider::echo("main");
        let mut session = harness.start(&provider, vec![], Arc::new(crate::AutoApproveApprover));
        let session_id = session.session.id;
        let stored_before = harness.roles(session_id);
        session.gate = tokenising_gate_with([0u8; 32], Arc::new(BrokenDetector));

        let err = session.send("écris à mara.ellison@example.invalid").await;

        assert!(
            matches!(err, Err(ChatError::Privacy(_))),
            "a detection error must refuse the turn, got {err:?}"
        );
        assert_eq!(
            provider.request_count(),
            0,
            "nothing may reach the provider"
        );
        assert_eq!(
            harness.roles(session_id),
            stored_before,
            "a refused message leaves no row in the thread"
        );
    }

    /// A name detector for the canary: it finds one full name and says so.
    struct NameAware;

    impl kernel_privacy::safetext::Detector for NameAware {
        fn detect(
            &self,
            text: &str,
        ) -> Result<Vec<kernel_privacy::Span>, kernel_privacy::safetext::DetectError> {
            Ok(text
                .find("Mara Ellison")
                .map(|start| {
                    vec![kernel_privacy::Span::new(
                        kernel_privacy::EntityKind::Person,
                        start,
                        start + "Mara Ellison".len(),
                        0.9,
                        "name",
                    )]
                })
                .unwrap_or_default())
        }

        fn checks_names(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn a_full_name_never_reaches_the_provider_when_a_name_detector_runs() {
        let harness = Harness::new();
        let provider = FakeProvider::echo("main");
        let mut session = harness.start(&provider, vec![], Arc::new(crate::AutoApproveApprover));
        session.gate = tokenising_gate_with([0u8; 32], Arc::new(NameAware));

        session
            .send("Le dossier de Mara Ellison est prêt.")
            .await
            .unwrap();

        let requests = provider.requests();
        let sent = serde_json::to_string(&requests.last().unwrap().messages).unwrap();
        assert!(!sent.contains("Mara Ellison"), "the name was sent: {sent}");
        assert!(
            sent.contains("⟦PERSON_"),
            "the name was not tokenised: {sent}"
        );
    }

    #[tokio::test]
    async fn a_private_turn_keeps_static_tool_text_and_the_owner_name() {
        // K-FP: the person rules read "RFC 3339", "Download" and "Arguments"
        // in a description as names. The declaration is application text and
        // must reach the provider as written; the owner's name in the user
        // turn is still tokenised in the same request.
        let mut registry =
            builtin_registry(ShellSandbox::default(), kernel_core::WebConfig::default());
        registry.register_native(Box::new(FalsePositiveTool));
        let mut harness = Harness::with_registry(registry);
        harness.private(known_contacts());
        let provider = FakeProvider::echo("main");
        let mut session = harness.start(&provider, vec![], Arc::new(crate::AutoApproveApprover));

        session
            .send("Le dossier de Camille Exemple est prêt.")
            .await
            .unwrap();

        let requests = provider.requests();
        let request = requests.last().expect("the turn reached the provider");
        let system = request
            .messages
            .iter()
            .find(|message| message.role() == ChatRole::System)
            .map(|message| message.content().as_str())
            .unwrap_or_default();
        let tools = serde_json::to_string(&request.tools).unwrap();

        for needle in ["RFC 3339", "Download", "Arguments", "Exactly these calls"] {
            assert!(
                system.contains(needle) || tools.contains(needle),
                "static text `{needle}` was tokenised:\nsystem: {system}\ntools: {tools}"
            );
        }

        // Defence in depth: a value planted in a `'static` declaration is
        // redacted, never carried into the request.
        for planted in [
            "owner@example.com",
            "FR7630006000011234567890189",
            "+33 6 12 34 56 78",
        ] {
            assert!(
                !system.contains(planted) && !tools.contains(planted),
                "planted `{planted}` reached the provider:\n{tools}"
            );
        }
        for marker in ["[redacted:EMAIL]", "[redacted:IBAN]", "[redacted:PHONE]"] {
            assert!(
                system.contains(marker) || tools.contains(marker),
                "no `{marker}` in:\n{tools}"
            );
        }

        // NAMES-OFF (owner, 2026-10-19): the owner's name reaches it as written.
        let sent = serde_json::to_string(&request.messages).unwrap();
        assert!(sent.contains("Camille Exemple"), "{sent}");
        assert!(!sent.contains("⟦PERSON_"), "{sent}");
    }

    /// Detects `alice` and `bob`, and refuses any clear text still holding
    /// `LEAK`. Masking mints a pair before that check, so a `LEAK` message is
    /// refused with a pair already in the gate.
    /// Refuses a message that holds `LEAK`: its residue check fails, so the gate
    /// refuses the message. (FIN-5: a plain leftover value is now masked, not
    /// refused, so the refusal comes from a failing residue check instead.)
    #[derive(Default)]
    struct RefuseLeftover {
        leaking: std::sync::atomic::AtomicBool,
    }

    impl kernel_privacy::safetext::Detector for RefuseLeftover {
        fn detect(
            &self,
            text: &str,
        ) -> Result<Vec<kernel_privacy::Span>, kernel_privacy::safetext::DetectError> {
            self.leaking
                .store(text.contains("LEAK"), std::sync::atomic::Ordering::SeqCst);
            Ok(["alice", "bob"]
                .into_iter()
                .filter_map(|name| text.find(name).map(|start| (start, start + name.len())))
                .map(|(start, end)| {
                    kernel_privacy::Span::new(
                        kernel_privacy::EntityKind::Email,
                        start,
                        end,
                        1.0,
                        "test",
                    )
                })
                .collect())
        }

        fn residue(
            &self,
            _text: &str,
        ) -> Result<Vec<kernel_privacy::Span>, kernel_privacy::safetext::DetectError> {
            if self.leaking.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(kernel_privacy::safetext::DetectError::Panicked);
            }
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_refused_message_reports_no_pairs_and_leaves_none_for_the_next_report() {
        let mut gate = tokenising_gate_with([9u8; 32], Arc::new(RefuseLeftover::default()));
        let events = RecordingEvents::new();
        let sink: &dyn crate::events::TurnEvents = &*events;

        let tokens = Mutex::new(SessionTokenStore::default());
        let refused = issue_and_report(
            &mut gate,
            Some(sink),
            7,
            &tokens,
            &ChatMessage::user("alice LEAK"),
        );
        assert!(refused.is_err(), "the residue check refuses the message");
        assert!(
            events.minted.lock().unwrap().is_empty(),
            "a refused message records nothing"
        );

        issue_and_report(&mut gate, Some(sink), 7, &tokens, &ChatMessage::user("bob")).unwrap();
        let minted = events.minted.lock().unwrap().clone();
        assert_eq!(minted.len(), 1, "only the accepted message's pair");
        assert_eq!(minted[0].1, "bob");
        // The session's store holds exactly the reported pair, and resolves it.
        let stored = tokens.lock().unwrap().pairs();
        assert_eq!(stored, minted, "the session store keeps what was reported");
    }
}
