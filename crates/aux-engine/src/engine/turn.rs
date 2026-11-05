//! The turn loop: one user message in, provider calls and tool calls
//! out. Every message is persisted as it happens, so a crash mid-run
//! still leaves an honest history behind.

use super::budget::{request_model, settle_streamed, streamed_actual, usage_actual, StreamCapture};
use super::context::{
    assistant_meta, cap_reasoning, role_str, safe_tool_calls_meta, tool_calls_meta,
    tool_result_meta,
};
use super::privacy::withheld_marker;
use super::taint::batch_taint_source;
use super::tools::CallOutcome;
use super::{ChatError, ChatSession, TurnOutcome};
use crate::read_guard;
use crate::skill_runtime::command_skill;
use aux_providers::{
    ChatDelta, ChatMessage, ChatRequest, ChatRole, SafeMessage, SafeToolSpec, ToolCall,
};
use aux_runtime::executor::TokenResolver;
use aux_runtime::skills::fill::is_skill_tool;
use aux_runtime::skills::skill_tool_name;
use aux_store::{Message, StoreHandle};
use kernel_core::Lang;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

pub(super) fn with_unerased_document_result<R>(
    store: &StoreHandle<'_>,
    content: &str,
    persist: impl FnOnce(&str) -> Result<R, ChatError>,
) -> Result<R, ChatError> {
    let locks = store.with(|store| store.document_result_lifecycle_locks(content))?;
    #[cfg(test)]
    pause_after_document_result_lookup();
    let _guards = locks
        .iter()
        .map(|lock| kernel_core::lock_recover(lock))
        .collect::<Vec<_>>();
    let content = store.with(|store| store.scrub_erased_document_result(content))?;
    persist(&content)
}

/// DOCS-ERASED-MARKER: the raw bracketed marker is store-internal. A model
/// that quotes it never shows it to the owner: the plain sentence is used.
const RAW_DOCUMENT_ERASED_MARKER: &str = "[document erased]";

fn owner_facing_document_text(text: &str) -> String {
    if text.contains(RAW_DOCUMENT_ERASED_MARKER) {
        text.replace(
            RAW_DOCUMENT_ERASED_MARKER,
            aux_store::DOCUMENT_UNAVAILABLE_TEXT,
        )
    } else {
        text.to_string()
    }
}

/// Rewrites streamed reply text for display only. It holds back a trailing
/// prefix of the raw marker so a marker split across two provider deltas is
/// still replaced; [`finish`](Self::finish) releases any tail at the end.
#[derive(Default)]
struct ErasedMarkerStream {
    pending: String,
}

impl ErasedMarkerStream {
    fn push(&mut self, text: &str) -> String {
        self.pending.push_str(text);
        let mut display = owner_facing_document_text(&std::mem::take(&mut self.pending));
        let keep = trailing_marker_prefix(&display);
        let split = display.len() - keep;
        self.pending = display.split_off(split);
        display
    }

    fn finish(&mut self) -> String {
        std::mem::take(&mut self.pending)
    }
}

/// The longest suffix of `text` that may be the start of the raw marker.
fn trailing_marker_prefix(text: &str) -> usize {
    let max = text.len().min(RAW_DOCUMENT_ERASED_MARKER.len());
    (1..=max)
        .rev()
        .find(|len| {
            text.is_char_boundary(text.len() - len)
                && RAW_DOCUMENT_ERASED_MARKER.starts_with(&text[text.len() - len..])
        })
        .unwrap_or(0)
}

#[cfg(test)]
std::thread_local! {
    pub(super) static DOCUMENT_RESULT_LOOKUP_PAUSE: std::cell::RefCell<Option<(
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    )>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn pause_after_document_result_lookup() {
    DOCUMENT_RESULT_LOOKUP_PAUSE.with(|slot| {
        if let Some((ready, resume)) = slot.borrow_mut().take() {
            let _ = ready.send(());
            let _ = resume.recv();
        }
    });
}

/// The only tool whose results are document content. Every other tool's text
/// is ordinary text, whatever it starts with (F1).
const DOCUMENT_TOOL: &str = "docs_ingest";

/// The first bytes of a document result, checked in addition to the producing
/// tool: a docs row already rewritten, withheld or answered with an error is
/// not re-scrubbed.
const DOCUMENT_RESULT_PREFIX: &str = "[untrusted document content";

fn is_document_tool(name: &str) -> bool {
    name == DOCUMENT_TOOL
}

/// Tools that return the owner's own raw text (a file, a memory note), which
/// may start with the document marker by chance. Only these are exempt from
/// the marker rule: every other tool whose result carries the marker is still
/// treated as a document on erase, so erase coverage never narrows.
fn is_raw_text_tool(name: &str) -> bool {
    matches!(name, "read_file" | "recall")
}

/// Whether a tool result is one the erase path must inspect. The assistant
/// row that requested the call is the provenance: a `read_file` or `recall`
/// result is never a document, even when its text opens with the marker. A
/// result whose call the window no longer holds cannot be attributed (an old
/// row), so the marker is the only evidence and it still counts, failing
/// closed in the store's scrubber.
fn is_document_result(
    message: &SafeMessage,
    calls: &std::collections::HashMap<&str, bool>,
) -> bool {
    if message.role() != ChatRole::Tool
        || !message
            .content()
            .as_str()
            .starts_with(DOCUMENT_RESULT_PREFIX)
    {
        return false;
    }
    match message.tool_call_id().and_then(|id| calls.get(id.as_str())) {
        Some(is_document) => *is_document,
        None => true,
    }
}

/// The tool results an erase must rewrite, in window order. Provenance is
/// scoped to the call's own batch, so a provider that reuses a call id across
/// turns cannot hand one tool's result another tool's class.
/// Map each call id of one assistant batch to "its result may be a
/// document". Ids can repeat in a batch (a model can reuse one): a repeated id
/// is a document as soon as ANY call with it is not a raw-text tool, so a
/// `read_file` sharing an id with `docs_ingest` never exempts the document
///
fn call_kinds<'a>(
    calls: impl Iterator<Item = (&'a str, &'a str)>,
) -> std::collections::HashMap<&'a str, bool> {
    let mut kinds = std::collections::HashMap::new();
    for (id, name) in calls {
        let document = !is_raw_text_tool(name);
        kinds
            .entry(id)
            .and_modify(|kind: &mut bool| *kind |= document)
            .or_insert(document);
    }
    kinds
}

#[cfg(test)]
mod call_kind_tests {
    use super::call_kinds;

    #[test]
    fn a_repeated_call_id_is_a_document_if_any_call_is_not_raw_text() {
        for batch in [
            vec![("x", "docs_ingest"), ("x", "read_file")],
            vec![("x", "read_file"), ("x", "docs_ingest")],
            vec![("x", "recall"), ("x", "delegate")],
        ] {
            assert_eq!(
                call_kinds(batch.clone().into_iter()).get("x"),
                Some(&true),
                "{batch:?}"
            );
        }
        let raw =
            call_kinds([("a", "read_file"), ("a", "recall"), ("b", "docs_ingest")].into_iter());
        assert_eq!(raw.get("a"), Some(&false));
        assert_eq!(raw.get("b"), Some(&true));
    }
}

fn document_results(messages: &[SafeMessage]) -> Vec<(usize, &SafeMessage)> {
    let mut calls: std::collections::HashMap<&str, bool> = std::collections::HashMap::new();
    let mut results = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        if message.role() == ChatRole::Assistant {
            calls = call_kinds(
                message
                    .tool_calls()
                    .iter()
                    .map(|call| (call.id().as_str(), call.name().as_str())),
            );
            continue;
        }
        if is_document_result(message, &calls) {
            results.push((index, message));
        }
    }
    results
}

/// Keep erasure and all attempts inside one provider completion ordered. A
/// provider may retry or fall back after an await, so releasing the locks at
/// the first poll would allow a later HTTP attempt to send the old snapshot.
struct DocumentDispatchGuard {
    release: std::sync::mpsc::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl DocumentDispatchGuard {
    async fn release(self) {
        drop(self.release);
        let _ = self.task.await;
    }
}

/// Replace erased excerpts inside every string leaf of a tool call's
/// arguments. True when something changed.
fn scrub_value_echo(value: &mut serde_json::Value, echoes: &[String]) -> bool {
    match value {
        serde_json::Value::String(text) => match aux_store::scrub_erased_echo(text, echoes) {
            Some(scrubbed) => {
                *text = scrubbed;
                true
            }
            None => false,
        },
        serde_json::Value::Object(object) => object.values_mut().fold(false, |changed, child| {
            scrub_value_echo(child, echoes) | changed
        }),
        serde_json::Value::Array(items) => items.iter_mut().fold(false, |changed, child| {
            scrub_value_echo(child, echoes) | changed
        }),
        _ => false,
    }
}

impl<'a> ChatSession<'a> {
    async fn guard_document_dispatch(
        &mut self,
        turn_start: usize,
    ) -> Result<Option<DocumentDispatchGuard>, ChatError> {
        let payloads: Vec<serde_json::Value> = document_results(&self.messages)
            .into_iter()
            .filter_map(|(_, message)| {
                let text = message.content().as_str();
                let body = text.split_once('\n').map_or(text, |(_, body)| body);
                serde_json::from_str(body).ok()
            })
            .collect();
        if payloads.is_empty() {
            // Still scrub a malformed result instead of sending it unchanged.
            if self.scrub_document_messages(turn_start)? {
                return Err(ChatError::DocumentErased);
            }
            return Ok(None);
        }
        // One aggregate lookup keeps the store's canonical hash ordering for
        // multi-document results and avoids taking the same lock twice.
        let payload = serde_json::Value::Array(payloads).to_string();
        let locks = self
            .store
            .with(|store| store.document_result_lifecycle_locks(&payload))?;
        if locks.is_empty() {
            if self.scrub_document_messages(turn_start)? {
                return Err(ChatError::DocumentErased);
            }
            return Ok(None);
        }
        // Each guard owns a blocking worker while the provider is in flight.
        // Bound that cost so document turns cannot exhaust Tokio's pool.
        static DISPATCH_SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        let permit =
            Arc::clone(DISPATCH_SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32))))
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("document dispatch slots closed"))?;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _guards: Vec<_> = locks
                .iter()
                .map(|lock| kernel_core::lock_recover(lock))
                .collect();
            if ready_tx.send(()).is_ok() {
                let _ = released.recv();
            }
        });
        ready_rx
            .await
            .map_err(|_| std::io::Error::other("document dispatch lock failed"))?;
        let guard = DocumentDispatchGuard { release, task };
        match self.scrub_document_messages(turn_start) {
            Ok(false) => Ok(Some(guard)),
            Ok(true) => {
                guard.release().await;
                Err(ChatError::DocumentErased)
            }
            Err(err) => {
                guard.release().await;
                Err(err)
            }
        }
    }

    /// Rewrites erased document results in the buffer. Returns true when a
    /// result added since `turn_start` changed: an erase landed mid-turn, and
    /// the model may already have echoed the excerpt in its own text or in a
    /// tool call's arguments. Those cannot be told apart from other text, so
    /// the turn stops instead of sending anything more (fail closed).
    fn scrub_document_messages(&mut self, turn_start: usize) -> Result<bool, ChatError> {
        let replacements = document_results(&self.messages)
            .into_iter()
            .map(|(index, message)| {
                let content = self
                    .store
                    .with(|store| store.scrub_erased_document_result(message.content().as_str()))?;
                Ok((
                    index,
                    content,
                    message.tool_call_id().map(|id| id.as_str().to_string()),
                ))
            })
            .collect::<Result<Vec<_>, ChatError>>()?;
        let mut erased_mid_turn = false;
        let mut echoes: BTreeSet<String> = BTreeSet::new();
        for (index, content, call_id) in replacements {
            let before = self.messages[index].content().as_str();
            if content != before {
                erased_mid_turn |= index >= turn_start;
                echoes.extend(aux_store::erased_document_texts(before, &content));
                let message = ChatMessage::tool_result(call_id.unwrap_or_default(), content);
                let safe = self.issue_keeping_handed(&message)?;
                Arc::make_mut(&mut self.messages)[index] = safe;
            }
        }
        if !echoes.is_empty() {
            // Longest first, so a text that contains another is replaced whole.
            let mut echoes: Vec<String> = echoes.into_iter().collect();
            echoes.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
            self.scrub_assistant_echoes(&echoes)?;
        }
        Ok(erased_mid_turn)
    }

    /// ERASE-ASSISTANT-ECHO: an earlier reply (or one of its tool calls) that
    /// quoted an erased excerpt verbatim is rewritten in the buffer, so a
    /// later request of this conversation no longer carries the text. The
    /// buffer holds the gated copy, like the store, so the match runs on the
    /// representation the provider saw. Paraphrases are out of reach.
    fn scrub_assistant_echoes(&mut self, echoes: &[String]) -> Result<(), ChatError> {
        let rewritten: Vec<(usize, ChatMessage)> = self
            .messages
            .iter()
            .enumerate()
            .filter(|(_, message)| message.role() == ChatRole::Assistant)
            .filter_map(|(index, message)| {
                let mut changed = false;
                let content = aux_store::scrub_erased_echo(message.content().as_str(), echoes)
                    .inspect(|_| changed = true)
                    .unwrap_or_else(|| message.content().as_str().to_string());
                let calls = message
                    .tool_calls()
                    .iter()
                    .map(|call| {
                        let mut arguments = call.arguments().as_value().clone();
                        changed |= scrub_value_echo(&mut arguments, echoes);
                        ToolCall::new(call.id().as_str(), call.name().as_str(), arguments)
                    })
                    .collect();
                let reasoning = message.reasoning_content().map(|text| {
                    aux_store::scrub_erased_echo(text.as_str(), echoes)
                        .inspect(|_| changed = true)
                        .unwrap_or_else(|| text.as_str().to_string())
                });
                changed.then(|| {
                    let mut local = ChatMessage::assistant_with_tool_calls(content, calls)
                        .with_reasoning_content(reasoning);
                    if let Some(provider) = message.reasoning_provider() {
                        local = local.with_reasoning_provider(provider);
                    }
                    (index, local)
                })
            })
            .collect();
        for (index, local) in rewritten {
            let safe = self.issue_keeping_handed(&local)?;
            Arc::make_mut(&mut self.messages)[index] = safe;
        }
        Ok(())
    }

    /// Send one user message, running the tool loop until the model answers
    /// (or the round cap is reached).
    pub async fn send(&mut self, input: &str) -> Result<TurnOutcome, ChatError> {
        let outcome = self.run_turn(input).await;
        self.current_owner_input = None;
        self.current_owner_row_id = None;
        // The save nudge always comes after the read nudge: remove it first.
        for at in [self.save_nudge_at.take(), self.read_nudge_at.take()]
            .into_iter()
            .flatten()
        {
            let messages = Arc::make_mut(&mut self.messages);
            if at < messages.len() {
                messages.remove(at);
            }
        }
        self.remember_private();
        outcome
    }

    async fn run_turn(&mut self, input: &str) -> Result<TurnOutcome, ChatError> {
        self.current_owner_input = if self.input_source.is_some() {
            self.inherited_owner_words.take()
        } else {
            Some(input.to_string())
        };
        // The first step boundary, before anything is stored. The mode is read
        // when the turn starts and the tools are built after that, so a switch
        // during setup is seen only here: no raw row may be written under a mode
        // that has already changed.
        self.enforce_stop()?;
        // A turn may run its skill once (F2): the flag belongs to this turn.
        self.skill_ran_this_turn.store(false, Ordering::Relaxed);
        // A new turn resets the per-turn fetch counter and re-points the daily
        // one at the local day; reservations happen before every connect.
        // A poisoned lock falls back to the guarded value: the counters are
        // plain integers a panic mid-update cannot corrupt beyond an
        // off-by-one.
        {
            let mut budget = match self.web_budget.lock() {
                Ok(budget) => budget,
                Err(poisoned) => poisoned.into_inner(),
            };
            budget.start_turn();
            if let Ok(day) = self.store.with(|store| store.local_day()) {
                budget.set_day(&day);
            }
        }
        let user = ChatMessage::user(input);
        // Gate before storing: a refusal leaves no row and sends nothing.
        let outbound = self.issue_keeping_handed(&user)?;
        // DELEGATION-SOURCE-1: the row says who wrote it. A delegated ask is
        // not the owner's words, and the source is what tells them apart.
        let user_meta = self.input_meta();
        let user_row = self.persist(&user, user_meta.as_deref(), &outbound)?;
        self.current_owner_row_id = Some(user_row.id);
        self.emit_message(&user_row);
        Arc::make_mut(&mut self.messages).push(outbound);
        let mut last_persisted = user_row.id;

        // A leading `/<command>` forces its skill for the turn's first round:
        // that skill's tool is the only one offered.
        let forced_skill = command_skill(input, &self.runtime_skills).and_then(|skill| {
            self.runtime_skills
                .iter()
                .position(|known| known.name == skill.name)
        });
        let forced_name: Option<String> =
            forced_skill.map(|index| self.runtime_skills[index].name.clone());
        // CAL-NO-TOOL-GUESS: the readable domain this turn asks about (none for a `/command`).
        let read_domain = match forced_skill {
            Some(_) => None,
            None => {
                let specs = self.round_tool_specs(None);
                let offered =
                    read_guard::offered_domains(specs.iter().map(|spec| spec.name().as_str()));
                read_guard::asked_domain(input, &offered)
            }
        };
        let mut read_retried = false;
        // FOLLOWUP-READ-FIRST: a forced skill that mails a contact first reads
        // the last exchange with them, so its fill quotes the real thread.
        if let Some(index) = forced_skill {
            if let Some(row) = self.read_last_exchange(input, index).await? {
                last_persisted = row;
            }
        }
        // MEM-FORGET-HANG: a reply may say "saved" only after a memory write
        // (or a delegate, whose agent answers for its own) ran this turn. A
        // note kept on a client's card is a memory write too (CRM-NOTE-CHAT-1).
        let memory_turn = read_guard::asks_to_save(input);
        let mut memory_written = false;
        let mut save_retried = false;
        let mut rounds = 0usize;
        let mut skill_called = false;
        let mut executed_calls = 0usize;
        // ERASE-ACTIVE-TURN: document results from this index on came in this
        // turn; an erase of one of them stops the turn.
        let turn_start = self.messages.len();
        while rounds < self.max_rounds {
            // Kill switch, cancellation and budgets are checked before every
            // provider call, not just at the start of the turn: a long tool
            // loop cannot outrun its cap, STOP/abort lands at the next step
            // boundary, and a cancelled turn spends nothing more.
            self.enforce_stop()?;
            self.check_cancel()?;
            let document_guard = if let Some(cancel) = self.cancel.clone() {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Err(ChatError::Cancelled),
                    guard = self.guard_document_dispatch(turn_start) => guard?,
                }
            } else {
                self.guard_document_dispatch(turn_start).await?
            };
            self.enforce_stop()?;
            self.check_cancel()?;
            rounds += 1;
            // E-13: the request shares the session's conversation buffer (no
            // deep copy per round). The `Arc::make_mut` calls below copy only
            // if something still holds the previous request alive.
            let mut request = ChatRequest::shared(Arc::clone(&self.messages))
                .with_tools(self.round_tool_specs(forced_skill));
            // A forced `/command` must reach its skill: each round tells the
            // provider to call it (`tool_choice`, F3) until the model has called
            // it once. Later rounds only offer it, so the model may answer once
            // the run is over.
            if let (false, Some(name)) = (skill_called, forced_name.as_deref()) {
                request = request.with_forced_tool(skill_tool_name(name));
            }
            // Reserve the estimated spend *inside the store transaction that
            // checks the cap*: a concurrent turn sees this reservation plus
            // its own reserve in the admission test and is denied instead of
            // both turns spending the same headroom.
            let reservation = self.reserve_budget(&request)?;
            // A capped output direction only reserved the remaining headroom
            // (the store clamps it); pass that as the provider's completion
            // cap so a compliant provider cannot settle above the admitted
            // reservation. With no output cap there is no cap to honor, so
            // the request keeps the provider's default.
            if let Some(reservation) = reservation.as_ref().map(|hold| hold.reservation()) {
                if reservation.caps.tokens_out.is_some() {
                    let cap = u32::try_from(reservation.estimate.tokens_out).unwrap_or(u32::MAX);
                    request = request.with_max_tokens(cap);
                }
            }
            if let Some(events) = &self.events {
                events.request(&request);
            }
            let provider = self.provider;
            // Streaming sink: transient text deltas for a live front-end.
            // They never touch persistence — the assembled response is still
            // persisted exactly once below. `draft` numbers the round so a
            // consumer can tell two rounds of one turn apart; `seq` is the
            // 1-based position within that round's text stream.
            //
            // The same sink feeds `capture`, so a call that dies mid-stream
            // (cancel, provider error, idle timeout, `stream_too_large`) can
            // settle a conservative estimate of what the provider already
            // generated instead of releasing the reservation at zero (I-01).
            let live = self.events.clone();
            let session_id = self.session.id;
            let draft = rounds as u64;
            let delta_seq = std::sync::atomic::AtomicU64::new(0);
            let capture = Arc::new(StreamCapture::default());
            // A turn dropped mid-call (its future cancelled while the provider
            // has the request) settles the larger of the reserved estimate
            // and what already streamed, never less than the reservation.
            let reservation = reservation.map(|hold| {
                let (capture, request, prices) = (Arc::clone(&capture), &request, self.prices);
                hold.or_known(move || streamed_actual(request, &capture, provider, prices))
            });
            // CAL-NO-TOOL-GUESS: while a data question has read nothing, the
            // text is held, so a guess the guard drops never reaches the app.
            let mut held: Option<Arc<Mutex<Vec<String>>>> = ((read_domain.is_some()
                && executed_calls == 0)
                || (memory_turn && !memory_written))
                .then(Default::default);
            let display_stream = Arc::new(Mutex::new(ErasedMarkerStream::default()));
            let sink = {
                let capture = Arc::clone(&capture);
                let held = held.clone();
                let live = live.clone();
                let display_stream = Arc::clone(&display_stream);
                let delta_seq = &delta_seq;
                move |delta: ChatDelta| {
                    capture.record(&delta);
                    if let ChatDelta::Text(text) = delta {
                        if let Some(held) = &held {
                            kernel_core::lock_recover(held).push(text);
                        } else if let Some(events) = &live {
                            let display = kernel_core::lock_recover(&display_stream).push(&text);
                            if display.is_empty() {
                                return;
                            }
                            let seq =
                                delta_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            events.message_delta(session_id, draft, seq, &display);
                        }
                    }
                }
            };
            let completion = if let Some(cancel) = self.cancel.clone() {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        // A cancelled provider call never completed: settle
                        // the estimate of what already streamed, so the spend
                        // the provider may bill is not recorded as zero. The
                        // taint marks already written for earlier untrusted
                        // dispatches are untouched.
                        if let Some(reservation) = reservation {
                            settle_streamed(
                                reservation,
                                &request,
                                &capture,
                                self.provider,
                                self.prices,
                            );
                        }
                        return Err(ChatError::Cancelled);
                    }
                    completion = provider.complete_streaming(&request, &sink) => completion,
                }
            } else {
                provider.complete_streaming(&request, &sink).await
            };
            if let Some(guard) = document_guard {
                guard.release().await;
            }
            if held.is_none() {
                if let Some(events) = &live {
                    let tail = kernel_core::lock_recover(&display_stream).finish();
                    if !tail.is_empty() {
                        let seq = delta_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        events.message_delta(session_id, draft, seq, &tail);
                    }
                }
            }
            let response = match completion {
                Ok(response) => response,
                Err(err) => {
                    if let Some(reservation) = reservation {
                        // The call failed after the provider had already been
                        // fed the prompt (and may already have generated some
                        // of the answer): settle the conservative estimate
                        // instead of releasing at zero (I-01). A failed
                        // settle is retried; the reservation stays held.
                        settle_streamed(
                            reservation,
                            &request,
                            &capture,
                            self.provider,
                            self.prices,
                        );
                    }
                    return Err(err.into());
                }
            };
            // Consumed whole (never left as `None`), so `request` is free below.
            let settled = reservation.map(|reservation| {
                let model = request_model(self.provider, &request);
                reservation.settle(&usage_actual(&request, &response, model, self.prices))
            });
            match settled {
                Some(settled) => settled?,
                None => self.record_usage(&request, &response)?,
            }
            self.record_usage_call(&request, &response, rounds);
            drop(request);
            let mut assistant = response.message;
            cap_reasoning(&mut assistant);
            // CAL-NO-TOOL-GUESS: a domain answer that read nothing this turn is a
            // guess. It is dropped (never stored) and the model is asked once to
            // check; a second guess becomes the fixed honest line.
            if let (true, 0, Some(domain)) =
                (assistant.tool_calls.is_empty(), executed_calls, read_domain)
            {
                if !read_retried {
                    if let Some(events) = &self.events {
                        events.read_check(self.session.id, domain.label(), true);
                    }
                    read_retried = true;
                    let nudge = self.issue_outbound(&ChatMessage::system(read_guard::NUDGE))?;
                    let messages = Arc::make_mut(&mut self.messages);
                    self.read_nudge_at = Some(messages.len());
                    messages.push(nudge);
                    continue;
                }
                // In doubt the answer stands: only one that states a fact
                // (a number, a day, a count) is replaced.
                if read_guard::states_fact(assistant.content.as_str()) {
                    if let Some(events) = &self.events {
                        events.read_check(self.session.id, domain.label(), false);
                    }
                    let lang = read_guard::question_lang(input);
                    assistant = ChatMessage::assistant(domain.honest_line(lang));
                    held = None;
                }
            }
            if assistant.tool_calls.is_empty()
                && !memory_written
                && read_guard::claims_save(input, assistant.content.as_str())
            {
                if !save_retried {
                    save_retried = true;
                    let nudge =
                        self.issue_outbound(&ChatMessage::system(read_guard::SAVE_NUDGE))?;
                    let messages = Arc::make_mut(&mut self.messages);
                    self.save_nudge_at = Some(messages.len());
                    messages.push(nudge);
                    continue;
                }
                assistant = ChatMessage::assistant(read_guard::not_saved_line(
                    read_guard::question_lang(input),
                ));
                held = None;
            }
            // MEM-FORGET-HANG: a card nobody answered is said in a fixed line.
            if let (true, Some(tool)) = (assistant.tool_calls.is_empty(), &self.card_expired) {
                let line = read_guard::card_expired_line(read_guard::question_lang(input), tool);
                let text = assistant.content.as_str().trim_end();
                assistant = ChatMessage::assistant(format!("{text}\n\n{line}").trim_start());
                self.card_expired = None;
            }
            // The held text of a kept answer or a tool call is released now.
            if let (Some(held), Some(events)) = (held, &self.events) {
                let mut stream = ErasedMarkerStream::default();
                for text in std::mem::take(&mut *kernel_core::lock_recover(&held)) {
                    let display = stream.push(&text);
                    if display.is_empty() {
                        continue;
                    }
                    let seq = delta_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    events.message_delta(self.session.id, draft, seq, &display);
                }
                let tail = stream.finish();
                if !tail.is_empty() {
                    let seq = delta_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    events.message_delta(self.session.id, draft, seq, &tail);
                }
            }
            // DOCS-ERASED-MARKER: the owner never reads the store's raw marker.
            assistant.content = owner_facing_document_text(&assistant.content);
            let outbound = self.issue_model_output(&assistant)?;
            // Reasoning is kept only in an open turn (a private turn stores
            // none), in the row's meta, which no client surface reads.
            let meta = if self.raw_text {
                assistant_meta(&assistant)
            } else {
                tool_calls_meta(&assistant.tool_calls)
            };
            let assistant_row = self.persist(&assistant, meta.as_deref(), &outbound)?;
            self.emit_message(&assistant_row);
            last_persisted = assistant_row.id;

            if assistant.tool_calls.is_empty() {
                self.emit_done(last_persisted);
                let text = assistant.content.clone();
                Arc::make_mut(&mut self.messages).push(outbound);
                return Ok(TurnOutcome {
                    text,
                    capped: false,
                    rounds,
                });
            }

            const MAX_CALLS_PER_ROUND: usize = 8;
            const MAX_CALLS_PER_TURN: usize = 24;
            let calls = assistant.tool_calls.clone();
            skill_called |= calls
                .iter()
                .any(|call| is_skill_tool(&call.name) == forced_name.as_deref());
            // A tool result from this batch can enter the model context before
            // the batch finishes. Treat every call as tainted up front so an
            // earlier memory write/read cannot outrun a later untrusted tool.
            let batch_taint = batch_taint_source(&calls, &self.registry());
            Arc::make_mut(&mut self.messages).push(outbound);
            for (index, call) in calls.iter().enumerate() {
                // STOP and cancellation abort between two tool calls as well:
                // an engaged switch must never let the rest of the batch run.
                // Either way the batch is closed with synthetic results so
                // the persisted assistant `tool_calls` row never dangles:
                // a dangling row makes the whole thread a permanent provider
                // 400.
                if let Err(err) = self.enforce_stop() {
                    self.fail_batch(
                        &calls,
                        index,
                        assistant_row.id,
                        "the kill switch stopped it",
                    );
                    return Err(err);
                }
                if let Err(err) = self.check_cancel() {
                    self.fail_batch(&calls, index, assistant_row.id, "the turn was cancelled");
                    return Err(err);
                }
                // An erase that landed while the model answered: the call's
                // arguments may carry the excerpt (a delegation brief, a
                // mail body), so no further call runs.
                match self.scrub_document_messages(turn_start) {
                    Ok(false) => {}
                    Ok(true) => {
                        self.fail_batch(
                            &calls,
                            index,
                            assistant_row.id,
                            "a document it used was erased",
                        );
                        return Err(ChatError::DocumentErased);
                    }
                    Err(err) => {
                        self.fail_batch(&calls, index, assistant_row.id, "the turn failed");
                        return Err(err);
                    }
                }
                self.emit_tool_start(assistant_row.id, index, call);
                let outcome = if index < MAX_CALLS_PER_ROUND && executed_calls < MAX_CALLS_PER_TURN
                {
                    executed_calls += 1;
                    // A forced turn offers and runs only its own skill; a call
                    // to anything else is refused without running.
                    let offered = match &forced_name {
                        Some(name) => is_skill_tool(&call.name) == Some(name.as_str()),
                        None => true,
                    };
                    // A `skill__<name>` call goes to the skill executor; every
                    // other call takes the plain tool path.
                    let call_outcome = match is_skill_tool(&call.name) {
                        _ if !offered => Ok(CallOutcome {
                            content: "error: this turn runs only its forced skill".to_string(),
                            status: "unknown_tool",
                            taint: None,
                            error_kind: Some("not_offered"),
                        }),
                        Some(skill) => self.run_skill_call(call, skill).await,
                        None => self.run_call(call, batch_taint.as_ref()).await,
                    };
                    match call_outcome {
                        Ok(outcome) => {
                            // A skill's connector replies are
                            // untrusted, so the turn is tainted before the
                            // model sees them (`run_call` marks its own); a
                            // mark that cannot be persisted forces the card.
                            if let (Some(_), Some(source)) =
                                (is_skill_tool(&call.name), &outcome.taint)
                            {
                                match self.record_untrusted_dispatch(source) {
                                    Ok(()) => self.taint.record(source.clone()),
                                    Err(_) => self.taint.mark_unknown(),
                                }
                            }
                            outcome
                        }
                        Err(err) => {
                            let reason = if matches!(err, ChatError::Cancelled) {
                                "the turn was cancelled"
                            } else {
                                "the turn failed before this tool call ran"
                            };
                            self.fail_batch(&calls, index, assistant_row.id, reason);
                            return Err(err);
                        }
                    }
                } else {
                    CallOutcome {
                        content: format!(
                            "error: tool call budget for this turn is exhausted (max {MAX_CALLS_PER_TURN})"
                        ),
                        status: "capped",
                        taint: None,
                        error_kind: None,
                    }
                };
                // A switch to private, or a STOP, that landed during the call
                // ends the batch here. The output is dropped: it is neither
                // stored nor shown, since it was produced under the old mode.
                // The batch is still closed, so the thread stays valid.
                if let Err(err) = self.enforce_stop() {
                    self.fail_batch(
                        &calls,
                        index,
                        assistant_row.id,
                        "the turn was stopped during the call, so its result is withheld",
                    );
                    return Err(err);
                }
                // The trust label is engine-written metadata: it is what lets
                // a resumed session rebuild the taint state without trusting
                // any message content.
                let meta = tool_result_meta(call, &outcome);
                let persisted = if is_document_tool(&call.name) && outcome.status == "ok" {
                    let store = self.store.clone();
                    with_unerased_document_result(&store, &outcome.content, |content| {
                        self.issue_and_persist_tool_result(call, content, &meta)
                    })
                } else {
                    self.issue_and_persist_tool_result(call, &outcome.content, &meta)
                };
                let (content, outbound, tool_row) = match persisted {
                    Ok(result) => result,
                    Err(err @ ChatError::Privacy(_)) => {
                        self.fail_batch(
                            &calls,
                            index,
                            assistant_row.id,
                            "the local privacy check withheld its output",
                        );
                        return Err(err);
                    }
                    Err(err) => return Err(err),
                };
                self.emit_tool_end(
                    assistant_row.id,
                    index,
                    call,
                    outcome.status,
                    &content,
                    outcome.error_kind,
                );
                self.emit_message(&tool_row);
                last_persisted = tool_row.id;
                Arc::make_mut(&mut self.messages).push(outbound);
                memory_written |= outcome.status == "ok"
                    && matches!(call.name.as_str(), "remember" | "delegate" | "crm_add_note");
            }
        }

        self.emit_done(last_persisted);
        Ok(TurnOutcome {
            text: "[stopped: tool loop reached its cap]".to_string(),
            capped: true,
            rounds,
        })
    }

    /// Persist one message: a store row when the text may be stored, else a
    /// memory-only row holding the gated copy (`crate::private`). A private
    /// row is stored as that gated copy (G1); the feed sees the same (C7).
    fn issue_and_persist_tool_result(
        &mut self,
        call: &ToolCall,
        content: &str,
        meta: &str,
    ) -> Result<(String, SafeMessage, Message), ChatError> {
        // A handed value stays whole after the gate reads it.
        let content = kernel_broker::sanitize_external_text(content, 128 * 1024);
        let message = ChatMessage::tool_result(call.id.clone(), content);
        let outbound = if call.name == "delegate" {
            self.issue_model_output(&message)?
        } else {
            self.issue_keeping_handed(&message)?
        };
        let row = self.persist(&message, Some(meta), &outbound)?;
        Ok((message.content, outbound, row))
    }

    /// Persist one message: a store row when the text may be stored, else a
    /// memory-only row holding the gated copy (`crate::private`). A private
    /// row is stored as that gated copy (G1); the feed sees the same (C7).
    pub(super) fn persist(
        &self,
        message: &ChatMessage,
        meta: Option<&str>,
        outbound: &SafeMessage,
    ) -> Result<aux_store::Message, ChatError> {
        if !self.raw_text && !self.keep_history {
            return Ok(self.local_row(role_str(message.role), outbound.content().as_str(), meta));
        }
        if !self.raw_text {
            // PRIVATE-TRANSCRIPT: the row is the copy the provider read or
            // wrote, tokens and all; the pairs its tokens stand for go to the
            // session's token table first, in the same encrypted store.
            let content = outbound.content().as_str();
            let meta = match message.role {
                ChatRole::Assistant => safe_tool_calls_meta(outbound),
                _ => meta.map(str::to_string),
            };
            let pairs = self.pairs_in(&[content, meta.as_deref().unwrap_or_default()]);
            let (dropped, row) = self.store.with(|store| {
                let dropped = store.record_session_tokens(self.session.id, &pairs)?;
                let row = store.append_message(
                    self.session.id,
                    role_str(message.role),
                    content,
                    meta.as_deref(),
                )?;
                Ok::<_, aux_store::StoreError>((dropped, row))
            })?;
            if dropped > 0 {
                tracing::warn!(
                    session = self.session.id,
                    dropped,
                    "session token table full: pairs not stored"
                );
            }
            return Ok(row);
        }
        Ok(self.store.with(|store| {
            store.append_message(
                self.session.id,
                role_str(message.role),
                &message.content,
                meta,
            )
        })?)
    }

    /// This session's `(token, value)` pairs whose token occurs in `texts`.
    fn pairs_in(&self, texts: &[&str]) -> Vec<(String, String)> {
        let mut pairs = self.token_snapshot().pairs();
        pairs.retain(|(token, _)| texts.iter().any(|text| text.contains(token.as_str())));
        pairs
    }

    /// DELEGATION-SOURCE-1: the metadata this turn stamps on its own input
    /// row: the source that says who wrote it. A turn with no source (the
    /// owner's own words) carries none, so the row reads as it always did.
    fn input_meta(&self) -> Option<String> {
        let source = self.input_source.as_deref()?;
        Some(serde_json::json!({ "source": source }).to_string())
    }

    /// A row that exists only in memory: a private turn's message as the event
    /// feed sees it. Its id is negative, so it never collides with a store row.
    fn local_row(&self, role: &str, content: &str, meta: Option<&str>) -> aux_store::Message {
        aux_store::Message {
            id: self
                .local_rows
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed)
                - 1,
            session_id: self.session.id,
            role: role.to_string(),
            content: content.to_string(),
            created_at: String::new(),
            meta: meta.map(str::to_string),
        }
    }

    /// The synthetic results of a cancelled batch in a private conversation:
    /// each one is gated, kept in the context, and returned as a memory row.
    fn remember_batch(
        &mut self,
        rows: &[(String, String, String)],
    ) -> Option<Vec<aux_store::Message>> {
        let mut stored = Vec::with_capacity(rows.len());
        for (role, content, meta) in rows {
            let text = match self.gate.text(content) {
                Ok((text, _)) => text,
                Err(_) => self.gate.text(withheld_marker(Lang::from_env())).ok()?.0,
            };
            let safe = SafeMessage::from_text(ChatRole::Tool, text);
            stored.push(self.local_row(role, safe.content().as_str(), Some(meta)));
            Arc::make_mut(&mut self.messages).push(safe);
        }
        Some(stored)
    }

    /// The tools one round offers: the plain tools and one `skill__<name>` per
    /// loaded skill. A forced skill (an owner `/command`) is the only tool for
    /// every round of its turn.
    fn round_tool_specs(&self, forced_skill: Option<usize>) -> Vec<SafeToolSpec> {
        match forced_skill {
            Some(index) => self.skill_specs.get(index).cloned().into_iter().collect(),
            None => {
                let closed: Vec<&str> = self
                    .tool_gates
                    .iter()
                    .filter(|(_, gate)| !gate())
                    .map(|(name, _)| name.as_str())
                    .collect();
                self.tool_specs
                    .iter()
                    .filter(|spec| !closed.contains(&spec.name().as_str()))
                    .chain(&self.skill_specs)
                    .cloned()
                    .collect()
            }
        }
    }

    pub(super) fn emit_message(&self, message: &aux_store::Message) {
        if let Some(events) = &self.events {
            events.message(message);
        }
    }

    pub(super) fn emit_tool_start(&self, message_id: i64, index: usize, call: &ToolCall) {
        if let Some(events) = &self.events {
            events.tool_start(self.session.id, message_id, index, call);
        }
    }

    pub(super) fn emit_tool_end(
        &self,
        message_id: i64,
        index: usize,
        call: &ToolCall,
        status: &str,
        result: &str,
        error_kind: Option<&str>,
    ) {
        if let Some(events) = &self.events {
            events.tool_end(
                self.session.id,
                message_id,
                index,
                call,
                crate::events::ToolEndOutcome {
                    status,
                    result,
                    error_kind,
                },
            );
        }
    }

    fn emit_done(&self, message_id: i64) {
        if let Some(events) = &self.events {
            events.done(self.session.id, message_id);
        }
    }

    /// Close a tool batch the turn will never answer (cancel or STOP between
    /// two calls): persist one synthetic `cancelled` tool result per
    /// unanswered call **in one transaction**, so the stored assistant
    /// `tool_calls` row never dangles without matching results. A
    /// dangling row is rejected by every provider, and because the same
    /// prefix is re-sent on every resume the thread would 400 forever.
    ///
    /// Best-effort by design: the caller is already aborting, and a store
    /// failure here leaves the history exactly as it was (all-or-nothing
    /// transaction).
    pub(super) fn fail_batch(
        &mut self,
        calls: &[ToolCall],
        from: usize,
        assistant_id: i64,
        reason: &str,
    ) {
        let unanswered = &calls[from..];
        if unanswered.is_empty() {
            return;
        }
        let rows: Vec<(String, String, String)> = unanswered
            .iter()
            .map(|call| {
                let content = format!(
                    "error: {reason}; `{}` has no result (this result was written by the engine)",
                    call.name
                );
                // Keep the trust class: an untrusted-class call was
                // write-ahead tainted before dispatch, and a resumed session
                // must not read this row as a clean one (fail closed).
                let meta = serde_json::json!({
                    "tool_call_id": call.id,
                    "tool": call.name,
                    "status": "cancelled",
                    "tainted": self.registry().is_untrusted_output(&call.name),
                })
                .to_string();
                ("tool".to_string(), content, meta)
            })
            .collect();
        // A private batch goes into the context as its gated copy, which is
        // also what the store keeps when it keeps the history (G1).
        let gated = if self.raw_text {
            None
        } else {
            match self.remember_batch(&rows) {
                Some(gated) => Some(gated),
                None => return,
            }
        };
        let stored = if self.raw_text || self.keep_history {
            let refs: Vec<(&str, &str, Option<&str>)> = rows
                .iter()
                .enumerate()
                .map(|(index, (role, content, meta))| {
                    let content = gated
                        .as_ref()
                        .and_then(|gated| gated.get(index))
                        .map_or(content.as_str(), |row| row.content.as_str());
                    (role.as_str(), content, Some(meta.as_str()))
                })
                .collect();
            match self
                .store
                .with(|store| store.append_messages_atomic(self.session.id, &refs))
            {
                Ok(stored) => stored,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        session = self.session.id,
                        "could not close a cancelled tool batch; the thread may need repair"
                    );
                    return;
                }
            }
        } else {
            gated.unwrap_or_default()
        };
        for (offset, row) in stored.iter().enumerate() {
            let index = from + offset;
            if offset == 0 {
                // Only the call that actually started has a matching
                // `tool.start` event; the rest never began.
                self.emit_tool_end(
                    assistant_id,
                    index,
                    &calls[index],
                    "cancelled",
                    &row.content,
                    None,
                );
            }
            self.emit_message(row);
        }
    }

    /// Abort the turn when the injected kill-switch gate reads engaged.
    pub(super) fn enforce_stop(&self) -> Result<(), ChatError> {
        match &self.stop {
            Some(stop) if stop.is_stopped() => Err(ChatError::Stopped),
            _ => Ok(()),
        }
    }

    /// Abort the turn when the cancellation token fired.
    pub(super) fn check_cancel(&self) -> Result<(), ChatError> {
        match &self.cancel {
            Some(cancel) if cancel.is_cancelled() => Err(ChatError::Cancelled),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testsupport::*;
    use super::super::{ChatError, MAX_TOOL_ROUNDS};
    use crate::stop::StopCheck;
    use async_trait::async_trait;
    use aux_providers::{
        ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, FakeProvider,
        ProviderError, ToolCall,
    };
    use kernel_broker::{
        Action, Risk, Rule, ShellSandbox, Tool, ToolClass, ToolCtx, ToolError, ToolOutput,
    };
    use kernel_core::budget::Budgets;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct DocumentResults(String);

    struct EraseOrDelegate {
        name: &'static str,
        store: Arc<Mutex<aux_store::Store>>,
        hash: String,
        seen: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    #[async_trait]
    impl Tool for EraseOrDelegate {
        fn class(&self) -> ToolClass {
            ToolClass::default()
        }
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            self.name
        }
        fn schema(&self) -> serde_json::Value {
            json!({"type":"object"})
        }
        async fn run(
            &self,
            args: &serde_json::Value,
            _: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            if self.name == "erase_fixture" {
                let lifecycle = aux_store::evidence_lifecycle_lock(&self.hash);
                let _guard = kernel_core::lock_recover(&lifecycle);
                let store = self.store.lock().unwrap();
                store
                    .erase_document_by_hash_prefix(&self.hash[..12])
                    .unwrap();
                store.finish_evidence_erasure(&self.hash).unwrap();
            } else {
                self.seen.lock().unwrap().push(args.clone());
            }
            Ok(ToolOutput::ok(
                args.get("note").and_then(|v| v.as_str()).unwrap_or("done"),
            ))
        }
        fn risk(&self) -> Risk {
            Risk::Low
        }
    }

    #[tokio::test]
    async fn an_erase_after_an_echo_stops_the_turn_before_any_later_request_or_delegation() {
        const EXCERPT: &str = "ERASED-EXCERPT-REVISION";
        const PART: &str = "ERASED-EXCERPT";
        const KEEP: &str = "RETAINED-OTHER-DOCUMENT";
        let harness = Harness::new();
        let hash = "f".repeat(64);
        let id = append_test_document(&harness.store(), &hash, "echo.txt");
        let kept = append_test_document(&harness.store(), &"a".repeat(64), "keep.txt");
        let content = format!(
            "[untrusted document content]\n{}",
            json!({"matches":[{"document_id": id, "excerpt": EXCERPT}, {"document_id":kept,"excerpt":KEEP}]})
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        {
            let mut registry = harness.registry.write().unwrap();
            registry.register(Box::new(DocumentResults(content)));
            for name in ["erase_fixture", "delegate"] {
                registry.register(Box::new(EraseOrDelegate {
                    name,
                    store: Arc::clone(&harness.store),
                    hash: hash.clone(),
                    seen: Arc::clone(&seen),
                }));
            }
        }
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("read", "docs_ingest", json!({}))],
                )),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    format!("{PART} and {KEEP}"),
                    vec![
                        ToolCall::new("erase", "erase_fixture", json!({"note":EXCERPT})),
                        ToolCall::new(
                            "delegation",
                            "delegate",
                            json!({"task":format!("summarize {PART}")}),
                        ),
                    ],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let rules = ["docs_ingest", "erase_fixture", "delegate"]
            .iter()
            .map(|name| Rule::new("main", *name, Action::Allow))
            .collect();
        let mut session = harness.start(&provider, rules, RecordingApprover::new(true));
        let result = session.send("find the document").await;
        assert!(
            matches!(result, Err(ChatError::DocumentErased)),
            "got {:?}",
            result.map(|reply| reply.text)
        );
        // Request 1 read the document, request 2 echoed it before the erase.
        // Nothing after the erase left: no third request, no delegation.
        let requests = provider.requests();
        assert_eq!(requests.len(), 2, "a request left after the erase");
        assert!(
            seen.lock().unwrap().is_empty(),
            "the delegation ran with an erased excerpt in its brief"
        );
    }

    #[async_trait]
    impl Tool for DocumentResults {
        fn class(&self) -> ToolClass {
            ToolClass::default()
        }
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "docs_ingest"
        }
        fn schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }
        async fn run(&self, _: &serde_json::Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok(self.0.clone()))
        }
        fn risk(&self) -> Risk {
            Risk::Low
        }
    }

    /// A non-document tool that answers with raw text, as `read_file` and
    /// `recall` do: the engine must classify the result by this tool, not by
    /// what the text happens to start with.
    struct RawResults(&'static str, String);

    #[async_trait]
    impl Tool for RawResults {
        fn class(&self) -> ToolClass {
            ToolClass::default()
        }
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            self.0
        }
        fn schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }
        async fn run(&self, _: &serde_json::Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok(self.1.clone()))
        }
        fn risk(&self) -> Risk {
            Risk::Low
        }
    }

    struct EraseAtToolEnd {
        store: Arc<Mutex<aux_store::Store>>,
        hash: String,
        calls: std::sync::atomic::AtomicUsize,
        erase_after: usize,
    }

    impl crate::events::TurnEvents for EraseAtToolEnd {
        fn message(&self, _: &aux_store::Message) {}
        fn tool_start(&self, _: i64, _: i64, _: usize, _: &ToolCall) {}
        fn tool_end(
            &self,
            _: i64,
            _: i64,
            _: usize,
            _: &ToolCall,
            _: crate::events::ToolEndOutcome<'_>,
        ) {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.erase_after
            {
                let lock = aux_store::evidence_lifecycle_lock(&self.hash);
                let _guard = kernel_core::lock_recover(&lock);
                let store = self.store.lock().unwrap();
                assert!(matches!(
                    store
                        .erase_document_by_hash_prefix(&self.hash[..12])
                        .unwrap(),
                    aux_store::DocumentEraseResult::Erased(_)
                ));
                store.finish_evidence_erasure(&self.hash).unwrap();
            }
        }
        fn done(&self, _: i64, _: i64) {}
    }

    #[tokio::test]
    async fn erased_document_excerpts_do_not_reach_later_requests_in_the_same_turn() {
        for private in [false, true] {
            check_active_document_erase(private, false, 1).await;
            check_active_document_erase(private, false, 2).await;
        }
    }

    #[tokio::test]
    async fn erasing_an_unrelated_document_keeps_active_excerpts() {
        check_active_document_erase(false, true, 1).await;
        check_active_document_erase(true, true, 1).await;
    }

    async fn check_active_document_erase(private: bool, unrelated: bool, erase_after: usize) {
        const EXCERPT_A: &str = "ERASED-EXCERPT-ALPHA";
        const EXCERPT_B: &str = "ERASED-EXCERPT-BETA";
        const KEEP: &str = "OTHER-DOCUMENT-KEEP";
        let mut harness = Harness::new();
        if private {
            harness.private(known_contacts());
        }
        let hash = "a".repeat(64);
        let other_hash = "b".repeat(64);
        let unrelated_hash = "c".repeat(64);
        let (id, other_id) = {
            let store = harness.store();
            append_test_document(&store, &unrelated_hash, "unrelated.txt");
            (
                append_test_document(&store, &hash, "erase.txt"),
                append_test_document(&store, &other_hash, "keep.txt"),
            )
        };
        let content = format!(
            "[untrusted document content]\n{}",
            json!({"matches": [
                {"document_id": id, "excerpt": EXCERPT_A},
                {"document_id": id, "excerpt": EXCERPT_B},
                {"document_id": other_id, "excerpt": KEEP}
            ]})
        );
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(DocumentResults(content)));
        let call = |id| {
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new(id, "docs_ingest", json!({}))],
            ))
        };
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                call("first"),
                call("second"),
                ChatResponse::assistant("done"),
            ],
        );
        let events = Arc::new(EraseAtToolEnd {
            store: Arc::clone(&harness.store),
            hash: if unrelated { unrelated_hash } else { hash },
            calls: std::sync::atomic::AtomicUsize::new(0),
            erase_after,
        });
        let mut session = harness.start_with_events(
            &provider,
            vec![Rule::new("main", "docs_ingest", Action::Allow)],
            RecordingApprover::new(true),
            events,
        );
        let result = session.send("find the document").await;
        let requests = provider.requests();
        if !unrelated {
            // The erase lands at the end of tool call `erase_after`: the
            // turn stops before the next request, so only the earlier ones,
            // made before the erase, ever left.
            assert!(
                matches!(result, Err(ChatError::DocumentErased)),
                "got {:?}",
                result.map(|reply| reply.text)
            );
            assert_eq!(
                requests.len(),
                erase_after,
                "a request left after the erase"
            );
            return;
        }
        result.unwrap();
        assert_eq!(requests.len(), 3);
        for (index, request) in requests.iter().enumerate().skip(1) {
            let body = serde_json::to_string(request).unwrap();
            if unrelated || index < erase_after {
                assert!(
                    body.contains(EXCERPT_A) && body.contains(EXCERPT_B),
                    "request {index} lost an unrelated excerpt"
                );
            } else {
                assert!(
                    !body.contains(EXCERPT_A) && !body.contains(EXCERPT_B),
                    "request {index} leaked an erased excerpt"
                );
                assert!(
                    body.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
                    "missing erased marker in request {index}"
                );
            }
            assert!(
                body.contains(KEEP),
                "other document was removed in request {index}"
            );
        }
    }

    /// ERASE-ASSISTANT-ECHO: Aux quoted a document in an earlier turn; the
    /// owner erases it; the next turn's request carries the marker in place
    /// of the quote, in the running session and in a resumed one, in both modes.
    #[tokio::test]
    async fn an_erase_rewrites_the_assistants_earlier_quote_before_the_next_turn() {
        for private in [false, true] {
            for resumed in [false, true] {
                check_assistant_echo_erase(private, resumed).await;
            }
        }
    }

    async fn check_assistant_echo_erase(private: bool, resumed: bool) {
        const ERASED: &str = "ERASED-LEASE-CLAUSE-ALPHA-SEVENTEEN";
        const KEPT: &str = "KEPT-DELIVERY-CLAUSE-BETA-THIRTY";
        let mut harness = Harness::new();
        if private {
            harness.private(known_contacts());
        }
        let hash = "a".repeat(64);
        let (id, other_id) = {
            let store = harness.store();
            (
                append_test_document(&store, &hash, "lease.txt"),
                append_test_document(&store, &"b".repeat(64), "delivery.txt"),
            )
        };
        let content = format!(
            "[untrusted document content]\n{}",
            json!({"matches": [
                {"document_id": id, "excerpt": ERASED},
                {"document_id": other_id, "excerpt": KEPT}
            ]})
        );
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(DocumentResults(content)));
        let quote = format!("The lease says: {ERASED}. The delivery note says: {KEPT}.");
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("first", "docs_ingest", json!({}))],
                )),
                ChatResponse::assistant(quote.clone()),
                ChatResponse::assistant("noted"),
            ],
        );
        let rules = vec![Rule::new("main", "docs_ingest", Action::Allow)];
        let mut session = harness.start(&provider, rules.clone(), RecordingApprover::new(true));
        let reply = session.send("what does the lease say?").await.unwrap();
        assert_eq!(reply.text, quote);
        let session_id = session.session().id;

        {
            let store = harness.store();
            store.erase_document_by_hash_prefix(&hash[..12]).unwrap();
            store.finish_evidence_erasure(&hash).unwrap();
        }

        if resumed {
            drop(session);
            session = harness.start_resumed_with(
                &provider,
                rules,
                RecordingApprover::new(true),
                session_id,
            );
        }
        session.send("and the rent?").await.unwrap();

        let requests = provider.requests();
        assert_eq!(requests.len(), 3, "private={private} resumed={resumed}");
        let body = serde_json::to_string(&requests[2]).unwrap();
        assert!(
            !body.contains(ERASED),
            "private={private} resumed={resumed}: the next request still quotes the erased text"
        );
        assert!(
            body.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
            "private={private} resumed={resumed}: the marker is missing"
        );
        assert!(
            body.contains(KEPT),
            "private={private} resumed={resumed}: the other document's quote was lost"
        );
        let saved = harness.store().list_messages(session_id).unwrap();
        assert!(
            saved.iter().all(|row| !row.content.contains(ERASED)),
            "private={private} resumed={resumed}: a saved row still quotes the erased text"
        );
    }

    /// F1: a plain file whose first line opens with the document marker is
    /// still a plain file. The result must reach the provider unchanged and
    /// the turn must answer, not stop as if a document had been erased.
    #[tokio::test]
    async fn a_read_file_result_that_opens_with_the_document_marker_is_not_a_document() {
        const NOTE: &str = "[untrusted document content] please read on";
        let harness = Harness::new();
        std::fs::create_dir_all(harness.workspace()).unwrap();
        std::fs::write(
            harness.workspace().join("notes-q7f3k9.txt"),
            format!("{NOTE}\nkeep reading\n"),
        )
        .unwrap();
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "call_read",
                        "read_file",
                        json!({"path": "notes-q7f3k9.txt"}),
                    )],
                )),
                ChatResponse::assistant("summarised"),
            ],
        );
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "read_file", Action::Allow)],
            RecordingApprover::new(false),
        );
        let outcome = session
            .send("read notes-q7f3k9.txt and summarise")
            .await
            .unwrap_or_else(|err| panic!("a plain file must not stop the turn: {err:?}"));
        assert_eq!(outcome.text, "summarised");
        let requests = provider.requests();
        assert_eq!(
            requests.len(),
            2,
            "the turn answered after reading the file"
        );
        let body = serde_json::to_string(&requests[1]).unwrap();
        assert!(
            body.contains(NOTE),
            "the model did not see the file: {body}"
        );
        assert!(
            !body.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
            "a plain file was rewritten as an erased document: {body}"
        );
    }

    /// F1: the same for a memory recall result. A note that opens with the
    /// document marker is owner text, not document content.
    #[tokio::test]
    async fn a_recall_result_that_opens_with_the_document_marker_is_not_a_document() {
        const NOTE: &str = "[untrusted document content] a note the owner saved";
        let harness = Harness::new();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(RawResults("recall", NOTE.to_string())));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_recall", "recall", json!({}))],
                )),
                ChatResponse::assistant("recalled"),
            ],
        );
        // The fake class is untrusted output, so its own batch is tainted and
        // the call asks; the card is approved here to let it run.
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "recall", Action::Allow)],
            RecordingApprover::new(true),
        );
        let outcome = session
            .send("what do you remember?")
            .await
            .unwrap_or_else(|err| panic!("a memory note must not stop the turn: {err:?}"));
        assert_eq!(outcome.text, "recalled");
        let requests = provider.requests();
        assert_eq!(requests.len(), 2, "the turn answered after the recall");
        let body = serde_json::to_string(&requests[1]).unwrap();
        assert!(
            body.contains(NOTE),
            "the model did not see the note: {body}"
        );
        assert!(
            !body.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
            "a memory note was rewritten as an erased document: {body}"
        );
    }

    /// F1 fail-closed path: an old documents row with no producing tool in the
    /// window is still a document. The marker is the only evidence left, and
    /// the erase must scrub it before the next request.
    #[tokio::test]
    async fn a_document_row_without_tool_provenance_is_still_scrubbed_on_erase() {
        const LEGACY: &str = "LEGACY-EXCERPT-NO-TOOL-META";
        let harness = Harness::new();
        let hash = "b".repeat(64);
        let id = append_test_document(&harness.store(), &hash, "legacy.txt");
        let session_id = {
            let provider = FakeProvider::repeating("fake", ChatResponse::assistant("first"));
            let mut first = harness.start(&provider, vec![], RecordingApprover::new(false));
            first.send("one").await.unwrap();
            first.session().id
        };
        let content = format!(
            "[untrusted document content]\n{}",
            json!({"matches":[{"document_id": id, "excerpt": LEGACY}]})
        );
        // A row written before the tool name was kept: its meta names only the
        // call, and no assistant row in the window answers it.
        harness
            .store()
            .append_message(
                session_id,
                "tool",
                &content,
                Some(r#"{"tool_call_id":"legacy"}"#),
            )
            .unwrap();
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(EraseOrDelegate {
                name: "erase_fixture",
                store: Arc::clone(&harness.store),
                hash: hash.clone(),
                seen: Arc::new(Mutex::new(Vec::new())),
            }));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("erase", "erase_fixture", json!({}))],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let mut resumed = harness.start_resumed_with(
            &provider,
            vec![Rule::new("main", "erase_fixture", Action::Allow)],
            RecordingApprover::new(true),
            session_id,
        );
        assert_eq!(resumed.send("two").await.unwrap().text, "done");
        let requests = provider.requests();
        assert_eq!(requests.len(), 2);
        let body = serde_json::to_string(&requests[1]).unwrap();
        assert!(
            !body.contains(LEGACY),
            "an old document row leaked its erased excerpt: {body}"
        );
        assert!(
            body.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
            "an old document row was not scrubbed: {body}"
        );
    }

    #[tokio::test]
    async fn document_dispatch_holds_lifecycle_lock_until_completion_and_releases_it() {
        let harness = Harness::new();
        let hash = "d".repeat(64);
        let id = append_test_document(&harness.store(), &hash, "in-flight.txt");
        let provider = FakeProvider::echo("fake");
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
        let message = ChatMessage::tool_result(
            "call",
            format!(
                "[untrusted document content]\n{}",
                json!({"document_id": id, "excerpt": "IN-FLIGHT"})
            ),
        );
        let safe = session.issue_keeping_handed(&message).unwrap();
        Arc::make_mut(&mut session.messages).push(safe);
        let guard = session.guard_document_dispatch(0).await.unwrap().unwrap();
        let lock = aux_store::evidence_lifecycle_lock(&hash);
        assert!(matches!(
            lock.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        guard.release().await;
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn erase_after_the_final_answer_only_scrubs_saved_history() {
        let harness = Harness::new();
        let hash = "e".repeat(64);
        let id = append_test_document(&harness.store(), &hash, "finished.txt");
        let content = format!(
            "[untrusted document content]\n{}",
            json!({"document_id": id, "excerpt": "FINISHED-EXCERPT"})
        );
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(DocumentResults(content)));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("one", "docs_ingest", json!({}))],
                )),
                ChatResponse::assistant("finished"),
            ],
        );
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "docs_ingest", Action::Allow)],
            RecordingApprover::new(true),
        );
        let session_id = session.session.id;
        assert_eq!(
            session.send("find the document").await.unwrap().text,
            "finished"
        );
        let before = provider.requests();
        assert!(serde_json::to_string(&before[1])
            .unwrap()
            .contains("FINISHED-EXCERPT"));
        let lock = aux_store::evidence_lifecycle_lock(&hash);
        let _guard = kernel_core::lock_recover(&lock);
        let store = harness.store();
        store.erase_document_by_hash_prefix(&hash[..12]).unwrap();
        store.finish_evidence_erasure(&hash).unwrap();
        assert_eq!(provider.requests(), before);
        let saved = store.list_messages(session_id).unwrap();
        assert!(saved
            .iter()
            .all(|row| !row.content.contains("FINISHED-EXCERPT")));
        assert!(saved
            .iter()
            .any(|row| row.content.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT)));
    }

    #[tokio::test]
    async fn streaming_deltas_arrive_in_order_and_only_the_final_message_is_persisted() {
        let harness = Harness::new();
        let provider = FakeProvider::echo("fake").with_stream_chunks(3);
        let events = RecordingEvents::new();
        let mut session = harness.start_with_events(
            &provider,
            vec![],
            RecordingApprover::new(false),
            events.clone(),
        );
        let session_id = session.session.id;

        let outcome = session.send("hello").await.unwrap();

        assert_eq!(outcome.text, "[fake:fake] hello");
        let calls = events.calls();
        let recorded = deltas(&calls);
        assert!(
            recorded.len() > 2,
            "chunked streaming must report several deltas: {calls:?}"
        );
        assert!(
            recorded.iter().all(|(draft, _, _)| *draft == 1),
            "one draft per provider round: {recorded:?}"
        );
        assert_eq!(
            recorded.iter().map(|(_, seq, _)| *seq).collect::<Vec<_>>(),
            (1..=recorded.len() as u64).collect::<Vec<_>>(),
            "seq is 1-based and monotonic: {recorded:?}"
        );
        let streamed: String = recorded.iter().map(|(_, _, text)| text.as_str()).collect();
        assert_eq!(streamed, "[fake:fake] hello");

        // The final message is still persisted exactly once, and the deltas
        // arrived before it.
        assert_eq!(
            harness.roles(session_id),
            vec!["system", "user", "assistant"]
        );
        let first_delta = calls.iter().position(|c| c.starts_with("delta:")).unwrap();
        let assistant = calls
            .iter()
            .position(|c| c.starts_with("message:") && c.ends_with(":assistant"))
            .unwrap();
        assert!(
            first_delta < assistant,
            "transient deltas must precede the persisted message: {calls:?}"
        );
        assert_eq!(provider.request_count(), 1);
    }

    /// DOCS-ERASED-MARKER: the raw store marker never reaches the app through
    /// a streamed delta, even when the provider splits it across two chunks.
    #[tokio::test]
    async fn a_streamed_raw_erased_marker_reaches_the_app_as_the_plain_sentence() {
        const RAW: &str = "[document erased]";
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant(format!("A{RAW}B")))
            .with_stream_chunks(4);
        let events = RecordingEvents::new();
        let mut session = harness.start_with_events(
            &provider,
            vec![],
            RecordingApprover::new(false),
            events.clone(),
        );

        let outcome = session.send("hello").await.unwrap();

        let streamed: String = deltas(&events.calls())
            .iter()
            .map(|(_, _, text)| text.as_str())
            .collect();
        assert!(
            !streamed.contains(RAW),
            "raw marker reached the app: {streamed}"
        );
        assert!(
            streamed.contains(aux_store::DOCUMENT_UNAVAILABLE_TEXT),
            "{streamed}"
        );
        assert_eq!(streamed, outcome.text);
    }

    /// CAL-NO-TOOL-GUESS: a session that can read the calendar, and the live
    /// prompt that made the Calendar agent answer "3" with no tool call.
    const COUNT_PROMPT: &str =
        "Ask the Calendar agent: how many events this week? Reply with only the number";

    const NO_CALENDAR_CHECK: &str = "I didn't check your calendar, so I can't say.";

    fn calendar_harness() -> Harness {
        let mut registry =
            builtin_registry(ShellSandbox::default(), kernel_core::WebConfig::default());
        registry.register_native(Box::new(FalsePositiveTool));
        Harness::with_registry(registry)
    }

    fn has_nudge(request: &ChatRequest) -> bool {
        request.messages.iter().any(|message| {
            message.role() == ChatRole::System
                && message.content().as_str().contains("Check with your tools")
        })
    }

    #[tokio::test]
    async fn a_calendar_count_given_without_a_tool_is_retried_once_then_answered_honestly() {
        let harness = calendar_harness();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("3"));
        let events = RecordingEvents::new();
        let approver = RecordingApprover::new(false);
        let mut session = harness.start_with_events(&provider, vec![], approver, events.clone());
        let id = session.session.id;

        let outcome = session.send(COUNT_PROMPT).await.unwrap();

        assert_eq!(outcome.text, NO_CALENDAR_CHECK);
        assert_eq!(provider.request_count(), 2, "one retry, never a loop");
        let requests = provider.requests();
        assert!(!has_nudge(&requests[0]));
        assert!(has_nudge(&requests[1]), "the retry carries the nudge");
        let stored = harness.store().list_messages(id).unwrap();
        assert!(
            stored.iter().all(|row| row.content != "3"),
            "a guess is never stored"
        );
        // The receipt sink sees the retry, then the replaced answer.
        let checks: Vec<String> = events
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("read_check:"))
            .collect();
        let expected = [true, false].map(|retried| format!("read_check:{id}:calendar:{retried}"));
        assert_eq!(checks, expected);
        // A dropped guess never streams: the app never shows the "3".
        assert!(
            events
                .calls()
                .iter()
                .all(|call| !call.starts_with("delta:")),
            "a held guess is never published"
        );
        // The nudge belongs to the turn: the next turn does not carry it.
        session.send("thanks").await.unwrap();
        assert!(!has_nudge(provider.requests().last().unwrap()));
    }

    #[tokio::test]
    async fn the_retry_reads_the_calendar_and_its_answer_stands() {
        let harness = calendar_harness();
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::assistant("3"),
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_cal", "calendar_list_events", json!({}))],
                )),
                ChatResponse::assistant("2"),
            ],
        );
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "calendar_list_events", Action::Allow)],
            RecordingApprover::new(false),
        );

        let outcome = session.send(COUNT_PROMPT).await.unwrap();

        assert_eq!(outcome.text, "2");
        assert_eq!(provider.request_count(), 3);
    }

    #[tokio::test]
    async fn an_answer_after_a_tool_call_or_to_a_greeting_is_not_retried() {
        let harness = calendar_harness();
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_cal", "calendar_list_events", json!({}))],
                )),
                ChatResponse::assistant("3"),
                ChatResponse::assistant("You're welcome."),
            ],
        );
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "calendar_list_events", Action::Allow)],
            RecordingApprover::new(false),
        );

        assert_eq!(session.send(COUNT_PROMPT).await.unwrap().text, "3");
        assert_eq!(
            session.send("thanks!").await.unwrap().text,
            "You're welcome."
        );
        assert_eq!(provider.request_count(), 3);
    }

    #[tokio::test]
    async fn a_second_answer_that_states_no_fact_is_kept_and_streamed_once() {
        let harness = calendar_harness();
        let advice = "Which calendar should I look at, work or personal?";
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant(advice));
        let events = RecordingEvents::new();
        let approver = RecordingApprover::new(false);
        let mut session = harness.start_with_events(&provider, vec![], approver, events.clone());
        let id = session.session.id;

        let outcome = session.send("am I busy tomorrow?").await.unwrap();

        assert_eq!(outcome.text, advice);
        assert_eq!(provider.request_count(), 2);
        let deltas: Vec<String> = events
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("delta:"))
            .collect();
        assert_eq!(deltas, [format!("delta:{id}:2:1:{advice}")]);
    }

    #[tokio::test]
    async fn the_honest_line_answers_in_the_owners_language() {
        let harness = calendar_harness();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("3"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        let outcome = session
            .send("Combien de réunions cette semaine ?")
            .await
            .unwrap();

        assert_eq!(
            outcome.text,
            "Je n'ai pas vérifié votre agenda, je ne peux donc pas répondre."
        );
    }

    #[tokio::test]
    async fn a_private_turn_is_retried_the_same_way() {
        let mut harness = calendar_harness();
        harness.private(known_contacts());
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("3"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        let outcome = session.send("am I free Tuesday for a call?").await.unwrap();

        assert_eq!(outcome.text, NO_CALENDAR_CHECK);
        assert_eq!(provider.request_count(), 2);
    }

    #[tokio::test]
    async fn tool_loop_stops_at_the_round_cap() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating(
            "fake",
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![write_file_call("call_loop", "loop.txt", "again")],
            )),
        );
        let mut session = harness.start(
            &provider,
            vec![Rule::new("main", "write_file", Action::Allow)],
            RecordingApprover::new(false),
        );
        let session_id = session.session.id;

        let outcome = session.send("loop forever").await.unwrap();

        assert!(outcome.capped);
        assert_eq!(outcome.rounds, MAX_TOOL_ROUNDS);
        assert_eq!(provider.request_count(), MAX_TOOL_ROUNDS);
        let roles = harness.roles(session_id);
        assert_eq!(roles.len(), 1 + 1 + MAX_TOOL_ROUNDS * 2);
        assert_eq!(roles[0], "system");
        assert_eq!(roles[1], "user");
        assert_eq!(roles[roles.len() - 1], "tool");
    }

    #[tokio::test]
    async fn provider_error_persists_the_user_message_and_surfaces() {
        let harness = Harness::new();
        let provider = FakeProvider::scripted("fake", vec![]);
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
        let session_id = session.session.id;

        let err = session.send("anyone there?").await.unwrap_err();

        assert!(matches!(err, ChatError::Provider(_)), "got {err:?}");
        assert_eq!(harness.roles(session_id), vec!["system", "user"]);
    }

    // ---- kill switch ----

    /// Stop gate the test can flip at any moment.
    #[derive(Default)]
    struct FlipStop(Mutex<bool>);

    impl FlipStop {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn engage(&self) {
            *self.0.lock().unwrap() = true;
        }
    }

    impl StopCheck for FlipStop {
        fn is_stopped(&self) -> bool {
            *self.0.lock().unwrap()
        }
    }

    /// Provider that engages the stop gate as it serves a completion, so the
    /// engine sees STOP exactly between the provider call and the tool call.
    struct TripProvider {
        inner: FakeProvider,
        stop: Arc<FlipStop>,
    }

    #[async_trait]
    impl ChatProvider for TripProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.stop.engage();
            self.inner.complete(req).await
        }

        fn name(&self) -> &str {
            self.inner.name()
        }
    }

    #[tokio::test]
    async fn engaged_stop_aborts_before_the_first_provider_call() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("never"));
        let stop = FlipStop::new();
        stop.engage();
        let mut session = harness.start_with_stop(
            &provider,
            vec![],
            RecordingApprover::new(false),
            &harness.budgets,
            stop,
        );
        let session_id = session.session.id;

        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::Stopped), "got {err:?}");
        assert_eq!(provider.request_count(), 0, "no provider call may happen");
        // The stop is read before the user row is stored, so a stopped
        // turn leaves no raw row behind.
        assert_eq!(harness.roles(session_id), vec!["system"]);
    }

    #[tokio::test]
    async fn stop_engaged_mid_loop_skips_the_remaining_tool_calls() {
        let harness = Harness::new();
        let stop = FlipStop::new();
        let provider = TripProvider {
            inner: scripted_tool_then_text(),
            stop: Arc::clone(&stop),
        };
        let mut session = harness.start_with_stop(
            &provider,
            vec![],
            RecordingApprover::new(true),
            &harness.budgets,
            stop,
        );
        let session_id = session.session.id;

        let err = session.send("write a note").await.unwrap_err();

        assert!(matches!(err, ChatError::Stopped), "got {err:?}");
        assert_eq!(provider.inner.request_count(), 1, "only round one ran");
        assert!(
            !harness.workspace().join("note.txt").exists(),
            "the tool call after the engaged stop must not run"
        );
        // The batch is closed with a synthetic result instead of a
        // dangling assistant `tool_calls` row.
        assert_eq!(
            harness.roles(session_id),
            vec!["system", "user", "assistant", "tool"]
        );
        let stored = harness.store().list_messages(session_id).unwrap();
        let tool_row = stored.last().unwrap();
        assert!(tool_row
            .meta
            .as_deref()
            .unwrap()
            .contains(r#""status":"cancelled""#));
        assert!(
            tool_row.content.contains("kill switch"),
            "{}",
            tool_row.content
        );
    }

    /// A tool whose call is the owner's switch to private: it runs while the
    /// mode changes, and what it returns is raw.
    struct SwitchToPrivateTool {
        mode: Arc<Mutex<kernel_core::privacy::PrivacyMode>>,
    }

    #[async_trait]
    impl Tool for SwitchToPrivateTool {
        fn class(&self) -> ToolClass {
            ToolClass::default()
        }

        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }

        fn name(&self) -> &str {
            "switch_read"
        }

        fn schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            *self.mode.lock().unwrap() = kernel_core::privacy::PrivacyMode::Private;
            Ok(ToolOutput::ok("RAW-TOOL-OUTPUT-0417 Camille Exemple"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }
    }

    /// An Open turn whose tool call lands after the owner switched
    /// to private must not store the tool's raw output.
    #[tokio::test]
    async fn a_tool_result_that_lands_after_a_switch_to_private_is_not_stored_raw() {
        let harness = Harness::new();
        let mode = Arc::new(Mutex::new(kernel_core::privacy::PrivacyMode::Open));
        harness
            .registry
            .write()
            .unwrap()
            .register(Box::new(SwitchToPrivateTool {
                mode: Arc::clone(&mode),
            }));
        let live = Arc::clone(&mode);
        let stop: Arc<dyn StopCheck> = Arc::new(crate::ModeChangeStop::new(
            kernel_core::privacy::PrivacyMode::Open,
            Arc::new(move || *live.lock().unwrap()),
        ));
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new("call_1", "switch_read", json!({}))],
                )),
                ChatResponse::assistant("never"),
            ],
        );
        let budgets = Budgets::default();
        let mut session = harness.start_with_stop(
            &provider,
            vec![Rule::new("main", "switch_read", Action::Allow)],
            RecordingApprover::new(true),
            &budgets,
            stop,
        );
        let session_id = session.session.id;

        let err = session.send("lis la note").await.unwrap_err();

        assert!(matches!(err, ChatError::Stopped), "got {err:?}");
        assert_eq!(
            provider.request_count(),
            1,
            "no provider round after the switch"
        );
        let stored = harness.store().list_messages(session_id).unwrap();
        assert!(
            stored
                .iter()
                .all(|row| !row.content.contains("RAW-TOOL-OUTPUT-0417")),
            "the tool's raw output was stored: {stored:?}"
        );
        assert_eq!(
            harness.roles(session_id),
            vec!["system", "user", "assistant", "tool"]
        );
    }

    #[tokio::test]
    async fn turn_events_follow_the_persisted_messages_in_order() {
        let harness = Harness::new();
        let provider = scripted_tool_then_text();
        let events = RecordingEvents::new();
        let rules = vec![Rule::new("main", "write_file", Action::Allow)];
        let mut session = harness.start_with_events(
            &provider,
            rules,
            RecordingApprover::new(false),
            events.clone(),
        );

        session.send("do it").await.unwrap();

        // System prompt is id 1; user/assistant/tool/assistant follow. The
        // final round's non-streaming provider still reports its whole answer
        // as one transient delta (draft 2, seq 1) before the persisted row.
        assert_eq!(
            events.calls(),
            vec![
                "message:2:user",
                "message:3:assistant",
                "tool_start:1:3:0:write_file",
                "tool_end:1:3:0:write_file:ok",
                "message:4:tool",
                "delta:1:2:1:done",
                "message:5:assistant",
                "done:1:5",
            ]
        );

        // The workspace write really happened (the tool ran, not just a
        // decision).
        let note = harness.workspace().join("note.txt");
        assert_eq!(std::fs::read_to_string(note).unwrap(), "hello from aux");
    }

    #[tokio::test]
    async fn turn_events_report_a_denied_tool_and_still_done() {
        let harness = Harness::new();
        let provider = scripted_tool_then_text();
        let events = RecordingEvents::new();
        let mut session = harness.start_with_events(
            &provider,
            vec![],
            RecordingApprover::new(false),
            events.clone(),
        );

        session.send("do it").await.unwrap();

        let calls = events.calls();
        assert_eq!(
            calls,
            vec![
                "message:2:user",
                "message:3:assistant",
                "tool_start:1:3:0:write_file",
                "tool_end:1:3:0:write_file:denied",
                "message:4:tool",
                "delta:1:2:1:done",
                "message:5:assistant",
                "done:1:5",
            ]
        );
    }
}
