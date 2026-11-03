//! Budgets and usage: reserving the estimated spend before a call,
//! settling it after, and recording what the turn actually cost.

use super::{ChatError, ChatSession, DEFAULT_OUTPUT_RESERVE, ESTIMATED_UNIT};
use aux_providers::{ChatDelta, ChatMessage, ChatProvider, ChatRequest, ChatResponse, SafeMessage};
use aux_store::{StoreError, StoreHandle};
use kernel_core::budget::{
    audit_denial, Denial, DenialReason, PriceTable, Reservation, ReserveOutcome, UsageActual,
    UsageKind, UsageTotals,
};

fn unit_for(estimated: bool) -> &'static str {
    if estimated {
        ESTIMATED_UNIT
    } else {
        "tokens"
    }
}

/// Text and provider usage captured from a streaming sink.
///
/// A call that fails, times out, is cancelled or overflows the stream body
/// cap after deltas have already gone out has no `ChatResponse` to settle
/// from. The sink records what actually streamed, so [`settle_streamed`] can
/// settle the same estimate the success path would use when the provider
/// reports no usage (I-01).
#[derive(Default)]
pub(super) struct StreamCapture {
    text: std::sync::Mutex<String>,
    usage: std::sync::Mutex<Option<aux_providers::Usage>>,
}

impl StreamCapture {
    pub(super) fn record(&self, delta: &ChatDelta) {
        match delta {
            ChatDelta::Text(text) => kernel_core::lock_recover(&self.text).push_str(text),
            ChatDelta::Usage(usage) => *kernel_core::lock_recover(&self.usage) = Some(*usage),
            ChatDelta::ToolCall(_) => {}
        }
    }

    pub(super) fn text(&self) -> String {
        kernel_core::lock_recover(&self.text).clone()
    }

    pub(super) fn usage(&self) -> Option<aux_providers::Usage> {
        *kernel_core::lock_recover(&self.usage)
    }
}

pub(super) fn settle_streamed(
    store: &StoreHandle<'_>,
    reservation: &Reservation,
    request: &ChatRequest,
    capture: &StreamCapture,
    provider: &dyn ChatProvider,
    prices: &PriceTable,
) {
    let mut response = ChatResponse::assistant(capture.text());
    response.usage = capture.usage();
    let actual = usage_actual(request, &response, request_model(provider, request), prices);
    if let Err(err) = store.with(|store| store.settle_reservation(reservation, &actual)) {
        tracing::warn!(
            reservation = reservation.id,
            error = %err,
            "could not settle a failed streaming call's estimated usage"
        );
    }
}

pub(super) fn usage_actual(
    request: &ChatRequest,
    response: &ChatResponse,
    model: Option<&str>,
    prices: &PriceTable,
) -> UsageActual {
    let usage = response.usage;
    let (tokens_in, tokens_in_estimated) =
        match usage.map(|usage| usage.prompt_tokens).filter(|n| *n > 0) {
            Some(tokens) => (tokens, false),
            None => (estimate_request_tokens(request), true),
        };
    let (tokens_out, tokens_out_estimated) = match usage
        .map(|usage| usage.completion_tokens)
        .filter(|n| *n > 0)
    {
        Some(tokens) => (tokens, false),
        None => (estimate_response_tokens(response), true),
    };
    let usd_cents = provider_cost_cents(usage)
        .unwrap_or_else(|| priced_cents(prices, model, tokens_in, tokens_out));
    UsageActual {
        tokens_in,
        tokens_in_estimated,
        tokens_out,
        tokens_out_estimated,
        usd_cents,
    }
}

fn reservation_estimate(
    request: &ChatRequest,
    model: Option<&str>,
    prices: &PriceTable,
) -> UsageTotals {
    let tokens_in = estimate_request_tokens(request).max(1);
    UsageTotals {
        tokens_in,
        tokens_out: DEFAULT_OUTPUT_RESERVE,
        usd_cents: priced_cents(prices, model, tokens_in, DEFAULT_OUTPUT_RESERVE),
    }
}

pub(super) fn request_model<'r>(
    provider: &'r dyn ChatProvider,
    request: &'r ChatRequest,
) -> Option<&'r str> {
    request
        .model
        .as_ref()
        .map(|model| model.as_str())
        .or_else(|| provider.model())
}

static UNPRICED_MODEL_NOTICE: std::sync::Once = std::sync::Once::new();

fn notice_unpriced_model(model: Option<&str>) {
    UNPRICED_MODEL_NOTICE.call_once(|| {
        tracing::warn!(
            model = model.unwrap_or("<unreported>"),
            "no price table entry for this model: the daily usd_cents cap cannot bind; \
             the token caps are the effective ones (add [prices.models.<model>] to config.toml)"
        );
    });
}

fn priced_cents(prices: &PriceTable, model: Option<&str>, tokens_in: u64, tokens_out: u64) -> u64 {
    match model {
        Some(model) if prices.price(model).is_some() => {
            prices.usd_cents_for(Some(model), tokens_in, tokens_out)
        }
        _ => {
            notice_unpriced_model(model);
            0
        }
    }
}

fn provider_cost_cents(usage: Option<aux_providers::Usage>) -> Option<u64> {
    let cost = usage?.cost_usd?;
    if !cost.is_finite() || cost <= 0.0 {
        return Some(0);
    }
    Some((cost * 100.0).ceil().min(u64::MAX as f64) as u64)
}

pub(super) fn estimate_tokens(text: &str) -> u64 {
    let mut weighted: u64 = 0;
    for character in text.chars() {
        weighted += if character.is_ascii() { 1 } else { 3 };
    }
    weighted.div_ceil(4)
}

fn estimate_message_tokens(message: &ChatMessage) -> u64 {
    let calls: u64 = message
        .tool_calls
        .iter()
        .map(|call| estimate_tokens(&call.arguments.to_string()))
        .sum();
    let reasoning = message
        .reasoning_content
        .as_deref()
        .map_or(0, estimate_tokens);
    estimate_tokens(&message.content) + calls + reasoning
}

fn estimate_safe_message_tokens(message: &SafeMessage) -> u64 {
    let calls: u64 = message
        .tool_calls()
        .iter()
        .map(|call| estimate_tokens(&call.arguments().as_value().to_string()))
        .sum();
    let reasoning = message
        .reasoning_content()
        .map_or(0, |text| estimate_tokens(text.as_str()));
    estimate_tokens(message.content().as_str()) + calls + reasoning
}

pub(super) fn estimate_request_tokens(request: &ChatRequest) -> u64 {
    let messages: u64 = request
        .messages
        .iter()
        .map(estimate_safe_message_tokens)
        .sum();
    let tools: u64 = request
        .tools
        .iter()
        .map(|tool| {
            estimate_tokens(tool.name().as_str())
                + estimate_tokens(tool.description().as_str())
                + estimate_tokens(&tool.parameters().as_value().to_string())
        })
        .sum();
    messages + tools
}

fn estimate_response_tokens(response: &ChatResponse) -> u64 {
    estimate_message_tokens(&response.message)
}

impl<'a> ChatSession<'a> {
    /// Reserve the estimated spend for one provider call, or fail the turn
    /// when a daily cap is reached. The reservation is taken atomically with
    /// the cap check, the caller's own reserve included, so concurrent turns
    /// cannot spend the same headroom; denials are audited as `budget.denied`
    /// before returning.
    ///
    /// A capped output direction is clamped to the remaining headroom (the
    /// caller passes the clamped reservation to the provider as `max_tokens`);
    /// a capped input direction that does not fit is denied. A day latched
    /// closed by an earlier crossing settle is denied with
    /// [`kernel_core::budget::DenialReason::FailClosed`].
    ///
    /// Returns `None` only for an explicit `unlimited = true` (or an empty
    /// per-agent cap set): usage is still recorded after the call. A fresh
    /// config no longer takes this path (E-17) — it carries the conservative
    /// defaults.
    pub(super) fn reserve_budget(
        &self,
        request: &ChatRequest,
    ) -> Result<Option<Reservation>, ChatError> {
        let caps = self.budgets.caps_for(&self.agent);
        if caps.is_unlimited() {
            if caps.unlimited {
                tracing::warn!(
                    agent = %self.agent,
                    "budgets.unlimited = true: no daily cap is enforced for this agent"
                );
            }
            return Ok(None);
        }
        // The budget day is the Mac's local day at *check* time, not at
        // session start: a turn that crosses midnight starts enforcing the
        // new day on its next provider call.
        let day = self.current_day()?;
        let estimate =
            reservation_estimate(request, request_model(self.provider, request), self.prices);
        match self.store.with(|store| {
            store.try_reserve_for(self.run_id.as_deref(), &self.agent, &day, &caps, &estimate)
        }) {
            Ok(ReserveOutcome::Reserved(reservation)) => Ok(Some(reservation)),
            Ok(ReserveOutcome::Denied(denial)) => {
                let denial = self.store.with(|store| audit_denial(store, denial));
                Err(ChatError::BudgetDenied {
                    reason: denial.reason_text(),
                })
            }
            Err(err) => {
                let denial = self.store.with(|store| {
                    audit_denial(
                        store,
                        Denial {
                            agent: self.agent.clone(),
                            day,
                            reason: DenialReason::LedgerUnavailable {
                                message: err.to_string(),
                            },
                            audit_error: None,
                        },
                    )
                });
                Err(ChatError::BudgetDenied {
                    reason: denial.reason_text(),
                })
            }
        }
    }

    /// Test seam: replace the budget day source for one session.
    #[cfg(test)]
    fn set_day_source(&mut self, source: Box<dyn Fn() -> Result<String, StoreError> + Send>) {
        self.day_source = Some(source);
    }

    /// The local day the next budget check applies to.
    fn current_day(&self) -> Result<String, ChatError> {
        #[cfg(test)]
        if let Some(source) = &self.day_source {
            return source().map_err(|err| self.day_error(err));
        }
        self.store
            .with(|store| store.local_day())
            .map_err(|err| self.day_error(err))
    }

    /// Fail closed when the day itself cannot be read, with an audit trail.
    fn day_error(&self, err: StoreError) -> ChatError {
        let denial = self.store.with(|store| {
            audit_denial(
                store,
                Denial {
                    agent: self.agent.clone(),
                    day: "unknown".to_string(),
                    reason: DenialReason::LedgerUnavailable {
                        message: err.to_string(),
                    },
                    audit_error: None,
                },
            )
        });
        ChatError::BudgetDenied {
            reason: denial.reason_text(),
        }
    }

    /// Record the provider call's usage when no cap required a reservation.
    ///
    /// Provider-reported `prompt_tokens`/`completion_tokens` are recorded
    /// verbatim with the `tokens` unit. A direction the provider did not
    /// report (absent `usage`, a missing field, or a zero count) falls back
    /// to the length estimate tagged with [`ESTIMATED_UNIT`], so budgets
    /// stay conservative on providers that report nothing. `usd_cents` is
    /// recorded from the provider-reported cost when the gateway sends one,
    /// otherwise from the configured per-model price table.
    pub(super) fn record_usage(
        &self,
        request: &ChatRequest,
        response: &ChatResponse,
    ) -> Result<(), ChatError> {
        let actual = usage_actual(
            request,
            response,
            request_model(self.provider, request),
            self.prices,
        );
        if actual.tokens_in > 0 {
            self.record_usage_row(
                UsageKind::TokensIn,
                actual.tokens_in,
                unit_for(actual.tokens_in_estimated),
            )?;
        }
        if actual.tokens_out > 0 {
            self.record_usage_row(
                UsageKind::TokensOut,
                actual.tokens_out,
                unit_for(actual.tokens_out_estimated),
            )?;
        }
        if actual.usd_cents > 0 {
            self.record_usage_row(UsageKind::UsdCents, actual.usd_cents, "cents")?;
        }
        Ok(())
    }

    /// INFER-COST-1: one row per brain call with the provider-reported counts.
    /// A failed write is logged, never fatal: budgets use the usage rows.
    pub(super) fn record_usage_call(
        &self,
        request: &ChatRequest,
        response: &ChatResponse,
        round: usize,
    ) {
        let usage = response.usage;
        let call = aux_store::UsageCall {
            run_id: self.run_id.as_deref(),
            agent: &self.agent,
            provider: self.provider.name(),
            model: request_model(self.provider, request),
            call_index: u32::try_from(round).unwrap_or(u32::MAX),
            prompt_tokens: usage.map(|usage| usage.prompt_tokens),
            cached_tokens: usage.and_then(|usage| usage.cached_prompt_tokens),
            completion_tokens: usage.map(|usage| usage.completion_tokens),
        };
        if let Err(err) = self.store.with(|store| store.record_usage_call(&call)) {
            tracing::warn!(error = %err, "could not record a brain call's token counts");
        }
    }

    /// Insert one usage row, stamped with this turn's identity when it has one.
    fn record_usage_row(&self, kind: UsageKind, amount: u64, unit: &str) -> Result<(), ChatError> {
        let recorded = self.store.with(|store| match self.run_id.as_deref() {
            Some(run_id) => store.record_usage_for(run_id, &self.agent, kind, amount, unit),
            None => store.record_usage(&self.agent, kind, amount, unit),
        });
        recorded?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testsupport::*;
    use super::super::ChatError;
    use super::*;
    use crate::cancel::TurnCancel;
    use async_trait::async_trait;
    use aux_providers::{
        ChatDelta, ChatMessage, ChatProvider, ChatRequest, ChatResponse, FakeProvider,
        ProviderError, SafeMessage, SafeToolSpec, ToolCall, ToolSpec, Usage,
    };
    use kernel_core::budget::{Budgets, PriceTable, UsageKind};
    use kernel_privacy::safetext::Gate;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    // ---- streaming (WS-F1) ----

    /// Provider whose stream emits one delta, then hangs: cancellation must
    /// abort it promptly and settle nothing.
    struct HangingStreamProvider {
        inner: FakeProvider,
        started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl ChatProvider for HangingStreamProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.inner.complete(req).await
        }

        async fn complete_streaming(
            &self,
            req: &ChatRequest,
            sink: &(dyn Fn(ChatDelta) + Send + Sync),
        ) -> Result<ChatResponse, ProviderError> {
            let response = self.inner.complete(req).await?;
            sink(ChatDelta::Text("partial ".to_string()));
            self.started.notify_one();
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(response)
        }

        fn name(&self) -> &str {
            self.inner.name()
        }
    }

    #[tokio::test]
    async fn streaming_cancellation_aborts_mid_stream_and_settles_the_streamed_estimate() {
        let harness = Harness::new();
        let cancel = TurnCancel::new();
        let provider = HangingStreamProvider {
            inner: FakeProvider::echo("fake"),
            started: Arc::new(tokio::sync::Notify::new()),
        };
        let events = RecordingEvents::new();
        let mut session = harness.start_cancellable_with_events(
            &provider,
            vec![],
            RecordingApprover::new(false),
            cancel.clone(),
            events.clone(),
        );
        let session_id = session.session.id;

        let started = Arc::clone(&provider.started);
        let canceller = tokio::spawn(async move {
            started.notified().await;
            cancel.cancel();
        });

        let err = session.send("hello").await.unwrap_err();
        canceller.await.unwrap();

        assert!(matches!(err, ChatError::Cancelled), "got {err:?}");
        assert_eq!(
            harness.roles(session_id),
            vec!["system", "user"],
            "a cancelled stream persists no partial assistant row"
        );
        // I-01: the tokens the provider was already fed (and the partial
        // answer it already generated) are settled, not released at zero.
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert!(
            totals.tokens_in > 0,
            "the request's input estimate must be settled: {totals:?}"
        );
        assert_eq!(
            totals.tokens_out,
            estimate_tokens("partial "),
            "the streamed text is settled as output: {totals:?}"
        );
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "the reservation is settled, never left open"
        );
        let recorded = deltas(&events.calls());
        assert_eq!(
            recorded.len(),
            1,
            "the delta emitted before the cancel reached the sink"
        );
        assert_eq!(recorded[0].2, "partial ");
    }

    /// A provider that emits one delta and then fails the way a real stream
    /// can: a mid-stream protocol error, an idle timeout, or the body
    /// ceiling. All three must settle the streamed estimate (I-01).
    struct DeltaThenFail {
        kind: FailKind,
        started: Arc<tokio::sync::Notify>,
    }

    #[derive(Debug, Clone, Copy)]
    enum FailKind {
        Error,
        Timeout,
        TooLarge,
    }

    impl FailKind {
        fn error(self) -> ProviderError {
            match self {
                Self::Error => ProviderError::InvalidResponse {
                    provider: "fake".to_string(),
                    message: "upstream reset mid-stream".to_string(),
                },
                Self::Timeout => ProviderError::Timeout {
                    provider: "fake".to_string(),
                },
                Self::TooLarge => ProviderError::InvalidResponse {
                    provider: "fake".to_string(),
                    message: format!(
                        "stream_too_large: stream line exceeds {} bytes without a newline",
                        4 * 1024 * 1024
                    ),
                },
            }
        }
    }

    #[async_trait]
    impl ChatProvider for DeltaThenFail {
        async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            Err(self.kind.error())
        }

        async fn complete_streaming(
            &self,
            _req: &ChatRequest,
            sink: &(dyn Fn(ChatDelta) + Send + Sync),
        ) -> Result<ChatResponse, ProviderError> {
            sink(ChatDelta::Text("partial answer ".to_string()));
            self.started.notify_one();
            tokio::task::yield_now().await;
            Err(self.kind.error())
        }

        fn name(&self) -> &str {
            "fake"
        }
    }

    #[tokio::test]
    async fn a_stream_that_fails_mid_answer_settles_the_streamed_estimate() {
        for kind in [FailKind::Error, FailKind::Timeout, FailKind::TooLarge] {
            let harness = Harness::new();
            let provider = DeltaThenFail {
                kind,
                started: Arc::new(tokio::sync::Notify::new()),
            };
            let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
            let session_id = session.session.id;

            let err = session.send("hello").await.unwrap_err();
            assert!(
                matches!(err, ChatError::Provider(_)),
                "{kind:?}: got {err:?}"
            );
            assert_eq!(
                harness.roles(session_id),
                vec!["system", "user"],
                "{kind:?}: a failed stream persists no partial row"
            );
            let day = harness.store().local_day().unwrap();
            let totals = harness.store().usage_totals("main", &day).unwrap();
            assert!(
                totals.tokens_in > 0,
                "{kind:?}: the input estimate must be settled: {totals:?}"
            );
            assert_eq!(
                totals.tokens_out,
                estimate_tokens("partial answer "),
                "{kind:?}: the streamed text is settled as output: {totals:?}"
            );
            assert_eq!(
                harness.store().reservation_count().unwrap(),
                0,
                "{kind:?}: the reservation is settled exactly once"
            );
        }
    }

    /// I-02: the reservation TTL must outlive the longest stream one call can
    /// run, or a concurrent turn could reserve the same headroom while the
    /// provider is still generating (and billing).
    #[test]
    fn reservation_ttl_covers_the_maximum_stream_life() {
        let max_stream = aux_providers::openai_compat::DEFAULT_TIMEOUT
            * aux_providers::openai_compat::STREAM_TOTAL_TIMEOUT_FACTOR;
        assert!(
            kernel_core::budget::RESERVATION_TTL > max_stream,
            "RESERVATION_TTL ({:?}) must exceed the maximum stream life ({max_stream:?})",
            kernel_core::budget::RESERVATION_TTL
        );
    }

    #[tokio::test]
    async fn streaming_settles_the_budget_once_with_provider_reported_usage() {
        let harness = Harness::new();
        let usage = Usage {
            prompt_tokens: 11,
            completion_tokens: 7,
            cost_usd: None,
            cached_prompt_tokens: None,
        };
        let provider = FakeProvider::scripted(
            "fake",
            vec![ChatResponse::assistant("done").with_usage(usage)],
        )
        .with_stream_chunks(2);
        let events = RecordingEvents::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(10_000);
        let mut session = harness.start_cancellable_with_events_and_budget(
            &provider,
            vec![],
            RecordingApprover::new(false),
            &budgets,
            TurnCancel::new(),
            events.clone(),
        );
        let session_id = session.session.id;

        session.send("hello").await.unwrap();

        let day = harness.store().local_day().unwrap();
        assert_eq!(
            harness.store().usage_totals("main", &day).unwrap(),
            kernel_core::UsageTotals {
                tokens_in: 11,
                tokens_out: 7,
                usd_cents: 0,
            },
            "the streamed usage settles the reservation exactly once"
        );
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "the reservation is settled, never left open"
        );
        assert_eq!(
            harness.roles(session_id),
            vec!["system", "user", "assistant"]
        );
        let streamed: String = deltas(&events.calls())
            .iter()
            .map(|(_, _, text)| text.as_str())
            .collect();
        assert_eq!(streamed, "done");
    }

    // ---- budgets & usage ----

    /// Provider that never reports usage: exercises the estimate fallback.
    struct NoUsageProvider {
        requests: Mutex<Vec<ChatRequest>>,
        response: ChatResponse,
    }

    impl NoUsageProvider {
        fn new(response: ChatResponse) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                response,
            }
        }

        fn requests(&self) -> Vec<ChatRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ChatProvider for NoUsageProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.requests.lock().unwrap().push(req.clone());
            Ok(self.response.clone())
        }

        fn name(&self) -> &str {
            "no-usage"
        }
    }

    #[tokio::test]
    async fn usage_is_recorded_after_each_provider_call() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        // The fake reports one token per character (not the chars/4 estimate).
        let request = &provider.requests()[0];
        let expected_in: u64 = request
            .messages
            .iter()
            .map(|message| message.content().as_str().chars().count() as u64)
            .sum();
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_in, expected_in, "got {totals:?}");
        assert_eq!(totals.tokens_out, 2, "`hi` is two characters: {totals:?}");
        assert_ne!(
            totals.tokens_in,
            estimate_request_tokens(request),
            "reported usage must not be the estimate"
        );
        assert_eq!(totals.usd_cents, 0, "no pricing data: usd_cents unrecorded");
        // A single completion records both directions for this agent only.
        assert_eq!(
            harness.store().usage_totals("axis", &day).unwrap(),
            kernel_core::UsageTotals::default()
        );
    }

    #[tokio::test]
    async fn each_brain_call_of_a_turn_records_its_own_counts() {
        let harness = Harness::new();
        let usage = |cached| Usage {
            prompt_tokens: 100,
            completion_tokens: 5,
            cost_usd: None,
            cached_prompt_tokens: cached,
        };
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![write_file_call("call_1", "note.txt", "hello from aux")],
                ))
                .with_usage(usage(None)),
                ChatResponse::assistant("done").with_usage(usage(Some(80))),
            ],
        );
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));

        assert_eq!(session.send("write a note").await.unwrap().rounds, 2);

        let day = harness.store().local_day().unwrap();
        let c = harness
            .store()
            .usage_call_totals(Some("main"), &day)
            .unwrap();
        let counts = (c.calls, c.max_call_index, c.prompt_tokens, c.cached_tokens);
        assert_eq!(counts, (2, 2, 200, 80), "{c:?}");
        assert_eq!(
            c.cache_hit_percent(),
            Some(80.0),
            "unreported call left out"
        );
    }

    #[tokio::test]
    async fn provider_reported_usage_lands_in_usage_totals() {
        let harness = Harness::new();
        let response = ChatResponse::assistant("done").with_usage(Usage {
            prompt_tokens: 1_234,
            completion_tokens: 567,
            cost_usd: None,
            cached_prompt_tokens: None,
        });
        let provider = FakeProvider::repeating("fake", response);
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(
            totals,
            kernel_core::UsageTotals {
                tokens_in: 1_234,
                tokens_out: 567,
                usd_cents: 0,
            },
            "real numbers land verbatim; usd_cents stays unrecorded"
        );
    }

    #[tokio::test]
    async fn missing_usage_falls_back_to_the_estimate() {
        let harness = Harness::new();
        let provider = NoUsageProvider::new(ChatResponse::assistant("hi"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        let request = &provider.requests()[0];
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_in, estimate_request_tokens(request));
        assert_eq!(
            totals.tokens_out,
            estimate_response_tokens(&ChatResponse::assistant("hi"))
        );
        assert!(totals.tokens_in > 0 && totals.tokens_out > 0);
    }

    #[tokio::test]
    async fn zero_usage_field_falls_back_per_direction() {
        let harness = Harness::new();
        // Prompt missing (0) but completion reported: directions are
        // independent, the missing one falls back to the estimate.
        let response = ChatResponse::assistant("hi").with_usage(Usage {
            prompt_tokens: 0,
            completion_tokens: 77,
            cost_usd: None,
            cached_prompt_tokens: None,
        });
        let provider = NoUsageProvider::new(response);
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        let request = &provider.requests()[0];
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_in, estimate_request_tokens(request));
        assert_eq!(totals.tokens_out, 77);
    }

    #[tokio::test]
    async fn a_agent_over_its_daily_cap_is_denied_before_any_provider_call() {
        let harness = Harness::new();
        let day = harness.store().local_day().unwrap();
        harness
            .store()
            .record_usage_at("main", UsageKind::TokensIn, 5, "tokens", &day)
            .unwrap();
        let mut budgets = Budgets::default();
        budgets.default.tokens_in = Some(5);

        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("never"));
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let session_id = session.session.id;

        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(
            err.to_string().contains("tokens_in"),
            "reason should name the cap: {err}"
        );
        assert_eq!(provider.request_count(), 0, "no provider call may happen");
        assert_eq!(harness.roles(session_id), vec!["system", "user"]);
        assert_eq!(
            harness.store().event_count("budget.denied").unwrap(),
            1,
            "the denial is audited"
        );
    }

    #[tokio::test]
    async fn a_turn_that_reaches_the_cap_blocks_the_next_one() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));

        // The engine's input estimate is internal, and admission now requires
        // the caller's own reserve to fit under the cap (B-01R). So run the
        // first turn with a generous cap, then pin the cap to exactly what it
        // recorded: the next turn's reserve can never fit again.
        let mut generous = Budgets::default();
        generous.default.tokens_in = Some(1_000_000);
        let first = {
            let mut session =
                harness.start_with(&provider, vec![], RecordingApprover::new(false), &generous);
            session.send("hello").await.unwrap()
        };
        assert_eq!(first.text, "hi");
        let day = harness.store().local_day().unwrap();
        let recorded = harness
            .store()
            .usage_totals("main", &day)
            .unwrap()
            .tokens_in;
        assert!(recorded >= 1);
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "the reservation was replaced by the real rows"
        );

        let mut exact = Budgets::default();
        exact.default.tokens_in = Some(recorded);
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &exact);
        let err = session.send("again").await.unwrap_err();
        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert_eq!(provider.request_count(), 1, "the second call is blocked");
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
    }

    #[tokio::test]
    async fn budget_day_is_recomputed_at_every_check() {
        let harness = Harness::new();
        // The output cap is already spent on the *next* local day; a session
        // that pinned its day at start would keep checking the old one.
        harness
            .store()
            .record_usage_at("main", UsageKind::TokensOut, 10, "tokens", "2026-10-04")
            .unwrap();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(10);

        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![write_file_call("call_1", "note.txt", "content")],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let calls = Arc::new(AtomicUsize::new(0));
        let day_calls = Arc::clone(&calls);
        session.set_day_source(Box::new(move || {
            let index = day_calls.fetch_add(1, Ordering::SeqCst);
            Ok(if index == 0 {
                "2026-10-03"
            } else {
                "2026-10-04"
            }
            .to_string())
        }));

        let err = session.send("write a note").await.unwrap_err();

        let reason = match err {
            ChatError::BudgetDenied { reason } => reason,
            other => panic!("expected a budget denial, got {other:?}"),
        };
        assert!(
            reason.contains("2026-10-04"),
            "the denial must name the recomputed day: {reason}"
        );
        assert_eq!(provider.request_count(), 1, "the second call is denied");
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "the day is read again for every provider call"
        );
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
    }

    #[tokio::test]
    async fn default_budgets_deny_a_turn_once_the_day_is_spent() {
        // E-17 regression: `Budgets::default()` carries the conservative
        // daily caps, so a fresh config enforces them before any provider
        // call (on the old code the cap was unset and the call went through).
        let harness = Harness::new();
        harness
            .store()
            .record_usage(
                "main",
                UsageKind::TokensIn,
                kernel_core::budget::DEFAULT_DAILY_TOKENS_IN,
                "tokens",
            )
            .unwrap();
        let provider = FakeProvider::echo("fake");
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert_eq!(
            provider.request_count(),
            0,
            "the cap must be enforced before the provider is called"
        );
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "a denied call leaves no reservation behind"
        );
    }

    #[tokio::test]
    async fn explicit_unlimited_is_the_only_uncapped_path() {
        let harness = Harness::new();
        harness
            .store()
            .record_usage(
                "main",
                UsageKind::TokensIn,
                kernel_core::budget::DEFAULT_DAILY_TOKENS_IN,
                "tokens",
            )
            .unwrap();
        let mut budgets = Budgets::default();
        budgets.default.unlimited = true;
        let provider = FakeProvider::echo("fake");
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        // The day is over the (ignored) default cap; an explicit opt-out
        // still runs, and usage is recorded rather than reserved.
        session.send("hello").await.unwrap();
        assert_eq!(provider.request_count(), 1);
        assert_eq!(harness.store().reservation_count().unwrap(), 0);
    }

    // ---- B-01R: concurrency bound and fail-closed latch ----

    /// Provider that holds every call at a rendezvous until `parties` calls
    /// are in flight, so all reservations are taken before any settle, then
    /// either honors `max_tokens` (compliant) or ignores it and returns a
    /// huge completion.
    struct BatchProvider {
        parties: usize,
        ignore_max_tokens: bool,
        arrived: AtomicUsize,
        requests: Mutex<Vec<ChatRequest>>,
    }

    impl BatchProvider {
        fn new(parties: usize, ignore_max_tokens: bool) -> Self {
            Self {
                parties,
                ignore_max_tokens,
                arrived: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ChatRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn max_tokens_seen(&self) -> Vec<u32> {
            self.requests()
                .iter()
                .map(|request| {
                    request
                        .max_tokens
                        .expect("a capped agent passes max_tokens")
                })
                .collect()
        }
    }

    #[async_trait]
    impl ChatProvider for BatchProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.requests.lock().unwrap().push(req.clone());
            self.arrived.fetch_add(1, Ordering::SeqCst);
            while self.arrived.load(Ordering::SeqCst) < self.parties {
                tokio::task::yield_now().await;
            }
            let completion = if self.ignore_max_tokens {
                100_000
            } else {
                u64::from(req.max_tokens.unwrap_or(0))
            };
            let text = "x".repeat(completion as usize);
            Ok(ChatResponse::assistant(text).with_usage(Usage {
                prompt_tokens: 1,
                completion_tokens: completion,
                cost_usd: None,
                cached_prompt_tokens: None,
            }))
        }

        fn name(&self) -> &str {
            "batch"
        }
    }

    #[tokio::test]
    async fn two_concurrent_turns_cannot_overshoot_a_compliant_cap() {
        // The B-01R reproducer: cap_out = 5 000, two ordinary turns. Both
        // reserve before either settles (the provider rendezvous); with a
        // provider that honors `max_tokens`, the day settles at the cap.
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(5_000);
        let provider = BatchProvider::new(2, false);

        let mut first =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut second =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let (first, second) = tokio::join!(first.send("one"), second.send("two"));
        first.unwrap();
        second.unwrap();

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(
            totals.tokens_out, 5_000,
            "both calls settle their clamped reserves, never past the cap: {totals:?}"
        );
        assert_eq!(
            provider.max_tokens_seen(),
            vec![4_096, 904],
            "the first call reserves 4096, the second gets the 904 left"
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);

        // The day is at its cap: a third call is denied before any provider
        // call (the second settle latched it closed).
        let mut third =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let err = third.send("three").await.unwrap_err();
        let reason = match err {
            ChatError::BudgetDenied { reason } => reason,
            other => panic!("expected a budget denial, got {other:?}"),
        };
        assert!(reason.contains("failing closed"), "{reason}");
        assert_eq!(provider.requests().len(), 2, "no third provider call");
    }

    #[tokio::test]
    async fn eight_concurrent_turns_cannot_overshoot_a_compliant_cap() {
        // Same race, 8-way: every admitted reservation fits under the cap, so
        // the compliant day settles at 8 × 4096 <= 50 000.
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(50_000);
        let provider = BatchProvider::new(8, false);

        let mut s1 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s2 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s3 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s4 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s5 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s6 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s7 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s8 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let results = tokio::join!(
            s1.send("1"),
            s2.send("2"),
            s3.send("3"),
            s4.send("4"),
            s5.send("5"),
            s6.send("6"),
            s7.send("7"),
            s8.send("8"),
        );
        for result in [
            results.0, results.1, results.2, results.3, results.4, results.5, results.6, results.7,
        ] {
            result.unwrap();
        }

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_out, 8 * 4_096);
        assert!(
            totals.tokens_out <= 50_000,
            "compliant output stays under the cap: {totals:?}"
        );
        assert_eq!(
            provider.max_tokens_seen(),
            vec![4_096; 8],
            "each of the 8 calls reserved the default output budget"
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn concurrent_non_compliant_calls_settle_then_the_day_latches() {
        // A provider that ignores `max_tokens` can only overshoot with the
        // calls already in flight; once a settle reaches the cap, the day is
        // latched and no further call starts.
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(5_000);
        let provider = BatchProvider::new(2, true);

        let mut first =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut second =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let (first, second) = tokio::join!(first.send("one"), second.send("two"));
        first.unwrap();
        second.unwrap();

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(
            totals.tokens_out, 200_000,
            "the two in-flight calls are recorded honestly"
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);

        let mut third =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let err = third.send("three").await.unwrap_err();
        let reason = match err {
            ChatError::BudgetDenied { reason } => reason,
            other => panic!("expected a budget denial, got {other:?}"),
        };
        assert!(reason.contains("failing closed"), "{reason}");
        assert!(
            reason.contains("tokens_out budget"),
            "the latch names the crossed cap: {reason}"
        );
        assert_eq!(
            provider.requests().len(),
            2,
            "the latched day admits no third call"
        );
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
        // The latch itself is audited once, before any denial.
        assert_eq!(harness.store().event_count("budget.latched").unwrap(), 1);
    }

    #[tokio::test]
    async fn a_provider_that_ignores_max_tokens_is_latched_closed() {
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(5_000);
        let provider = BatchProvider::new(1, true);

        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        session.send("hello").await.unwrap();

        // The provider was asked for at most 4096 output tokens and returned
        // 100 000; the ledger records that honestly.
        assert_eq!(provider.max_tokens_seen(), vec![4_096]);
        let day = harness.store().local_day().unwrap();
        assert_eq!(
            harness
                .store()
                .usage_totals("main", &day)
                .unwrap()
                .tokens_out,
            100_000
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);

        let err = session.send("again").await.unwrap_err();
        match err {
            ChatError::BudgetDenied { reason } => assert!(
                reason.contains("failing closed")
                    && reason.contains("tokens_out budget (100000/5000)"),
                "{reason}"
            ),
            other => panic!("expected a budget denial, got {other:?}"),
        }
        assert_eq!(provider.requests().len(), 1);

        // The audit trail shows the refusal and the closure.
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
        assert_eq!(harness.store().event_count("budget.latched").unwrap(), 1);
    }

    #[test]
    fn token_estimates_round_up() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
    }

    #[test]
    fn token_estimates_weight_non_ascii_three_times() {
        // 5 emoji: (5 × 3).div_ceil(4) = 4, versus 2 for the old chars/4.
        assert_eq!(estimate_tokens("😀😀😀😀😀"), 4);
        // 4 CJK characters: (4 × 3).div_ceil(4) = 3.
        assert_eq!(estimate_tokens("你好世界"), 3);
        // Mixed text weights only the non-ASCII characters.
        assert_eq!(estimate_tokens("abcd你好"), (4u64 + 6).div_ceil(4));
        // ASCII-only estimates are unchanged.
        assert_eq!(estimate_tokens("hello world"), 3);
    }

    #[test]
    fn token_estimates_cover_requests_and_responses() {
        let mut gate = tokenising_gate([6u8; 32]);
        let issue =
            |gate: &mut Gate, message: ChatMessage| SafeMessage::issue(gate, &message).unwrap();
        let request = ChatRequest::new(vec![issue(&mut gate, ChatMessage::user("hello"))]);
        assert_eq!(estimate_request_tokens(&request), 2);

        let call = ToolCall::new("call_1", "shell", json!({ "cmd": "ls" }));
        let tool = ToolSpec::new("shell", "run a command", json!({ "type": "object" }));
        let request = ChatRequest::new(vec![issue(
            &mut gate,
            ChatMessage::assistant_with_tool_calls("", vec![call]),
        )])
        .with_tools(vec![SafeToolSpec::issue(&mut gate, &tool).unwrap()]);
        assert!(
            estimate_request_tokens(&request) > 0,
            "tool payloads count toward input usage"
        );

        assert_eq!(
            estimate_response_tokens(&ChatResponse::assistant("done")),
            1
        );
    }

    struct HangingProvider;

    #[async_trait]
    impl ChatProvider for HangingProvider {
        async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Err(ProviderError::Unauthorized {
                provider: "hanging".to_string(),
            })
        }

        fn name(&self) -> &str {
            "hanging"
        }
    }

    #[tokio::test]
    async fn cancelling_a_provider_call_settles_the_input_estimate_once() {
        // I-01: the provider-phase path no longer releases at zero. A
        // cancelled call settles the request's input estimate (the prompt was
        // sent) with zero output (nothing streamed), exactly once — a
        // repeated cancel cannot settle twice (the store deletes the
        // reservation on the first settle).
        let harness = Harness::new();
        let provider = HangingProvider;
        let cancel = TurnCancel::new();
        let mut session = harness.start_cancellable(
            &provider,
            vec![],
            RecordingApprover::new(false),
            Arc::clone(&cancel),
        );

        let mut turn = Box::pin(session.send("go"));
        let cancel_when_reserved = async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while harness.store().reservation_count().unwrap() != 1 {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the reservation never appeared"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            cancel.cancel();
            // A second cancel must be a no-op, not a second settle.
            cancel.cancel();
        };
        let joined = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(&mut turn, cancel_when_reserved)
        })
        .await
        .expect("cancellation must end the turn promptly");
        assert!(matches!(joined.0.unwrap_err(), ChatError::Cancelled));

        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "a cancelled provider call settles its reservation, never leaves it open"
        );
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert!(
            totals.tokens_in > 0,
            "the cancelled request's input estimate is settled: {totals:?}"
        );
        assert_eq!(
            totals.tokens_out, 0,
            "nothing streamed before the cancel: {totals:?}"
        );
    }

    #[tokio::test]
    async fn an_upgraded_config_with_an_empty_budgets_table_is_still_capped() {
        // M12/P1-1: the exact bytes a pre-E-17 install carries must enforce
        // the conservative defaults before any provider call. H-03 raised the
        // default value; the empty table is still capped.
        let harness = Harness::new();
        let day = harness.store().local_day().unwrap();
        harness
            .store()
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                kernel_core::budget::DEFAULT_DAILY_TOKENS_IN,
                "tokens",
                &day,
            )
            .unwrap();
        let budgets: Budgets = toml::from_str("[default]\n").unwrap();

        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("never"));
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(err.to_string().contains("tokens_in"), "{err}");
        assert_eq!(provider.request_count(), 0, "no provider call may happen");
    }

    #[tokio::test]
    async fn the_daily_usd_cap_binds_from_the_price_table() {
        // P2-3: token counts priced by `[prices]` become recorded usd_cents,
        // so the money cap can latch the day and warn at 80 %.
        let mut harness = Harness::new();
        let mut prices = PriceTable::default();
        prices.models.insert(
            "priced-model".to_string(),
            kernel_core::budget::ModelPrice {
                input_cents_per_million: 100,
                output_cents_per_million: 100,
            },
        );
        harness.prices = prices;
        let mut budgets = Budgets::default();
        budgets.default.tokens_in = Some(10_000_000);
        budgets.default.tokens_out = Some(10_000_000);
        budgets.default.usd_cents = Some(50);

        let response = ChatResponse::assistant("done").with_usage(aux_providers::Usage {
            prompt_tokens: 399_600,
            completion_tokens: 400,
            cost_usd: None,
            cached_prompt_tokens: None,
        });
        let provider = FakeProvider::repeating("fake", response).with_model("priced-model");
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        session.send("hello").await.unwrap();

        let day = harness.store().local_day().unwrap();
        assert_eq!(
            harness
                .store()
                .usage_totals("main", &day)
                .unwrap()
                .usd_cents,
            40,
            "400k tokens at 100 cents/M = 40 cents"
        );
        assert_eq!(
            harness.store().event_count("budget.warning").unwrap(),
            1,
            "landing exactly on 80 % of the money cap warns"
        );

        // A second call crosses the cap: the settle latches the day.
        session.send("again").await.unwrap();
        assert_eq!(
            harness
                .store()
                .usage_totals("main", &day)
                .unwrap()
                .usd_cents,
            80
        );

        // The latched day denies the next call pre-flight.
        let err = session.send("once more").await.unwrap_err();
        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(
            err.to_string().contains("usd_cents"),
            "the latch names the money cap: {err}"
        );
        assert_eq!(provider.request_count(), 2, "the third call is blocked");
    }
}
