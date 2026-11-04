//! Fallback across brains.
//!
//! A hop happens only on a transport error or a 5xx (`docs/providers.md` §6):
//! never on 4xx, never on a refusal, never on content. Every hop writes one
//! `provider.fallback {from, to, reason}` Ledger row — the hop only, no
//! content.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use kernel_core::privacy::{admit_call, Destination, Grant, ModeFn, PathId};

use crate::config::shown_id_plain;
use crate::error::ProviderError;
use crate::provider::{ChatProvider, Contact};
use crate::types::{ChatDelta, ChatRequest, ChatResponse};

/// Sink for the `provider.fallback` Ledger row. The production sink writes an
/// `events` row; tests use [`RecordingLedger`].
pub trait FallbackLedger: Send + Sync {
    /// Record one hop. `reason` is a short code, never content.
    fn provider_fallback(&self, from: &str, to: &str, reason: &str);
}

/// A sink that drops the row. Production never uses it.
#[derive(Debug, Default)]
pub struct NoopLedger;

impl FallbackLedger for NoopLedger {
    fn provider_fallback(&self, _from: &str, _to: &str, _reason: &str) {}
}

/// One recorded hop, for tests and assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackHop {
    /// Provider that failed.
    pub from: String,
    /// Provider tried next.
    pub to: String,
    /// Short reason code.
    pub reason: String,
}

/// An in-memory [`FallbackLedger`].
#[derive(Debug, Default)]
pub struct RecordingLedger {
    hops: std::sync::Mutex<Vec<FallbackHop>>,
}

impl RecordingLedger {
    /// The hops recorded so far, in order.
    pub fn hops(&self) -> Vec<FallbackHop> {
        self.hops.lock().unwrap().clone()
    }
}

impl FallbackLedger for RecordingLedger {
    fn provider_fallback(&self, from: &str, to: &str, reason: &str) {
        self.hops.lock().unwrap().push(FallbackHop {
            from: from.to_string(),
            to: to.to_string(),
            reason: reason.to_string(),
        });
    }
}

/// True when an error may trigger a fallback hop: a transport error or a 5xx.
/// A 4xx (including 408 and 429), a refusal and a bad body are never eligible.
pub fn is_fallback_eligible(err: &ProviderError) -> bool {
    match err {
        ProviderError::Server { status, .. } => (500..=599).contains(status),
        ProviderError::Request { .. } | ProviderError::Timeout { .. } => true,
        ProviderError::Unauthorized { .. }
        | ProviderError::RateLimited { .. }
        | ProviderError::Client { .. }
        | ProviderError::OllamaNotRunning { .. }
        | ProviderError::InvalidResponse { .. }
        | ProviderError::ScriptExhausted { .. }
        | ProviderError::PrivacyDisabled { .. }
        | ProviderError::Refused { .. }
        | ProviderError::Config(_)
        | ProviderError::Key(_)
        | ProviderError::AcpBackend { .. } => false,
    }
}

/// Short reason code for a hop. Never content.
pub fn fallback_reason(err: &ProviderError) -> &'static str {
    match err {
        ProviderError::Server { .. } => "server_error",
        ProviderError::Timeout { .. } => "timeout",
        ProviderError::Request { .. } => "transport",
        _ => "ineligible",
    }
}

/// The live admission a fallback hop must pass before it is sent.
///
/// The primary provider is admitted by [`GatedChat`](crate::GatedChat); every
/// fallback destination is a *different* vendor and must be admitted too
/// A refusal stops the chain: no request is sent and
/// no Ledger row is written.
pub trait FallbackAdmission: Send + Sync {
    /// Admit `provider` for `path` (`A1` streaming, `A2` one body).
    ///
    /// `Ok(None)` means no kernel check (Open-only callers); `Ok(Some(grant))`
    /// holds the grant for the hop.
    fn admit(&self, provider: &str, path: PathId) -> Result<Option<Grant>, ProviderError>;
}

/// No admission: for Open-only callers and tests.
pub struct NoopAdmission;

impl FallbackAdmission for NoopAdmission {
    fn admit(&self, _provider: &str, _path: PathId) -> Result<Option<Grant>, ProviderError> {
        Ok(None)
    }
}

/// Real kernel admission, one call per fallback destination, read live at hop
/// time (a turn that switched to Private mid-flight is seen).
pub struct KernelFallbackAdmission {
    live: ModeFn,
}

impl KernelFallbackAdmission {
    /// Admit through `live`, the mode in force when the hop is attempted.
    pub fn new(live: ModeFn) -> Self {
        Self { live }
    }
}

impl FallbackAdmission for KernelFallbackAdmission {
    fn admit(&self, provider: &str, path: PathId) -> Result<Option<Grant>, ProviderError> {
        admit_call(
            path,
            (self.live)(),
            Destination::Vendor(provider.to_string()),
        )
        .map(Some)
        .map_err(|refused| ProviderError::PrivacyDisabled {
            provider: shown_id_plain(provider),
            path: refused.path.as_str(),
        })
    }
}

/// A chain of providers tried in order. The first eligible failure hops to the
/// next entry; every hop is admitted and written to the Ledger.
pub struct FallbackProvider {
    providers: Vec<Box<dyn ChatProvider>>,
    ledger: Arc<dyn FallbackLedger>,
    admission: Arc<dyn FallbackAdmission>,
    contacted_hosts: std::sync::Mutex<Vec<String>>,
    served_host: std::sync::Mutex<Option<String>>,
    /// Every attempt, append-only, never deduplicated (one row per hop).
    attempts: std::sync::Mutex<Vec<Contact>>,
}

impl FallbackProvider {
    /// A chain with no Ledger sink or admission (tests only).
    pub fn new(providers: Vec<Box<dyn ChatProvider>>) -> Self {
        Self {
            providers,
            ledger: Arc::new(NoopLedger),
            admission: Arc::new(NoopAdmission),
            contacted_hosts: std::sync::Mutex::new(Vec::new()),
            served_host: std::sync::Mutex::new(None),
            attempts: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A chain that records every hop (no admission).
    pub fn with_ledger(
        providers: Vec<Box<dyn ChatProvider>>,
        ledger: Arc<dyn FallbackLedger>,
    ) -> Self {
        Self {
            providers,
            ledger,
            admission: Arc::new(NoopAdmission),
            contacted_hosts: std::sync::Mutex::new(Vec::new()),
            served_host: std::sync::Mutex::new(None),
            attempts: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A chain that records every hop and admits each fallback destination
    /// through `live` before the hop is sent.
    pub fn gated(
        providers: Vec<Box<dyn ChatProvider>>,
        ledger: Arc<dyn FallbackLedger>,
        live: ModeFn,
    ) -> Self {
        Self {
            providers,
            ledger,
            admission: Arc::new(KernelFallbackAdmission::new(live)),
            contacted_hosts: std::sync::Mutex::new(Vec::new()),
            served_host: std::sync::Mutex::new(None),
            attempts: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A chain with an explicit admission (tests inject a stub).
    pub fn with_admission(
        providers: Vec<Box<dyn ChatProvider>>,
        ledger: Arc<dyn FallbackLedger>,
        admission: Arc<dyn FallbackAdmission>,
    ) -> Self {
        Self {
            providers,
            ledger,
            admission,
            contacted_hosts: std::sync::Mutex::new(Vec::new()),
            served_host: std::sync::Mutex::new(None),
            attempts: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Provider ids in chain order.
    pub fn names(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Log one attempt before it is sent, so a hop whose future is dropped
    /// (Stop, cancel) is still on record.
    fn record_attempt(&self, provider: &dyn ChatProvider) {
        self.attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Contact {
                host: provider.endpoint_host(),
                on_this_mac: provider.on_this_mac(),
            });
    }

    fn record_contact(&self, provider: &dyn ChatProvider, served: bool) {
        if let Some(host) = provider.endpoint_host() {
            let mut contacted = self
                .contacted_hosts
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !contacted.contains(&host) {
                contacted.push(host.clone());
            }
            if served {
                *self.served_host.lock().unwrap_or_else(|p| p.into_inner()) = Some(host);
            }
        }
    }
}

#[async_trait]
impl ChatProvider for FallbackProvider {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let mut last: Option<ProviderError> = None;
        let mut pending_reason: Option<&'static str> = None;
        for (index, provider) in self.providers.iter().enumerate() {
            // The primary provider was admitted by `GatedChat`; each fallback
            // destination is admitted live here, before the hop is sent
            // A refusal returns before any request.
            let _grant = if index == 0 {
                None
            } else {
                let grant = self.admission.admit(provider.name(), PathId::A2)?;
                self.ledger.provider_fallback(
                    self.providers[index - 1].name(),
                    provider.name(),
                    pending_reason.unwrap_or("transport"),
                );
                grant
            };
            self.record_attempt(provider.as_ref());
            match provider.complete(req).await {
                Ok(response) => {
                    self.record_contact(provider.as_ref(), true);
                    return Ok(response);
                }
                Err(err) => {
                    self.record_contact(provider.as_ref(), false);
                    if self.providers.get(index + 1).is_some() && is_fallback_eligible(&err) {
                        pending_reason = Some(fallback_reason(&err));
                        last = Some(err);
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(last.unwrap_or_else(|| ProviderError::InvalidResponse {
            provider: "fallback".to_string(),
            message: "the fallback chain has no providers".to_string(),
        }))
    }

    async fn complete_streaming(
        &self,
        req: &ChatRequest,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        let mut last: Option<ProviderError> = None;
        let mut pending_reason: Option<&'static str> = None;
        for (index, provider) in self.providers.iter().enumerate() {
            let _grant = if index == 0 {
                None
            } else {
                let grant = self.admission.admit(provider.name(), PathId::A1)?;
                self.ledger.provider_fallback(
                    self.providers[index - 1].name(),
                    provider.name(),
                    pending_reason.unwrap_or("transport"),
                );
                grant
            };
            let emitted = AtomicBool::new(false);
            let guarded = |delta: ChatDelta| {
                emitted.store(true, Ordering::SeqCst);
                sink(delta);
            };
            self.record_attempt(provider.as_ref());
            match provider.complete_streaming(req, &guarded).await {
                Ok(response) => {
                    self.record_contact(provider.as_ref(), true);
                    return Ok(response);
                }
                Err(err) => {
                    self.record_contact(provider.as_ref(), false);
                    // A hop may only happen before any byte was shown: a
                    // re-send after a visible delta would duplicate the turn.
                    let eligible = is_fallback_eligible(&err) && !emitted.load(Ordering::SeqCst);
                    if self.providers.get(index + 1).is_some() && eligible {
                        pending_reason = Some(fallback_reason(&err));
                        last = Some(err);
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(last.unwrap_or_else(|| ProviderError::InvalidResponse {
            provider: "fallback".to_string(),
            message: "the fallback chain has no providers".to_string(),
        }))
    }

    fn name(&self) -> &str {
        self.providers
            .first()
            .map(|provider| provider.name())
            .unwrap_or("fallback")
    }

    fn model(&self) -> Option<&str> {
        self.providers.first().and_then(|provider| provider.model())
    }

    fn endpoint_host(&self) -> Option<String> {
        self.served_host
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn endpoint_hosts(&self) -> Vec<String> {
        self.contacted_hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn contact_log(&self) -> Option<Vec<Contact>> {
        Some(
            self.attempts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::privacy::PrivacyMode;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    struct Stub {
        name: &'static str,
        host: Option<String>,
        outcome: Mutex<Option<Result<ChatResponse, ProviderError>>>,
    }

    impl Stub {
        fn ok(name: &'static str, content: &str) -> Self {
            Self {
                name,
                host: None,
                outcome: Mutex::new(Some(Ok(ChatResponse::assistant(content)))),
            }
        }
        fn err(name: &'static str, err: ProviderError) -> Self {
            Self {
                name,
                host: None,
                outcome: Mutex::new(Some(Err(err))),
            }
        }
    }

    #[async_trait]
    impl ChatProvider for Stub {
        async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.outcome.lock().unwrap().take().expect("one call")
        }
        fn name(&self) -> &str {
            self.name
        }

        fn endpoint_host(&self) -> Option<String> {
            self.host.clone()
        }
    }

    /// A fallback provider that counts every request it receives.
    struct CountingStub {
        name: &'static str,
        content: &'static str,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ChatProvider for CountingStub {
        async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ChatResponse::assistant(self.content))
        }
        fn name(&self) -> &str {
            self.name
        }
    }

    /// A real kernel admission on `A3`, which is `Disabled` in Private mode: a
    /// fallback that must be refused without a send.
    struct DisabledKernelAdmission;

    impl FallbackAdmission for DisabledKernelAdmission {
        fn admit(&self, provider: &str, _path: PathId) -> Result<Option<Grant>, ProviderError> {
            admit_call(
                PathId::A3,
                PrivacyMode::Private,
                Destination::Vendor(provider.to_string()),
            )
            .map(Some)
            .map_err(|refused| ProviderError::PrivacyDisabled {
                provider: shown_id_plain(provider),
                path: refused.path.as_str(),
            })
        }
    }

    fn fixed_private() -> ModeFn {
        Arc::new(|| PrivacyMode::Private)
    }

    fn empty_request() -> ChatRequest {
        ChatRequest::new(Vec::new())
    }

    fn server(name: &str, status: u16) -> ProviderError {
        ProviderError::Server {
            provider: name.to_string(),
            status,
        }
    }

    fn timeout(name: &str) -> ProviderError {
        ProviderError::Timeout {
            provider: name.to_string(),
        }
    }

    #[tokio::test]
    async fn a_503_hops_once_and_the_second_provider_answers() {
        let ledger = Arc::new(RecordingLedger::default());
        let chain = FallbackProvider::with_ledger(
            vec![
                Box::new(Stub::err("deepseek", server("deepseek", 503))),
                Box::new(Stub::ok("anthropic", "answered")),
            ],
            ledger.clone(),
        );
        let response = chain.complete(&empty_request()).await.unwrap();
        assert_eq!(response.content(), "answered");
        assert_eq!(
            ledger.hops(),
            vec![FallbackHop {
                from: "deepseek".into(),
                to: "anthropic".into(),
                reason: "server_error".into(),
            }]
        );
    }

    #[tokio::test]
    async fn a_fallback_reports_the_serving_host_and_every_host_tried() {
        let mut first = Stub::err("deepseek", timeout("deepseek"));
        first.host = Some("api.deepseek.test".into());
        let mut second = Stub::ok("anthropic", "answered");
        second.host = Some("api.anthropic.test".into());
        let chain = FallbackProvider::new(vec![Box::new(first), Box::new(second)]);

        assert!(chain.complete(&empty_request()).await.is_ok());

        assert_eq!(chain.endpoint_host().as_deref(), Some("api.anthropic.test"));
        assert_eq!(
            chain.endpoint_hosts(),
            ["api.deepseek.test", "api.anthropic.test"]
        );
    }

    #[tokio::test]
    async fn a_529_hop_is_eligible_and_a_timeout_is_eligible() {
        for (err, reason) in [
            (server("deepseek", 529), "server_error"),
            (timeout("deepseek"), "timeout"),
        ] {
            let ledger = Arc::new(RecordingLedger::default());
            let chain = FallbackProvider::with_ledger(
                vec![
                    Box::new(Stub::err("deepseek", err)),
                    Box::new(Stub::ok("anthropic", "answered")),
                ],
                ledger.clone(),
            );
            assert!(chain.complete(&empty_request()).await.is_ok());
            assert_eq!(ledger.hops()[0].reason, reason);
        }
    }

    #[tokio::test]
    async fn a_400_or_a_429_never_hops() {
        for err in [
            ProviderError::Client {
                provider: "deepseek".into(),
                status: 400,
                message: "bad request".into(),
            },
            ProviderError::RateLimited {
                provider: "deepseek".into(),
                retry_after: None,
            },
            ProviderError::Unauthorized {
                provider: "deepseek".into(),
            },
        ] {
            let ledger = Arc::new(RecordingLedger::default());
            let chain = FallbackProvider::with_ledger(
                vec![
                    Box::new(Stub::err("deepseek", err)),
                    Box::new(Stub::ok("anthropic", "answered")),
                ],
                ledger.clone(),
            );
            assert!(chain.complete(&empty_request()).await.is_err());
            assert!(ledger.hops().is_empty(), "an ineligible error must not hop");
        }
    }

    #[tokio::test]
    async fn a_refusal_never_hops() {
        let ledger = Arc::new(RecordingLedger::default());
        let chain = FallbackProvider::with_ledger(
            vec![
                Box::new(Stub::err(
                    "anthropic",
                    ProviderError::Refused {
                        provider: "anthropic".into(),
                        category: "refusal".into(),
                    },
                )),
                Box::new(Stub::ok("deepseek", "answered")),
            ],
            ledger.clone(),
        );
        assert!(chain.complete(&empty_request()).await.is_err());
        assert!(ledger.hops().is_empty());
    }

    #[tokio::test]
    async fn every_eligible_hop_is_recorded_in_order_and_then_the_turn_fails() {
        let ledger = Arc::new(RecordingLedger::default());
        let chain = FallbackProvider::with_ledger(
            vec![
                Box::new(Stub::err("deepseek", server("deepseek", 500))),
                Box::new(Stub::err("anthropic", server("anthropic", 502))),
                Box::new(Stub::err("ollama-cloud", timeout("ollama-cloud"))),
            ],
            ledger.clone(),
        );
        assert!(chain.complete(&empty_request()).await.is_err());
        assert_eq!(
            ledger
                .hops()
                .iter()
                .map(|hop| (hop.from.as_str(), hop.to.as_str()))
                .collect::<Vec<_>>(),
            vec![("deepseek", "anthropic"), ("anthropic", "ollama-cloud")]
        );
    }

    #[tokio::test]
    async fn streaming_does_not_hop_after_a_visible_delta() {
        // A provider that emits one delta and then fails mid-stream must not
        // be replayed on the next provider.
        struct HalfStream;
        #[async_trait]
        impl ChatProvider for HalfStream {
            async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
                unreachable!()
            }
            async fn complete_streaming(
                &self,
                _req: &ChatRequest,
                sink: &(dyn Fn(ChatDelta) + Send + Sync),
            ) -> Result<ChatResponse, ProviderError> {
                sink(ChatDelta::Text("half".into()));
                Err(ProviderError::Timeout {
                    provider: "half".into(),
                })
            }
            fn name(&self) -> &str {
                "half"
            }
        }
        let ledger = Arc::new(RecordingLedger::default());
        let chain = FallbackProvider::with_ledger(
            vec![
                Box::new(HalfStream),
                Box::new(Stub::ok("anthropic", "answered")),
            ],
            ledger.clone(),
        );
        let seen = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| seen.lock().unwrap().push(delta);
        assert!(chain
            .complete_streaming(&empty_request(), &sink)
            .await
            .is_err());
        assert!(ledger.hops().is_empty());
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn streaming_hops_before_any_delta() {
        let ledger = Arc::new(RecordingLedger::default());
        let chain = FallbackProvider::with_ledger(
            vec![
                Box::new(Stub::err("deepseek", server("deepseek", 503))),
                Box::new(Stub::ok("anthropic", "answered")),
            ],
            ledger.clone(),
        );
        let seen = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| seen.lock().unwrap().push(delta);
        let response = chain
            .complete_streaming(&empty_request(), &sink)
            .await
            .unwrap();
        assert_eq!(response.content(), "answered");
        assert_eq!(ledger.hops().len(), 1);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// A fallback destination that is not admitted must
    /// get zero requests and leave no Ledger hop row.
    #[tokio::test]
    async fn private_mode_fallback_is_not_admitted_and_gets_no_request() {
        let ledger = Arc::new(RecordingLedger::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let chain = FallbackProvider::with_admission(
            vec![
                Box::new(Stub::err("deepseek", server("deepseek", 503))),
                Box::new(CountingStub {
                    name: "anthropic",
                    content: "must not run",
                    calls: Arc::clone(&calls),
                }),
            ],
            ledger.clone(),
            Arc::new(DisabledKernelAdmission),
        );

        let err = chain.complete(&empty_request()).await.unwrap_err();

        assert!(
            matches!(err, ProviderError::PrivacyDisabled { .. }),
            "got {err:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a refused fallback must get zero requests"
        );
        assert!(
            ledger.hops().is_empty(),
            "a refused hop writes no provider.fallback row"
        );
    }

    /// When the hop *is* admitted, the fallback runs and
    /// the `provider.fallback` row still appears.
    #[tokio::test]
    async fn an_admitted_hop_writes_the_ledger_row_and_reaches_the_fallback() {
        let ledger = Arc::new(RecordingLedger::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let chain = FallbackProvider::gated(
            vec![
                Box::new(Stub::err("deepseek", server("deepseek", 503))),
                Box::new(CountingStub {
                    name: "anthropic",
                    content: "answered",
                    calls: Arc::clone(&calls),
                }),
            ],
            ledger.clone(),
            fixed_private(),
        );

        let response = chain.complete(&empty_request()).await.unwrap();

        assert_eq!(response.content(), "answered");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(ledger.hops().len(), 1);
        assert_eq!(
            (ledger.hops()[0].from.as_str(), ledger.hops()[0].to.as_str()),
            ("deepseek", "anthropic")
        );
    }
}
