//! The provider choke point (`docs/phase1.md` §2: every byte that reaches a
//! provider passes `admit()` and a `Gate`).
//!
//! [`GatedChat`] wraps the provider a turn, an agent run or a channel reply uses.
//! Every completion asks the privacy gate first, so a provider cannot be
//! reached around it. Streaming is A1, a single completion is A2.
//!
//! The mode is read at each completion, not once when the wrapper is built: a
//! turn that started in public mode must not keep calling a provider after the
//! owner switches to private.

use crate::config::shown_id_plain;
use crate::error::ProviderError;
use crate::provider::ChatProvider;
use crate::types::{ChatDelta, ChatRequest, ChatResponse};
use async_trait::async_trait;
use kernel_core::privacy::{admit_call, Destination, Grant, ModeFn, PathId};

/// A chat provider behind the privacy gate.
pub struct GatedChat<'a> {
    inner: &'a dyn ChatProvider,
    live: ModeFn,
}

impl<'a> GatedChat<'a> {
    /// Gate `inner`. `live` returns the mode in force for each completion.
    pub fn new(inner: &'a dyn ChatProvider, live: ModeFn) -> Self {
        Self { inner, live }
    }

    /// Admit one completion on `path`. The grant lives for the call.
    fn admit(&self, path: PathId) -> Result<Grant, ProviderError> {
        let provider = self.inner.name();
        let mode = (self.live)();
        admit_call(path, mode, Destination::Vendor(provider.to_string())).map_err(|refused| {
            ProviderError::PrivacyDisabled {
                provider: shown_id_plain(provider),
                path: refused.path.as_str(),
            }
        })
    }
}

#[async_trait]
impl ChatProvider for GatedChat<'_> {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let _grant = self.admit(PathId::A2)?;
        self.inner.complete(req).await
    }

    async fn complete_streaming(
        &self,
        req: &ChatRequest,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        let _grant = self.admit(PathId::A1)?;
        self.inner.complete_streaming(req, sink).await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn model(&self) -> Option<&str> {
        self.inner.model()
    }

    fn endpoint_host(&self) -> Option<String> {
        self.inner.endpoint_host()
    }

    fn endpoint_hosts(&self) -> Vec<String> {
        self.inner.endpoint_hosts()
    }

    fn contact_log(&self) -> Option<Vec<crate::Contact>> {
        self.inner.contact_log()
    }

    fn on_this_mac(&self) -> bool {
        self.inner.on_this_mac()
    }

    fn subscription_billed(&self) -> bool {
        self.inner.subscription_billed()
    }
}

#[cfg(test)]
mod tests {

    /// A gate that tokenises: C9 is the one covered row private mode allows.
    fn tokenising_gate(key: [u8; 32]) -> kernel_privacy::safetext::Gate {
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        kernel_privacy::safetext::Gate::for_tests(&grant, key, crate::test_gate::names_checked())
    }
    use super::*;
    use crate::fake::FakeProvider;
    use crate::types::{ChatMessage, SafeMessage};
    use kernel_core::privacy::PrivacyMode;
    use std::sync::Arc;

    fn request() -> ChatRequest {
        let hello =
            SafeMessage::issue(&mut tokenising_gate([5u8; 32]), &ChatMessage::user("hello"))
                .unwrap();
        ChatRequest::new(vec![hello])
    }

    fn fixed(mode: PrivacyMode) -> ModeFn {
        Arc::new(move || mode)
    }

    #[tokio::test]
    async fn private_mode_admits_the_covered_chat_paths() {
        // kernel-0.0.2 covers A1 and A2 in private mode. The names check runs
        // upstream, in the session gate: a request reaching this wrapper is
        // already SafeMessage, so the wrapper only admits the call.
        let fake = FakeProvider::echo("main");
        let gated = GatedChat::new(&fake, fixed(PrivacyMode::Private));

        assert!(gated.complete(&request()).await.is_ok(), "A2 runs");
        assert!(
            gated
                .complete_streaming(&request(), &|_: ChatDelta| {})
                .await
                .is_ok(),
            "A1 runs"
        );
        assert_eq!(fake.request_count(), 2, "both calls reach the adapter");
    }

    #[tokio::test]
    async fn public_mode_passes_calls_through_unchanged() {
        let fake = FakeProvider::echo("main");
        let gated = GatedChat::new(&fake, fixed(PrivacyMode::Open));

        assert!(gated.complete(&request()).await.is_ok());
        assert_eq!(gated.name(), "main");
        assert_eq!(fake.request_count(), 1);
    }

    #[tokio::test]
    async fn the_mode_is_read_at_each_completion() {
        // The same wrapper, built once, reads the mode for every completion: a
        // switch is seen by the next call, in either direction.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let private = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let (flag, count) = (Arc::clone(&private), Arc::clone(&reads));
        let live: ModeFn = Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            if flag.load(Ordering::SeqCst) {
                PrivacyMode::Private
            } else {
                PrivacyMode::Open
            }
        });
        let fake = FakeProvider::echo("main");
        let gated = GatedChat::new(&fake, live);

        assert!(gated.complete(&request()).await.is_ok(), "public: runs");
        private.store(true, Ordering::SeqCst);
        assert!(gated.complete(&request()).await.is_ok(), "private: A2 runs");
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "one mode read per completion"
        );
        assert_eq!(fake.request_count(), 2);
    }
}
