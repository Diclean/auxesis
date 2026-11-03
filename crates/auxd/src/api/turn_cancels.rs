//! In-flight turn cancellation tokens, keyed by agent (B-API v3 × E-18).
//!
//! EH-1 made one turn cancellable through a per-turn [`TurnCancel`] token
//! (client disconnect, request timeout). B-API v3 made per-agent pause/kill
//! and stop-all end a turn at the next engine step boundary. Merged, the
//! control endpoints also fire the tokens of every turn currently running for
//! that agent (every agent for stop-all), so a kill lands immediately: the engine
//! aborts its provider/tool await, the shell tool reaps its process tree, and
//! the runner retires the turn's pending approvals (P2-1) — the same cleanup
//! a client-disconnect cancellation gets, instead of waiting for the next
//! boundary.
//!
//! Registration is scoped to one route call: the guard returned by
//! [`TurnCancels::register`] keeps the token reachable and removes it when the
//! turn ends (or the request is dropped).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aux_engine::TurnCancel;

/// Every in-flight turn's cancellation token, keyed by agent.
#[derive(Debug, Default)]
pub struct TurnCancels {
    inner: Mutex<HashMap<String, Vec<Arc<TurnCancel>>>>,
}

impl TurnCancels {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a token for a new turn of `agent` and keep it registered until
    /// the returned guard drops.
    pub fn register(self: &Arc<Self>, agent: &str) -> TurnRegistration {
        let token = TurnCancel::new();
        kernel_core::lock_recover(&self.inner)
            .entry(agent.to_string())
            .or_default()
            .push(Arc::clone(&token));
        TurnRegistration {
            registry: Arc::clone(self),
            agent: agent.to_string(),
            token,
        }
    }

    /// True while a turn of `agent` is in flight.
    pub fn in_flight(&self, agent: &str) -> bool {
        kernel_core::lock_recover(&self.inner).contains_key(agent)
    }

    /// Fire every in-flight token of `agent` (per-agent pause/kill).
    pub fn cancel_agent(&self, agent: &str) {
        let tokens: Vec<Arc<TurnCancel>> = kernel_core::lock_recover(&self.inner)
            .get(agent)
            .cloned()
            .unwrap_or_default();
        for token in tokens {
            token.cancel();
        }
    }

    /// Fire every in-flight token (stop-all).
    pub fn cancel_all(&self) {
        let tokens: Vec<Arc<TurnCancel>> = kernel_core::lock_recover(&self.inner)
            .values()
            .flatten()
            .cloned()
            .collect();
        for token in tokens {
            token.cancel();
        }
    }
}

/// One registered turn: the guard keeps the token in the registry and removes
/// it on drop (the turn finished, cancelled or not).
pub struct TurnRegistration {
    registry: Arc<TurnCancels>,
    agent: String,
    token: Arc<TurnCancel>,
}

impl TurnRegistration {
    /// The turn's cancellation token, to hand to the runner and to the
    /// route's drop guard.
    pub fn token(&self) -> Arc<TurnCancel> {
        Arc::clone(&self.token)
    }
}

impl Drop for TurnRegistration {
    fn drop(&mut self) {
        let mut inner = kernel_core::lock_recover(&self.registry.inner);
        if let Some(tokens) = inner.get_mut(&self.agent) {
            tokens.retain(|token| !Arc::ptr_eq(token, &self.token));
            if tokens.is_empty() {
                inner.remove(&self.agent);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kill_fires_only_the_agents_in_flight_tokens() {
        let cancels = Arc::new(TurnCancels::new());
        let main = cancels.register("main");
        let scout = cancels.register("scout");

        cancels.cancel_agent("main");
        assert!(main.token().is_cancelled());
        assert!(!scout.token().is_cancelled());

        // A turn that finished is deregistered: the next kill cannot fire it.
        drop(main);
        cancels.cancel_agent("main");
        assert!(!scout.token().is_cancelled());
    }

    #[test]
    fn stop_all_fires_every_in_flight_token_and_registration_cleans_up() {
        let cancels = Arc::new(TurnCancels::new());
        let main = cancels.register("main");
        let scout = cancels.register("scout");
        cancels.cancel_all();
        assert!(main.token().is_cancelled());
        assert!(scout.token().is_cancelled());

        drop(main);
        drop(scout);
        assert!(
            kernel_core::lock_recover(&cancels.inner).is_empty(),
            "the registry must not leak finished turns"
        );
    }
}
