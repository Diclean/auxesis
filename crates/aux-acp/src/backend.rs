//! The turn-level ACP backend.
//!
//! One turn = spawn the agent, initialize, `session/new`, one
//! `session/prompt`, then persist **one** assistant message and settle the
//! budget conservatively. The backend is the only place ACP output reaches
//! the engine: everything it returns is marked tainted, and the wall-clock
//! and output caps are enforced here.
//!
//! TODO: once the streaming `message.delta` path lands, the
//! [`TurnObserver::message_chunk`] callback becomes a live delta
//! emitter; today the backend accumulates and emits the final message only.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use kernel_broker::sandbox::ShellSandbox;
use kernel_broker::{Approver, CancelToken};
use kernel_privacy::SafeText;

use crate::client::{AcpClient, PromptOutcome, TurnObserver, TurnStats};
use crate::config::{AcpAgentSpec, AcpLimits};
use crate::error::AcpError;
use crate::handlers::{HandlerLimits, HostGate, TurnState};
use crate::ledger::TurnHost;
use crate::protocol::UsageUpdate;
use crate::supervisor::SupervisorSpec;

/// Runtime configuration of one ACP backend.
#[derive(Debug, Clone)]
pub struct AcpBackendConfig {
    /// Master flag (`[acp] enabled`): refuses every turn while false.
    pub enabled: bool,
    /// Agent the turns belong to (approval cards, budgets, taint).
    pub agent_name: String,
    /// The resolved agent.
    pub agent: AcpAgentSpec,
    /// Hard caps.
    pub limits: AcpLimits,
    /// Sandbox settings (network is always on for ACP: the agent must reach
    /// its vendor API).
    pub sandbox: ShellSandbox,
    /// Per-agent scratch workspace.
    pub workspace: PathBuf,
    /// Read-only turn (an ACP turn used as a brain): the broker refuses every
    /// write or exec method. `false` keeps the coding-agent behaviour.
    pub read_only: bool,
    /// Test seam: the "real home" the sandbox denies. `None` reads `$HOME`.
    pub sandbox_home: Option<PathBuf>,
}

/// One turn's input.
pub struct AcpTurnRequest {
    /// The user prompt, already through the privacy gate: only a [`SafeText`]
    /// the session's gate issued can reach the agent.
    pub prompt: SafeText,
    /// The turn's cancellation token (client disconnect, timeout, kill).
    pub cancel: Option<Arc<CancelToken>>,
    /// Turns already run in this task (thread): refused at
    /// `[acp] max_turns_per_task`.
    pub turns_used: u32,
}

/// One turn's result.
#[derive(Debug, Clone, PartialEq)]
pub struct AcpTurnResult {
    /// Final assistant text (capped).
    pub text: String,
    /// The agent's `stopReason`.
    pub stop_reason: Option<String>,
    /// Best-effort usage observed from `usage_update`.
    pub usage: UsageUpdate,
    /// Stream counters.
    pub stats: TurnStats,
    /// Id of the persisted assistant message.
    pub message_id: i64,
}

/// A turn-level agent backend (the engine's alternative to the
/// provider+tool loop).
#[async_trait]
pub trait AgentBackend: Send {
    /// Backend kind label (`acp`).
    fn kind(&self) -> &'static str;

    /// Agent id (`opencode`, ...).
    fn agent_id(&self) -> &str;

    /// Run one turn to completion.
    async fn run_turn(
        &mut self,
        request: AcpTurnRequest,
        observer: &mut dyn TurnObserver,
    ) -> Result<AcpTurnResult, AcpError>;
}

/// The ACP implementation of [`AgentBackend`].
pub struct AcpBackend {
    config: AcpBackendConfig,
    approver: Arc<dyn Approver>,
    host: Box<dyn TurnHost>,
    /// The private-mode session gate for host text (D2, D3, D4); `None` in open mode.
    host_gate: Option<Arc<dyn HostGate>>,
    /// Private mode: the neutral directory the agent process lives in; the
    /// configured workspace then belongs to the host handlers alone.
    agent_scratch: Option<PathBuf>,
    /// Per-turn random marker injected into the agent's and terminals'
    /// environments (the reaper's env anchor).
    turn_marker: String,
}

impl AcpBackend {
    /// Build a backend for one agent.
    pub fn new(
        config: AcpBackendConfig,
        approver: Arc<dyn Approver>,
        host: Box<dyn TurnHost>,
    ) -> Self {
        Self {
            config,
            approver,
            host,
            host_gate: None,
            agent_scratch: None,
            turn_marker: crate::reaper::new_turn_marker(),
        }
    }

    /// Run this backend's turns in private mode: file reads and terminal output
    /// the host serves the agent are tokenised through `gate`, and permission
    /// asks are shown to the owner with their values. The agent itself runs in
    /// `scratch`, an empty directory (its cwd and the only place its sandbox
    /// opens), so the real workspace reaches it only through those handlers.
    /// Its environment keeps only the variables it authenticates with.
    pub fn with_host_gate(mut self, gate: Arc<dyn HostGate>, scratch: PathBuf) -> Self {
        self.host_gate = Some(gate);
        self.agent_scratch = Some(scratch);
        self
    }

    /// The configured agent.
    pub fn agent(&self) -> &AcpAgentSpec {
        &self.config.agent
    }

    /// Mutable access to the agent spec (tests: swap scenarios between
    /// turns).
    pub fn agent_mut(&mut self) -> &mut AcpAgentSpec {
        &mut self.config.agent
    }

    /// Build the supervisor spec for this backend.
    fn supervisor_spec(&self) -> Result<SupervisorSpec, AcpError> {
        // The workspace itself is created by the daemon through the verified
        // home gateway before this backend runs (`run_acp_turn`); a missing
        // workspace fails closed in `AgentProcess::spawn`.
        let mut env_passthrough = Vec::new();
        for name in &self.config.agent.env_passthrough {
            // Private: a passthrough value is host text the gate never saw; only
            // the agent's own credentials cross.
            if self.host_gate.is_some() && !crate::config::env_name_is_credential(name) {
                tracing::debug!(name = %name, "acp: passthrough dropped in private mode");
                continue;
            }
            match std::env::var_os(name) {
                Some(value) => {
                    let value = value.to_string_lossy().into_owned();
                    env_passthrough.push((name.clone(), value));
                }
                None => tracing::debug!(name = %name, "acp: passthrough variable is unset"),
            }
        }
        let (workspace, host_workspace) = match &self.agent_scratch {
            Some(scratch) => (scratch.clone(), Some(self.config.workspace.clone())),
            None => (self.config.workspace.clone(), None),
        };
        Ok(SupervisorSpec {
            command: self.config.agent.command.clone(),
            args: self.config.agent.args.clone(),
            workspace,
            host_workspace,
            vendor_data_read: self.config.agent.vendor_data_dir.clone(),
            env_passthrough,
            sandbox: self.config.sandbox.clone(),
            sandbox_home: self.config.sandbox_home.clone(),
            turn_marker: self.turn_marker.clone(),
            max_cpu_seconds: if self.config.limits.max_cpu_seconds > 0 {
                self.config.limits.max_cpu_seconds
            } else {
                self.config.limits.turn_timeout.as_secs().saturating_add(30)
            },
            max_file_bytes: self.config.limits.max_file_bytes,
            max_open_files: self.config.limits.max_open_files,
            max_processes: self.config.limits.max_processes,
            max_memory_bytes: self.config.limits.max_memory_bytes,
            kill_grace: crate::supervisor::DEFAULT_KILL_GRACE,
            stderr_cap_bytes: crate::supervisor::DEFAULT_STDERR_CAP_BYTES,
            stderr_max_lines: crate::supervisor::DEFAULT_STDERR_MAX_LINES,
        })
    }

    /// The message metadata persisted with the final assistant row.
    fn assistant_meta(&self, outcome: &PromptOutcome) -> String {
        json!({
            "tool": "acp",
            "status": "ok",
            // Every agent-originated text is untrusted, exactly like web
            // content: the conversation must stay tainted.
            "tainted": true,
            "acp": {
                "agent": self.config.agent.id,
                "model": self.config.agent.model,
                "stop_reason": outcome.stop_reason,
                "chunks": outcome.stats.chunks,
                "thoughts": outcome.stats.thoughts,
                "tool_calls": outcome.stats.tool_calls,
                "plans": outcome.stats.plans,
                "unknown_updates": outcome.stats.unknown,
                "dropped_updates": outcome.stats.dropped,
                "truncated": outcome.stats.truncated,
                "usage": {
                    "used": outcome.usage.used,
                    "size": outcome.usage.size,
                    "cost_amount": outcome.usage.cost_amount,
                    "cost_currency": outcome.usage.cost_currency,
                },
            },
        })
        .to_string()
    }
}

#[async_trait]
impl AgentBackend for AcpBackend {
    fn kind(&self) -> &'static str {
        "acp"
    }

    fn agent_id(&self) -> &str {
        &self.config.agent.id
    }

    async fn run_turn(
        &mut self,
        request: AcpTurnRequest,
        observer: &mut dyn TurnObserver,
    ) -> Result<AcpTurnResult, AcpError> {
        if !self.config.enabled {
            return Err(AcpError::Config(
                "ACP is disabled: set `[acp] enabled = true` in config.toml to opt in".to_string(),
            ));
        }
        let max_turns = self.config.limits.max_turns_per_task;
        if max_turns > 0 && request.turns_used >= max_turns {
            return Err(AcpError::Config(format!(
                "this task reached its {max_turns}-turn ACP cap"
            )));
        }
        let limits = self.config.limits.clone();
        // Reserve the fixed conservative estimate *before* anything runs.
        let reservation = self.host.reserve_turn(limits.turn_cost_estimate_cents)?;
        let spec = self.supervisor_spec()?;
        let state = Arc::new(TurnState::default());
        let approver = Arc::clone(&self.approver);
        let agent_name = self.config.agent_name.clone();
        let prompt = request.prompt.clone();
        let cancel = request.cancel.clone();

        let fut = run_session(
            spec,
            agent_name,
            limits.clone(),
            approver,
            state,
            prompt,
            cancel,
            self.config.read_only,
            self.host_gate.clone(),
            observer,
        );
        let result = tokio::time::timeout(limits.turn_timeout, fut).await;

        match result {
            Err(_) => {
                // The agent had the whole window: settle conservatively.
                if let Err(err) = self.host.settle_turn(reservation, &UsageUpdate::default()) {
                    tracing::warn!(error = %err, "acp: settling a timed-out turn failed");
                }
                self.host.taint_session("acp (timed out)");
                Err(AcpError::TurnTimeout {
                    limit_secs: limits.turn_timeout.as_secs(),
                })
            }
            Ok(Err(err)) => {
                // Even a failed or cancelled turn may have consumed quota;
                // settle the fixed estimate (conservative by design).
                if let Err(settle_err) = self.host.settle_turn(reservation, &UsageUpdate::default())
                {
                    tracing::warn!(error = %settle_err, "acp: settling a failed turn failed");
                }
                self.host.taint_session("acp");
                Err(err)
            }
            Ok(Ok(mut outcome)) => {
                // Defence in depth: scrub and tag at the persistence/return
                // boundary even though the client already did, so no path
                // can store or forward raw agent text. Agent-controlled
                // metadata (`stopReason`, usage currency) is scrubbed too.
                outcome.text =
                    crate::scrub::tagged_agent_text(&crate::scrub::scrub_agent_text(&outcome.text));
                outcome.stop_reason = outcome
                    .stop_reason
                    .as_deref()
                    .map(crate::scrub::scrub_agent_text);
                outcome.usage.cost_currency = outcome
                    .usage
                    .cost_currency
                    .as_deref()
                    .map(crate::scrub::scrub_agent_text);
                if outcome.stats.truncated {
                    outcome.text.push_str(&format!(
                        "\n[output truncated at {} bytes]",
                        limits.max_output_bytes
                    ));
                }
                let meta = self.assistant_meta(&outcome);
                // Write-ahead taint *before* the agent text is persisted: a
                // crash right after cannot launder the conversation.
                self.host.taint_session("acp");
                self.host
                    .settle_turn(reservation, &outcome.usage)
                    .map_err(|err| {
                        tracing::warn!(error = %err, "acp: settling the turn failed");
                        err
                    })?;
                let message = self.host.persist_assistant(&outcome.text, &meta)?;
                self.host.emit_message(&message);
                self.host.emit_done(message.id);
                Ok(AcpTurnResult {
                    text: outcome.text,
                    stop_reason: outcome.stop_reason,
                    usage: outcome.usage,
                    stats: outcome.stats,
                    message_id: message.id,
                })
            }
        }
    }
}

/// Spawn, handshake, prompt, then always shut the process down.
#[allow(clippy::too_many_arguments)] // one call site; a struct would not read better
async fn run_session(
    spec: SupervisorSpec,
    agent_name: String,
    limits: AcpLimits,
    approver: Arc<dyn Approver>,
    state: Arc<TurnState>,
    prompt: SafeText,
    cancel: Option<Arc<CancelToken>>,
    read_only: bool,
    host_gate: Option<Arc<dyn HostGate>>,
    observer: &mut dyn TurnObserver,
) -> Result<PromptOutcome, AcpError> {
    let handler_limits = HandlerLimits {
        host_gate,
        permission_timeout: limits.permission_timeout,
        terminal_wait_timeout: limits.turn_timeout,
        sandbox: spec.sandbox.clone(),
        turn_marker: spec.turn_marker.clone(),
        ..HandlerLimits::default()
    };
    let mut client = AcpClient::start(
        &spec,
        &agent_name,
        &limits,
        approver,
        handler_limits,
        state,
        read_only,
    )
    .await?;
    let result = client.prompt(&prompt, cancel, observer).await;
    // Graceful first: SIGTERM, then the whole tree. `prompt` already sent
    // `session/cancel` on its cancellation path.
    client.shutdown().await;
    result
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
        kernel_privacy::safetext::Gate::for_tests(
            &grant,
            key,
            aux_providers::test_gate::names_checked(),
        )
    }

    use super::*;
    fn safe(text: &str) -> SafeText {
        tokenising_gate([7u8; 32]).text(text).unwrap().0
    }

    use crate::ledger::{TurnHost, TurnReservation};
    use crate::protocol::UsageUpdate;
    use aux_store::Message;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingHost {
        reserved: Mutex<Vec<u64>>,
        settled: Mutex<usize>,
        persisted: Mutex<Vec<(String, String)>>,
        taints: Mutex<Vec<String>>,
        messages: Mutex<Vec<i64>>,
        dones: Mutex<Vec<i64>>,
    }

    impl TurnHost for RecordingHost {
        fn reserve_turn(&mut self, cost_cents: u64) -> Result<Option<TurnReservation>, AcpError> {
            self.reserved.lock().unwrap().push(cost_cents);
            // No store in this test: an "unlimited" admission.
            Ok(None)
        }

        fn settle_turn(
            &mut self,
            _reservation: Option<TurnReservation>,
            _observed: &UsageUpdate,
        ) -> Result<(), AcpError> {
            *self.settled.lock().unwrap() += 1;
            Ok(())
        }

        fn persist_assistant(&mut self, text: &str, meta: &str) -> Result<Message, AcpError> {
            self.persisted
                .lock()
                .unwrap()
                .push((text.to_string(), meta.to_string()));
            Ok(Message {
                id: 7,
                session_id: 1,
                role: "assistant".to_string(),
                content: text.to_string(),
                meta: Some(meta.to_string()),
                created_at: String::new(),
            })
        }

        fn emit_message(&mut self, message: &Message) {
            self.messages.lock().unwrap().push(message.id);
        }

        fn emit_done(&mut self, message_id: i64) {
            self.dones.lock().unwrap().push(message_id);
        }

        fn taint_session(&mut self, source: &str) {
            self.taints.lock().unwrap().push(source.to_string());
        }
    }

    fn backend(host: RecordingHost, enabled: bool, max_turns: u32) -> AcpBackend {
        let limits = AcpLimits {
            max_turns_per_task: max_turns,
            ..AcpLimits::default()
        };
        AcpBackend::new(
            AcpBackendConfig {
                enabled,
                agent_name: "main".to_string(),
                agent: AcpAgentSpec::new("fake", "/bin/true", vec![]),
                limits,
                sandbox: ShellSandbox::new(false, false, true)
                    .with_test_sandbox_exec("/nonexistent"),
                workspace: std::env::temp_dir().join("aux-acp-backend-test"),
                sandbox_home: None,
                read_only: false,
            },
            Arc::new(aux_engine::DenyApprover),
            Box::new(host),
        )
    }

    #[tokio::test]
    async fn disabled_backend_refuses_before_anything_runs() {
        let mut backend = backend(RecordingHost::default(), false, 20);
        let err = backend
            .run_turn(
                AcpTurnRequest {
                    prompt: safe("hi"),
                    cancel: None,
                    turns_used: 0,
                },
                &mut crate::client::NullObserver,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disabled"), "{err}");
    }

    #[tokio::test]
    async fn turn_cap_refuses_before_reserving() {
        let mut backend = backend(RecordingHost::default(), true, 2);
        let err = backend
            .run_turn(
                AcpTurnRequest {
                    prompt: safe("hi"),
                    cancel: None,
                    turns_used: 2,
                },
                &mut crate::client::NullObserver,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cap"), "{err}");
    }

    #[test]
    fn assistant_meta_is_tainted_and_carries_the_counters() {
        let host = RecordingHost::default();
        let backend = backend(host, true, 20);
        let outcome = PromptOutcome {
            text: "hi".to_string(),
            stop_reason: Some("end_turn".to_string()),
            usage: UsageUpdate {
                used: Some(10),
                size: Some(100),
                cost_amount: None,
                cost_currency: None,
            },
            stats: TurnStats {
                chunks: 2,
                tool_calls: 1,
                ..TurnStats::default()
            },
        };
        let meta: serde_json::Value =
            serde_json::from_str(&backend.assistant_meta(&outcome)).unwrap();
        assert_eq!(meta["tainted"], true);
        assert_eq!(meta["acp"]["agent"], "fake");
        assert_eq!(meta["acp"]["stop_reason"], "end_turn");
        assert_eq!(meta["acp"]["usage"]["used"], 10);
    }
}
